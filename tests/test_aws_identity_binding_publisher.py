"""Network-denied adapter tests; no secret or real account is used."""
import asyncio
from datetime import datetime, timedelta, timezone
import socket
import sqlite3
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.aws_identity_binding_publisher import AwsIdentityBindingPublisher, IdentityPublicationError
from mapit.aws_tenant_session_reader import AwsTenantSessionReader, AwsTenantSessionReaderError
from mapit.durable_tenants import DurableTenantGuard, DurableTenantRecord, SQLiteTenantStore
from mapit.identity_binding import SecretPublicationReceipt
from mapit.tenant_router import InvitedTenantAuthority, tenant_key

ACCOUNT = "123456789012"
TOKEN = "synthetic-refresh-publisher"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("external networking forbidden")
    monkeypatch.setattr(socket, "create_connection", deny)


@pytest.fixture
def context():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    policy = CognitoDevPolicy("eu-west-1_Abcdefghi", "a1b2c3d4e5", "SyntheticClient", "00000000-0000-4000-8000-000000000001")
    key = tenant_key(b"t" * 32, policy.issuer_url, policy.owner_subject)
    authority = InvitedTenantAuthority({key: policy}, {"test": public}, environment="dev")
    now = int(time.time())
    token = jwt.encode({"iss": policy.issuer_url, "aud": policy.audience, "sub": policy.owner_subject,
                        "client_id": policy.client_id, "token_use": "access", "iat": now - 1,
                        "exp": now + 3600, "scope": policy.required_scope}, private,
                       algorithm="RS256", headers={"kid": "test"})
    grant = asyncio.run(authority.authenticate(token))
    connection = sqlite3.connect(":memory:")
    store = SQLiteTenantStore.initialize(connection)
    assert store.cas(key, None, DurableTenantRecord(key, "active", 1))
    guard = DurableTenantGuard(authority, store)
    yield authority, grant, guard, guard.capture(grant), store
    connection.close()


class Client:
    def __init__(self, *, change=None, after_put=None, fail_put=False):
        self.meta = SimpleNamespace(service_model=SimpleNamespace(service_name="ssm"),
                                    region_name="eu-west-1", endpoint_url="https://ssm.eu-west-1.amazonaws.com",
                                    config=SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=2))
        self.calls = []
        self.values = {}
        self.change, self.after_put, self.fail_put = change, after_put, fail_put

    def put_parameter(self, **kwargs):
        self.calls.append(("put", kwargs))
        if self.fail_put:
            raise TimeoutError("synthetic secret must not appear in diagnostics")
        self.values[kwargs["Name"]] = kwargs["Value"]
        if self.after_put:
            self.after_put()
        return {"Version": 1, "Tier": "Standard", "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_parameter(self, **kwargs):
        self.calls.append(("get", kwargs))
        path = kwargs["Name"].removesuffix(":1")
        parameter = {"Name": path, "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{path}",
                     "Type": "SecureString", "DataType": "text", "Version": 1, "Selector": ":1", "Value": self.values.get(path, TOKEN)}
        parameter.update(self.change or {})
        return {"Parameter": parameter, "ResponseMetadata": {"HTTPStatusCode": 200}}


def publisher(context, client, **overrides):
    authority, grant, guard, snapshot, _ = context
    kwargs = dict(authority=authority, grant=grant, durable_guard=guard, snapshot=snapshot,
                  environment="dev", account_id=ACCOUNT, deadline=time.monotonic() + 12,
                  account_verifier=lambda exact_client, account: exact_client is client and account == ACCOUNT)
    kwargs.update(overrides)
    return AwsIdentityBindingPublisher(client, **kwargs)


def publish(context, adapter, **overrides):
    path = f"/honda-mapit-mcp/dev/tenants/{context[1].key}/mapit-refresh-token"
    args = dict(path=path, version=1, refresh_token=TOKEN, create_only=True)
    args.update(overrides)
    return adapter.publish(**args)


def test_positive_create_only_exact_readback_and_no_replay(context):
    client = Client()
    adapter = publisher(context, client)
    result = publish(context, adapter)
    assert type(result) is SecretPublicationReceipt and result.created is True and result.version == 1
    assert len(client.calls) == 2
    assert client.calls[0][1] == dict(Name=result.path, Value=TOKEN, Type="SecureString", Tier="Standard",
                                      KeyId="alias/aws/ssm", DataType="text", Overwrite=False)
    assert client.calls[1][1] == dict(Name=result.path + ":1", WithDecryption=True)
    assert TOKEN not in repr(adapter) + repr(result)
    with pytest.raises(IdentityPublicationError, match="publication_already_used"):
        publish(context, adapter)
    assert len(client.calls) == 2


@pytest.mark.parametrize("change", [{"Version": True}, {"Version": 2}, {"Value": "foreign-refresh"},
                                   {"Type": "String"}, {"Selector": ":2"}, {"ARN": "foreign-arn"},
                                   {"SourceResult": "unexpected"}])
def test_readback_mismatch_fails_closed_and_consumes(context, change):
    client = Client(change=change)
    adapter = publisher(context, client)
    with pytest.raises(IdentityPublicationError, match="publication_readback_invalid"):
        publish(context, adapter)
    with pytest.raises(IdentityPublicationError, match="publication_already_used"):
        publish(context, adapter)
    assert len(client.calls) == 2


@pytest.mark.parametrize("change", [{"path": "/honda-mapit-mcp/prod/mapit-refresh-token"}, {"version": True},
                                   {"version": 2}, {"create_only": False}, {"refresh_token": "x" * 4097}])
def test_invalid_request_has_zero_calls(context, change):
    client = Client()
    with pytest.raises(IdentityPublicationError, match="publication_request_invalid"):
        publish(context, publisher(context, client), **change)
    assert not client.calls


def test_ambiguous_write_is_not_retried(context):
    client = Client(fail_put=True)
    adapter = publisher(context, client)
    with pytest.raises(IdentityPublicationError, match="publication_write_failed"):
        publish(context, adapter)
    with pytest.raises(IdentityPublicationError, match="publication_already_used"):
        publish(context, adapter)
    assert len(client.calls) == 1


def test_account_preflight_denial_has_zero_ssm_writes_and_consumes(context):
    client = Client()
    adapter = publisher(context, client, account_verifier=lambda exact_client, account: False)
    with pytest.raises(IdentityPublicationError, match="publication_unauthorized"):
        publish(context, adapter)
    with pytest.raises(IdentityPublicationError, match="publication_already_used"):
        publish(context, adapter)
    assert not client.calls


@pytest.mark.parametrize("result", [None, 1, "true"])
def test_non_boolean_account_proof_is_denied(context, result):
    client = Client()
    adapter = publisher(context, client, account_verifier=lambda exact_client, account: result)
    with pytest.raises(IdentityPublicationError, match="publication_unauthorized"):
        publish(context, adapter)
    assert not client.calls


def test_revocation_during_account_preflight_has_zero_ssm_calls(context):
    _, grant, _, _, store = context
    client = Client()
    def verify(exact_client, account):
        assert exact_client is client and account == ACCOUNT
        assert store.cas(grant.key, 1, DurableTenantRecord(grant.key, "revoked", 2))
        return True
    adapter = publisher(context, client, account_verifier=verify)
    with pytest.raises(IdentityPublicationError, match="publication_unauthorized"):
        publish(context, adapter)
    assert not client.calls


def test_revocation_after_write_prevents_readback_and_receipt(context):
    _, grant, _, _, store = context
    client = Client(after_put=lambda: store.cas(grant.key, 1, DurableTenantRecord(grant.key, "revoked", 2)))
    with pytest.raises(IdentityPublicationError, match="publication_unauthorized"):
        publish(context, publisher(context, client))
    assert len(client.calls) == 1


def test_wrong_environment_and_retry_configuration_rejected_before_calls(context):
    client = Client()
    with pytest.raises(IdentityPublicationError, match="publication_configuration_invalid"):
        publisher(context, client, environment="prod")
    client.meta.config.retries = {"total_max_attempts": 2}
    with pytest.raises(IdentityPublicationError, match="publication_configuration_invalid"):
        publisher(context, client)
    assert not client.calls


def test_explicit_dev_reader_never_reads_prod(context):
    authority, grant, _, _, _ = context
    client = Client()
    reader = AwsTenantSessionReader(authority, grant, client, account_id=ACCOUNT, version=1,
                                   tier="Standard", environment="dev")
    result = reader.read_refresh_token(deadline=time.monotonic() + 12)
    assert result.refresh_token == TOKEN
    assert client.calls[0][1]["Name"].startswith("/honda-mapit-mcp/dev/tenants/")
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_configuration_invalid"):
        AwsTenantSessionReader(authority, grant, client, account_id=ACCOUNT, version=1,
                               tier="Standard", environment="prod")


def test_actual_sdk_shapes_with_stubber_no_network(context):
    boto3 = pytest.importorskip("boto3")
    botocore = pytest.importorskip("botocore.config")
    from botocore.stub import Stubber
    client = boto3.client("ssm", region_name="eu-west-1", aws_access_key_id="synthetic",
                          aws_secret_access_key="synthetic", config=botocore.Config(
                              retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=2))
    adapter = publisher(context, client)
    path = f"/honda-mapit-mcp/dev/tenants/{context[1].key}/mapit-refresh-token"
    with Stubber(client) as stub:
        stub.add_response("put_parameter", {"Version": 1, "Tier": "Standard", "ResponseMetadata": {"HTTPStatusCode": 200}},
                          dict(Name=path, Value=TOKEN, Type="SecureString", Tier="Standard", KeyId="alias/aws/ssm", DataType="text", Overwrite=False))
        stub.add_response("get_parameter", {"Parameter": {"Name": path, "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{path}",
                          "Type": "SecureString", "DataType": "text", "Version": 1, "Selector": ":1", "Value": TOKEN},
                          "ResponseMetadata": {"HTTPStatusCode": 200}}, dict(Name=path + ":1", WithDecryption=True))
        assert publish(context, adapter).created
        stub.assert_no_pending_responses()
    client.close()


def test_registry_composes_real_adapter_contract_without_network(tmp_path):
    from test_identity_binding import TOKEN_A, _make_setup
    env = _make_setup(tmp_path)
    registry = env["factory"]()
    client = Client()
    adapter = AwsIdentityBindingPublisher(
        client, authority=env["authority"], grant=env["grant_a"],
        durable_guard=env["guard"], snapshot=env["snapshot_a"],
        environment="dev", account_id=ACCOUNT,
        account_verifier=lambda exact_client, account: exact_client is client and account == ACCOUNT,
        deadline=time.monotonic() + 12,
    )
    binding = registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=adapter)
    registry.validate_binding(env["grant_a"], env["snapshot_a"], binding)
    assert binding.secret_version == 1 and len(client.calls) == 2
    assert client.values[binding.secret_path] == TOKEN_A
    dump = "".join(registry._connection.iterdump())
    assert TOKEN_A not in dump
