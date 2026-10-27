"""New handler composition with real parsers/providers and synthetic SDK shapes."""
import asyncio
from dataclasses import asdict, replace
import hashlib
import json
import time
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit import aws_dev_enrolled_entrypoint as entry
from mapit.aws_binding_keys import BindingKeyMaterial, encode_binding_keys
from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.aws_enrollment_clients import EnrollmentAwsClients
from mapit.dev_enrolled_manifest import MANIFEST_FILENAME, INVITATION_JWKS_FILENAME, MAPIT_JWKS_FILENAME
from test_aws_binding_keys import client_and_response
from test_aws_dev_multiuser_entrypoint import _b64u
from test_aws_identity_binding import TABLE_ARN, _DynamoDocument, _registry
from test_enrolled_provider import ACCOUNT_ID, _Mapit, _PublishingSecrets, _SelectingAuth
from test_identity_binding import KEY_A, KEY_B, NOW, SUBJECT_A, SUBJECT_B, TOKEN_A, TOKEN_B, _AuthTransport, _make_setup
from test_invited_dev_lambda import _call, _token

NEW_TABLE = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT_ID}:table/honda-mapit-mcp-dev-mapit-identity-bindings"
KEY_PATH = "/honda-mapit-mcp/dev/mapit-identity-binding-config"


class _MapitDocument(_DynamoDocument):
    def get_item(self, **request):
        assert request["TableName"] == NEW_TABLE
        return super().get_item(**{**request, "TableName": TABLE_ARN})


def _jwks(public, kid):
    numbers = public.public_numbers()
    return json.dumps({"keys": [{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
        "n": _b64u(numbers.n), "e": _b64u(numbers.e)}]}, separators=(",", ":")).encode()


@pytest.fixture
def handler_setup(tmp_path, monkeypatch):
    monkeypatch.setattr(entry, "_BINDING", None)
    monkeypatch.setattr(entry, "_LAST_WALL", None)
    env, db, publisher, calls = _make_setup(tmp_path), _MapitDocument(), _PublishingSecrets(), []
    for label, refresh in (("a", TOKEN_A), ("b", TOKEN_B)):
        registry = _registry(env, db, auth=_AuthTransport(env["tokens"][refresh]),
            namespace="mapit", table_arn=NEW_TABLE)
        registry.enroll(env["grant_" + label], env["snapshot_" + label], refresh, publisher=publisher)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    invitation = _jwks(private.public_key(), "dev-key")
    mapit = _jwks(serialization.load_pem_public_key(env["mapit_public"]), "mapit-test-key")
    config = asdict(env["config"])
    del config["email"], config["password"]
    a = replace(CognitoDevPolicy("eu-west-1_InvitePool123", "a1b2c3d4e5", "InviteClient123", SUBJECT_A),
        request_deadline_seconds=14.0)
    b = replace(a, owner_subject=SUBJECT_B)
    value = {"schema": 1, "builder": "build_dev_enrolled_archive", "environment": "dev", "mode": "mapit-enrolled",
        "source_sha": "1" * 40, "api_id": a.api_id, "user_pool_id": a.user_pool_id, "client_id": a.client_id,
        "invitation_jwks_sha256": hashlib.sha256(invitation).hexdigest(),
        "mapit_jwks_sha256": hashlib.sha256(mapit).hexdigest(),
        "authorization_table_arn": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT_ID}:table/honda-mapit-mcp-dev-tenants",
        "binding_table_arn": NEW_TABLE, "key_parameter_path": KEY_PATH, "mapit_config": config,
        "key_publication_start_epoch": int(NOW.timestamp()) - 1,
        "key_publication_end_epoch": int(NOW.timestamp()) + 3599,
        "tenants": [{"key": KEY_A, "subject": SUBJECT_A}, {"key": KEY_B, "subject": SUBJECT_B}]}
    raw = json.dumps(value, separators=(",", ":")).encode()
    files = {MANIFEST_FILENAME: raw, INVITATION_JWKS_FILENAME: invitation, MAPIT_JWKS_FILENAME: mapit}
    def read(name, ceiling):
        assert len(files[name]) <= ceiling
        return files[name]
    monkeypatch.setattr(entry, "_read", read)
    now = int(time.time())
    for key, val in {"MAPIT_MCP_ENV": "dev", "AWS_REGION": "eu-west-1", "MAPIT_DEV_ENROLLED_MODE": "mapit-enrolled",
        "MAPIT_DEV_ENROLLED_MANIFEST_SHA256": hashlib.sha256(raw).hexdigest(),
        "MAPIT_DEV_EXPECTED_ACCOUNT_ID": ACCOUNT_ID, "MAPIT_DEV_EXECUTION_START_EPOCH": str(now - 1),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(now + 299), "MAPIT_SOURCE_SHA256": value["source_sha"],
        "MAPIT_COGNITO_JWKS_SHA256": value["invitation_jwks_sha256"], "MAPIT_IDENTITY_JWKS_SHA256": value["mapit_jwks_sha256"],
        "MAPIT_OBSERVED_API_ID": a.api_id, "MAPIT_COGNITO_USER_POOL_ID": a.user_pool_id,
        "MAPIT_COGNITO_CLIENT_ID": a.client_id}.items():
        monkeypatch.setenv(key, val)
    ssm, _, _, _ = client_and_response()
    def get_parameter(*, Name, WithDecryption):
        calls.append(("ssm", Name, WithDecryption))
        path = Name.removesuffix(":1")
        value = (encode_binding_keys(BindingKeyMaterial(b"b" * 32, b"v" * 32), account_id=ACCOUNT_ID,
                    config=env["config"], namespace="mapit") if path == KEY_PATH else publisher.values[path])
        parameter = {"Name": path, "Type": "SecureString", "Version": 1, "DataType": "text", "LastModifiedDate": NOW,
            "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT_ID}:parameter{path}"}
        if Name.endswith(":1"):
            parameter["Selector"] = ":1"
        if WithDecryption:
            parameter["Value"] = value
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": parameter}
    ssm.get_parameter = get_parameter
    class Ddb:
        def get_item(self, **request):
            if request["TableName"] == NEW_TABLE:
                return db.get_item(**request)
            assert request["TableName"] == value["authorization_table_arn"] and request["ConsistentRead"] is True
            key = request["Key"]["key"]["S"]
            assert key in {KEY_A, KEY_B}
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Item": {
                "key": {"S": key}, "status": {"S": "active"}, "revision": {"N": "1"}}}
    # The registry also validates the actual bounded SDK metadata.
    Ddb.meta = db.meta
    def clients(deadline):
        calls.append(("clients", deadline))
        def identity(client, account):
            calls.append(("identity",))
            return client is ssm and account == ACCOUNT_ID
        ddb = Ddb()
        def ddb_identity(client, account):
            calls.append(("ddb_identity",))
            return client is ddb and account == ACCOUNT_ID
        return EnrollmentAwsClients(ssm, identity, ddb, ddb_identity)
    monkeypatch.setattr(entry, "_clients", clients)
    class Transport:
        def __init__(self, config, *, deadline):
            assert config == env["config"] and deadline > time.monotonic()
            self.auth = _SelectingAuth(env["tokens"])
        def cognito_json(self, *args):
            return self.auth(*args)
        def mapit_request(self, *args):
            label = "A" if self.auth.id_token == env["tokens"][TOKEN_A] else "B"
            calls.append(("business", label))
            return _Mapit(label, 11 if label == "A" else 22)(*args)
    monkeypatch.setattr(entry, "CloudDirectTransport", Transport)
    yield SimpleNamespace(runtime=SimpleNamespace(handler=entry.handler), private=private, a=a, b=b,
        calls=calls, files=files, writes=len(db.put_calls), db=db)
    env["connection"].close()


def test_new_entrypoint_full_protocol_restores_both_real_provider_bindings_offline(handler_setup):
    setup = handler_setup
    async def scenario():
        for policy, label in ((setup.a, "A"), (setup.b, "B")):
            result = await _call(setup.runtime, policy, _token(setup.private, policy))
            assert not result.is_error and result.structured_content["status"] == label
    asyncio.run(scenario())
    assert [call for call in setup.calls if call[0] == "business"] == [("business", "A"), ("business", "B")]
    assert len(setup.db.put_calls) == setup.writes


@pytest.mark.parametrize("case", ["prod", "expired", "source", "mapit_jwks", "digest"])
def test_handler_fails_before_sdk_for_invalid_binding(handler_setup, monkeypatch, case):
    key, value = {"prod": ("MAPIT_MCP_ENV", "prod"), "expired": ("MAPIT_DEV_EXECUTION_END_EPOCH", "1"),
        "source": ("MAPIT_SOURCE_SHA256", "0" * 40), "mapit_jwks": ("MAPIT_IDENTITY_JWKS_SHA256", "0" * 64),
        "digest": ("MAPIT_DEV_ENROLLED_MANIFEST_SHA256", "0" * 64)}[case]
    monkeypatch.setenv(key, value)
    result = entry.handler({}, SimpleNamespace(get_remaining_time_in_millis=lambda: 30_000))
    assert result["statusCode"] == 503 and handler_setup.calls == []
