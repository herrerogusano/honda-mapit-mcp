"""Offline namespace separation tests; no cloud clients or keys are persisted."""
import base64
import json
import hashlib
from types import SimpleNamespace

import pytest

from mapit.aws_binding_keys import (
    BindingKeysError,
    MAPIT_PARAMETER_PATH,
    PARAMETER_PATH,
    decode_binding_keys,
    encode_binding_keys,
    generate_binding_keys,
    load_binding_keys,
)
from mapit.aws_identity_binding import DynamoDBIdentityBindingRegistry
from mapit.aws_enrollment_clients import EnrollmentAwsClients
from mapit.cloud_enrollment import CloudEnrollmentFactory, EnrollmentCredentials
from mapit.config import MapitConfig
from mapit.identity_binding import IdentityBindingError
from mapit.mapit_identity import json_bytes
from test_identity_binding import NOW, _make_setup

ACCOUNT = "123456789012"
CONFIG = MapitConfig(user_pool_id="eu-west-1_Synthetic", user_pool_client_id="synthetic")
SYNTHETIC_TABLE = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-identity-bindings"
MAPIT_TABLE = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-mapit-identity-bindings"


def test_legacy_synthetic_key_document_remains_schema_one_and_byte_exact():
    material = generate_binding_keys()
    encoded = encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG)
    config_fields = ("region", "user_pool_id", "user_pool_client_id", "identity_pool_id", "core_api_url",
                     "geo_api_url", "frontend_url", "discovery_enabled", "http_timeout")
    config_digest = hashlib.sha256(json_bytes({key: getattr(CONFIG, key) for key in config_fields})).hexdigest()
    legacy_bytes = json.dumps({"schema": 1, "environment": "dev", "account_id": ACCOUNT,
        "table_arn": SYNTHETIC_TABLE, "parameter_path": PARAMETER_PATH,
        "mapit_config_sha256": config_digest,
        "binding_mac_key": base64.urlsafe_b64encode(material.binding_mac_key).rstrip(b"=").decode(),
        "identity_proof_hmac_key": base64.urlsafe_b64encode(material.identity_proof_hmac_key).rstrip(b"=").decode()},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert encoded == legacy_bytes
    assert encoded == encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG,
                                           namespace="synthetic")
    assert decode_binding_keys(encoded, account_id=ACCOUNT, config=CONFIG) == material
    doc = json.loads(encoded)
    assert doc["schema"] == 1
    assert doc["parameter_path"] == PARAMETER_PATH
    assert doc["table_arn"] == SYNTHETIC_TABLE


def test_mapit_key_document_has_distinct_schema_path_and_context():
    material = generate_binding_keys()
    encoded = encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG, namespace="mapit")
    assert decode_binding_keys(encoded, account_id=ACCOUNT, config=CONFIG,
                               namespace="mapit") == material
    doc = json.loads(encoded)
    assert doc["schema"] == 2 and doc["namespace"] == "mapit"
    assert doc["parameter_path"] == MAPIT_PARAMETER_PATH
    assert doc["table_arn"] == MAPIT_TABLE
    with pytest.raises(BindingKeysError):
        decode_binding_keys(encoded, account_id=ACCOUNT, config=CONFIG)
    with pytest.raises(BindingKeysError):
        decode_binding_keys(encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG),
                            account_id=ACCOUNT, config=CONFIG, namespace="mapit")


def test_mapit_key_reader_requests_only_fixed_mapit_parameter():
    material = generate_binding_keys()
    expected_arn = f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{MAPIT_PARAMETER_PATH}"
    calls = []
    response = {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": {
        "Name": MAPIT_PARAMETER_PATH, "Type": "SecureString", "Version": 1, "Selector": ":1",
        "DataType": "text", "ARN": expected_arn,
        "Value": encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG, namespace="mapit"),
    }}
    client = SimpleNamespace(get_parameter=lambda **kw: (calls.append(kw), response)[1], meta=SimpleNamespace(
        service_model=SimpleNamespace(service_name="ssm"), region_name="eu-west-1",
        endpoint_url="https://ssm.eu-west-1.amazonaws.com", config=SimpleNamespace(
            retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=2)))
    assert load_binding_keys(client, account_id=ACCOUNT, config=CONFIG, namespace="mapit",
        account_verifier=lambda c, a: c is client and a == ACCOUNT,
        deadline=114, monotonic=lambda: 100) == material
    assert calls == [{"Name": MAPIT_PARAMETER_PATH + ":1", "WithDecryption": True}]


def _table_client():
    class Client:
        def __init__(self):
            self.requests = []
            self.meta = SimpleNamespace(service_model=SimpleNamespace(service_name="dynamodb"),
                region_name="eu-west-1", endpoint_url="https://dynamodb.eu-west-1.amazonaws.com",
                config=SimpleNamespace(retries={"total_max_attempts": 1},
                                       connect_timeout=2, read_timeout=2))

        def get_item(self, **kwargs):
            self.requests.append(kwargs)
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def put_item(self, **kwargs):
            raise AssertionError("constructor/read-only test must not write")

    return Client()


def test_registry_accepts_only_exact_dev_namespace_table_mapping(tmp_path):
    env = _make_setup(tmp_path)
    db = _table_client()
    registry = DynamoDBIdentityBindingRegistry(db, None, table_arn=MAPIT_TABLE,
        account_id=ACCOUNT, authority=env["authority"], durable_guard=env["guard"],
        environment="dev", namespace="mapit", config=env["config"], verifier=env["verifier"],
        binding_key=b"m" * 32, auth_transport=lambda **_: {}, clock=lambda: NOW,
        deadline=20, monotonic=lambda: 10)
    assert registry._path("tenant-" + "a" * 64) == (
        "/honda-mapit-mcp/dev/tenants/tenant-" + "a" * 64 + "/mapit-refresh-token")
    assert db.requests[0]["TableName"] == MAPIT_TABLE


@pytest.mark.parametrize("namespace,environment,table", [
    ("synthetic", "dev", MAPIT_TABLE),
    ("mapit", "dev", SYNTHETIC_TABLE),
    ("mapit", "prod", f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-prod-identity-bindings"),
])
def test_registry_rejects_cross_namespace_or_prod_mapit_before_read(tmp_path, namespace, environment, table):
    env = _make_setup(tmp_path)
    db = _table_client()
    with pytest.raises(IdentityBindingError, match="^identity_binding_configuration_invalid$"):
        DynamoDBIdentityBindingRegistry(db, None, table_arn=table, account_id=ACCOUNT,
            authority=env["authority"], durable_guard=env["guard"], environment=environment,
            namespace=namespace, config=env["config"], verifier=env["verifier"],
            binding_key=b"m" * 32, auth_transport=lambda **_: {}, clock=lambda: NOW,
            deadline=20, monotonic=lambda: 10)
    assert db.requests == []


def test_registry_rejects_malformed_environment_without_leaking_type_error(tmp_path):
    env = _make_setup(tmp_path)
    db = _table_client()
    with pytest.raises(IdentityBindingError, match="^identity_binding_configuration_invalid$"):
        DynamoDBIdentityBindingRegistry(db, None, table_arn=SYNTHETIC_TABLE, account_id=ACCOUNT,
            authority=env["authority"], durable_guard=env["guard"], environment=[],
            config=env["config"], verifier=env["verifier"], binding_key=b"m" * 32,
            auth_transport=lambda **_: {}, clock=lambda: NOW, deadline=20, monotonic=lambda: 10)
    assert db.requests == []


def test_mapit_namespace_rejects_unknown_values_and_foreign_config_context():
    material = generate_binding_keys()
    for namespace in ("prod", "MAPIT", "", None):
        with pytest.raises(BindingKeysError):
            encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG, namespace=namespace)
    with pytest.raises(BindingKeysError):
        decode_binding_keys(encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG,
                                                namespace="mapit"),
                            account_id="999999999999", config=CONFIG, namespace="mapit")
    with pytest.raises(BindingKeysError):
        decode_binding_keys(encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG,
                                                namespace="mapit"),
                            account_id=ACCOUNT, config=MapitConfig(http_timeout=1), namespace="mapit")
    with pytest.raises(BindingKeysError):
        encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG,
                            namespace="mapit", environment="prod")
    with pytest.raises(BindingKeysError):
        decode_binding_keys(encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG,
                                                namespace="mapit"),
                            account_id=ACCOUNT, config=CONFIG, namespace="mapit", environment="prod")


def test_cloud_enrollment_selects_only_fixed_namespace_table(tmp_path, monkeypatch):
    from test_aws_identity_binding_publisher import Client as SsmClient

    env = _make_setup(tmp_path)
    db, ssm = _table_client(), SsmClient()
    monkeypatch.setattr("mapit.cloud_enrollment.create_enrollment_clients", lambda **_: EnrollmentAwsClients(
        ssm, lambda client, account: client is ssm and account == ACCOUNT,
        db, lambda client, account: client is db and account == ACCOUNT))
    factory = CloudEnrollmentFactory(authority=env["authority"], durable_guard=env["guard"],
        environment="dev", namespace="mapit", account_id=ACCOUNT, config=env["config"],
        verifier=env["verifier"], binding_key=b"m" * 32,
        auth_transport=lambda **_: {}, clock=lambda: NOW,
        credentials_supplier=lambda: EnrollmentCredentials("a", "b", "c"), monotonic=lambda: 10)
    registry, _ = factory(grant=env["grant_a"], snapshot=env["snapshot_a"], deadline=20)
    assert registry._namespace == "mapit"
    assert db.requests[0]["TableName"] == MAPIT_TABLE
    with pytest.raises(ValueError, match="^cloud_enrollment_configuration_invalid$"):
        CloudEnrollmentFactory(authority=env["authority"], durable_guard=env["guard"],
            environment="prod", namespace="mapit", account_id=ACCOUNT, config=env["config"],
            verifier=env["verifier"], binding_key=b"m" * 32,
            auth_transport=lambda **_: {}, clock=lambda: NOW,
            credentials_supplier=lambda: EnrollmentCredentials("a", "b", "c"), monotonic=lambda: 10)
