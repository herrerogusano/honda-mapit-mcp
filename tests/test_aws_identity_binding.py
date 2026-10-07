from __future__ import annotations

import copy
import json

import pytest

from mapit.aws_identity_binding import DynamoDBIdentityBindingRegistry
from mapit.identity_binding import IdentityBindingError

from test_enrolled_provider import ACCOUNT_ID, _Mapit, _PublishingSecrets, _SSM
from test_identity_binding import KEY_A, KEY_B, NOW, TOKEN_A, TOKEN_B, _AuthTransport, _make_setup
from mapit.enrolled_provider import EnrolledCloudServicesProvider, EnrolledProviderError
from mapit.mapit_identity import MapitIdentityVerifier

TABLE_ARN = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT_ID}:table/honda-mapit-mcp-dev-identity-bindings"
DOC_KEY = "identity-bindings-v1"
_USE_DB = object()


class _ConditionalConflict(Exception):
    def __init__(self):
        self.response = {
            "Error": {"Code": "ConditionalCheckFailedException"},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        }
        super().__init__("synthetic conditional conflict")


class _DynamoDocument:
    def __init__(self, *, before_write=None, ambiguous_after_write=False):
        self.item = None
        self.get_calls = []
        self.put_calls = []
        self.before_write = before_write
        self.ambiguous_after_write = ambiguous_after_write
        self.meta = type("Meta", (), {
            "service_model": type("ServiceModel", (), {"service_name": "dynamodb"})(),
            "region_name": "eu-west-1",
            "endpoint_url": "https://dynamodb.eu-west-1.amazonaws.com",
            "config": type("Config", (), {
                "retries": {"total_max_attempts": 1}, "connect_timeout": 2, "read_timeout": 2,
            })(),
        })()

    def get_item(self, **request):
        self.get_calls.append(copy.deepcopy(request))
        assert request == {
            "TableName": TABLE_ARN,
            "Key": {"key": {"S": DOC_KEY}},
            "ConsistentRead": True,
            "ReturnConsumedCapacity": "NONE",
        }
        response = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        if self.item is not None:
            response["Item"] = copy.deepcopy(self.item)
        return response

    def put_item(self, **request):
        self.put_calls.append(copy.deepcopy(request))
        if self.before_write is not None:
            hook, self.before_write = self.before_write, None
            hook(self)
        condition = request["ConditionExpression"]
        if condition == "attribute_not_exists(#pk)":
            if self.item is not None:
                raise _ConditionalConflict()
        elif condition == "#revision = :revision":
            expected = request["ExpressionAttributeValues"][":revision"]["N"]
            if self.item is None or self.item["revision"]["N"] != expected:
                raise _ConditionalConflict()
        else:
            raise AssertionError("unexpected condition expression")
        self.item = copy.deepcopy(request["Item"])
        if self.ambiguous_after_write:
            self.ambiguous_after_write = False
            raise TimeoutError("synthetic ambiguous write")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


def _registry(env, db, *, auth=None, reader=None, writer=_USE_DB, **changes):
    selected_writer = db if writer is _USE_DB else writer
    account_id = changes.pop("account_id", ACCOUNT_ID)
    account_verifier = changes.pop("account_verifier", None)
    if selected_writer is not None and account_verifier is None:
        account_verifier = lambda client, account: client is selected_writer and account == account_id
    return DynamoDBIdentityBindingRegistry(
        reader if reader is not None else db,
        selected_writer,
        table_arn=changes.pop("table_arn", TABLE_ARN),
        account_id=account_id,
        authority=changes.pop("authority", env["authority"]),
        durable_guard=changes.pop("durable_guard", env["guard"]),
        environment=changes.pop("environment", "dev"),
        config=changes.pop("config", env["config"]),
        verifier=changes.pop("verifier", env["verifier"]),
        binding_key=changes.pop("binding_key", b"b" * 32),
        auth_transport=auth if auth is not None else _AuthTransport(env["tokens"][TOKEN_A]),
        clock=changes.pop("clock", lambda: NOW),
        deadline=changes.pop("deadline", 20.0),
        account_verifier=account_verifier,
        monotonic=changes.pop("monotonic", lambda: 10.0),
        **changes,
    )


def test_shared_document_cas_enrollment_provider_and_revocation(tmp_path):
    env = _make_setup(tmp_path)
    db = _DynamoDocument()
    publisher = _PublishingSecrets()
    registry_a = _registry(env, db, auth=_AuthTransport(env["tokens"][TOKEN_A]))
    binding_a = registry_a.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)

    # A second registry instance sees the same shared document and claims a
    # different verified account without overwriting A.
    registry_b = _registry(env, db, auth=_AuthTransport(env["tokens"][TOKEN_B]))
    binding_b = registry_b.enroll(env["grant_b"], env["snapshot_b"], TOKEN_B, publisher=publisher)
    assert binding_a.tenant_key == KEY_A and binding_b.tenant_key == KEY_B
    assert len(db.put_calls) == 6  # pending, proof, active for each tenant
    assert all(call["ReturnValues"] == "NONE" for call in db.put_calls)
    assert db.item["key"] == {"S": DOC_KEY}
    assert len(db.item["payload"]["S"]) < 96 * 1024
    assert "subject" not in db.item["payload"]["S"].lower()
    assert TOKEN_A not in db.item["payload"]["S"] and TOKEN_B not in db.item["payload"]["S"]

    fresh_verifier = MapitIdentityVerifier(
        env["config"], {"mapit-test-key": env["mapit_public"]}, b"v" * 32,
        clock=lambda: NOW,
    )
    reopened = _registry(env, db, verifier=fresh_verifier, auth=_AuthTransport(env["tokens"][TOKEN_A]))
    restored = reopened.get_binding(env["grant_a"], env["snapshot_a"])
    fresh_verifier.ensure_continuity(fresh_verifier.verify(env["tokens"][TOKEN_A]), restored.expected_identity_proof)

    # The accepted composition can use the shared backend, but still scopes the
    # secret read by tenant and checks durable revocation around business calls.
    runtime_registry = _registry(env, db, writer=None, auth=_AuthTransport(env["tokens"][TOKEN_A]))
    mapit = _Mapit("shared-a", 7)
    provider = EnrolledCloudServicesProvider(
        runtime_registry, authority=env["authority"], grant=env["grant_a"],
        durable_guard=env["guard"], snapshot=env["snapshot_a"],
        ssm_client=_SSM(publisher.values), account_id=ACCOUNT_ID,
        auth_transport=_AuthTransport(env["tokens"][TOKEN_A]),
        mapit_transport=mapit, deadline=20.0, monotonic=lambda: 10.0,
    )
    assert provider._registry is runtime_registry
    assert provider.get().get_vehicle_status().status == "shared-a"
    registry_a.revoke(env["grant_a"], env["snapshot_a"])
    with pytest.raises(IdentityBindingError, match="identity_binding_revoked"):
        registry_b.get_binding(env["grant_a"], env["snapshot_a"])
    with pytest.raises(EnrolledProviderError, match="enrolled_unauthorized"):
        provider.get().get_vehicle_status()
    assert len(mapit.calls) == 1


def test_identity_claim_is_unique_across_registry_instances_and_revocation_is_tombstoned(tmp_path):
    env = _make_setup(tmp_path)
    db, publisher = _DynamoDocument(), _PublishingSecrets()
    registry_a = _registry(env, db, auth=_AuthTransport(env["tokens"][TOKEN_A]))
    registry_a.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    # B's refresh authenticates to A's signed identity. The pending reservation
    # remains, but the identity claim prevents a second account binding.
    registry_b = _registry(env, db, auth=_AuthTransport(env["tokens"][TOKEN_A]))
    before = len(db.put_calls)
    with pytest.raises(IdentityBindingError, match="identity_binding_identity_in_use"):
        registry_b.enroll(env["grant_b"], env["snapshot_b"], TOKEN_B, publisher=publisher)
    assert len(db.put_calls) == before + 1  # only durable pending intent
    registry_a.revoke(env["grant_a"], env["snapshot_a"])
    with pytest.raises(IdentityBindingError, match="identity_binding_revoked"):
        registry_a.get_binding(env["grant_a"], env["snapshot_a"])
    before = len(db.put_calls)
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry_a.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(db.put_calls) == before


def test_ambiguous_initial_cas_is_not_retried_and_fresh_read_fences_enrollment(tmp_path):
    env = _make_setup(tmp_path)
    db = _DynamoDocument(ambiguous_after_write=True)
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    publisher = _PublishingSecrets()
    registry = _registry(env, db, auth=auth)
    # Constructor made one strong read; the first enrollment write commits but
    # returns an ambiguous timeout. No auth or publication follows it.
    with pytest.raises(IdentityBindingError, match="identity_binding_store_failed"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(db.put_calls) == 1 and auth.calls == [] and publisher.calls == []
    reopened = _registry(env, db, auth=auth)
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        reopened.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(db.put_calls) == 1 and auth.calls == [] and publisher.calls == []


def test_ambiguous_precommit_timeout_fences_same_registry_instance(tmp_path):
    env = _make_setup(tmp_path)
    db = _DynamoDocument()
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    publisher = _PublishingSecrets()
    registry = _registry(env, db, auth=auth)

    def timeout_before_commit(_db):
        raise TimeoutError("synthetic timeout before commit")

    db.before_write = timeout_before_commit
    with pytest.raises(IdentityBindingError, match="identity_binding_store_failed"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert db.item is None
    assert len(db.put_calls) == 1 and auth.calls == [] and publisher.calls == []

    # Even though a fresh read currently sees no item, the original request
    # may still have committed. The same registry instance is permanently
    # fenced from another write/authentication attempt.
    with pytest.raises(IdentityBindingError, match="identity_binding_store_failed"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(db.put_calls) == 1 and auth.calls == [] and publisher.calls == []


def test_document_copy_to_other_account_table_fails_context_mac(tmp_path):
    env = _make_setup(tmp_path)
    source_db = _DynamoDocument()
    source = _registry(env, source_db, auth=_AuthTransport(env["tokens"][TOKEN_A]))
    source.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=_PublishingSecrets())

    copied_db = _DynamoDocument()
    copied_db.item = copy.deepcopy(source_db.item)
    foreign_account = "999999999999"
    with pytest.raises(IdentityBindingError, match="identity_binding_integrity_failed"):
        _registry(
            env, copied_db, writer=None, account_id=foreign_account,
            table_arn=TABLE_ARN.replace(ACCOUNT_ID, foreign_account),
        )

def test_same_credential_account_verifier_runs_once_before_first_write(tmp_path):
    env = _make_setup(tmp_path)
    db, auth, publisher = _DynamoDocument(), _AuthTransport(env["tokens"][TOKEN_A]), _PublishingSecrets()
    verified = []
    registry = _registry(
        env, db, auth=auth,
        account_verifier=lambda client, account: verified.append((client, account)) or False,
    )
    with pytest.raises(IdentityBindingError, match="identity_binding_unauthorized"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert verified == [(db, ACCOUNT_ID)]
    assert db.put_calls == [] and auth.calls == [] and publisher.calls == []


def test_auth_latency_past_deadline_keeps_only_nonreplayable_pending_intent(tmp_path):
    env = _make_setup(tmp_path)
    db, publisher = _DynamoDocument(), _PublishingSecrets()
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    monotonic = [10.0]

    def late_auth(url, headers, payload):
        result = auth(url, headers, payload)
        monotonic[0] = 20.0
        return result

    registry = _registry(env, db, auth=late_auth, monotonic=lambda: monotonic[0])
    with pytest.raises(IdentityBindingError, match="identity_binding_deadline_expired"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(db.put_calls) == 1
    assert len(auth.calls) == 1 and publisher.calls == []
    item_payload = json.loads(db.item["payload"]["S"])
    assert len(item_payload["records"]) == 1
    assert item_payload["records"][0]["status"] == "pending"


def test_capacity_cas_conflict_and_document_integrity_fail_closed(tmp_path):
    env = _make_setup(tmp_path)
    db = _DynamoDocument()
    registry = _registry(env, db)
    records = {}
    for index in range(16):
        key = "tenant-" + f"{index + 1:064x}"
        path = f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
        records[key] = registry._record(key, None, path, "pending", 1, None)
    registry._write_document(0, records)
    before = len(db.put_calls)
    with pytest.raises(IdentityBindingError, match="identity_binding_capacity_exhausted"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=_PublishingSecrets())
    assert len(db.put_calls) == before

    stale_registry = _registry(env, db)
    stale_revision, stale_records = stale_registry._read_document()
    # A different committed write makes the first document revision stale.
    stale_registry._write_document(stale_revision, stale_records)
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        stale_registry._write_document(stale_revision, stale_records)

    db.item["mac"]["S"] = "0" * 64
    with pytest.raises(IdentityBindingError, match="identity_binding_integrity_failed"):
        _registry(env, db)


def test_cas_race_has_one_winner_and_reader_only_registry_cannot_enroll(tmp_path):
    env = _make_setup(tmp_path)
    db, publisher = _DynamoDocument(), _PublishingSecrets()
    auth_a = _AuthTransport(env["tokens"][TOKEN_A])
    auth_b = _AuthTransport(env["tokens"][TOKEN_B])
    registry_a = _registry(env, db, auth=auth_a)
    registry_b = _registry(env, db, auth=auth_b)

    # The second registry commits while A is between its strong read and
    # conditional put. A's stale attribute_not_exists write must lose without
    # authenticating or publishing.
    db.before_write = lambda _db: registry_b.enroll(
        env["grant_b"], env["snapshot_b"], TOKEN_B, publisher=publisher,
    )
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry_a.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert auth_a.calls == []
    assert len(auth_b.calls) == 3
    assert len(publisher.calls) == 1
    with pytest.raises(IdentityBindingError, match="identity_binding_not_active"):
        registry_a.get_binding(env["grant_a"], env["snapshot_a"])
    assert registry_b.get_binding(env["grant_b"], env["snapshot_b"]).tenant_key == KEY_B

    read_only = _registry(env, db, writer=None)
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        read_only.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert read_only.get_binding(env["grant_b"], env["snapshot_b"]).tenant_key == KEY_B


def test_exact_table_account_and_sdk_request_contract_are_required(tmp_path):
    env = _make_setup(tmp_path)
    db = _DynamoDocument()
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        _registry(env, db, table_arn=TABLE_ARN.replace("eu-west-1", "us-east-1"))
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        _registry(env, db, table_arn=TABLE_ARN.replace(ACCOUNT_ID, "999999999999"))

    pytest.importorskip("botocore")
    import boto3
    from botocore.config import Config
    from botocore.stub import Stubber

    client = boto3.client(
        "dynamodb", region_name="eu-west-1", endpoint_url="https://dynamodb.eu-west-1.amazonaws.com",
        aws_access_key_id="synthetic", aws_secret_access_key="synthetic", aws_session_token="synthetic",
        config=Config(connect_timeout=2, read_timeout=2,
                      retries={"total_max_attempts": 1, "mode": "standard"}),
    )
    stubber = Stubber(client)
    stubber.add_response("get_item", {"Item": {
        "key": {"S": DOC_KEY}, "revision": {"N": "1"},
        "payload": {"S": '{"records":[],"schema":1}'}, "mac": {"S": "0" * 64},
    }, "ResponseMetadata": {"HTTPStatusCode": 200}}, {
        "TableName": TABLE_ARN, "Key": {"key": {"S": DOC_KEY}},
        "ConsistentRead": True, "ReturnConsumedCapacity": "NONE",
    })
    canonical_payload = '{"records":[],"schema":1}'
    registry = _registry(env, _DynamoDocument())
    expected_item = {
        "key": {"S": DOC_KEY}, "revision": {"N": "1"},
        "payload": {"S": canonical_payload},
        "mac": {"S": registry._document_mac(1, canonical_payload)},
    }
    # A bad MAC must be rejected even when the botocore request shape is exact.
    env["connection"].close()
    with stubber:
        with pytest.raises(IdentityBindingError, match="identity_binding_integrity_failed"):
            _registry(env, db, reader=client, writer=client)
    # The same pinned SDK model validates the precise conditional PutItem
    # shape separately; this does not make a network request.
    writer_stubber = Stubber(client)
    writer_stubber.add_response("put_item", {"ResponseMetadata": {"HTTPStatusCode": 200}}, {
        "TableName": TABLE_ARN, "Item": expected_item,
        "ConditionExpression": "attribute_not_exists(#pk)",
        "ExpressionAttributeNames": {"#pk": "key"},
        "ReturnValues": "NONE", "ReturnConsumedCapacity": "NONE",
    })
    with writer_stubber:
        registry._write_document(0, {})
