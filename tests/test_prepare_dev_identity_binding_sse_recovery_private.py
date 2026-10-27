"""Metadata-only private preparation; never use live clients or credentials."""
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import prepare_dev_identity_binding_sse_recovery_private as module
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_retained_dev_bootstrap import load_authorization
from tests.test_run_aws_dev_identity_binding_bootstrap import _binding
from scripts.build_aws_dev_identity_binding_bootstrap import STACK_NAME


def _fixture(tmp_path):
    parent = tmp_path / "private"
    parent.mkdir()
    history = parent / "history"
    history.mkdir()
    binding = _binding()
    binding["tenant_keys"] = tuple(binding["tenant_keys"])
    (history / "bindings.json").write_text(json.dumps(binding), encoding="utf-8")
    states = []
    for name in ("bootstrap", "probe", "keys"):
        directory = history / name
        directory.mkdir()
        state = {"schema": 1, "fixture": name}
        FileJournal(directory).save(state)
        states.append(state)
    states[0]["acknowledged_stack_id"] = f"arn:aws:cloudformation:eu-west-1:{binding['account_id']}:stack/{STACK_NAME}/12345678-1234-1234-1234-123456789012"
    FileJournal(history / "bootstrap").save(states[0])
    calls = []

    class Sts:
        def get_caller_identity(self):
            calls.append("identity")
            return {"ResponseMetadata": {"HTTPStatusCode": 200},
                    "Account": binding["account_id"], "Arn": binding["operator_user_arn"]}

    class Ddb:
        def describe_table(self, **kwargs):
            calls.append("table")
            assert kwargs == {"TableName": "honda-mapit-mcp-dev-identity-bindings"}
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Table": {
                "TableArn": f"arn:aws:dynamodb:eu-west-1:{binding['account_id']}:table/honda-mapit-mcp-dev-identity-bindings",
                "TableStatus": "ACTIVE", "TableId": "12345678-1234-1234-1234-123456789012",
                "CreationDateTime": datetime.fromtimestamp(1000, timezone.utc),
                "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS",
                    "KMSMasterKeyArn": f"arn:aws:kms:eu-west-1:{binding['account_id']}:key/12345678-1234-1234-1234-123456789012"},
            }}

    class Cfn:
        def describe_stack_resources(self, **kwargs):
            calls.append("resources")
            stack_id = FileJournal(history / "bootstrap").load()["acknowledged_stack_id"]
            assert kwargs == {"StackName": stack_id}
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "StackResources": [
                {"LogicalResourceId": logical, "ResourceType": kind,
                 "PhysicalResourceId": "observed-policy-id" if logical == "RuntimeIdentityBindingPolicy" else logical,
                 "StackId": stack_id, "StackName": STACK_NAME, "ResourceStatus": "CREATE_COMPLETE"}
                for logical, kind in {
                    "MapitIdentityBindings": "AWS::DynamoDB::Table",
                    "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
                    "IdentityEnrollerRole": "AWS::IAM::Role",
                    "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy"}.items()]}

    clients = {"sts": Sts(), "dynamodb": Ddb(), "cloudformation": Cfn()}
    kwargs = dict(parent=parent, historical_directory=history, source_sha="b" * 40,
                  ci_run_id=19, client_factory=lambda: clients,
                  client_validator=lambda value: value is clients,
                  source_ci_validator=lambda _: None, protection_validator=lambda _: None,
                  acl_checker=lambda _: True, clock=lambda: 2000.0, monotonic=lambda: 1.0)
    return SimpleNamespace(parent=parent, history=history, binding=binding, states=states,
                           calls=calls, clients=clients, kwargs=kwargs)


def test_private_preparation_reads_only_identity_and_table_and_preserves_history(tmp_path):
    f = _fixture(tmp_path)
    before = {p: p.read_bytes() for p in f.history.rglob("*") if p.is_file()}
    validated = []
    f.kwargs["lineage_validator"] = lambda *args: validated.append(args)
    target = module.prepare(**f.kwargs)
    assert f.calls == ["identity", "table", "resources"]
    assert {p: p.read_bytes() for p in f.history.rglob("*") if p.is_file()} == before
    assert len(validated) == 1 and validated[0][:4] == (f.binding, *f.states)
    metadata = json.loads((target / "recovery-binding.json").read_bytes())
    assert metadata == validated[0][4]
    assert metadata["table_creation_time"] == "1970-01-01T00:16:40+00:00"
    assert metadata["sse_key_arn"].endswith("/12345678-1234-1234-1234-123456789012")
    assert metadata["runtime_policy_physical_id"] == "observed-policy-id"
    assert metadata["bootstrap_state_sha256"] == module._digest(f.states[0])
    assert metadata["probe_state_sha256"] == module._digest(f.states[1])
    assert metadata["key_state_sha256"] == module._digest(f.states[2])
    assert (target / "update").is_dir() and (target / "probe").is_dir()
    auth = load_authorization(target / "authorization.json")
    assert auth["source_sha"] == "b" * 40 and auth["ci_run_id"] == 19
    assert auth["start"] == 2000 and auth["end"] == 5600
    assert set(p.name for p in target.iterdir()) == {
        "update", "probe", "recovery-binding.json", "authorization.json"}


def test_source_gate_failure_precedes_client_construction_and_local_authority(tmp_path):
    f = _fixture(tmp_path)
    def denied(_):
        raise ValueError("source_ci_failed")
    f.kwargs.update(source_ci_validator=denied, client_factory=lambda: pytest.fail("clients constructed"),
                    lineage_validator=lambda *_: None)
    with pytest.raises(ValueError, match="source_ci_failed"):
        module.prepare(**f.kwargs)
    assert list(f.parent.iterdir()) == [f.history] and f.calls == []


def test_lineage_rejection_never_publishes_a_recovery_authority(tmp_path):
    f = _fixture(tmp_path)
    def denied(*_):
        raise ValueError("historical_lineage_invalid")
    f.kwargs["lineage_validator"] = denied
    with pytest.raises(ValueError, match="historical_lineage_invalid"):
        module.prepare(**f.kwargs)
    assert f.calls == ["identity", "table", "resources"] and list(f.parent.iterdir()) == [f.history]


def test_wrong_caller_stops_before_table_or_authority(tmp_path):
    f = _fixture(tmp_path)
    f.clients["sts"].get_caller_identity = lambda: {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Account": f.binding["account_id"], "Arn": "wrong"}
    f.kwargs["lineage_validator"] = lambda *_: None
    with pytest.raises(ValueError, match="private_preparation_failed"):
        module.prepare(**f.kwargs)
    assert f.calls == [] and list(f.parent.iterdir()) == [f.history]


def test_client_construction_is_inside_the_read_deadline(tmp_path):
    f = _fixture(tmp_path)
    values = iter([1.0, 1.0, 15.0])
    f.kwargs.update(monotonic=lambda: next(values), lineage_validator=lambda *_: None)
    with pytest.raises(ValueError, match="private_preparation_failed"):
        module.prepare(**f.kwargs)
    assert f.calls == [] and list(f.parent.iterdir()) == [f.history]


def test_failed_metadata_write_does_not_publish_authority(tmp_path, monkeypatch):
    f = _fixture(tmp_path)
    f.kwargs["lineage_validator"] = lambda *_: None
    original = Path.open
    def guarded(path, *args, **kwargs):
        if path.name == "recovery-binding.json" and args == ("xb",):
            raise OSError("fixture failure")
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "open", guarded)
    with pytest.raises(OSError):
        module.prepare(**f.kwargs)
    assert not list(f.parent.glob("sse-*/authorization.json"))


@pytest.mark.parametrize("table_id", [None, "", 123, "not-an-id", "f" * 36])
def test_missing_or_malformed_table_identity_never_publishes_authority(tmp_path, table_id):
    f = _fixture(tmp_path)
    original = f.clients["dynamodb"].describe_table
    def changed(**kwargs):
        reply = original(**kwargs)
        reply["Table"]["TableId"] = table_id
        return reply
    f.clients["dynamodb"].describe_table = changed
    f.kwargs["lineage_validator"] = lambda *_: pytest.fail("invalid table identity reached lineage")
    with pytest.raises(ValueError, match="private_preparation_failed"):
        module.prepare(**f.kwargs)
    assert list(f.parent.iterdir()) == [f.history]


def test_explicit_client_validation_rejection_precedes_sdk_reads(tmp_path):
    f = _fixture(tmp_path)
    f.kwargs.update(client_validator=lambda _: False, lineage_validator=lambda *_: None)
    with pytest.raises(ValueError, match="private_preparation_failed"):
        module.prepare(**f.kwargs)
    assert f.calls == [] and list(f.parent.iterdir()) == [f.history]


@pytest.mark.parametrize("gate", ["source_ci_validator", "protection_validator"])
def test_explicit_source_or_protection_rejection_precedes_sdk_reads(tmp_path, gate):
    f = _fixture(tmp_path)
    f.kwargs[gate] = lambda _: False
    f.kwargs["lineage_validator"] = lambda *_: None
    with pytest.raises(ValueError, match="source_ci_failed|protection_failed"):
        module.prepare(**f.kwargs)
    assert f.calls == [] and list(f.parent.iterdir()) == [f.history]


def test_private_preparation_composes_with_actual_recovery_lineage(tmp_path):
    from tests.test_aws_dev_identity_binding_sse_recovery import _lineage
    f = _fixture(tmp_path)
    binding, bootstrap, probe, keys, recovery = _lineage()
    recovery["runtime_policy_physical_id"] = "observed-policy-id"
    (f.history / "bindings.json").write_text(json.dumps(binding), encoding="utf-8")
    for name, state in zip(("bootstrap", "probe", "keys"), (bootstrap, probe, keys)):
        FileJournal(f.history / name).save(state)
    f.clients["sts"].get_caller_identity = lambda: {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Account": binding["account_id"],
        "Arn": binding["operator_user_arn"]}
    f.clients["dynamodb"].describe_table = lambda **_: {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Table": {
            "TableArn": f"arn:aws:dynamodb:eu-west-1:{binding['account_id']}:table/honda-mapit-mcp-dev-identity-bindings",
            "TableStatus": "ACTIVE", "TableId": recovery["table_id"],
            "CreationDateTime": datetime.fromisoformat(recovery["table_creation_time"]),
            "SSEDescription": {"Status": "ENABLED", "SSEType": "KMS",
                               "KMSMasterKeyArn": recovery["sse_key_arn"]}}}
    before = {p: p.read_bytes() for p in f.history.rglob("*") if p.is_file()}
    target = module.prepare(**f.kwargs)
    assert json.loads((target / "recovery-binding.json").read_bytes()) == recovery
    assert {p: p.read_bytes() for p in f.history.rglob("*") if p.is_file()} == before


@pytest.mark.parametrize("sse", [None, {}, {"Status": "UPDATING", "SSEType": "KMS"},
    {"Status": "ENABLED", "SSEType": "KMS", "KMSMasterKeyArn": "wrong"}])
def test_unbound_prior_encryption_never_publishes_authority(tmp_path, sse):
    f = _fixture(tmp_path)
    original = f.clients["dynamodb"].describe_table
    def changed(**kwargs):
        reply = original(**kwargs)
        reply["Table"]["SSEDescription"] = sse
        return reply
    f.clients["dynamodb"].describe_table = changed
    f.kwargs["lineage_validator"] = lambda *_: pytest.fail("invalid SSE reached lineage")
    with pytest.raises(ValueError, match="private_preparation_failed"):
        module.prepare(**f.kwargs)
    assert list(f.parent.iterdir()) == [f.history]


@pytest.mark.parametrize("fault", ["wrong_stack", "duplicate", "wrong_type", "invalid_policy_id"])
def test_unbound_stack_resource_never_publishes_authority(tmp_path, fault):
    f = _fixture(tmp_path)
    original = f.clients["cloudformation"].describe_stack_resources
    def changed(**kwargs):
        reply = original(**kwargs)
        rows = reply["StackResources"]
        if fault == "wrong_stack":
            rows[0]["StackId"] = "wrong"
        elif fault == "duplicate":
            rows[-1] = dict(rows[0])
        elif fault == "wrong_type":
            rows[-1]["ResourceType"] = "AWS::IAM::Role"
        else:
            rows[-1]["PhysicalResourceId"] = "bad\nidentifier"
        return reply
    f.clients["cloudformation"].describe_stack_resources = changed
    f.kwargs["lineage_validator"] = lambda *_: pytest.fail("invalid CFN binding reached lineage")
    with pytest.raises(ValueError, match="private_preparation_failed"):
        module.prepare(**f.kwargs)
    assert list(f.parent.iterdir()) == [f.history]
