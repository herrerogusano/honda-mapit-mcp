from __future__ import annotations

from datetime import datetime, timezone
import time

import pytest

from mapit.aws_binding_keys import generate_binding_keys
from scripts import run_dev_identity_binding_storage_probe as probe
from scripts.run_dev_identity_binding_storage_probe import _exercise
from scripts.run_aws_retained_dev_bootstrap import validate_authorization
from scripts.run_dev_identity_binding_storage_probe import StorageProbeError
from test_aws_identity_binding import _DynamoDocument
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
from scripts.aws_dev_identity_binding_bootstrap import _canonical, _digest
from scripts.run_aws_dev_identity_binding_bootstrap import _COORDINATOR_FIELDS


ACCOUNT = "123456789012"


class _ClientMeta:
    def __init__(self, service: str):
        self.service_model = type("ServiceModel", (), {"service_name": service})()
        self.region_name = "eu-west-1"
        self.endpoint_url = f"https://{service}.eu-west-1.amazonaws.com"
        if service == "ssm":
            self.endpoint_url = "https://ssm.eu-west-1.amazonaws.com"
        elif service == "sts":
            self.endpoint_url = "https://sts.eu-west-1.amazonaws.com"
        elif service == "dynamodb":
            self.endpoint_url = "https://dynamodb.eu-west-1.amazonaws.com"
        self.config = type("Config", (), {
            "retries": {"total_max_attempts": 1}, "connect_timeout": 2, "read_timeout": 2,
        })()


class _STS:
    def __init__(self):
        self.meta = _ClientMeta("sts")
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/honda-mapit-mcp-dev-identity-enroller/storage-probe-7"}


class _SSM:
    def __init__(self):
        self.meta = _ClientMeta("ssm")
        self.values = {}
        self.calls = []

    def put_parameter(self, **request):
        self.calls.append(("put", request["Name"], request["Overwrite"]))
        if request["Name"] in self.values or request["Overwrite"] is not False:
            raise AssertionError("must be create-only")
        self.values[request["Name"]] = request["Value"]
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Version": 1, "Tier": "Standard"}

    def get_parameter(self, *, Name, WithDecryption):
        self.calls.append(("get", Name, WithDecryption))
        path, _, selector = Name.rpartition(":")
        path = path if selector == "1" else Name
        if path not in self.values:
            raise AssertionError("unexpected parameter read")
        parameter = {
            "Name": path, "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{path}",
            "Type": "SecureString", "Value": self.values[path], "Version": 1,
            "DataType": "text",
        }
        if selector == "1":
            parameter["Selector"] = ":1"
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": parameter}


def test_synthetic_storage_exercise_isolates_and_revokes_without_real_network():
    account = ACCOUNT
    clients = {"sts": _STS(), "dynamodb": _DynamoDocument(), "ssm": _SSM()}
    binding = {"account_id": account, "tenant_keys": (
        "tenant-" + "a" * 64, "tenant-" + "b" * 64,
    )}
    material = generate_binding_keys()
    result = _exercise(clients, binding, material, wall_clock=time.time,
                       monotonic=lambda: 100.0)
    assert result == {
        "tenant_a_enrolled": True, "tenant_b_enrolled": True,
        "tenant_results_isolated": True, "tenant_a_revoked": True,
        "tenant_b_remained_active": True,
    }
    assert clients["dynamodb"].item is not None
    assert len(clients["dynamodb"].put_calls) == 7
    paths = {call[1] for call in clients["ssm"].calls if call[0] == "put"}
    assert paths == {
        f"/honda-mapit-mcp/dev/tenants/{binding['tenant_keys'][0]}/mapit-refresh-token",
        f"/honda-mapit-mcp/dev/tenants/{binding['tenant_keys'][1]}/mapit-refresh-token",
    }
    assert all(call[2] is False for call in clients["ssm"].calls if call[0] == "put")
    assert clients["sts"].calls >= 3


def test_exercise_intent_is_saved_before_external_operation_and_consumed(monkeypatch):
    account = ACCOUNT
    auth = validate_authorization({
        "account": account, "source_sha": "a" * 40, "run_id": 7,
        "expected_caller_arn": f"arn:aws:iam::{account}:user/operator",
        "start": 1_800_000_000, "end": 1_800_003_600, "ci_run_id": 9,
    })
    binding = {name: "placeholder" for name in probe._BINDING_FIELDS}
    binding.update({"account_id": account, "operator_user_arn": auth["expected_caller_arn"],
                    "tenant_keys": ("tenant-" + "a" * 64, "tenant-" + "b" * 64)})
    stack_id = f"arn:aws:cloudformation:eu-west-1:{account}:stack/honda-mapit-mcp-dev-identity-bindings-bootstrap/00000000-0000-4000-8000-000000000001"
    bootstrap_sha = "b" * 64
    accepted_bootstrap = {}
    monkeypatch.setattr(probe, "_bootstrap_receipt", lambda *_: (bootstrap_sha, stack_id))
    monkeypatch.setattr(probe, "_load_context", lambda *_args, **_kwargs: (
        bootstrap_sha, stack_id, {}, {"sts": object(), "ssm": object(), "dynamodb": object()},
    ))
    monkeypatch.setattr(probe, "_load_key_journal_state", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(probe, "_load_keys", lambda *_args, **_kwargs: generate_binding_keys())
    monkeypatch.setattr(probe, "_check_probe_parameters_absent", lambda *_args, **_kwargs: None)
    def publish_keys(clients, *_args, **_kwargs):
        assert set(clients) == {"sts", "ssm"}
        return {"ok": True, "category": "protected_key_handoff_verified"}
    monkeypatch.setattr(probe, "publish_keys", publish_keys)
    probe_journal = probe._MemoryJournal()
    probe_journal.value = probe._receipt_state(auth, binding, bootstrap_sha, stack_id,
        phase="preflight_verified", intent=None, flags={"preflight": True})
    key_journal = probe._MemoryJournal()
    key_journal.value = None
    calls = []

    def exercise(*_args, **_kwargs):
        calls.append(True)
        assert probe_journal.value["phase"] == "intent_saved"
        assert probe_journal.value["intent"] == "storage_exercise"
        return {"tenant_a_enrolled": True, "tenant_b_enrolled": True,
                "tenant_results_isolated": True, "tenant_a_revoked": True,
                "tenant_b_remained_active": True}

    monkeypatch.setattr(probe, "_exercise", exercise)
    args = (auth, binding, accepted_bootstrap, probe_journal, key_journal, "exercise")
    validators = {
        "source_ci_validator": lambda _auth: None,
        "protection_validator": lambda _binding: None,
        "client_factory": lambda: {}, "explicit_client_factory": lambda _creds: {},
        "wall_clock": lambda: 1_800_000_100, "monotonic": lambda: 100.0,
    }
    first = probe.run_storage_probe_step(*args, **validators)
    assert first["ok"] is True and first["category"] == "storage_exercise_verified", first
    assert probe_journal.value["phase"] == "accepted"
    second = probe.run_storage_probe_step(*args, **validators)
    assert second["ok"] is False and second["category"] == "preflight_conflict"
    assert len(calls) == 1


def test_assumed_storage_calls_are_fenced_by_immutable_authorization_window():
    now = [100.0]
    calls = []
    class Client:
        def mutate(self):
            calls.append("mutate")
            return True
    wrapped = probe._window_bound_clients({"ssm": Client()}, {"start": 100, "end": 110}, lambda: now[0])
    assert wrapped["ssm"].mutate() is True
    now[0] = 110.0
    with pytest.raises(StorageProbeError) as exc:
        wrapped["ssm"].mutate()
    assert exc.value.category == "window_expired"
    assert calls == ["mutate"]


def test_bootstrap_receipt_uses_the_exact_coordinator_binding_projection():
    import hashlib
    account = ACCOUNT
    caller = f"arn:aws:iam::{account}:user/dev-operator"
    binding = {
        "account_id": account, "operator_user_arn": caller,
        "tenant_keys": ("tenant-" + "1" * 64, "tenant-" + "2" * 64),
        "ssm_key_arn": f"arn:aws:kms:eu-west-1:{account}:key/11111111-1111-1111-1111-111111111111",
        "accepted_runtime_journal_path": "C:/private/accepted/runtime.json",
        "app_stack_arn": f"arn:aws:cloudformation:eu-west-1:{account}:stack/honda-mapit-mcp-dev-retained/12345678-1234-1234-1234-123456789abc",
        "app_run_id": 1234, "api_id": "abc123def4", "user_pool_id": "eu-west-1_Abc123",
        "client_id": "Abc123456789", "template_sha256": "a" * 64,
        "code_sha256": "b" * 64,
        "handler_role_arn": f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-handler-role",
        "handler_trust_sha256": "c" * 64, "handler_policies_sha256": "d" * 64,
        "github_owner_id": 12345, "github_repository_id": 67890,
    }
    source, run_id, start, end = "e" * 40, 111, 1_700_000_000, 1_700_003_600
    template = build_dev_identity_binding_bootstrap(
        account_id=account, operator_user_arn=caller,
        tenant_keys=binding["tenant_keys"], ssm_key_arn=binding["ssm_key_arn"],
    )
    template_sha = hashlib.sha256(_canonical(template)).hexdigest()
    projection = {key: binding[key] for key in _COORDINATOR_FIELDS if key != "tenant_keys"}
    token = "dev-identity-bindings-" + hashlib.sha256(
        f"{account}:{source}:{run_id}".encode("ascii")
    ).hexdigest()
    stack_id = f"arn:aws:cloudformation:eu-west-1:{account}:stack/{probe.STACK_NAME}/12345678-1234-1234-1234-123456789abc"
    receipt = {
        "schema": 1, "kind": "dev-identity-binding-bootstrap", "account": account,
        "source_sha": source, "run_id": run_id, "template_sha256": template_sha,
        "binding_sha256": _digest(projection), "expected_caller_arn": caller,
        "authorized_from_epoch": start, "authorized_until_epoch": end,
        "last_observed_epoch": start + 1,
        "preflight": True, "intent": {"token": token, "stack_name": probe.STACK_NAME},
        "acknowledged": True, "acknowledged_stack_id": stack_id,
        "readback": True, "readback_receipt": {"stack_id": stack_id, "template_sha256": template_sha},
    }
    assert probe._bootstrap_receipt(receipt, binding) == (template_sha, stack_id)


def test_expired_window_is_rejected_before_any_sdk_client_construction(monkeypatch):
    auth = {"start": 100, "end": 200, "account": ACCOUNT}
    binding = {"account_id": ACCOUNT}
    monkeypatch.setattr(probe, "_bootstrap_receipt", lambda *_: ("a" * 64, "stack"))
    created = []
    with pytest.raises(StorageProbeError) as exc:
        probe._load_context(
            auth, binding, {}, "preflight", acl_checker=None,
            source_ci_validator=lambda _: None, protection_validator=lambda _: None,
            client_factory=lambda: created.append(True), explicit_client_factory=lambda _: {},
            wall_clock=lambda: 200, monotonic=lambda: 10.0,
        )
    assert exc.value.category == "window_expired"
    assert created == []


def test_repeated_private_journal_roots_are_rejected(tmp_path):
    root = tmp_path / "private"
    root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    with pytest.raises(StorageProbeError) as exc:
        probe._ensure_distinct_state_directories(root, root, other)
    assert exc.value.category == "private_state_invalid"


def test_slow_explicit_client_factory_cannot_dispatch_after_window_cutoff():
    now = [100.0]
    explicit_calls = []

    class BaseSTS:
        meta = _ClientMeta("sts")
        def get_caller_identity(self):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT,
                    "Arn": f"arn:aws:iam::{ACCOUNT}:user/dev-operator"}
        def assume_role(self, **_kwargs):
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Credentials": {
                "AccessKeyId": "AKIAFAKE", "SecretAccessKey": "fake-secret", "SessionToken": "fake-session",
                "Expiration": datetime.fromtimestamp(1_000, timezone.utc),
            }}

    class AssumedSTS:
        meta = _ClientMeta("sts")
        def get_caller_identity(self):
            explicit_calls.append("get_caller_identity")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT,
                    "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/honda-mapit-mcp-dev-identity-enroller/storage-probe-7"}

    base = probe._window_bound_clients({"sts": BaseSTS()}, {"start": 100, "end": 200},
                                       lambda: now[0], monotonic=lambda: 1.0, mono_start=1.0)
    def slow_factory(_credentials):
        now[0] = 200.0
        return {"sts": AssumedSTS(), "dynamodb": type("DDB", (), {"meta": _ClientMeta("dynamodb")})(),
                "ssm": _SSM()}
    with pytest.raises(StorageProbeError) as exc:
        probe._assume_clients(
            base, {"start": 100, "end": 200, "expected_caller_arn": f"arn:aws:iam::{ACCOUNT}:user/dev-operator",
                   "run_id": 7},
            {"account_id": ACCOUNT, "operator_user_arn": f"arn:aws:iam::{ACCOUNT}:user/dev-operator"},
            slow_factory, lambda: now[0], [0], lambda: 1.0, 1.0,
        )
    assert exc.value.category == "window_expired"
    assert explicit_calls == []


def test_probe_budget_is_independent_and_shared_call_cap_fences_dispatch():
    calls = []
    class Client:
        def mutate(self):
            calls.append(True)
            return True
    shared = [probe._PROBE_CALL_LIMIT - 1]
    wrapped = probe._window_bound_clients(
        {"ssm": Client()}, {"start": 100, "end": 200}, lambda: 100,
        calls=shared, monotonic=lambda: 5.0, mono_start=5.0,
    )
    assert wrapped["ssm"].mutate() is True
    with pytest.raises(StorageProbeError) as exc:
        wrapped["ssm"].mutate()
    assert exc.value.category == "clients_invalid"
    assert len(calls) == 1 and shared[0] == probe._PROBE_CALL_LIMIT
    assert probe._PROBE_CALL_LIMIT > 48 and probe._PROBE_STEP_SECONDS > 30


def test_safe_cli_projection_discards_untrusted_fields_and_flags():
    import json
    from unittest.mock import patch
    result = {"step": "exercise", "ok": True, "category": "storage_exercise_verified",
              "flags": {"tenant_a_revoked": True, "subject": "private-canary"},
              "account": "123456789012", "refresh_token": "private-canary"}
    with patch("builtins.print") as output:
        probe._print_result(result)
    serialized = output.call_args.args[0]
    assert "private-canary" not in serialized and "account" not in serialized
    assert json.loads(serialized)["flags"] == {"tenant_a_revoked": True}
    readback = {"step": "readback", "ok": True, "category": "readback_verified",
                "flags": {"tenant_a_revoked": True, "tenant_b_active": True,
                          "tenant_parameter_versions_verified": True}}
    with patch("builtins.print") as output:
        probe._print_result(readback)
    assert json.loads(output.call_args.args[0])["flags"] == readback["flags"]


def test_cli_entrypoint_definitions_precede_dispatch_and_help_is_offline():
    import subprocess
    import sys
    from pathlib import Path
    script = Path(probe.__file__).resolve()
    result = subprocess.run([sys.executable, str(script), "--help"], cwd=script.parents[1],
                            capture_output=True, text=True, timeout=10, check=False)
    assert result.returncode == 0
    assert "One-shot synthetic DEV identity-binding storage proof" in result.stdout
    assert result.stderr == ""
