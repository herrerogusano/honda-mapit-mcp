from __future__ import annotations

import hashlib
import contextlib
import json
from pathlib import Path

from scripts import run_dev_multiuser_closed_update as runner


ACCOUNT = "123456789012"
SOURCE = "1" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
APP_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ROLES_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-cd-delivery/33333333-4444-4555-8666-777777777777"
OWNER_ID = "1234567"
REPOSITORY_ID = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPOSITORY_ID}:environment:dev"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
ARTIFACT_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4444-8555-666666666666"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
BUCKET = f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"


AUTH = {
    "account": ACCOUNT, "source_sha": SOURCE, "run_id": 42,
    "expected_caller_arn": CALLER, "start": 1_900_000_000,
    "end": 1_900_000_300, "ci_run_id": 99,
}
BINDINGS = {
    "account_id": ACCOUNT,
    "provider_arn": PROVIDER,
    "owner_id": OWNER_ID,
    "repository_id": REPOSITORY_ID,
    "observed_dev_subject_format": "immutable_environment",
    "observed_dev_subject_sha256": hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
    "api_arn": "arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5",
    "stack_arn": APP_STACK,
    "artifact_stack_arn": ARTIFACT_STACK,
    "handler_arn": HANDLER,
    "shutdown_state_machine_arn": SHUTDOWN,
    "artifact_bucket_arn": BUCKET,
    "execution_role_arn": EXECUTION_ROLE,
}


class _CloudFormation:
    def describe_stacks(self, **_kwargs):
        return {"Stacks": [{"StackId": APP_STACK}]}


def _patch_inputs(monkeypatch, *, source_validator=lambda _auth: None, client_factory=None):
    monkeypatch.setattr(runner, "validate_private_location", lambda path, acl_checker=None: Path(path))
    monkeypatch.setattr(runner, "load_authorization", lambda _path: dict(AUTH))
    monkeypatch.setattr(runner, "_load_bindings", lambda _path: dict(BINDINGS))
    monkeypatch.setattr(runner, "validate_source_and_ci", source_validator)
    if client_factory is not None:
        monkeypatch.setattr(runner, "_build_clients", client_factory)


def test_gate_failure_and_private_location_failure_happen_before_client_construction(monkeypatch):
    calls = []

    def source_failure(_auth):
        raise RuntimeError("source-canary")

    def client_factory():
        calls.append("client")
        raise AssertionError("AWS client construction must not occur")

    _patch_inputs(monkeypatch, source_validator=source_failure, client_factory=client_factory)
    result = runner.run(Path("auth"), Path("bindings"), Path("state"), operation="setup", step="preflight",
                        source_validator=source_failure, client_factory=client_factory)
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == []

    calls.clear()
    def private_failure(_path, acl_checker=None):
        raise ValueError("private-path-canary")

    monkeypatch.setattr(runner, "validate_private_location", private_failure)
    result = runner.run(Path("auth"), Path("bindings"), Path("state"), operation="setup", step="preflight",
                        source_validator=lambda _auth: None, client_factory=client_factory)
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == []


def test_setup_uses_fixed_closed_template_and_deterministic_operation_token(monkeypatch, tmp_path):
    client_factory = lambda: {"cloudformation": _CloudFormation(), "iam": object()}
    source_validator = lambda _auth: None
    _patch_inputs(monkeypatch, source_validator=source_validator, client_factory=client_factory)
    captured = []

    class FakeCore:
        def __init__(self, clients, journal, **kwargs):
            captured.append(kwargs)
            self.journal = journal
            self.binding = {
                "source": kwargs["source_sha"], "account": kwargs["account"],
                "caller": kwargs["caller_arn"], "start": kwargs["start"],
                "end": kwargs["end"], "token": kwargs["token"],
            }

        def run(self, step):
            if step == "preflight":
                self.journal.save({"binding": self.binding, "phase": "ready"})
            return {"ok": True, "step": step}

    monkeypatch.setattr(runner, "ClosedDevUpdate", FakeCore)
    journal_paths = []
    class Journal:
        def __init__(self, directory):
            journal_paths.append(Path(directory))
            self.state = None

        @contextlib.contextmanager
        def locked(self):
            yield

        def load(self):
            return self.state

        def save(self, value):
            self.state = value

    journals = {}
    def journal_factory(directory):
        key = Path(directory)
        if key not in journals:
            journals[key] = Journal(key)
        return journals[key]

    state_dir = Path(f"setup-{AUTH['run_id']}-{SOURCE[:12]}")
    roles_binding = tmp_path / "roles-binding.json"
    roles_binding.write_text(json.dumps({"stack_arn": ROLES_STACK, "original_creation_run_id": 7}), encoding="utf-8")
    app_binding = tmp_path / "app-binding.json"
    app_binding.write_text(json.dumps({"stack_arn": APP_STACK, "original_creation_run_id": 8}), encoding="utf-8")
    verifier = lambda *args, **kwargs: {"success": True}

    first = runner.run(Path("auth"), Path("bindings"), state_dir, operation="setup", step="preflight",
                       source_validator=source_validator, client_factory=client_factory,
                       journal_factory=journal_factory, roles_binding_path=roles_binding,
                       role_verifier=verifier, app_binding_path=app_binding)
    second = runner.run(Path("auth"), Path("bindings"), state_dir, operation="setup", step="update",
                        source_validator=source_validator, client_factory=client_factory,
                        journal_factory=journal_factory, roles_binding_path=roles_binding,
                        role_verifier=verifier, app_binding_path=app_binding)
    assert first == {"ok": True, "step": "preflight"}
    assert second == {"ok": True, "step": "update"}
    assert len(captured) == 2
    expected = "dev-multiuser-" + hashlib.sha256(f"setup:42:{SOURCE}".encode()).hexdigest()[:32]
    assert [item["token"] for item in captured] == [expected, expected]
    assert all(item["stack_arn"] == APP_STACK for item in captured)
    assert all(item["service_role_arn"] == f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update" for item in captured)
    assert all(item["prior_template"] == runner.build_retained_dev_template() for item in captured)
    assert all(item["target_template"] == runner.build_retained_dev_multiuser_setup(
        api_id="a1b2c3d4e5", callback_url=runner.CALLBACK
    ) for item in captured)
    assert journal_paths == [state_dir]


def test_setup_app_binding_is_required_before_clients_or_core(monkeypatch, tmp_path):
    calls = []
    _patch_inputs(monkeypatch, source_validator=lambda _auth: None,
                  client_factory=lambda: calls.append("client") or {})
    monkeypatch.setattr(runner, "_load_app_binding", lambda *args, **kwargs: calls.append("app") or
                        {"stack_arn": APP_STACK, "original_creation_run_id": 8})
    monkeypatch.setattr(runner, "ClosedDevUpdate", lambda *args, **kwargs: calls.append("core"))
    result = runner.run(
        Path("auth"), Path("bindings"),
        Path(f"setup-{AUTH['run_id']}-{SOURCE[:12]}"),
        operation="setup", step="preflight", roles_binding_path=None,
        app_binding_path=tmp_path / "app-binding.json",
        client_factory=lambda: calls.append("client") or {},
    )
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == ["app"]


def test_setup_foreign_app_binding_is_rejected_before_clients(monkeypatch, tmp_path):
    calls = []
    _patch_inputs(monkeypatch, source_validator=lambda _auth: None)
    monkeypatch.setattr(runner, "_load_app_binding", lambda *args, **kwargs: {
        "stack_arn": APP_STACK.replace(ACCOUNT, "210987654321"),
        "original_creation_run_id": 8,
    })
    monkeypatch.setattr(runner, "ClosedDevUpdate", lambda *args, **kwargs: calls.append("core"))
    result = runner.run(
        Path("auth"), Path("bindings"),
        Path(f"setup-{AUTH['run_id']}-{SOURCE[:12]}"),
        operation="setup", step="preflight", roles_binding_path=None,
        app_binding_path=tmp_path / "app-binding.json",
        client_factory=lambda: calls.append("client") or {},
    )
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == []


def test_setup_missing_app_binding_is_rejected_before_clients_or_core(monkeypatch, tmp_path):
    """A missing setup receipt must not reach SDK construction or the update core."""
    calls = []
    _patch_inputs(monkeypatch, source_validator=lambda _auth: None,
                  client_factory=lambda: calls.append("client") or {})
    monkeypatch.setattr(runner, "ClosedDevUpdate", lambda *args, **kwargs: calls.append("core"))

    result = runner.run(
        Path("auth"), Path("bindings"),
        Path(f"setup-{AUTH['run_id']}-{SOURCE[:12]}"),
        operation="setup", step="preflight",
        app_binding_path=tmp_path / "missing-app-binding.json",
        client_factory=lambda: calls.append("client") or {},
    )
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == []


def test_setup_malformed_app_binding_is_rejected_before_clients_or_core(monkeypatch, tmp_path):
    """A malformed private receipt must fail closed before SDK construction or core work."""
    app_binding = tmp_path / "app-binding.json"
    app_binding.write_text('{"stack_arn": "not-an-arn"}', encoding="utf-8")
    calls = []
    _patch_inputs(monkeypatch, source_validator=lambda _auth: None,
                  client_factory=lambda: calls.append("client") or {})
    monkeypatch.setattr(runner, "ClosedDevUpdate", lambda *args, **kwargs: calls.append("core"))

    result = runner.run(
        Path("auth"), Path("bindings"),
        Path(f"setup-{AUTH['run_id']}-{SOURCE[:12]}"),
        operation="setup", step="preflight",
        app_binding_path=app_binding,
        client_factory=lambda: calls.append("client") or {},
    )
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == []


def test_invalid_operation_is_rejected_without_loading_private_inputs(monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "load_authorization", lambda _path: calls.append("auth") or dict(AUTH))
    result = runner.run(Path("auth"), Path("bindings"), Path("state"), operation="prod", step="preflight")
    assert result == {"ok": False, "category": "closed_update_failed"}
    assert calls == []
