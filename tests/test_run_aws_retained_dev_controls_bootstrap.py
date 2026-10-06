from __future__ import annotations

import json
from pathlib import Path

import scripts.run_aws_retained_dev_controls_bootstrap as runner

ACCOUNT = "123456789012"
SOURCE = "a" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-controls-operator"
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"


def _auth():
    return {"account": ACCOUNT, "source_sha": SOURCE, "run_id": 2026100606, "expected_caller_arn": CALLER, "start": 1_900_000_000, "end": 1_900_003_000, "ci_run_id": 123}


def _binding():
    return {"account": ACCOUNT, "stack_id": STACK_ID, "api_id": "a1b2c3d4e5"}


def _write(tmp_path: Path):
    auth = tmp_path / "authorization.json"; auth.write_text(json.dumps(_auth()), encoding="utf-8")
    binding = tmp_path / "api-binding.json"; binding.write_text(json.dumps(_binding()), encoding="utf-8")
    state = tmp_path / "state"; state.mkdir()
    return auth, binding, state


def test_load_api_binding_is_exact_and_private(tmp_path: Path):
    import pytest
    path = tmp_path / "api-binding.json"
    path.write_text(json.dumps(_binding()), encoding="utf-8")
    assert runner.load_api_binding(path)["api_id"] == "a1b2c3d4e5"
    path.write_text(json.dumps({**_binding(), "extra": 1}), encoding="utf-8")
    with pytest.raises(runner.RetainedDevRunnerError) as error:
        runner.load_api_binding(path)
    assert error.value.category == "api_binding_invalid"


def test_runner_validates_ci_before_constructing_clients(tmp_path: Path):
    auth, binding, state = _write(tmp_path)
    calls = []
    def no_clients():
        calls.append(True)
        raise AssertionError("must not construct clients")
    result = runner.run_authorized_step(auth, binding, state, "preflight", acl_checker=lambda _path: True, source_ci_validator=lambda _auth: (_ for _ in ()).throw(runner.RetainedDevRunnerError("ci_verification_failed")), client_factory=no_clients)
    assert result == {"step": "preflight", "ok": False, "category": "ci_verification_failed", "calls": 0}
    assert calls == []


def test_runner_rejects_account_binding_mismatch(tmp_path: Path):
    auth, binding, state = _write(tmp_path)
    binding.write_text(json.dumps({**_binding(), "account": "210987654321", "stack_id": STACK_ID.replace(ACCOUNT, "210987654321")}), encoding="utf-8")
    result = runner.run_authorized_step(auth, binding, state, "preflight", acl_checker=lambda _path: True, source_ci_validator=lambda _auth: None, client_factory=lambda: {})
    assert result["category"] == "binding_mismatch"


def test_runner_projects_only_safe_result(tmp_path: Path, monkeypatch):
    auth, binding, state = _write(tmp_path)
    captured = []
    class FakeCoordinator:
        def __init__(self, clients, journal, **kwargs):
            captured.append((clients, journal, kwargs))
        def run_step(self, step):
            return {"step": step, "ok": True, "category": "preflight_verified", "calls": 2}
    monkeypatch.setattr(runner, "RetainedDevControlsCoordinator", FakeCoordinator)
    result = runner.run_authorized_step(auth, binding, state, "preflight", acl_checker=lambda _path: True, source_ci_validator=lambda _auth: None, client_factory=lambda: {"sts": object()}, journal_factory=lambda _path: object())
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 2}
    assert captured[0][2]["api_id"] == "a1b2c3d4e5"
    assert ACCOUNT not in json.dumps(result)


def test_runner_rejects_proxy_without_clients(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://secret.invalid")
    import pytest
    with pytest.raises(runner.RetainedDevRunnerError) as error:
        runner._build_clients()
    assert error.value.category == "proxy_or_custom_endpoint_rejected"
