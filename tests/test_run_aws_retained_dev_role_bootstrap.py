from __future__ import annotations

import json
from pathlib import Path

import scripts.run_aws_retained_dev_role_bootstrap as runner


def _auth():
    return {"account": "123456789012", "source_sha": "a" * 40, "run_id": 2026100601, "expected_caller_arn": "arn:aws:iam::123456789012:role/retained-artifact-operator", "start": 1900000000, "end": 1900003000, "ci_run_id": 1}


def _bindings():
    return {"account_id": "123456789012", "provider_arn": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com", "owner_id": "123", "repository_id": "456", "observed_dev_subject_format": "legacy_environment", "observed_dev_subject_sha256": "0" * 64, "stack_arn": "x", "artifact_stack_arn": "x", "handler_arn": "x", "api_arn": "x", "shutdown_state_machine_arn": "x", "artifact_bucket_arn": "x", "execution_role_arn": "x"}


def test_runner_validates_source_before_clients(tmp_path: Path):
    path = tmp_path / "authorization.json"; path.write_text(json.dumps(_auth()), encoding="utf-8")
    bindings = tmp_path / "bindings.json"; bindings.write_text(json.dumps(_bindings()), encoding="utf-8")
    state = tmp_path / "state"; state.mkdir(); called = []
    result = runner.run_authorized_step(path, bindings, state, "preflight", acl_checker=lambda _: True, source_ci_validator=lambda _: (_ for _ in ()).throw(runner.RetainedDevRunnerError("ci_verification_failed")), client_factory=lambda: called.append(True))
    assert result == {"step": "preflight", "ok": False, "category": "ci_verification_failed", "calls": 0}; assert called == []


def test_runner_rejects_proxy_without_details(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://secret.invalid")
    try: runner._build_clients()
    except runner.RetainedDevRunnerError as exc: assert exc.category == "proxy_or_custom_endpoint_rejected"
    else: raise AssertionError("proxy accepted")


def test_direct_entrypoint_imports():
    assert runner._ROOT.name == "honda-mapit-mcp"


def test_binding_account_mismatch_stops_before_clients(tmp_path: Path):
    auth = tmp_path / "authorization.json"; auth.write_text(json.dumps(_auth()), encoding="utf-8")
    binding = _bindings(); binding["account_id"] = "210987654321"
    bindings = tmp_path / "bindings.json"; bindings.write_text(json.dumps(binding), encoding="utf-8")
    state = tmp_path / "state"; state.mkdir(); called = []
    result = runner.run_authorized_step(auth, bindings, state, "preflight", acl_checker=lambda _: True, source_ci_validator=lambda _: None, client_factory=lambda: called.append(True))
    assert result["category"] == "binding_mismatch" and called == []
