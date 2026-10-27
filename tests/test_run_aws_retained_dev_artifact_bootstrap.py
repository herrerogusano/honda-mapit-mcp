from __future__ import annotations

import json
from pathlib import Path

import scripts.run_aws_retained_dev_artifact_bootstrap as runner


ACCOUNT = "123456789012"
SOURCE = "a" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-artifact-operator"


def _auth() -> dict[str, object]:
    return {"account": ACCOUNT, "source_sha": SOURCE, "run_id": 2026100601,
            "expected_caller_arn": CALLER, "start": 1_900_000_000,
            "end": 1_900_003_000, "ci_run_id": 123}


def test_runner_rejects_source_before_building_clients(tmp_path: Path):
    auth = tmp_path / "authorization.json"
    auth.write_text(json.dumps(_auth()), encoding="utf-8")
    (tmp_path / "state").mkdir()
    calls: list[bool] = []

    def no_clients():
        calls.append(True)
        raise AssertionError("must not construct clients")

    result = runner.run_authorized_step(
        auth, tmp_path / "state", "preflight", acl_checker=lambda _path: True,
        source_ci_validator=lambda _value: (_ for _ in ()).throw(runner.RetainedDevRunnerError("ci_verification_failed")),
        client_factory=no_clients,
    )
    assert result == {"step": "preflight", "ok": False, "category": "ci_verification_failed", "calls": 0}
    assert calls == []


def test_runner_projects_only_safe_coordinator_result(tmp_path: Path, monkeypatch):
    auth = tmp_path / "authorization.json"
    auth.write_text(json.dumps(_auth()), encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    captured = []

    class FakeCoordinator:
        def __init__(self, clients, journal, **kwargs):
            captured.append((clients, journal, kwargs))

        def run_step(self, step):
            return {"step": step, "ok": True, "category": "preflight_verified", "calls": 1}

    monkeypatch.setattr(runner, "RetainedDevArtifactCoordinator", FakeCoordinator)
    result = runner.run_authorized_step(
        auth, state, "preflight", acl_checker=lambda _path: True,
        source_ci_validator=lambda _value: None,
        client_factory=lambda: {"sts": object(), "cloudformation": object(), "s3": object()},
        journal_factory=lambda _path: object(),
    )
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 1}
    assert captured[0][2]["account_id"] == ACCOUNT
    assert ACCOUNT not in json.dumps(result)


def test_runner_maps_private_or_client_failures_without_details(tmp_path: Path):
    auth = tmp_path / "authorization.json"
    auth.write_text(json.dumps(_auth()), encoding="utf-8")
    (tmp_path / "state").mkdir()
    result = runner.run_authorized_step(
        auth, tmp_path / "state", "preflight", acl_checker=lambda _path: True,
        source_ci_validator=lambda _value: None,
        client_factory=lambda: (_ for _ in ()).throw(runner.RetainedDevRunnerError("client_construction_failed")),
    )
    assert result == {"step": "preflight", "ok": False, "category": "client_construction_failed", "calls": 0}


def test_runner_rejects_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://secret.invalid")
    try:
        runner._build_clients()
    except runner.RetainedDevRunnerError as exc:
        assert exc.category == "proxy_or_custom_endpoint_rejected"
    else:
        raise AssertionError("proxy must be rejected")
