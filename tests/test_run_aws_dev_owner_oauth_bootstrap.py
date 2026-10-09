from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import run_aws_dev_owner_oauth_bootstrap as runner
from scripts.build_aws_dev_owner_oauth import STACK_NAME


ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/dev-owner"
SOURCE = "a" * 40
OWNER_ID = 123456
REPOSITORY_ID = 789012
POOL = "eu-west-1_abcdefghijk"
API = "abcdefghij"
CONTEXT = "b" * 64
RUN_UUID = "123e4567-e89b-42d3-a456-426614174000"
CALLBACK = "http://127.0.0.1:8787/callback/dev-owner"


class _SDK:
    def __init__(self, clients, **kwargs):
        self.clients = clients
        self.kwargs = kwargs
        self.calls = 4

    def capture_context(self, exclude_client_id=None):
        assert exclude_client_id is None
        return {
            "verified": True, "account_id": ACCOUNT, "owner_pool_id": POOL,
            "api_id": API, "context_sha256": CONTEXT,
        }

    def proxy(self, service):
        return self.clients[service]

    def validate_candidate(self, *args):
        return {"verified": True, "client_id": "client12345678", "readback_sha256": "c" * 64}


def _clients():
    return {name: object() for name in runner._CLIENTS}


def _source(_auth):
    return None


def _protection(**kwargs):
    if kwargs:
        assert kwargs == {"expected_owner_id": OWNER_ID, "expected_repository_id": REPOSITORY_ID}
    return OWNER_ID, REPOSITORY_ID


def _prepare(tmp_path: Path, **kwargs):
    return runner.prepare_private_authorization(
        tmp_path / "authorization.json", tmp_path / "state", account_id=ACCOUNT,
        operator_user_arn=OPERATOR, source_sha=SOURCE, ci_run_id=1234,
        callback_url=CALLBACK, acl_checker=lambda _path: True,
        source_ci_validator=_source, protection_reader=_protection,
        client_factory=_clients, sdk_factory=_SDK,
        run_id_factory=lambda: (987654, RUN_UUID), wall_clock=lambda: 1_800_000_000,
        **kwargs,
    )


def test_prepare_creates_bound_private_pair_without_echoing_values(tmp_path):
    result = _prepare(tmp_path)
    assert result == {"ok": True, "category": "authority_prepared", "step": "prepare", "calls": 4}
    auth_path = tmp_path / "authorization.json"
    binding_path = tmp_path / runner._BINDING_NAME
    auth = json.loads(auth_path.read_text(encoding="utf-8"))
    binding = json.loads(binding_path.read_text(encoding="utf-8"))
    assert auth["account"] == ACCOUNT and auth["expected_caller_arn"] == OPERATOR
    assert auth["end"] - auth["start"] == 600
    assert binding["github_owner_id"] == OWNER_ID
    assert binding["github_repository_id"] == REPOSITORY_ID
    assert binding["authorization_sha256"] == runner._sha(auth)
    assert "client_secret" not in binding and "token" not in binding


@pytest.mark.parametrize("callback", [
    "http://127.0.0.1:8785/callback", "http://localhost:8786/callback",
    "https://127.0.0.1:8787/callback", "http://192.0.2.1:8787/callback",
])
def test_prepare_rejects_reserved_or_non_loopback_callback_before_clients(tmp_path, callback):
    calls = []
    result = runner.prepare_private_authorization(
        tmp_path / "authorization.json", tmp_path / "state", account_id=ACCOUNT,
        operator_user_arn=OPERATOR, source_sha=SOURCE, ci_run_id=1234,
        callback_url=callback, acl_checker=lambda _path: True,
        source_ci_validator=_source, protection_reader=_protection,
        client_factory=lambda: calls.append("clients") or _clients(), sdk_factory=_SDK,
        wall_clock=lambda: 1_800_000_000,
    )
    assert result == {"ok": False, "category": "binding_invalid", "step": "prepare", "calls": 0}
    assert calls == []
    assert not (tmp_path / "authorization.json").exists()
    assert not (tmp_path / runner._BINDING_NAME).exists()


def test_prepare_source_failure_prevents_client_construction_and_publication(tmp_path):
    calls = []

    def reject(_auth):
        raise RuntimeError("sensitive source diagnostic")

    result = runner.prepare_private_authorization(
        tmp_path / "authorization.json", tmp_path / "state", account_id=ACCOUNT,
        operator_user_arn=OPERATOR, source_sha=SOURCE, ci_run_id=1234,
        callback_url=CALLBACK, acl_checker=lambda _path: True,
        source_ci_validator=reject, protection_reader=_protection,
        client_factory=lambda: calls.append("clients") or _clients(), sdk_factory=_SDK,
        wall_clock=lambda: 1_800_000_000,
    )
    assert result == {"ok": False, "category": "source_ci_failed", "step": "prepare", "calls": 0}
    assert calls == []
    assert not (tmp_path / "authorization.json").exists()
    assert not (tmp_path / runner._BINDING_NAME).exists()
    assert "sensitive" not in repr(result)


def test_prepare_expired_window_does_not_publish_files(tmp_path):
    ticks = iter((1_800_000_000, 1_800_000_600))
    result = runner.prepare_private_authorization(
        tmp_path / "authorization.json", tmp_path / "state", account_id=ACCOUNT,
        operator_user_arn=OPERATOR, source_sha=SOURCE, ci_run_id=1234,
        callback_url=CALLBACK, acl_checker=lambda _path: True,
        source_ci_validator=_source, protection_reader=_protection,
        client_factory=_clients, sdk_factory=_SDK,
        run_id_factory=lambda: (987654, RUN_UUID), wall_clock=lambda: next(ticks),
    )
    assert result == {"ok": False, "category": "window_expired", "step": "prepare", "calls": 4}
    assert not (tmp_path / "authorization.json").exists()
    assert not (tmp_path / runner._BINDING_NAME).exists()


def test_run_step_revalidates_bound_github_ids_before_sdk_setup(tmp_path):
    auth_path = tmp_path / "authorization.json"
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    auth = {
        "account": ACCOUNT, "expected_caller_arn": OPERATOR, "source_sha": SOURCE,
        "run_id": 987654, "start": 1_800_000_000, "end": 1_800_000_600,
        "ci_run_id": 1234,
    }
    from scripts.run_aws_retained_dev_bootstrap import write_private_authorization
    write_private_authorization(auth_path, auth, acl_checker=lambda _path: True)
    runner._write_private_binding(runner._binding_path(auth_path), {
        "schema": 1, "kind": "dev-owner-oauth-authority", "account_id": ACCOUNT,
        "operator_user_arn": OPERATOR, "owner_pool_id": POOL, "api_id": API,
        "callback_url": CALLBACK, "context_sha256": CONTEXT, "run_uuid": RUN_UUID,
        "github_owner_id": OWNER_ID, "github_repository_id": REPOSITORY_ID,
        "authorization_sha256": runner._sha(auth),
        "state_directory": str(state_dir.resolve()),
    }, acl_checker=lambda _path: True)
    calls = []
    result = runner.run_authorized_step(
        auth_path, state_dir, "preflight", acl_checker=lambda _path: True,
        source_ci_validator=_source,
        protection_reader=lambda **kwargs: (OWNER_ID + 1, REPOSITORY_ID),
        client_factory=lambda: calls.append("clients") or _clients(), sdk_factory=_SDK,
    )
    assert result == {"step": "preflight", "ok": False, "category": "github_protection_failed", "calls": 0}
    assert calls == []


def test_run_step_rejects_relocated_journal_before_client_setup(tmp_path):
    auth_path = tmp_path / "authorization.json"
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    alternate = tmp_path / "alternate-state"
    alternate.mkdir()
    auth = {
        "account": ACCOUNT, "expected_caller_arn": OPERATOR, "source_sha": SOURCE,
        "run_id": 987654, "start": 1_800_000_000, "end": 1_800_000_600,
        "ci_run_id": 1234,
    }
    from scripts.run_aws_retained_dev_bootstrap import write_private_authorization
    write_private_authorization(auth_path, auth, acl_checker=lambda _path: True)
    runner._write_private_binding(runner._binding_path(auth_path), {
        "schema": 1, "kind": "dev-owner-oauth-authority", "account_id": ACCOUNT,
        "operator_user_arn": OPERATOR, "owner_pool_id": POOL, "api_id": API,
        "callback_url": CALLBACK, "context_sha256": CONTEXT, "run_uuid": RUN_UUID,
        "github_owner_id": OWNER_ID, "github_repository_id": REPOSITORY_ID,
        "authorization_sha256": runner._sha(auth),
        "state_directory": str(state_dir.resolve()),
    }, acl_checker=lambda _path: True)
    calls = []
    result = runner.run_authorized_step(
        auth_path, alternate, "preflight", acl_checker=lambda _path: True,
        source_ci_validator=_source, protection_reader=_protection,
        client_factory=lambda: calls.append("clients") or _clients(), sdk_factory=_SDK,
    )
    assert result == {"step": "preflight", "ok": False, "category": "journal_setup_failed", "calls": 0}
    assert calls == []


def test_run_step_passes_only_bound_context_into_coordinator(tmp_path, monkeypatch):
    auth_path = tmp_path / "authorization.json"
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    auth = {
        "account": ACCOUNT, "expected_caller_arn": OPERATOR, "source_sha": SOURCE,
        "run_id": 987654, "start": 1_800_000_000, "end": 1_800_000_600,
        "ci_run_id": 1234,
    }
    from scripts.run_aws_retained_dev_bootstrap import write_private_authorization
    write_private_authorization(auth_path, auth, acl_checker=lambda _path: True)
    runner._write_private_binding(runner._binding_path(auth_path), {
        "schema": 1, "kind": "dev-owner-oauth-authority", "account_id": ACCOUNT,
        "operator_user_arn": OPERATOR, "owner_pool_id": POOL, "api_id": API,
        "callback_url": CALLBACK, "context_sha256": CONTEXT, "run_uuid": RUN_UUID,
        "github_owner_id": OWNER_ID, "github_repository_id": REPOSITORY_ID,
        "authorization_sha256": runner._sha(auth),
        "state_directory": str(state_dir.resolve()),
    }, acl_checker=lambda _path: True)
    seen = {}

    class Coordinator:
        def __init__(self, clients, journal, **kwargs):
            seen.update(clients=clients, journal=journal, kwargs=kwargs)

        def run_step(self, step):
            return {"step": step, "ok": True, "category": "preflight_verified", "calls": 2}

    monkeypatch.setattr(runner, "DevOwnerOAuthBootstrapCoordinator", Coordinator)
    result = runner.run_authorized_step(
        auth_path, state_dir, "preflight", acl_checker=lambda _path: True,
        source_ci_validator=_source, protection_reader=_protection,
        client_factory=_clients, sdk_factory=_SDK,
        journal_factory=lambda path: ("journal", path),
    )
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 4}
    assert set(seen["clients"]) == {"cloudformation", "cognito"}
    assert seen["kwargs"]["account_id"] == ACCOUNT
    assert seen["kwargs"]["operator_user_arn"] == OPERATOR
    assert seen["kwargs"]["owner_pool_id"] == POOL
    assert seen["kwargs"]["api_id"] == API
    assert seen["kwargs"]["callback_url"] == CALLBACK
    assert seen["kwargs"]["expected_context_sha256"] == CONTEXT
