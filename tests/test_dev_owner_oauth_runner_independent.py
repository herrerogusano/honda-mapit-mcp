from __future__ import annotations

import contextlib
import copy
import json
from pathlib import Path
import time

import pytest

from scripts import run_aws_dev_owner_oauth_bootstrap as runner
from scripts.build_aws_dev_owner_oauth import STACK_NAME


ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/offline-operator"
SOURCE = "a" * 40
OWNER_ID = 123456
REPOSITORY_ID = 789012
POOL = "eu-west-1_abcdefghijk"
API = "abcdefghij"
CONTEXT = "b" * 64
RUN_UUID = "123e4567-e89b-42d3-a456-426614174000"
CALLBACK = "http://127.0.0.1:39031/callback/codex-dev-owner"


class _AwsError(Exception):
    def __init__(self, code, status, message):
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class _Journal:
    def __init__(self):
        self.value = None

    @contextlib.contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.value)

    def save(self, value):
        self.value = copy.deepcopy(value)


class _Clients:
    def __init__(self, *, fail_create=False):
        self.fail_create = fail_create
        self.creates = []
        self.cloudformation = self
        self.cognito = self

    def describe_stacks(self, **kwargs):
        assert kwargs == {"StackName": STACK_NAME}
        raise _AwsError("ValidationError", 400, f"Stack with id {STACK_NAME} does not exist")

    def describe_resource_server(self, **kwargs):
        assert kwargs == {
            "UserPoolId": POOL,
            "Identifier": f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp",
        }
        raise _AwsError("ResourceNotFoundException", 400, "resource absent")

    def create_stack(self, **kwargs):
        self.creates.append(copy.deepcopy(kwargs))
        if self.fail_create:
            raise _AwsError("ServiceUnavailable", 503, "sensitive synthetic error")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "StackId": "invalid-fixture"}


class _Sdk:
    def __init__(self, clients, **_kwargs):
        self.clients = clients
        self.calls = 0

    def capture_context(self, exclude_client_id=None):
        assert exclude_client_id is None
        self.calls += 1
        return {
            "verified": True, "account_id": ACCOUNT, "owner_pool_id": POOL,
            "api_id": API, "context_sha256": CONTEXT,
        }

    def proxy(self, service):
        owner = self

        class Proxy:
            def __getattr__(self, method):
                def call(**kwargs):
                    owner.calls += 1
                    return getattr(owner.clients[service], method)(**kwargs)
                return call

        return Proxy()

    def validate_candidate(self, *_args):
        raise AssertionError("candidate validation is not part of these steps")


def _source_ok(_auth):
    return None


def _protection_ok(**kwargs):
    if kwargs:
        assert kwargs == {"expected_owner_id": OWNER_ID, "expected_repository_id": REPOSITORY_ID}
    return OWNER_ID, REPOSITORY_ID


def _clients():
    clients = _Clients()
    return {name: (clients if name in {"cloudformation", "cognito"} else object())
            for name in runner._CLIENTS}


def _prepare(tmp_path: Path, *, sdk_factory=_Sdk, source=_source_ok,
             client_factory=_clients, protection= _protection_ok):
    now = int(time.time())
    result = runner.prepare_private_authorization(
        tmp_path / "authorization.json", tmp_path / "state",
        account_id=ACCOUNT, operator_user_arn=OPERATOR, source_sha=SOURCE,
        ci_run_id=4321, callback_url=CALLBACK,
        acl_checker=lambda _path: True,
        source_ci_validator=source,
        protection_reader=protection,
        client_factory=client_factory,
        sdk_factory=sdk_factory,
        run_id_factory=lambda: (987654, RUN_UUID),
        wall_clock=lambda: now,
    )
    return result


def _run_preflight(tmp_path, *, clients, journal, **kwargs):
    return runner.run_authorized_step(
        tmp_path / "authorization.json", tmp_path / "state", "preflight",
        acl_checker=lambda _path: True,
        source_ci_validator=_source_ok,
        protection_reader=_protection_ok,
        client_factory=lambda: clients,
        sdk_factory=_Sdk,
        journal_factory=lambda path: journal,
        **kwargs,
    )


def test_prepare_and_real_coordinator_preflight_use_only_bound_state_root(tmp_path):
    prepared = _prepare(tmp_path)
    assert prepared == {"ok": True, "category": "authority_prepared", "step": "prepare", "calls": 1}
    assert (tmp_path / "state").is_dir()
    binding = json.loads((tmp_path / runner._BINDING_NAME).read_text(encoding="utf-8"))
    assert binding["state_directory"] == str((tmp_path / "state").resolve())

    clients = _clients()
    journal = _Journal()
    result = _run_preflight(tmp_path, clients=clients, journal=journal)
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 3}
    assert journal.value["phase"] == "preflight"
    assert clients["cloudformation"].creates == []


def test_alternate_empty_state_root_is_rejected_before_sdk_or_journal(tmp_path):
    assert _prepare(tmp_path)["ok"]
    alternate = tmp_path / "attacker-controlled-state"
    alternate.mkdir()
    clients = _clients()
    journal = _Journal()
    constructed = []

    def make_sdk(*args, **kwargs):
        constructed.append(True)
        return _Sdk(*args, **kwargs)

    result = runner.run_authorized_step(
        tmp_path / "authorization.json", alternate, "preflight",
        acl_checker=lambda _path: True, source_ci_validator=_source_ok,
        protection_reader=_protection_ok,
        client_factory=lambda: clients, sdk_factory=make_sdk,
        journal_factory=lambda _path: journal,
    )
    assert result == {"step": "preflight", "ok": False, "category": "journal_setup_failed", "calls": 0}
    assert constructed == []
    assert journal.value is None
    assert clients["cloudformation"].creates == []


def test_corrupt_binding_sidecar_fails_before_client_construction(tmp_path):
    assert _prepare(tmp_path)["ok"]
    binding_path = tmp_path / runner._BINDING_NAME
    payload = json.loads(binding_path.read_text(encoding="utf-8"))
    payload["state_directory"] = str((tmp_path / "other" / "state").resolve())
    binding_path.write_text(json.dumps(payload), encoding="utf-8")
    clients = _clients()
    constructed = []

    def make_clients():
        constructed.append(True)
        return clients

    result = runner.run_authorized_step(
        tmp_path / "authorization.json", tmp_path / "state", "preflight",
        acl_checker=lambda _path: True, source_ci_validator=_source_ok,
        protection_reader=_protection_ok, client_factory=make_clients,
        sdk_factory=_Sdk, journal_factory=lambda _path: _Journal(),
    )
    assert result["ok"] is False
    assert result["category"] in {"binding_invalid", "authorization_binding_mismatch"}
    assert result["calls"] == 0
    assert constructed == []


def test_failed_final_authorization_write_leaves_no_usable_authority(tmp_path, monkeypatch):
    def fail_write(*_args, **_kwargs):
        raise OSError("private write failed")

    monkeypatch.setattr(runner, "write_private_authorization", fail_write)
    result = _prepare(tmp_path)
    assert result["ok"] is False
    assert result["category"] in {"authority_write_failed", "runner_internal_error"}
    assert not (tmp_path / "authorization.json").exists()
    assert (tmp_path / runner._BINDING_NAME).exists()
    clients = _clients()
    constructed = []
    replay = runner.run_authorized_step(
        tmp_path / "authorization.json", tmp_path / "state", "preflight",
        acl_checker=lambda _path: True, source_ci_validator=_source_ok,
        protection_reader=_protection_ok,
        client_factory=lambda: constructed.append(True) or clients,
        sdk_factory=_Sdk, journal_factory=lambda _path: _Journal(),
    )
    assert replay["ok"] is False and replay["calls"] == 0
    assert constructed == []


def test_unknown_create_outcome_stays_consumed_on_runner_reentry(tmp_path):
    assert _prepare(tmp_path)["ok"]
    raw_clients = _Clients(fail_create=True)
    clients = {name: (raw_clients if name in {"cloudformation", "cognito"} else object())
               for name in runner._CLIENTS}
    journal = _Journal()

    def run(step):
        return runner.run_authorized_step(
            tmp_path / "authorization.json", tmp_path / "state", step,
            acl_checker=lambda _path: True, source_ci_validator=_source_ok,
            protection_reader=_protection_ok, client_factory=lambda: clients,
            sdk_factory=_Sdk, journal_factory=lambda _path: journal,
        )

    preflight = run("preflight")
    assert preflight["ok"] is True
    first = run("create")
    assert first["ok"] is False and first["category"] == "create_outcome_unknown"
    assert journal.value["phase"] == "create_intent"
    assert len(raw_clients.creates) == 1
    again = run("create")
    assert again["ok"] is False and again["category"] == "create_intent_present"
    assert len(raw_clients.creates) == 1
    assert "sensitive" not in repr(first) + repr(again)
