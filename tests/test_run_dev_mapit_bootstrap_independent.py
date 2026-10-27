from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import scripts.run_dev_mapit_bootstrap as runner


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-mapit-operator"
SOURCE = "a" * 40
START = 1_900_000_000
END = START + 600
CI_RUN = 123456789
CI_SHA = "b" * 64
RUNTIME_SHA = "c" * 64
KEY_ARN = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"
TENANT_KEYS = ["tenant-" + f"{n:064x}" for n in (201, 202)]
OLD_KEYS = ["tenant-" + f"{n:064x}" for n in (101, 102)]
GITHUB = {"github_owner_id": 12345, "github_repository_id": 67890}


def _inputs():
    source = {
        "account": ACCOUNT, "source_sha": SOURCE, "run_id": 42,
        "expected_caller_arn": CALLER, "start": START, "end": END,
        "ci_run_id": CI_RUN,
    }
    authority = {
        "account_id": ACCOUNT, "operator_user_arn": CALLER, "source_sha": SOURCE,
        "run_id": 42, "expected_caller_arn": CALLER,
        "authorized_from_epoch": START, "authorized_until_epoch": END,
        "ci_evidence_sha256": runner.ci_evidence_digest(source, GITHUB),
        "runtime_evidence_sha256": RUNTIME_SHA, "ssm_key_arn": KEY_ARN,
        "tenant_keys": TENANT_KEYS, "excluded_tenant_keys": OLD_KEYS,
    }
    return {"schema": 1, "kind": runner.KIND, "authority": authority,
            "source_authorization": source, "github": dict(GITHUB)}


def _write_json(path: Path, value):
    path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    return path


def test_authority_loader_rejects_duplicate_json_and_bad_ci_digest(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema":1,"schema":1}', encoding="utf-8")
    with pytest.raises(runner.MapitBootstrapRunnerError):
        runner.load_runner_authority(duplicate, acl_checker=lambda _: True)

    document = _inputs()
    document["authority"]["ci_evidence_sha256"] = "d" * 64
    path = _write_json(tmp_path / "bad-digest.json", document)
    with pytest.raises(runner.MapitBootstrapRunnerError):
        runner.load_runner_authority(path, acl_checker=lambda _: True)


@pytest.mark.parametrize("change", [
    lambda value: value.update(schema=True),
    lambda value: value["authority"].update(run_id=True),
    lambda value: value["github"].update(github_owner_id=True),
    lambda value: value["source_authorization"].update(source_sha="f" * 40),
])
def test_invalid_authority_and_source_bindings_stop_before_client_factory(tmp_path, change):
    document = _inputs()
    change(document)
    authority_path = _write_json(tmp_path / "authority.json", document)
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    historical = tmp_path / "historical"
    historical.mkdir()
    for filename in ("binding.json", "authorization.json"):
        (historical / filename).write_text("{}", encoding="utf-8")
    state = tmp_path / "new-state"
    state.mkdir()
    calls = []

    result = runner.run_authorized_step(
        authority_path, evidence, historical / "binding.json", historical / "authorization.json",
        historical, state, "preflight", acl_checker=lambda _: True,
        client_factory=lambda: calls.append("client") or {},
        journal_factory=lambda _: calls.append("journal"),
        runtime_verifier_factory=lambda **_: calls.append("runtime-verifier"),
    )
    assert result["ok"] is False
    assert calls == []


def test_historical_state_collision_is_rejected_before_journal_or_sdk(tmp_path):
    authority = _write_json(tmp_path / "authority.json", _inputs())
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    historical = tmp_path / "historical"
    historical.mkdir()
    binding = historical / "binding.json"
    authorization = historical / "authorization.json"
    binding.write_text("{}", encoding="utf-8")
    authorization.write_text("{}", encoding="utf-8")
    calls = []

    result = runner.run_authorized_step(
        authority, evidence, binding, authorization, historical, historical, "preflight",
        acl_checker=lambda _: True,
        client_factory=lambda: calls.append("client") or {},
        journal_factory=lambda _: calls.append("journal"),
        runtime_verifier_factory=lambda **_: calls.append("runtime-verifier"),
        command_runner=lambda *_args, **_kwargs: calls.append("command"),
    )
    assert result["ok"] is False
    assert calls == []


def test_fresh_source_and_protection_callbacks_run_bounded_commands(monkeypatch, tmp_path):
    from scripts.github_cd_protections import REPOSITORY
    from tests.test_github_cd_protections import _branch_readback, _environment_readback

    authority_path = _write_json(tmp_path / "authority.json", _inputs())
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    historical = tmp_path / "historical"
    historical.mkdir()
    binding = historical / "binding.json"
    authorization = historical / "authorization.json"
    binding.write_text("{}", encoding="utf-8")
    authorization.write_text("{}", encoding="utf-8")
    state = tmp_path / "new-state"
    state.mkdir()

    private_state = runner.validate_private_location(state, acl_checker=lambda _: True)
    historical_state = runner.validate_private_location(historical, acl_checker=lambda _: True)
    protected = [runner.validate_private_location(path, acl_checker=lambda _: True)
                 for path in (binding, authorization)]
    assert private_state != historical_state
    assert historical_state not in private_state.parents
    assert all(private_state != path and private_state not in path.parents for path in protected)

    gh_run = {
        "status": "completed", "conclusion": "success", "headSha": SOURCE,
        "headBranch": "develop", "event": "push", "workflowName": "CI",
        "databaseId": CI_RUN, "workflowDatabaseId": 987654321,
        "jobs": [{"name": name, "status": "completed", "conclusion": "success"}
                  for name in runner.validate_source_and_ci.__globals__["CI_JOB_NAMES"]],
    }
    branch_payloads = [
        {"full_name": REPOSITORY, "id": GITHUB["github_repository_id"],
         "owner": {"login": "herrerogusano", "id": GITHUB["github_owner_id"]}},
        _branch_readback(),
        _environment_readback("dev", owner_id=GITHUB["github_owner_id"]),
        {"total_count": 1, "branch_policies": [
            {"name": "develop", "type": "branch", "id": 701, "node_id": "MDQ6R2F0ZTE="},
        ]},
    ]
    commands = []
    setup_events = []

    def command(args, **_kwargs):
        commands.append(list(args))
        if args[:2] == ["git", "-C"]:
            if "rev-parse" in args:
                output = SOURCE + "\n"
            elif "branch" in args:
                output = "develop\n"
            else:
                output = ""
        elif args[:3] == ["gh", "run", "view"]:
            output = json.dumps(gh_run)
        elif args[:2] == ["gh", "api"] and "actions/workflows/" in args[2]:
            output = json.dumps({"id": 987654321, "path": ".github/workflows/ci.yml",
                                 "name": "CI", "state": "active"})
        elif args[:2] == ["gh", "api"]:
            suffix = len([c for c in commands if c[:2] == ["gh", "api"]
                          and "actions/workflows/" not in c[2]])
            output = json.dumps(branch_payloads[(suffix - 1) % len(branch_payloads)])
        else:
            raise AssertionError("unexpected command shape")
        return SimpleNamespace(returncode=0, stdout=output.encode("utf-8"), stderr=b"")

    phases = []

    class FakeCoordinator:
        STEPS = ("preflight", "create", "readback")

        def __init__(self, clients, journal, *, authority, fresh_source,
                     fresh_protections, closed_runtime_verifier):
            assert set(clients) == {"synthetic-client"}
            assert clients["synthetic-client"].client is object_marker
            assert journal == "fresh-journal"
            self.authority = authority
            self.fresh_source = fresh_source
            self.fresh_protections = fresh_protections
            self.runtime = closed_runtime_verifier

        def run_step(self, step):
            source_result = self.fresh_source(self.authority)
            protection_result = self.fresh_protections(self.authority)
            phases.append((source_result, protection_result))
            return {"step": step, "ok": True, "category": "adapter_test", "calls": 0}

    object_marker = object()
    monkeypatch.setattr(runner, "MapitBootstrapCoordinator", FakeCoordinator)

    def clients_after_fresh_gates():
        assert len(commands) == 9
        return {"synthetic-client": object_marker}

    result = runner.run_authorized_step(
        authority_path, evidence, binding, authorization, historical, state, "preflight",
        acl_checker=lambda _: True, command_runner=command,
        client_factory=clients_after_fresh_gates,
        journal_factory=lambda path: setup_events.append("journal") or "fresh-journal",
        runtime_verifier_factory=lambda **_: setup_events.append("runtime") or (lambda *_args, **_kwargs: {}),
    )
    assert result == {"step": "preflight", "ok": True, "category": "adapter_test",
                      "calls": 0, "command_calls": 18, "budget_calls": 0}, (result, commands, setup_events)
    assert len(phases) == 1
    source_result, protection_result = phases[0]
    assert source_result["verified"] is True and source_result["calls"] == 5
    assert source_result["branch"] == "develop"
    assert protection_result["verified"] is True and protection_result["calls"] == 4
    assert protection_result["environment"] == "dev"
    assert len(commands) == 18  # initial fresh gates plus one coordinator callback each
    assert commands[0][:2] == ["git", "-C"]


def test_failed_fresh_command_is_counted_and_stops_before_clients(monkeypatch, tmp_path):
    authority = _write_json(tmp_path / "authority.json", _inputs())
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    historical = tmp_path / "historical"
    historical.mkdir()
    binding = historical / "binding.json"
    authorization = historical / "authorization.json"
    binding.write_text("{}", encoding="utf-8")
    authorization.write_text("{}", encoding="utf-8")
    state = tmp_path / "new-state"
    state.mkdir()
    calls = []

    def fail_after_one_command(_authorization, *, command_runner):
        command_runner(["git", "-C", "repo", "rev-parse", "--verify", "HEAD"])
        raise RuntimeError("safe-category-only")

    def command(args, **_kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout=b"", stderr=b"canary")

    monkeypatch.setattr(runner, "validate_source_and_ci", fail_after_one_command)
    result = runner.run_authorized_step(
        authority, evidence, binding, authorization, historical, state, "preflight",
        acl_checker=lambda _: True, command_runner=command,
        client_factory=lambda: pytest.fail("client factory must remain lazy"),
        journal_factory=lambda _: pytest.fail("journal must remain unopened"),
        runtime_verifier_factory=lambda **_: lambda *_args, **_kwargs: {},
    )
    assert result == {"step": "preflight", "ok": False,
                      "category": "mapit_bootstrap_runner_unverified",
                      "calls": 0, "command_calls": 1}, (result, calls)
    assert len(calls) == 1


def test_failed_wrapped_sdk_dispatch_is_counted_after_nine_fresh_gates(monkeypatch, tmp_path):
    from scripts.github_cd_protections import REPOSITORY
    from tests.test_github_cd_protections import _branch_readback, _environment_readback

    authority_path = _write_json(tmp_path / "authority.json", _inputs())
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}", encoding="utf-8")
    historical = tmp_path / "historical"
    historical.mkdir()
    binding = historical / "binding.json"
    authorization = historical / "authorization.json"
    binding.write_text("{}", encoding="utf-8")
    authorization.write_text("{}", encoding="utf-8")
    state = tmp_path / "new-state"
    state.mkdir()

    gh_run = {
        "status": "completed", "conclusion": "success", "headSha": SOURCE,
        "headBranch": "develop", "event": "push", "workflowName": "CI",
        "databaseId": CI_RUN, "workflowDatabaseId": 987654321,
        "jobs": [{"name": name, "status": "completed", "conclusion": "success"}
                  for name in runner.validate_source_and_ci.__globals__["CI_JOB_NAMES"]],
    }
    branch_payloads = [
        {"full_name": REPOSITORY, "id": GITHUB["github_repository_id"],
         "owner": {"login": "herrerogusano", "id": GITHUB["github_owner_id"]}},
        _branch_readback(),
        _environment_readback("dev", owner_id=GITHUB["github_owner_id"]),
        {"total_count": 1, "branch_policies": [
            {"name": "develop", "type": "branch", "id": 701, "node_id": "MDQ6R2F0ZTE="},
        ]},
    ]
    commands = []

    def command(args, **_kwargs):
        commands.append(list(args))
        if args[:2] == ["git", "-C"]:
            if "rev-parse" in args:
                output = SOURCE + "\n"
            elif "branch" in args:
                output = "develop\n"
            else:
                output = ""
        elif args[:3] == ["gh", "run", "view"]:
            output = json.dumps(gh_run)
        elif args[:2] == ["gh", "api"] and "actions/workflows/" in args[2]:
            output = json.dumps({"id": 987654321, "path": ".github/workflows/ci.yml",
                                 "name": "CI", "state": "active"})
        elif args[:2] == ["gh", "api"]:
            suffix = len([c for c in commands if c[:2] == ["gh", "api"]
                          and "actions/workflows/" not in c[2]])
            output = json.dumps(branch_payloads[(suffix - 1) % len(branch_payloads)])
        else:
            raise AssertionError("unexpected command shape")
        return SimpleNamespace(returncode=0, stdout=output.encode("utf-8"), stderr=b"")

    class FailingSTS:
        def get_caller_identity(self):
            raise RuntimeError("private SDK error must not escape")

    class FakeCoordinator:
        STEPS = ("preflight", "create", "readback")

        def __init__(self, clients, journal, **_kwargs):
            assert journal == "fresh-journal"
            self.clients = clients

        def run_step(self, _step):
            self.clients["sts"].get_caller_identity()

    monkeypatch.setattr(runner, "MapitBootstrapCoordinator", FakeCoordinator)
    result = runner.run_authorized_step(
        authority_path, evidence, binding, authorization, historical, state, "preflight",
        acl_checker=lambda _: True,
        command_runner=command,
        client_factory=lambda: {"sts": FailingSTS()},
        journal_factory=lambda _: "fresh-journal",
        runtime_verifier_factory=lambda **_: lambda *_args, **_kwargs: {},
    )

    assert len(commands) == 9
    assert result == {
        "step": "preflight", "ok": False,
        "category": "mapit_bootstrap_runner_unverified",
        "calls": 1, "command_calls": 9,
    }
