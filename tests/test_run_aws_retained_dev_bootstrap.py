from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.run_aws_retained_dev_bootstrap as runner


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-dev-bootstrap"
SOURCE = "a" * 40


def auth(**overrides):
    value = {
        "account": ACCOUNT,
        "source_sha": SOURCE,
        "run_id": 2026100601,
        "expected_caller_arn": CALLER,
        "start": 1_900_000_000,
        "end": 1_900_003_600,
        "ci_run_id": 123456789,
    }
    value.update(overrides)
    return value


def test_authorization_is_exact_bounded_and_redacts_extra_secret_fields():
    assert runner.validate_authorization(auth())["run_id"] == 2026100601
    for bad in (
        {**auth(), "password": "secret"},
        {**auth(), "source_sha": "0" * 40},
        {**auth(), "expected_caller_arn": f"arn:aws:iam::{ACCOUNT}:root"},
        {**auth(), "end": 1_900_003_601},
        {**auth(), "run_id": True},
    ):
        with pytest.raises(runner.RetainedDevRunnerError):
            runner.validate_authorization(bad)


def test_authorization_file_rejects_duplicate_json_and_symlink(tmp_path: Path):
    path = tmp_path / "authorization.json"
    path.write_text('{"account":"123456789012","account":"123456789012"}', encoding="utf-8")
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner.load_authorization(path)
    assert exc.value.category == "authorization_file_invalid"

    link = tmp_path / "link.json"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(runner.RetainedDevRunnerError):
        runner.load_authorization(link)


def test_write_private_authorization_is_canonical_bounded_and_exclusive(tmp_path: Path):
    target = tmp_path / "authorization.json"
    written = runner.write_private_authorization(target, auth(), acl_checker=lambda _: True)
    assert written == target
    assert json.loads(target.read_text(encoding="utf-8")) == auth()
    assert target.read_bytes() == json.dumps(auth(), sort_keys=True, separators=(",", ":")).encode("ascii")
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner.write_private_authorization(target, auth(), acl_checker=lambda _: True)
    assert exc.value.category == "authorization_file_exists"


def test_write_private_authorization_validates_before_creating_and_cleans_partial(tmp_path: Path):
    target = tmp_path / "authorization.json"
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner.write_private_authorization(target, {**auth(), "password": "never-written"}, acl_checker=lambda _: True)
    assert exc.value.category == "authorization_invalid"
    assert not target.exists()

    class BrokenFile:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def write(self, _payload):
            raise OSError("private failure")

        def flush(self):
            return None

        def fileno(self):
            return 1

    monkeypatch = pytest.MonkeyPatch()
    try:
        monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: BrokenFile())
        with pytest.raises(runner.RetainedDevRunnerError) as exc:
            runner.write_private_authorization(target, auth(), acl_checker=lambda _: True)
        assert exc.value.category == "authorization_file_write_failed"
    finally:
        monkeypatch.undo()
    assert not target.exists()


def test_ci_gate_requires_clean_develop_and_exact_successful_eight_jobs():
    commands = []
    run = {
        "status": "completed", "conclusion": "success", "headSha": SOURCE,
        "headBranch": "develop", "event": "push",
        "workflowName": "CI", "databaseId": 123456789, "workflowDatabaseId": 987654321,
        "jobs": [{"name": name, "status": "completed", "conclusion": "success"} for name in runner.CI_JOB_NAMES],
    }

    class Result:
        returncode = 0
        stdout = b""

    def command(args, **kwargs):
        commands.append(args)
        result = Result()
        if args[:2] == ["git", "-C"]:
            if "rev-parse" in args:
                result.stdout = (SOURCE + "\n").encode()
            elif "branch" in args:
                result.stdout = b"develop\n"
            else:
                result.stdout = b""
        elif args[:3] == ["gh", "run", "view"]:
            result.stdout = json.dumps(run).encode()
        else:
            result.stdout = json.dumps({
                "id": 987654321, "path": ".github/workflows/ci.yml", "name": "CI", "state": "active",
            }).encode()
        return result

    runner.validate_source_and_ci(auth(), command_runner=command)
    assert commands[-2][0:3] == ["gh", "run", "view"]
    assert commands[-1][:2] == ["gh", "api"]
    assert "--workflow" not in commands[-2]

    run["jobs"] = run["jobs"][:-1]
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner.validate_source_and_ci(auth(), command_runner=command)
    assert exc.value.category == "ci_verification_failed"


def test_private_location_rejects_repo_or_onedrive_and_requires_windows_acl(tmp_path: Path):
    with pytest.raises(runner.RetainedDevRunnerError):
        runner.validate_private_location(Path.cwd())
    assert runner.validate_private_location(tmp_path, acl_checker=lambda _: True) == tmp_path.resolve()
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner.validate_private_location(tmp_path, acl_checker=lambda _: False)
    assert exc.value.category == "private_acl_invalid"


def test_reparse_check_happens_before_resolve(monkeypatch, tmp_path: Path):
    called = []
    monkeypatch.setattr(runner.Path, "resolve", lambda *_args, **_kwargs: called.append(True) or tmp_path)
    monkeypatch.setattr(runner, "_is_reparse_or_symlink", lambda _path: True)
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner.validate_private_location(tmp_path, acl_checker=lambda _: True)
    assert exc.value.category == "private_location_invalid"
    assert called == []


def test_bounded_command_rejects_large_stderr_without_exposing_it():
    class Result:
        returncode = 0
        stdout = b"ok"
        stderr = b"secret-stderr" * (runner.MAX_COMMAND_OUTPUT_BYTES // 10)

    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner._bounded_command(["git"], runner=lambda *_args, **_kwargs: Result())
    assert exc.value.category == "verification_output_too_large"
    assert "secret-stderr" not in str(exc.value)


def test_runner_validates_source_before_client_factory_and_emits_safe_projection(tmp_path: Path, monkeypatch):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(json.dumps(auth()), encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    called = []

    def forbidden(_):
        called.append(True)
        raise AssertionError("client factory must not run")

    result = runner.run_authorized_step(
        authorization, state, "preflight", acl_checker=lambda _: True,
        source_ci_validator=lambda _auth: (_ for _ in ()).throw(runner.RetainedDevRunnerError("ci_verification_failed")),
        client_factory=forbidden,
    )
    assert result == {"step": "preflight", "ok": False, "category": "ci_verification_failed", "calls": 0}
    assert called == []
    assert "123456789012" not in json.dumps(result)


def test_runner_uses_injected_coordinator_and_never_prints_private_inputs(tmp_path: Path, monkeypatch):
    authorization = tmp_path / "authorization.json"
    authorization.write_text(json.dumps(auth()), encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    captured = []

    class FakeCoordinator:
        def __init__(self, clients, journal, **kwargs):
            captured.append((clients, journal, kwargs))

        def run_step(self, step):
            return {"step": step, "ok": True, "category": "preflight_verified", "calls": 1}

    monkeypatch.setattr(runner, "RetainedDevBootstrapCoordinator", FakeCoordinator)
    result = runner.run_authorized_step(
        authorization, state, "preflight", acl_checker=lambda _: True,
        source_ci_validator=lambda _auth: None,
        client_factory=lambda: {name: object() for name in ("sts", "cloudformation", "lambda", "logs", "iam", "apigatewayv2")},
        journal_factory=lambda _path: object(),
    )
    assert result["ok"] is True
    assert captured[0][2]["account_id"] == ACCOUNT
    assert "123456789012" not in json.dumps(result)


def test_build_clients_rejects_proxy_or_custom_endpoint_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid")
    with pytest.raises(runner.RetainedDevRunnerError) as exc:
        runner._build_clients()
    assert exc.value.category == "proxy_or_custom_endpoint_rejected"
