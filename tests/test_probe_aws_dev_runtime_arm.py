from __future__ import annotations

import base64
import hashlib
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import probe_aws_dev_runtime_arm as probe


def _checks(**overrides: bool) -> dict[str, bool]:
    result = {name: True for name in probe._CHECK_NAMES}
    result.update(overrides)
    return result


def test_output_parser_accepts_only_the_closed_boolean_matrix() -> None:
    assert probe._parse_check_matrix(json.dumps(_checks())) == _checks()
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_check_matrix(json.dumps({**_checks(), "access_token": "not-allowed"}))
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_check_matrix(json.dumps({**_checks(), "tools_list_exactly_ten": 1}))
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_check_matrix("prefix " + json.dumps(_checks()))
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_check_matrix('{"initialize":true,"initialize":false}')
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_check_matrix('{"initialize":NaN}')


def test_docker_command_is_pinned_offline_readonly_and_has_no_host_credential_mounts(tmp_path: Path) -> None:
    archive = tmp_path / "runtime.zip"
    run_id = "a" * 32
    container_name = probe._CONTAINER_NAME_PREFIX + run_id
    command = probe._docker_command(
        archive,
        context="desktop-linux",
        container_name=container_name,
        run_id=run_id,
        cid_file=tmp_path / "container.cid",
    )
    assert command[:7] == ["docker", "--context", "desktop-linux", "run", "--rm", "--pull=never", "-i"]
    assert "--platform" in command and command[command.index("--platform") + 1] == "linux/arm64"
    assert command[command.index("--network") + 1] == "none"
    assert command[command.index("--mount") + 1] == (
        f"type=bind,source={archive},target=/probe/runtime.zip,readonly"
    )
    assert command.count("--mount") == 1
    assert command[command.index("--name") + 1] == container_name
    assert command[command.index("--label") + 1] == f"{probe._OWNER_LABEL}=honda-mapit-mcp"
    assert command[command.index("--label") + 3] == f"{probe._RUN_LABEL}={run_id}"
    assert not any(arg in {"-e", "--env", "--env-file", "--privileged"} for arg in command)
    assert command[-3] == probe.IMAGE
    assert "@sha256:" in probe.IMAGE


def test_fixture_contains_public_jwks_and_tokens_without_persisting_signing_key() -> None:
    from mapit.aws_dev_runtime import cognito_dev_policy

    policy = cognito_dev_policy(
        user_pool_id="eu-west-1_A1b2C3d4E",
        api_id="a1b2c3d4e5",
        client_id="SyntheticCognitoClient012345",
        owner_subject="18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
    )
    snapshot, tokens = probe._synthetic_snapshot_and_tokens(policy, 1_800_000_000)
    document = json.loads(snapshot)
    assert set(document) == {"keys"}
    assert set(document["keys"][0]) == {"kty", "kid", "use", "alg", "n", "e"}
    assert set(tokens) == {"valid", "unknown_kid", "wrong_audience", "wrong_scope"}
    assert all(isinstance(value, str) and value.count(".") == 2 for value in tokens.values())
    assert not any(name in snapshot.decode("ascii").lower() for name in ("private", '"d"', '"p"', '"q"'))


def test_probe_subprocess_receives_tokens_only_as_stdin_and_output_is_allowlisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel_dir = tmp_path / "external-wheels"
    wheel_dir.mkdir()
    policy_snapshot = b'{"keys":[]}'
    tokens = {"valid": "synthetic-token-marker", "unknown_kid": "unknown-marker", "wrong_audience": "aud-marker", "wrong_scope": "scope-marker"}
    summary = SimpleNamespace(
        zip_bytes=12345,
        sha256="a" * 64,
        wheel_count=28,
        archive_entries=949,
        source_modules=14,
        public_key_count=1,
    )
    monkeypatch.setattr(probe.builder, "_validate_external_wheel_dir", lambda path, repo: wheel_dir)
    monkeypatch.setattr(probe.builder, "build_runtime_archive", lambda wheels, snapshot, archive, policy: (archive.write_bytes(b"zip"), summary)[1])
    monkeypatch.setattr(probe, "_synthetic_snapshot_and_tokens", lambda policy, now: (policy_snapshot, tokens))
    captured: dict[str, object] = {}

    def fake_run(args, *, input=None, capture_output, text, check, timeout):
        if args[1:3] == ["context", "show"]:
            return subprocess.CompletedProcess(args, 0, "desktop-linux\n", "")
        if args[1:4] == ["context", "inspect", "desktop-linux"]:
            return subprocess.CompletedProcess(args, 0, "npipe:////./pipe/dockerDesktopLinuxEngine\n", "")
        if "run" in args:
            captured.update(args=args, input=input, capture_output=capture_output, text=text, check=check, timeout=timeout)
            return subprocess.CompletedProcess(args, 0, json.dumps(_checks()), "synthetic stderr marker")
        if args[3:5] == ["container", "ls"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("unexpected Docker command in offline fake")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    result = probe.run_probe(wheel_dir)
    assert result["success"] is True
    assert result["category"] == "arm_probe_passed"
    assert result["zip_sha256"] == "a" * 64
    assert result["checks"] == _checks()
    assert captured["capture_output"] is True and captured["check"] is False
    payload = json.loads(captured["input"])
    assert payload["snapshot_sha256"] == hashlib.sha256(policy_snapshot).hexdigest()
    assert payload["tokens"] == tokens
    assert "synthetic-token-marker" not in json.dumps(result)
    assert "synthetic stderr marker" not in json.dumps(result)
    command = captured["args"]
    assert "--network" in command and command[command.index("--network") + 1] == "none"


def test_nonzero_probe_exit_is_safe_failure_even_if_matrix_is_all_true(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel_dir = tmp_path / "external-wheels"
    wheel_dir.mkdir()
    summary = SimpleNamespace(zip_bytes=1, sha256="b" * 64, wheel_count=28, archive_entries=1, source_modules=14, public_key_count=1)
    monkeypatch.setattr(probe.builder, "_validate_external_wheel_dir", lambda path, repo: wheel_dir)
    monkeypatch.setattr(probe.builder, "build_runtime_archive", lambda wheels, snapshot, archive, policy: (archive.write_bytes(b"zip"), summary)[1])
    monkeypatch.setattr(probe, "_synthetic_snapshot_and_tokens", lambda policy, now: (b"{}", {"valid": "token", "unknown_kid": "x", "wrong_audience": "y", "wrong_scope": "z"}))
    def fake_run(args, **kwargs):
        if args[1:3] == ["context", "show"]:
            return subprocess.CompletedProcess(args, 0, "desktop-linux\n", "")
        if args[1:4] == ["context", "inspect", "desktop-linux"]:
            return subprocess.CompletedProcess(args, 0, "unix:///var/run/docker.sock\n", "")
        if "run" in args:
            return subprocess.CompletedProcess(args, 2, json.dumps(_checks()), "hidden-provider-text")
        if args[3:5] == ["container", "ls"]:
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("unexpected Docker command in offline fake")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    result = probe.run_probe(wheel_dir)
    assert result["success"] is False
    assert result["category"] == "arm_probe_failed"
    assert result["checks"] == _checks()
    assert "hidden-provider-text" not in json.dumps(result)


def test_main_sanitizes_unexpected_setup_errors(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(probe, "run_probe", lambda _path: (_ for _ in ()).throw(RuntimeError("private-canary-value")))
    assert probe.main(["--wheel-dir", "synthetic-wheels"]) == 1
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"success": False, "category": "runtime_arm_probe_failed"}
    assert "private-canary-value" not in captured.out + captured.err


def test_docker_context_rejects_remote_tcp_endpoint() -> None:
    calls = 0

    def fake_run(args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess(args, 0, "remote-context\n", "")
        return subprocess.CompletedProcess(args, 0, "tcp://remote.invalid:2376\n", "")

    with pytest.raises(probe.ProbeError, match="local_docker_context_unavailable"):
        probe._docker_context(fake_run)
    assert calls == 2


def test_timeout_cleanup_removes_only_owned_container_and_verifies_absence(tmp_path: Path) -> None:
    run_id = "a" * 32
    name = probe._CONTAINER_NAME_PREFIX + run_id
    cid = "b" * 64
    cid_file = tmp_path / "container.cid"
    cid_file.write_text(cid + "\n", encoding="ascii")
    seen: list[list[str]] = []

    def fake_run(args, **kwargs):
        seen.append(args)
        if args[3:5] == ["container", "ls"]:
            count = sum(item[3:5] == ["container", "ls"] for item in seen)
            return subprocess.CompletedProcess(args, 0, f"{cid}\n" if count == 1 else "", "")
        if args[3:5] == ["container", "inspect"]:
            return subprocess.CompletedProcess(args, 0, f"{cid}|honda-mapit-mcp|{run_id}\n", "")
        if args[3:6] == ["container", "rm", "--force"]:
            assert args[6] == cid
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("unexpected cleanup command")

    assert probe._cleanup_owned_container("desktop-linux", name, run_id, cid_file, runner=fake_run)
    assert any(item[3:6] == ["container", "rm", "--force"] for item in seen)
    assert not any(item[3:5] == ["system", "prune"] for item in seen)


def test_timeout_cleanup_refuses_unowned_name_collision(tmp_path: Path) -> None:
    run_id = "c" * 32
    cid = "d" * 64
    name = probe._CONTAINER_NAME_PREFIX + run_id
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[3:5] == ["container", "ls"]:
            return subprocess.CompletedProcess(args, 0, cid + "\n", "")
        if args[3:5] == ["container", "inspect"]:
            return subprocess.CompletedProcess(args, 0, f"{cid}|different-owner|different-run\n", "")
        raise AssertionError("unowned container must never be removed")

    assert not probe._cleanup_owned_container("desktop-linux", name, run_id, tmp_path / "missing.cid", runner=fake_run)
    assert not any(item[3:5] == ["container", "rm"] for item in calls)


def test_cleanup_requires_successful_readback(tmp_path: Path) -> None:
    run_id = "e" * 32
    name = probe._CONTAINER_NAME_PREFIX + run_id

    def fake_run(args, **kwargs):
        if args[3:5] == ["container", "ls"]:
            return subprocess.CompletedProcess(args, 1, "", "daemon unavailable")
        raise AssertionError("no mutation after failed listing")

    assert not probe._cleanup_owned_container("desktop-linux", name, run_id, tmp_path / "missing.cid", runner=fake_run)


def test_run_timeout_cleans_exact_owned_container_before_reporting_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel_dir = tmp_path / "external-wheels"
    wheel_dir.mkdir()
    summary = SimpleNamespace(zip_bytes=1, sha256="f" * 64, wheel_count=28, archive_entries=1, source_modules=14, public_key_count=1)
    monkeypatch.setattr(probe.builder, "_validate_external_wheel_dir", lambda path, repo: wheel_dir)
    monkeypatch.setattr(probe.builder, "build_runtime_archive", lambda wheels, snapshot, archive, policy: (archive.write_bytes(b"zip"), summary)[1])
    monkeypatch.setattr(probe, "_synthetic_snapshot_and_tokens", lambda policy, now: (b"{}", {"valid": "token", "unknown_kid": "x", "wrong_audience": "y", "wrong_scope": "z"}))
    cid = "9" * 64
    calls: list[list[str]] = []
    list_count = 0

    def fake_run(args, **kwargs):
        nonlocal list_count
        calls.append(args)
        if args[1:3] == ["context", "show"]:
            return subprocess.CompletedProcess(args, 0, "desktop-linux\n", "")
        if args[1:4] == ["context", "inspect", "desktop-linux"]:
            return subprocess.CompletedProcess(args, 0, "npipe:////./pipe/dockerDesktopLinuxEngine\n", "")
        if "run" in args:
            cid_file = Path(args[args.index("--cidfile") + 1])
            cid_file.write_text(cid + "\n", encoding="ascii")
            assert kwargs["timeout"] == probe._MAX_DOCKER_SECONDS
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        if args[3:5] == ["container", "ls"]:
            list_count += 1
            return subprocess.CompletedProcess(args, 0, f"{cid}\n" if list_count == 1 else "", "")
        if args[3:5] == ["container", "inspect"]:
            run_id = args[-1].removeprefix(probe._CONTAINER_NAME_PREFIX)
            # The owner/run labels are checked against the UUID embedded in the unique name.
            assert run_id and len(run_id) == 32
            return subprocess.CompletedProcess(args, 0, f"{cid}|honda-mapit-mcp|{run_id}\n", "")
        if args[3:6] == ["container", "rm", "--force"]:
            assert args[6] == cid
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("unexpected Docker command")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    with pytest.raises(probe.ProbeError, match="arm_probe_execution_failed"):
        probe.run_probe(wheel_dir)
    assert list_count == 2
    assert any(args[3:6] == ["container", "rm", "--force"] for args in calls)
    assert not any("prune" in args or "rm" in args and "--force" not in args for args in calls)


def test_unverified_timeout_cleanup_never_reports_probe_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wheel_dir = tmp_path / "external-wheels"
    wheel_dir.mkdir()
    summary = SimpleNamespace(zip_bytes=1, sha256="0" * 64, wheel_count=28, archive_entries=1, source_modules=14, public_key_count=1)
    monkeypatch.setattr(probe.builder, "_validate_external_wheel_dir", lambda path, repo: wheel_dir)
    monkeypatch.setattr(probe.builder, "build_runtime_archive", lambda wheels, snapshot, archive, policy: (archive.write_bytes(b"zip"), summary)[1])
    monkeypatch.setattr(probe, "_synthetic_snapshot_and_tokens", lambda policy, now: (b"{}", {"valid": "token", "unknown_kid": "x", "wrong_audience": "y", "wrong_scope": "z"}))

    def fake_run(args, **kwargs):
        if args[1:3] == ["context", "show"]:
            return subprocess.CompletedProcess(args, 0, "desktop-linux\n", "")
        if args[1:4] == ["context", "inspect", "desktop-linux"]:
            return subprocess.CompletedProcess(args, 0, "unix:///var/run/docker.sock\n", "")
        if "run" in args:
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])
        if args[3:5] == ["container", "ls"]:
            return subprocess.CompletedProcess(args, 1, "", "daemon unavailable")
        raise AssertionError("no cleanup mutation without readback")

    monkeypatch.setattr(probe.subprocess, "run", fake_run)
    with pytest.raises(probe.ProbeError, match="cleanup_unverified"):
        probe.run_probe(wheel_dir)
