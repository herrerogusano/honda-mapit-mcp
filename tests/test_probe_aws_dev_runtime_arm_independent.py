from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import probe_aws_dev_runtime_arm as probe


def _checks() -> dict[str, bool]:
    return {name: True for name in probe._CHECK_NAMES}


def test_container_contract_has_300_second_bounded_window_and_synthetic_only_calls():
    code = probe._CONTAINER_PROBE
    assert '"MAPIT_DEV_EXECUTION_START_EPOCH":str(int(now)-1)' in code
    assert '"MAPIT_DEV_EXECUTION_END_EPOCH":str(int(now)+299)' in code
    assert 'os.environ["MAPIT_MCP_ENV"]="prod"' in code
    assert 'out["prod_isolation_503"]' in code
    assert 'out["missing_config_503"]' in code
    assert 'for index,(name,args) in enumerate(calls,1)' in code
    assert 'successes==10' in code
    assert 'len(first_names)==10 and len(second_names)==10' in code
    assert 'print(json.dumps(out,sort_keys=True,separators=(",",":")))' in code
    assert 'print(response' not in code and 'print(result' not in code


def test_child_process_result_size_is_bounded_before_json_parse():
    with pytest.raises(probe.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_check_matrix("x" * (probe._MAX_STDOUT_BYTES + 1))


def test_timed_out_child_maps_to_closed_error_without_echoing_output(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    summary = type("Summary", (), {
        "zip_bytes": 99, "sha256": "a" * 64, "wheel_count": 28,
        "archive_entries": 900, "source_modules": 14, "public_key_count": 1,
    })()
    monkeypatch.setattr(probe.builder, "_validate_external_wheel_dir", lambda path, repo: wheel_dir)
    monkeypatch.setattr(
        probe.builder,
        "build_runtime_archive",
        lambda _wheels, _snapshot, archive, _policy: (archive.write_bytes(b"synthetic-zip"), summary)[1],
    )
    monkeypatch.setattr(probe, "_synthetic_snapshot_and_tokens", lambda _policy, _now: (b"{}", {"valid": "synthetic-token"}))
    monkeypatch.setattr(probe, "_docker_context", lambda: "desktop-linux")
    monkeypatch.setattr(probe, "_cleanup_owned_container", lambda *_args, **_kwargs: True)

    def timed_out(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("docker", probe._MAX_DOCKER_SECONDS, output="stdout-private", stderr="stderr-private")

    monkeypatch.setattr(probe.subprocess, "run", timed_out)
    with pytest.raises(probe.ProbeError, match="arm_probe_execution_failed") as caught:
        probe.run_probe(wheel_dir)
    assert "private" not in str(caught.value)


def test_cleanup_cid_mismatch_never_removes_container(tmp_path: Path):
    run_id = "a" * 32
    name = probe._CONTAINER_NAME_PREFIX + run_id
    listed_cid = "b" * 64
    cid_file = tmp_path / "container.cid"
    cid_file.write_text("c" * 64 + "\n", encoding="ascii")
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[3:5] == ["container", "ls"]:
            return subprocess.CompletedProcess(args, 0, listed_cid + "\n", "")
        raise AssertionError("CID mismatch must stop before inspect/remove")

    assert not probe._cleanup_owned_container(
        "desktop-linux", name, run_id, cid_file, runner=fake_run
    )
    assert len(calls) == 1
    assert not any("rm" in call for call in calls)


def test_cleanup_readback_failure_never_counts_as_absence(tmp_path: Path):
    run_id = "d" * 32
    name = probe._CONTAINER_NAME_PREFIX + run_id
    cid = "e" * 64
    cid_file = tmp_path / "container.cid"
    cid_file.write_text(cid + "\n", encoding="ascii")
    list_count = 0
    calls: list[list[str]] = []

    def fake_run(args, **kwargs):
        nonlocal list_count
        calls.append(args)
        if args[3:5] == ["container", "ls"]:
            list_count += 1
            if list_count == 1:
                return subprocess.CompletedProcess(args, 0, cid + "\n", "")
            return subprocess.CompletedProcess(args, 1, "", "daemon-readback-failed")
        if args[3:5] == ["container", "inspect"]:
            return subprocess.CompletedProcess(args, 0, f"{cid}|honda-mapit-mcp|{run_id}\n", "")
        if args[3:6] == ["container", "rm", "--force"]:
            assert args[6] == cid
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError("unexpected cleanup command")

    assert not probe._cleanup_owned_container(
        "desktop-linux", name, run_id, cid_file, runner=fake_run
    )
    assert list_count == 2
    assert any(args[3:6] == ["container", "rm", "--force"] for args in calls)


def test_main_sanitizes_unexpected_synthetic_setup_failure(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys):
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    monkeypatch.setattr(probe.builder, "_validate_external_wheel_dir", lambda path, repo: wheel_dir)

    def fail_with_canary(_policy, _now):
        raise RuntimeError("private-token-canary")

    monkeypatch.setattr(probe, "_synthetic_snapshot_and_tokens", fail_with_canary)
    status = probe.main(["--wheel-dir", str(wheel_dir)])
    output = capsys.readouterr().out
    result = json.loads(output)
    assert status == 1
    assert result["success"] is False
    assert result["category"] in {"arm_probe_failed", "runtime_arm_probe_failed"}
    assert "private-token-canary" not in output
