import hashlib
import json
from pathlib import Path
import subprocess
import sys
import zipfile

import pytest

from mapit.dev_enrolled_manifest import parse_enrolled_dev_manifest
from scripts import probe_aws_dev_enrolled_arm as probe


def test_fixture_is_two_verifiers_without_private_sessions():
    raw, invitation, mapit, payload = probe._fixture()
    parsed = parse_enrolled_dev_manifest(raw, invitation, mapit,
        expected_digest=hashlib.sha256(raw).hexdigest(), account_id=payload["account_id"])
    assert len(parsed.policies) == 2 and invitation != mapit
    assert parsed.config.password is None and parsed.config.email is None
    assert b"refresh_token" not in raw and b"password" not in raw
    assert payload["end"] - payload["start"] == 300


def test_command_preserves_network_denied_pinned_arm_cleanup_labels(tmp_path):
    command = probe._docker_command(tmp_path / "runtime.zip", context="desktop-linux",
        name="synthetic", cidfile=tmp_path / "cid", run_id="run-1")
    for flag, value in (("--platform", "linux/arm64"), ("--network", "none"), ("--memory", "256m")):
        assert command[command.index(flag) + 1] == value
    assert "--pull=never" in command
    assert command[-1] == probe._CONTAINER_PROBE
    assert "com.honda-mapit.arm-probe.owner=honda-mapit-mcp" in command
    assert "com.honda-mapit.arm-probe.run=run-1" in command


@pytest.mark.parametrize("variant", ["extra", "integer", "missing", "string"])
def test_fixed_boolean_output_rejects_other_shapes(variant):
    checks = dict.fromkeys(probe.CHECKS, True)
    value = {"checks": checks}
    if variant == "extra": value["secret"] = "untrusted"
    elif variant == "integer": checks[probe.CHECKS[0]] = 1
    elif variant == "missing": checks.pop(probe.CHECKS[0])
    else: value["checks"] = "invalid"
    with pytest.raises(probe.multi.ProbeError, match="arm_probe_output_invalid"):
        probe._parse_output(json.dumps(value))


def test_actual_probe_program_with_local_sources(tmp_path):
    raw, invitation, mapit, payload = probe._fixture()
    archive_path = tmp_path / "runtime.zip"
    source = Path(__file__).resolve().parents[1] / "src" / "mapit"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for path in source.glob("*.py"):
            archive.write(path, "mapit/" + path.name)
        for name, value in ((probe.builder.MANIFEST_FILENAME, raw),
                            (probe.builder.INVITATION_JWKS_FILENAME, invitation),
                            (probe.builder.MAPIT_JWKS_FILENAME, mapit)):
            archive.writestr("mapit/" + name, value)
    code = probe._CONTAINER_PROBE.replace('"/probe/runtime.zip"', repr(str(archive_path)))
    result = subprocess.run([sys.executable, "-c", code],
        input=json.dumps({**payload, "checks": list(probe.CHECKS)}),
        capture_output=True, text=True, timeout=30, cwd=tmp_path)
    checks = probe._parse_output(result.stdout)
    assert result.returncode == 0, checks
    assert all(checks.values())


def test_cleanup_failure_is_not_success(tmp_path, monkeypatch):
    archive = tmp_path / "archive.zip"
    archive.write_bytes(b"synthetic")
    monkeypatch.setattr(probe.multi, "_run_bounded", lambda *args: (0,
        json.dumps({"checks": dict.fromkeys(probe.CHECKS, True)})))
    monkeypatch.setattr(probe.multi.docker_helpers, "_cleanup_owned_container", lambda *args: False)
    with pytest.raises(probe.multi.ProbeError, match="cleanup_unverified"):
        probe.probe_candidate_archive(archive, context="desktop-linux", payload={})
