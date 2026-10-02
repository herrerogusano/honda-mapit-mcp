from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import build_aws_dev_runtime as builder

POOL = "eu-west-1_abcdefghijk"
API = "a1b2c3d4e5"
CLIENT = "publicclient123"
OWNER = "12345678-1234-4234-8234-123456789abc"
CANARY_VALUES = (POOL, API, CLIENT, OWNER)


def binding_object() -> dict[str, str]:
    return {
        "user_pool_id": POOL,
        "api_id": API,
        "client_id": CLIENT,
        "owner_subject": OWNER,
    }


def write_binding(path: Path, value: bytes | str | dict) -> Path:
    if isinstance(value, dict):
        path.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    elif isinstance(value, str):
        path.write_text(value, encoding="utf-8")
    else:
        path.write_bytes(value)
    return path


def test_binding_file_parses_only_the_exact_validated_string_fields(tmp_path: Path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    path = write_binding(private / "binding.json", binding_object())
    policy = builder._read_binding_file(path, repo)
    assert (policy.user_pool_id, policy.api_id, policy.client_id, policy.owner_subject) == CANARY_VALUES
    assert path.read_text(encoding="utf-8") == json.dumps(binding_object(), separators=(",", ":"))


@pytest.mark.parametrize("raw", [
    b"",
    b"{not-json",
    b"\xff",
    b'{"user_pool_id":"eu-west-1_abcdefghijk","user_pool_id":"eu-west-1_abcdefghijk","api_id":"a1b2c3d4e5","client_id":"publicclient123","owner_subject":"12345678-1234-4234-8234-123456789abc"}',
])
def test_binding_file_rejects_malformed_utf8_json_and_duplicate_members(tmp_path: Path, raw: bytes):
    repo = tmp_path / "checkout"
    repo.mkdir()
    path = write_binding(tmp_path / "binding.json", raw)
    with pytest.raises(builder.BuildError) as exc:
        builder._read_binding_file(path, repo)
    assert exc.value.args == ("runtime_binding_invalid",)
    assert not any(value in str(exc.value) for value in CANARY_VALUES)


@pytest.mark.parametrize("change", [
    {"extra": "secret-canary"},
    {"owner_subject": 123},
    {"user_pool_id": None},
    {"api_id": True},
    {"client_id": ""},
    {"owner_subject": "not-a-uuid"},
])
def test_binding_file_rejects_extra_wrong_type_and_invalid_values(tmp_path: Path, change: dict):
    repo = tmp_path / "checkout"
    repo.mkdir()
    value = binding_object() | change
    path = write_binding(tmp_path / "binding.json", value)
    with pytest.raises(builder.BuildError, match="runtime_binding_invalid"):
        builder._read_binding_file(path, repo)


def test_binding_file_has_a_pre_read_four_kibibyte_bound(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "checkout"
    repo.mkdir()
    path = tmp_path / "binding.json"
    path.write_bytes(b" " * (builder.MAX_BINDING_BYTES + 1))
    monkeypatch.setattr(builder, "_read_bounded", lambda *_args: pytest.fail("must reject from stat before reading"))
    with pytest.raises(builder.BuildError, match="runtime_binding_file_invalid"):
        builder._read_binding_file(path, repo)


def test_binding_path_must_be_external_and_outside_onedrive(tmp_path: Path):
    repo = tmp_path / "checkout"
    repo.mkdir()
    inside = write_binding(repo / "binding.json", binding_object())
    with pytest.raises(builder.BuildError, match="runtime_binding_file_invalid"):
        builder._read_binding_file(inside, repo)

    synced = tmp_path / "OneDrive - Example Org"
    synced.mkdir()
    path = write_binding(synced / "binding.json", binding_object())
    with pytest.raises(builder.BuildError, match="runtime_binding_file_invalid"):
        builder._read_binding_file(path, repo)


def _summary() -> builder.BuildSummary:
    return builder.BuildSummary(7, "d" * 64, 28, 50, 14, 1, True, True, True, True)


def _common_args(tmp_path: Path) -> list[str]:
    return [
        "--wheel-dir", str(tmp_path / "wheels"),
        "--public-jwks", str(tmp_path / "jwks.json"),
        "--output", str(tmp_path / "runtime.zip"),
    ]


def test_cli_binding_file_is_single_source_and_never_echoes_binding_values(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    repo = tmp_path / "checkout"
    repo.mkdir()
    private = tmp_path / "private"
    private.mkdir()
    path = write_binding(private / "binding.json", binding_object())
    monkeypatch.setattr(builder, "_repo_root", lambda: repo)
    captured = {}

    def fake_build(wheel_dir, public_jwks, output, policy):
        captured["policy"] = policy
        return _summary()

    monkeypatch.setattr(builder, "build_runtime_archive", fake_build)
    status = builder.main(_common_args(tmp_path) + ["--binding-file", str(path)])
    output = capsys.readouterr().out
    assert status == 0
    assert captured["policy"].owner_subject == OWNER
    assert all(value not in output for value in CANARY_VALUES)
    assert json.loads(output)["category"] == "runtime_package_built"


@pytest.mark.parametrize("legacy", [
    ["--owner-subject", OWNER],
    ["--api-id", API, "--client-id", CLIENT, "--owner-subject", OWNER],
])
def test_cli_rejects_partial_legacy_binding_without_echoing_ids(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys, legacy):
    monkeypatch.setattr(builder, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(builder, "build_runtime_archive", lambda *_args: pytest.fail("partial binding must stop before build"))
    status = builder.main(_common_args(tmp_path) + legacy)
    output = capsys.readouterr().out
    assert status == 1
    assert json.loads(output) == {"success": False, "category": "runtime_package_build_failed"}
    assert all(value not in output for value in CANARY_VALUES)


def test_cli_rejects_mixed_binding_sources_without_echoing_owner_subject(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    repo = tmp_path / "checkout"
    repo.mkdir()
    path = write_binding(tmp_path / "binding.json", binding_object())
    monkeypatch.setattr(builder, "_repo_root", lambda: repo)
    monkeypatch.setattr(builder, "build_runtime_archive", lambda *_args: pytest.fail("mixed sources must stop before build"))
    args = _common_args(tmp_path) + ["--binding-file", str(path), "--owner-subject", OWNER]
    status = builder.main(args)
    output = capsys.readouterr().out
    assert status == 1
    assert all(value not in output for value in CANARY_VALUES)
    assert "runtime_package_build_failed" in output


def test_cli_retains_full_legacy_flags_for_synthetic_compatibility(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setattr(builder, "_repo_root", lambda: tmp_path)
    captured = {}
    def fake_build(_wheels, _snapshot, _output, policy):
        captured["policy"] = policy
        return _summary()

    monkeypatch.setattr(builder, "build_runtime_archive", fake_build)
    args = _common_args(tmp_path) + [
        "--user-pool-id", POOL, "--api-id", API,
        "--client-id", CLIENT, "--owner-subject", OWNER,
    ]
    status = builder.main(args)
    output = capsys.readouterr().out
    assert status == 0
    assert captured["policy"].owner_subject == OWNER
    assert all(value not in output for value in CANARY_VALUES)


def test_cli_argument_parse_errors_use_fixed_output_not_unrecognized_canary(tmp_path: Path, capsys):
    status = builder.main(_common_args(tmp_path) + ["--unknown-owner-canary"])
    output = capsys.readouterr().out
    assert status == 1
    assert "unknown-owner-canary" not in output
    assert json.loads(output)["category"] == "runtime_package_build_failed"
