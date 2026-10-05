from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control
from mapit import aws_dev_entrypoint
from scripts import build_aws_dev_runtime as builder
from mapit.aws_dev_runtime import cognito_dev_policy


def test_control_template_definition_string_roundtrips_null_result_paths():
    template = build_dev_shutdown_control(
        AwsDevShutdownPolicy("a1b2c3d4e5"), "2026-10-02T18:00:00"
    )
    properties = template["Resources"]["ShutdownStateMachine"]["Properties"]
    assert isinstance(properties["DefinitionString"], str)
    definition = json.loads(properties["DefinitionString"])
    assert definition["StartAt"] == "Initialize"
    assert definition["TimeoutSeconds"] == 45
    states = definition["States"]
    assert states["DisableApiEndpoint"]["ResultPath"] is None
    assert states["ReserveFunctionConcurrency"]["ResultPath"] is None
    assert states["ReadApiEndpoint"]["ResultPath"] == "$.api_response"
    assert states["ReadFunctionConcurrency"]["ResultPath"] == "$.function_response"


def test_runtime_lock_rejects_duplicate_and_unexpected_pins(tmp_path: Path):
    lock_path = tmp_path / "infra" / "aws" / "runtime-requirements.txt"
    lock_path.parent.mkdir(parents=True)
    line = "annotated-types==0.8.0 --hash=sha256:" + "a" * 64
    lock_path.write_text(line + "\n" + line + "\n", encoding="utf-8")
    with pytest.raises(builder.BuildError, match="runtime_lock_invalid"):
        builder._read_lock(tmp_path)

    all_lines = [
        f"{name}==1.0.0 --hash=sha256:{'b' * 64}"
        for name in sorted(builder.EXPECTED_DISTRIBUTIONS)
    ]
    all_lines[-1] = "unexpected-extra==1.0.0 --hash=sha256:" + "c" * 64
    lock_path.write_text("\n".join(all_lines) + "\n", encoding="utf-8")
    with pytest.raises(builder.BuildError, match="runtime_lock_invalid"):
        builder._read_lock(tmp_path)


def test_wheel_duplicate_paths_are_casefolded_before_packaging():
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("testpkg-1.0.0.dist-info/METADATA", b"Name: testpkg\nVersion: 1.0.0\n")
        archive.writestr("testpkg-1.0.0.dist-info/WHEEL", b"wheel")
        archive.writestr("testpkg/module.py", b"safe = True")
        archive.writestr("TestPkg/MODULE.py", b"malicious = True")
    locked = {"testpkg": ("1.0.0", hashlib.sha256(raw.getvalue()).hexdigest())}
    with pytest.raises(builder.BuildError, match="wheel_duplicate_path"):
        builder._unpack_wheels([("testpkg-1.0.0-py3-none-any.whl", raw.getvalue())], locked)


def test_wheel_dist_info_roots_must_match_the_locked_filename():
    entries = [
        ("testpkg-1.0.0.dist-info/METADATA", b"Name: testpkg\nVersion: 1.0.0\n"),
        ("testpkg-1.0.0.dist-info/WHEEL", b"wheel"),
        ("unexpected-1.0.0.dist-info/WHEEL", b"unexpected"),
    ]
    with pytest.raises(builder.BuildError, match="wheel_metadata_mismatch"):
        builder._validate_wheel_filename_and_metadata(
            "testpkg-1.0.0-py3-none-any.whl", entries, {"testpkg": ("1.0.0", "0" * 64)}
        )


def test_archive_output_is_rejected_inside_wheels_and_one_drive(tmp_path: Path):
    repo = builder._repo_root()
    wheel_dir = tmp_path / "wheel-input"
    wheel_dir.mkdir()
    jwks_path = tmp_path / "jwks.json"
    jwks_path.write_bytes(b"synthetic public fixture")
    with pytest.raises(builder.BuildError, match="output_path_invalid"):
        builder._output_path(wheel_dir / "nested.zip", repo, wheel_dir, jwks_path)

    one_drive = tmp_path / "OneDrive" / "output"
    one_drive.mkdir(parents=True)
    with pytest.raises(builder.BuildError, match="output_path_invalid"):
        builder._output_path(one_drive / "runtime.zip", repo, wheel_dir, jwks_path)


@pytest.mark.parametrize("folder_name", ["OneDrive", "onedrive", "OneDrive - Example Org"])
def test_wheel_snapshot_and_output_reject_common_onedrive_directory_names(tmp_path: Path, folder_name: str):
    repo = builder._repo_root()
    sync_root = tmp_path / folder_name
    sync_root.mkdir()
    wheels = sync_root / "wheels"
    wheels.mkdir()
    external_wheels = tmp_path / "external-wheels"
    external_wheels.mkdir()
    snapshot = sync_root / "jwks.json"
    snapshot.write_bytes(b"synthetic public fixture")

    with pytest.raises(builder.BuildError, match="wheel_directory_invalid"):
        builder._validate_external_wheel_dir(wheels, repo)
    with pytest.raises(builder.BuildError, match="public_jwks_file_invalid"):
        builder._snapshot_file(snapshot, repo)
    with pytest.raises(builder.BuildError, match="output_path_invalid"):
        builder._output_path(sync_root / "output.zip", repo, external_wheels, snapshot)


def test_built_public_jwks_artifacts_are_fixed_siblings_of_runtime_entrypoint(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "repo"
    repo.mkdir()
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    jwks_path = tmp_path / "jwks-input.json"
    jwks_path.write_bytes(b"synthetic snapshot fixture")
    out_dir = tmp_path / "artifacts"
    out_dir.mkdir()
    output_path = out_dir / "runtime.zip"
    policy = cognito_dev_policy(
        user_pool_id="eu-west-1_abcdefghijk",
        api_id="a1b2c3d4e5",
        client_id="publicclient123",
        owner_subject="12345678-1234-4234-8234-123456789abc",
    )
    snapshot = b'{"keys":[{"kid":"synthetic"}]}'
    monkeypatch.setattr(builder, "_repo_root", lambda: repo)
    monkeypatch.setattr(builder, "_read_lock", lambda _repo: {"fake-dist": ("1.0", "0" * 64)})
    monkeypatch.setattr(builder, "_validate_external_wheel_dir", lambda path, _repo: path)
    monkeypatch.setattr(builder, "_snapshot_file", lambda _path, _repo: snapshot)
    monkeypatch.setattr(builder, "_validate_policy", lambda value: value)
    monkeypatch.setattr(builder, "parse_cognito_jwks", lambda _raw: {"synthetic-kid": b"synthetic-pem"})
    monkeypatch.setattr(builder, "_wheel_file_inventory", lambda _root, _lock: [("fake-dist-1.0-py3-none-any.whl", b"fake")])
    monkeypatch.setattr(builder, "_unpack_wheels", lambda _wheels, _lock: [("fake_dist/__init__.py", b"pass\n")])
    monkeypatch.setattr(builder, "_source_entries", lambda _repo: [("mapit/aws_dev_entrypoint.py", b"pass\n")])

    summary = builder.build_runtime_archive(wheel_dir, jwks_path, output_path, policy)
    assert summary.archive_entries == 4
    with zipfile.ZipFile(output_path) as archive:
        names = set(archive.namelist())
        bundled_entrypoint = archive.read("mapit/aws_dev_entrypoint.py")
        bundled_snapshot = archive.read(f"mapit/{builder.JWKS_SNAPSHOT_FILENAME}")
        bundled_manifest = archive.read(f"mapit/{builder.JWKS_MANIFEST_FILENAME}")
    expected_snapshot = f"mapit/{builder.JWKS_SNAPSHOT_FILENAME}"
    expected_manifest = f"mapit/{builder.JWKS_MANIFEST_FILENAME}"
    assert {expected_snapshot, expected_manifest, "mapit/aws_dev_entrypoint.py", "fake_dist/__init__.py"} == names
    assert builder.JWKS_SNAPSHOT_FILENAME not in names
    assert builder.JWKS_MANIFEST_FILENAME not in names

    extracted_mapit = tmp_path / "extracted" / "mapit"
    extracted_mapit.mkdir(parents=True)
    entrypoint_path = extracted_mapit / "aws_dev_entrypoint.py"
    entrypoint_path.write_bytes(bundled_entrypoint)
    (extracted_mapit / builder.JWKS_SNAPSHOT_FILENAME).write_bytes(bundled_snapshot)
    (extracted_mapit / builder.JWKS_MANIFEST_FILENAME).write_bytes(bundled_manifest)
    monkeypatch.setattr(aws_dev_entrypoint, "__file__", str(entrypoint_path))
    assert aws_dev_entrypoint._read_fixed_sibling(
        builder.JWKS_SNAPSHOT_FILENAME, aws_dev_entrypoint.MAX_JWKS_SNAPSHOT_BYTES
    ) == snapshot
    assert aws_dev_entrypoint._read_fixed_sibling(
        builder.JWKS_MANIFEST_FILENAME, aws_dev_entrypoint.MAX_JWKS_MANIFEST_BYTES
    ) == bundled_manifest
