from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

import pytest

from scripts import build_aws_dev_enrolled_archive as enrolled
from scripts import build_aws_dev_runtime as base
from test_dev_enrolled_manifest import _manifest, ACCOUNT
from test_build_aws_dev_runtime import build_inputs, public_jwks


def _inputs(build_inputs):
    fixture_repo, wheels, _, output, _ = build_inputs
    source_root = fixture_repo / "src" / "mapit"
    actual_source = Path(__file__).resolve().parents[1] / "src" / "mapit"
    for name in enrolled.SOURCE_MODULES:
        source = actual_source / name
        assert source.is_file()
        shutil.copyfile(source, source_root / name)
    document, invitation, mapit = _manifest()
    manifest = output.parent / "dev-enrolled.manifest.json"
    invitation_path = output.parent / "invitation.jwks.json"
    mapit_path = output.parent / "mapit.jwks.json"
    manifest.write_bytes(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
    invitation_path.write_bytes(invitation)
    mapit_path.write_bytes(mapit)
    return wheels, manifest, invitation_path, mapit_path, output


def test_deterministic_archive_has_exact_enrolled_sources_and_public_keys(build_inputs):
    wheels, manifest, invitation, mapit, output = _inputs(build_inputs)
    first = enrolled.build_dev_enrolled_archive(wheels, manifest, invitation, mapit, output,
                                                 account_id=ACCOUNT)
    archive_bytes = output.read_bytes()
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert names == sorted(names)
        assert f"mapit/{enrolled.MANIFEST_FILENAME}" in names
        assert f"mapit/{enrolled.INVITATION_JWKS_FILENAME}" in names
        assert f"mapit/{enrolled.MAPIT_JWKS_FILENAME}" in names
        assert {f"mapit/{name}" for name in enrolled.SOURCE_MODULES} <= set(names)
        assert "mapit/aws_dev_enrolled_entrypoint.py" in names
        assert "mapit/dev_enrolled_manifest.py" in names
        assert "mapit/aws_dev_multiuser_entrypoint.py" in names
        assert "mapit/aws_dev_entrypoint.py" not in names
        assert "mapit/aws_prod_entrypoint.py" not in names
        assert archive.read(f"mapit/{enrolled.MANIFEST_FILENAME}") == manifest.read_bytes()
        assert archive.read(f"mapit/{enrolled.INVITATION_JWKS_FILENAME}") == invitation.read_bytes()
        assert archive.read(f"mapit/{enrolled.MAPIT_JWKS_FILENAME}") == mapit.read_bytes()
    output.unlink()
    second = enrolled.build_dev_enrolled_archive(wheels, manifest, invitation, mapit, output,
                                                  account_id=ACCOUNT)
    assert first == second
    assert output.read_bytes() == archive_bytes
    assert first.sha256 == hashlib.sha256(archive_bytes).hexdigest()
    assert first.public_key_count == 2
    assert first.wheel_count == 28
    assert first.dependencies_valid and first.source_allowlist_valid
    assert first.lock_valid and first.manifest_valid


def test_extracted_archive_imports_enrolled_entrypoint_and_manifest_parser(build_inputs, tmp_path):
    wheels, manifest, invitation, mapit, output = _inputs(build_inputs)
    enrolled.build_dev_enrolled_archive(wheels, manifest, invitation, mapit, output,
                                         account_id=ACCOUNT)
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with zipfile.ZipFile(output) as archive:
        archive.extractall(extracted)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(extracted)
    result = subprocess.run([sys.executable, "-c",
        "import mapit.aws_dev_enrolled_entrypoint; import mapit.dev_enrolled_manifest; print('imports-ok')"],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=20, check=False)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "imports-ok"


@pytest.mark.parametrize("field,value", [
    ("binding_table_arn", f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-identity-bindings"),
    ("key_parameter_path", "/honda-mapit-mcp/dev/identity-binding-config"),
    ("environment", "prod"),
])
def test_wrong_enrolled_namespace_manifest_fails_before_output(build_inputs, field, value):
    wheels, manifest, invitation, mapit, output = _inputs(build_inputs)
    document = json.loads(manifest.read_bytes())
    document[field] = value
    manifest.write_bytes(json.dumps(document, sort_keys=True, separators=(",", ":")).encode())
    with pytest.raises(base.BuildError, match="runtime_binding_invalid"):
        enrolled.build_dev_enrolled_archive(wheels, manifest, invitation, mapit, output,
                                             account_id=ACCOUNT)
    assert not output.exists()


def test_output_cannot_overwrite_manifest_or_existing_artifact(build_inputs):
    wheels, manifest, invitation, mapit, output = _inputs(build_inputs)
    with pytest.raises(base.BuildError, match="output_path_invalid"):
        enrolled.build_dev_enrolled_archive(wheels, manifest, invitation, mapit, manifest,
                                             account_id=ACCOUNT)
    output.write_bytes(b"preserve-me")
    with pytest.raises(base.BuildError, match="output_path_invalid"):
        enrolled.build_dev_enrolled_archive(wheels, manifest, invitation, mapit, output,
                                             account_id=ACCOUNT)
    assert output.read_bytes() == b"preserve-me"
