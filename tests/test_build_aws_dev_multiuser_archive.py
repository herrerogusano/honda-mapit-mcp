from __future__ import annotations

import hashlib
import json
import zipfile

import pytest

from scripts import build_aws_dev_multiuser_archive as multi
from scripts import build_aws_dev_runtime as base
from test_build_aws_dev_runtime import build_inputs, public_jwks


def _inputs(build_inputs, public_jwks):
    repo, wheels, jwks, output, policy = build_inputs
    for name in multi.SOURCE_MODULES:
        (repo / "src" / "mapit" / name).write_text("# fixture\n")
    value = {"schema": 1, "builder": "build_retained_dev_multiuser_archive", "environment": "dev",
             "synthetic": True, "source_sha": "a" * 40, "api_id": policy.api_id,
             "user_pool_id": policy.user_pool_id, "client_id": policy.client_id,
             "jwks_sha256": hashlib.sha256(public_jwks).hexdigest(),
             "table_arn": "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants",
             "tenants": [{"key": "tenant-" + "a" * 64, "subject": policy.owner_subject, "label": "synthetic-A"},
                         {"key": "tenant-" + "b" * 64, "subject": "22345678-1234-4234-8234-123456789abc", "label": "synthetic-B"}]}
    manifest = output.parent / "manifest.json"
    manifest.write_text(json.dumps(value))
    return wheels, manifest, jwks, output


def test_deterministic_manifest_and_explicit_source_allowlist(build_inputs, public_jwks):
    wheels, manifest, jwks, output = _inputs(build_inputs, public_jwks)
    first = multi.build_dev_multiuser_archive(wheels, manifest, jwks, output, account_id="123456789012")
    raw = output.read_bytes()
    with zipfile.ZipFile(output) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert archive.read("mapit/dev-multiuser.manifest.json") == manifest.read_bytes()
        assert archive.read("mapit/__init__.py") == b""
        assert "mapit/aws_prod_entrypoint.py" not in archive.namelist()
        assert "mapit/aws_session_reader.py" not in archive.namelist()
        assert {f"mapit/{name}" for name in multi.SOURCE_MODULES} <= set(archive.namelist())
    output.unlink()
    second = multi.build_dev_multiuser_archive(wheels, manifest, jwks, output, account_id="123456789012")
    assert first == second
    assert output.read_bytes() == raw
    assert first.wheel_count == 28


def test_reject_mismatched_key_snapshot_before_output(build_inputs, public_jwks):
    wheels, manifest, jwks, output = _inputs(build_inputs, public_jwks)
    value = json.loads(manifest.read_text())
    value["jwks_sha256"] = "0" * 64
    manifest.write_text(json.dumps(value))
    with pytest.raises(base.BuildError, match="public_jwks_invalid"):
        multi.build_dev_multiuser_archive(wheels, manifest, jwks, output, account_id="123456789012")
    assert not output.exists()


def test_no_overwrite_or_input_inside_repo(build_inputs, public_jwks):
    wheels, manifest, jwks, output = _inputs(build_inputs, public_jwks)
    output.write_bytes(b"preserved")
    with pytest.raises(base.BuildError, match="output_path_invalid"):
        multi.build_dev_multiuser_archive(wheels, manifest, jwks, output, account_id="123456789012")
    assert output.read_bytes() == b"preserved"
