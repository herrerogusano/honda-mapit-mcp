"""Independent synthetic checks for exact retained-artifact recovery."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pytest

from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts import run_cd_recovery as recovery
from scripts import run_cd_release as release
from scripts.build_aws_prod_runtime import _manifest
from test_run_cd_recovery import _bindings_and_jwks


def _archive_with_jwks_bytes(bindings, jwks_obj, jwks_bytes):
    manifest = _manifest(
        bindings["_validated_policy"], bindings["_validated_mapit_config"],
        bindings["account_id"], bindings["parameter_version"], bindings["parameter_tier"],
        hashlib.sha256(jwks_bytes).hexdigest(),
    )
    doc = json.loads(manifest)
    doc["geographic_queries"] = True
    manifest_bytes = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("ascii")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("mapit/mapit-prod.manifest.json", manifest_bytes)
        archive.writestr("mapit/cognito-public-jwks.json", jwks_bytes)
        archive.writestr("mapit/source-provenance.json", json.dumps({"schema": 1, "source_sha": "a" * 40}))
    return output.getvalue(), hashlib.sha256(manifest_bytes).hexdigest()


def test_retained_jwks_json_key_order_is_semantic_not_a_false_mismatch():
    bindings, jwks = _bindings_and_jwks()
    raw = json.dumps(jwks, separators=(",", ":"), sort_keys=False).encode("utf-8")
    assert raw != release._canonical(jwks)
    archive, manifest_sha = _archive_with_jwks_bytes(bindings, jwks, raw)
    assert recovery._validate_retained_zip(archive, bindings, expected_manifest_sha=manifest_sha) == len(archive)


def test_retained_package_rejects_current_jwks_or_policy_mismatch():
    bindings, jwks = _bindings_and_jwks()
    raw, manifest_sha = _archive_with_jwks_bytes(bindings, jwks, release._canonical(jwks))

    changed_jwks = json.loads(json.dumps(jwks))
    changed_jwks["keys"][0]["kid"] = "different-synthetic-key"
    altered = dict(bindings)
    altered["jwks"] = changed_jwks
    with pytest.raises(release.ReleaseError) as error:
        recovery._validate_retained_zip(raw, altered, expected_manifest_sha=manifest_sha)
    assert error.value.category == "artifact_binding_invalid"

    original = bindings["_validated_policy"]
    bindings["_validated_policy"] = CognitoProdPolicy(
        user_pool_id=original.user_pool_id, api_id=original.api_id,
        client_id=original.client_id, owner_subject="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
    )
    with pytest.raises(release.ReleaseError) as error:
        recovery._validate_retained_zip(raw, bindings, expected_manifest_sha=manifest_sha)
    assert error.value.category == "artifact_binding_invalid"


def test_recovery_binding_rejects_secret_field_without_echo():
    bindings, _ = _bindings_and_jwks()
    serializable = {key: value for key, value in bindings.items() if not key.startswith("_")}
    raw = json.dumps({**serializable, "session_token": "synthetic-private-canary"})
    with pytest.raises(release.ReleaseError) as error:
        release._parse_bindings(raw)
    assert error.value.category == "binding_invalid"
    assert "synthetic-private-canary" not in str(error.value)


def test_invalid_retained_target_stops_before_oidc_and_any_service_factory(monkeypatch, tmp_path):
    env = {
        "SOURCE_SHA": "a" * 40, "CHECKED_OUT_SHA": "a" * 40,
        "GITHUB_REPOSITORY": "herrerogusano/honda-mapit-mcp", "GITHUB_REF": "refs/heads/main",
        "TARGET": "prod", "GITHUB_ENVIRONMENT": "prod", "GITHUB_RUN_ID": "42",
        "GITHUB_REPOSITORY_ID": "7654321", "GITHUB_REPOSITORY_OWNER_ID": "1234567",
        "ROLLBACK_ARTIFACT_SHA256": "../runtime.zip", "ROLLBACK_MANIFEST_SHA256": "f" * 64,
        "MAPIT_CD_BINDING_JSON": "synthetic-binding",
    }
    monkeypatch.setattr(recovery.ordinary.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(recovery.ordinary, "_parse_bindings", lambda _raw: {"synthetic": True})
    oidc_calls = []
    client_calls = []
    monkeypatch.setattr(recovery.ordinary, "_assume_executor", lambda *a, **kw: oidc_calls.append(1))
    runner = recovery.CDRecoveryRunner(environ=env, client_factory=lambda *a, **kw: client_calls.append(1))
    result = runner.run("rollback-update")
    assert result == {"status": "failed", "phase": "rollback-update", "category": "artifact_binding_invalid"}
    assert oidc_calls == [] and client_calls == []
