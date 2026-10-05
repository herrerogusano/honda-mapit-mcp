from __future__ import annotations

import base64
import hashlib
import io
import json
import zipfile

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.config import MapitConfig
from scripts import run_cd_recovery as recovery
from scripts import run_cd_release as release
from scripts.build_aws_prod_runtime import _manifest


def _bindings_and_jwks():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    enc = lambda n: base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    jwks = {"keys": [{"kty": "RSA", "kid": "retained-test", "use": "sig", "alg": "RS256",
                       "n": enc(numbers.n), "e": enc(numbers.e)}]}
    policy = CognitoProdPolicy(user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
                               client_id="ProdClient123456", owner_subject="18d8ce2b-8f10-4d72-b80f-ea635b4c6189")
    config = MapitConfig(region="eu-west-1", user_pool_id=policy.user_pool_id,
                         user_pool_client_id=policy.client_id,
                         identity_pool_id="eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
                         core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me",
                         discovery_enabled=False, http_timeout=2)
    bindings = {
        "account_id": "123456789012", "stack_arn": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-prod/11111111-2222-3333-4444-555555555555",
        "prod_run_id": "11111111-2222-3333-4444-555555555555", "api_id": policy.api_id,
        "function_name": "honda-mapit-mcp-prod-handler",
        "shutdown_state_machine_arn": "arn:aws:states:eu-west-1:123456789012:stateMachine:honda-mapit-mcp-prod-shutdown",
        "artifact_bucket": "honda-mapit-mcp-prod-runtime-artifacts-123456789012",
        "policy": {"user_pool_id": policy.user_pool_id, "api_id": policy.api_id,
                    "client_id": policy.client_id, "owner_subject": policy.owner_subject},
        "mapit_config": {"region": config.region, "user_pool_id": config.user_pool_id,
                         "user_pool_client_id": config.user_pool_client_id,
                         "identity_pool_id": config.identity_pool_id, "core_api_url": config.core_api_url,
                         "geo_api_url": config.geo_api_url, "discovery_enabled": False, "http_timeout": 2},
        "parameter_version": 1, "parameter_tier": "Standard", "jwks": jwks,
        "service_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-prod-cfn-update",
        "executor_role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-prod-cd-executor",
        "owner_id": "1234567", "repository_id": "7654321", "initial_service_role_attachment": True,
        "artifact_tags_sha256": "f" * 64,
        "_validated_policy": policy, "_validated_mapit_config": config,
    }
    return bindings, jwks


def _archive(bindings, jwks):
    jwks_raw = release._canonical(jwks)
    manifest = _manifest(bindings["_validated_policy"], bindings["_validated_mapit_config"],
                         bindings["account_id"], 1, "Standard", hashlib.sha256(jwks_raw).hexdigest())
    manifest_doc = json.loads(manifest)
    manifest_doc["geographic_queries"] = True
    manifest = json.dumps(manifest_doc, sort_keys=True, separators=(",", ":")).encode("ascii")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("mapit/mapit-prod.manifest.json", manifest)
        zf.writestr("mapit/cognito-public-jwks.json", jwks_raw)
        zf.writestr("mapit/source-provenance.json", json.dumps({"schema": 1, "source_sha": "a" * 40},
                                                                  sort_keys=True, separators=(",", ":")))
    return buf.getvalue(), hashlib.sha256(manifest).hexdigest()


def test_retained_archive_must_match_current_manifest_and_public_jwks():
    bindings, jwks = _bindings_and_jwks()
    raw, manifest_sha = _archive(bindings, jwks)
    assert recovery._validate_retained_zip(raw, bindings, expected_manifest_sha=manifest_sha) == len(raw)
    with pytest.raises(release.ReleaseError) as error:
        recovery._validate_retained_zip(raw, bindings, expected_manifest_sha="0" * 64)
    assert error.value.category == "artifact_binding_invalid"


def test_retained_zip_body_is_bounded_and_checksum_bound():
    data = b"synthetic zip bytes"
    sha = hashlib.sha256(data).hexdigest()
    class Body(io.BytesIO):
        pass
    response = {"ResponseMetadata": {"HTTPStatusCode": 200}, "ContentLength": len(data),
                "ChecksumSHA256": base64.b64encode(bytes.fromhex(sha)).decode(),
                "ServerSideEncryption": "AES256", "Body": Body(data)}
    assert recovery._read_zip_body(response, expected_sha=sha, expected_size=len(data)) == data
    response["ContentLength"] = len(data) + 1
    with pytest.raises(release.ReleaseError):
        recovery._read_zip_body(response, expected_sha=sha, expected_size=len(data))


def test_invalid_rollback_digests_fail_before_oidc_or_aws(monkeypatch, tmp_path):
    env = {
        "SOURCE_SHA": "a" * 40, "CHECKED_OUT_SHA": "a" * 40,
        "GITHUB_REPOSITORY": "herrerogusano/honda-mapit-mcp", "GITHUB_REF": "refs/heads/main",
        "TARGET": "prod", "GITHUB_ENVIRONMENT": "prod", "GITHUB_RUN_ID": "42",
        "GITHUB_REPOSITORY_ID": "7654321", "GITHUB_REPOSITORY_OWNER_ID": "1234567",
        "ROLLBACK_ARTIFACT_SHA256": "../../other.zip", "ROLLBACK_MANIFEST_SHA256": "0" * 64,
    }
    monkeypatch.setattr(recovery.ordinary.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(recovery.ordinary, "_parse_bindings", lambda _raw: {"synthetic": True})
    assume_calls = []
    monkeypatch.setattr(recovery.ordinary, "_assume_executor", lambda *a, **kw: assume_calls.append(1))
    result = recovery.CDRecoveryRunner(environ=env).run("rollback-update")
    assert result == {"status": "failed", "phase": "rollback-update", "category": "artifact_binding_invalid"}
    assert assume_calls == []


def test_recovery_workflow_is_manual_current_main_and_separately_gated():
    from pathlib import Path
    text = Path(".github/workflows/cd-recovery.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text and "branches: [main]" not in text
    assert "github.ref == 'refs/heads/main'" in text
    assert "ROLLBACK_ARTIFACT_SHA256" in text and "ROLLBACK_MANIFEST_SHA256" in text
    assert "environment: prod" in text and text.count("environment: prod") == 2
    assert "needs.rollback-update.outputs.ready == 'true'" in text
    assert "persist-credentials: false" in text and "id-token: write" in text
    assert "configure-aws-credentials" not in text
    assert "upload-artifact" not in text and "download-artifact" not in text
    image_steps = text.count("Pull pinned public Lambda ARM image before any identity request")
    assert image_steps == 2
    assert text.count('docker pull "$IMAGE"') == 2
    for next_step in ("Restore only the exact retained object", "Reopen exact rollback journal after separate approval"):
        assert text.index("docker pull \"$IMAGE\"") < text.index(next_step)
