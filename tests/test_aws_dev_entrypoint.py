from __future__ import annotations

import base64
import hashlib
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit import aws_dev_entrypoint as entrypoint
from mapit.aws_dev_runtime import cognito_dev_policy

POOL_ID = "eu-west-1_A1b2C3d4E"
API_ID = "a1b2c3d4e5"
CLIENT_ID = "SyntheticCognitoClient012345"
OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
KID = "entrypoint-fixture-key"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwk(public_key):
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA",
        "kid": KID,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


class LambdaContext:
    def get_remaining_time_in_millis(self):
        return 30_000


@pytest.fixture(autouse=True)
def isolated_entrypoint(monkeypatch, tmp_path):
    monkeypatch.setattr(entrypoint, "__file__", str(tmp_path / "aws_dev_entrypoint.py"))
    monkeypatch.setattr(entrypoint, "_CACHED_RUNTIME", None)
    monkeypatch.setattr(entrypoint, "_CACHED_JWKS_SHA256", None)
    for name in (
        entrypoint.ENV_MAPIT_MCP_ENV,
        entrypoint.ENV_AWS_REGION,
        entrypoint.ENV_COGNITO_USER_POOL_ID,
        entrypoint.ENV_API_ID,
        entrypoint.ENV_COGNITO_CLIENT_ID,
        entrypoint.ENV_OWNER_SUBJECT,
        entrypoint.ENV_COGNITO_JWKS_SHA256,
    ):
        monkeypatch.delenv(name, raising=False)
    return tmp_path


def _fixture_bundle(tmp_path, *, manifest_changes=None, jwks_document=None, manifest_raw=None):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    policy = cognito_dev_policy(
        user_pool_id=POOL_ID,
        api_id=API_ID,
        client_id=CLIENT_ID,
        owner_subject=OWNER,
    )
    if jwks_document is None:
        jwks_document = json.dumps({"keys": [_jwk(private.public_key())]}, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(jwks_document).hexdigest()
    manifest = {
        "issuer": policy.issuer_url,
        "jwks_uri": f"{policy.issuer_url}/.well-known/jwks.json",
        "sha256": digest,
    }
    if manifest_changes:
        manifest.update(manifest_changes)
    if manifest_raw is None:
        manifest_raw = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    (tmp_path / entrypoint.JWKS_SNAPSHOT_FILENAME).write_bytes(jwks_document)
    (tmp_path / entrypoint.JWKS_MANIFEST_FILENAME).write_bytes(manifest_raw)
    _set_environment(digest)
    return private, policy, jwks_document, manifest_raw, digest


def _set_environment(expected_digest: str | None):
    import os

    os.environ[entrypoint.ENV_MAPIT_MCP_ENV] = "dev"
    os.environ[entrypoint.ENV_AWS_REGION] = "eu-west-1"
    os.environ[entrypoint.ENV_COGNITO_USER_POOL_ID] = POOL_ID
    os.environ[entrypoint.ENV_API_ID] = API_ID
    os.environ[entrypoint.ENV_COGNITO_CLIENT_ID] = CLIENT_ID
    os.environ[entrypoint.ENV_OWNER_SUBJECT] = OWNER
    if expected_digest is not None:
        os.environ[entrypoint.ENV_COGNITO_JWKS_SHA256] = expected_digest
    else:
        os.environ.pop(entrypoint.ENV_COGNITO_JWKS_SHA256, None)


def _signed_token(private, policy, *, kid=KID, **overrides):
    now = int(time.time())
    claims = {
        "iss": policy.issuer_url,
        "aud": policy.audience,
        "sub": policy.owner_subject,
        "client_id": policy.client_id,
        "token_use": "access",
        "iat": now,
        "exp": now + 300,
        "scope": policy.required_scope,
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def _rpc(method, params=None, request_id=1):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}, separators=(",", ":"))


def _event(policy, token, body):
    raw = body.encode("utf-8")
    return {
        "version": "2.0",
        "rawPath": "/mcp",
        "rawQueryString": "",
        "headers": {
            "host": policy.api_host,
            "authorization": f"Bearer {token}",
            "content-type": "application/json",
            "content-length": str(len(raw)),
            "accept": "application/json, text/event-stream",
        },
        "requestContext": {"stage": "$default", "http": {"method": "POST", "path": "/mcp"}},
        "body": body,
        "isBase64Encoded": False,
    }


def _request(private, policy, method="tools/list", params=None, request_id=1, *, kid=KID):
    token = _signed_token(private, policy, kid=kid)
    return entrypoint.handler(_event(policy, token, _rpc(method, params, request_id)), LambdaContext())


def test_public_environment_names_and_artifact_filenames_are_fixed():
    assert entrypoint.ENV_MAPIT_MCP_ENV == "MAPIT_MCP_ENV"
    assert entrypoint.ENV_AWS_REGION == "AWS_REGION"
    assert entrypoint.ENV_COGNITO_USER_POOL_ID == "MAPIT_COGNITO_USER_POOL_ID"
    assert entrypoint.ENV_API_ID == "MAPIT_API_ID"
    assert entrypoint.ENV_COGNITO_CLIENT_ID == "MAPIT_COGNITO_CLIENT_ID"
    assert entrypoint.ENV_OWNER_SUBJECT == "MAPIT_OWNER_SUBJECT"
    assert entrypoint.ENV_COGNITO_JWKS_SHA256 == "MAPIT_COGNITO_JWKS_SHA256"
    assert entrypoint.JWKS_SNAPSHOT_FILENAME == "cognito-public-jwks.json"
    assert entrypoint.JWKS_MANIFEST_FILENAME == "cognito-public-jwks.manifest.json"


def test_entrypoint_loads_only_exact_dev_environment_and_valid_snapshot(isolated_entrypoint):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path)
    response = _request(private, policy)
    assert response["statusCode"] == 200
    assert len(json.loads(response["body"])["result"]["tools"]) == 10
    assert entrypoint._CACHED_RUNTIME is not None


@pytest.mark.parametrize("bad_env", [
    (entrypoint.ENV_MAPIT_MCP_ENV, "prod"),
    (entrypoint.ENV_MAPIT_MCP_ENV, ""),
    (entrypoint.ENV_AWS_REGION, "us-east-1"),
])
def test_missing_or_prod_environment_returns_constant_503_before_file_read(isolated_entrypoint, monkeypatch, bad_env):
    _set_environment(None)
    monkeypatch.setenv(*bad_env)
    read_calls = []
    monkeypatch.setattr(entrypoint, "_read_fixed_sibling", lambda *args: read_calls.append(args) or b"secret-path")
    response = entrypoint.handler({"token": "must-not-echo"}, LambdaContext())
    assert response == entrypoint._unavailable()
    assert response["statusCode"] == 503
    assert "must-not-echo" not in response["body"]
    assert read_calls == []
    assert entrypoint._CACHED_RUNTIME is None


@pytest.mark.parametrize("missing_name", [
    entrypoint.ENV_COGNITO_USER_POOL_ID,
    entrypoint.ENV_API_ID,
    entrypoint.ENV_COGNITO_CLIENT_ID,
    entrypoint.ENV_OWNER_SUBJECT,
    entrypoint.ENV_COGNITO_JWKS_SHA256,
])
def test_missing_identity_or_digest_configuration_fails_closed(isolated_entrypoint, monkeypatch, missing_name):
    _set_environment("a" * 64)
    monkeypatch.delenv(missing_name, raising=False)
    response = entrypoint.handler(object(), LambdaContext())
    assert response == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None


def test_expected_digest_must_match_snapshot_and_manifest(isolated_entrypoint):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path)
    _set_environment("0" * 64)
    response = _request(private, policy)
    assert response == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None


@pytest.mark.parametrize("manifest_changes", [
    {"issuer": "https://cognito-idp.us-east-1.amazonaws.com/pool"},
    {"jwks_uri": "https://keys.example.invalid/jwks.json"},
    {"sha256": "A" * 64},
    {"unrecognized": "field"},
])
def test_manifest_binding_and_exact_fields_are_enforced(isolated_entrypoint, manifest_changes):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path, manifest_changes=manifest_changes)
    response = _request(private, policy)
    assert response == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None


@pytest.mark.parametrize("bad_manifest", [
    b'{"issuer":"x","issuer":"y","jwks_uri":"z","sha256":"' + b"0" * 64 + b'"}',
    b"{not-json",
    b"\xff",
    b"{}",
    b"{" + b" " * entrypoint.MAX_JWKS_MANIFEST_BYTES,
])
def test_malformed_duplicate_or_oversize_manifest_never_initializes(isolated_entrypoint, bad_manifest):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path, manifest_raw=bad_manifest)
    response = _request(private, policy)
    assert response == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None


def test_oversize_snapshot_fails_before_jwks_parser(isolated_entrypoint):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path, jwks_document=b"{" + b" " * entrypoint.MAX_JWKS_SNAPSHOT_BYTES + b"}")
    response = _request(private, policy)
    assert response == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None


def test_missing_snapshot_artifact_returns_static_unavailable(isolated_entrypoint):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path)
    (tmp_path / entrypoint.JWKS_SNAPSHOT_FILENAME).unlink()
    response = _request(private, policy)
    assert response == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None


def test_failed_initialization_does_not_cache_and_can_recover_after_local_fixture_repair(isolated_entrypoint):
    import os

    tmp_path = isolated_entrypoint
    private, policy, jwks, _, digest = _fixture_bundle(tmp_path, manifest_changes={"issuer": "wrong"})
    failed = _request(private, policy)
    assert failed == entrypoint._unavailable()
    assert entrypoint._CACHED_RUNTIME is None
    manifest = {
        "issuer": policy.issuer_url,
        "jwks_uri": f"{policy.issuer_url}/.well-known/jwks.json",
        "sha256": digest,
    }
    (tmp_path / entrypoint.JWKS_SNAPSHOT_FILENAME).write_bytes(jwks)
    (tmp_path / entrypoint.JWKS_MANIFEST_FILENAME).write_text(json.dumps(manifest, separators=(",", ":")), encoding="utf-8")
    os.environ[entrypoint.ENV_COGNITO_JWKS_SHA256] = digest
    recovered = _request(private, policy)
    assert recovered["statusCode"] == 200
    assert entrypoint._CACHED_RUNTIME is not None


def test_successful_snapshot_is_cached_once_and_reused_only_for_same_policy_and_digest(isolated_entrypoint, monkeypatch):
    import os

    tmp_path = isolated_entrypoint
    private, policy, _, _, digest = _fixture_bundle(tmp_path)
    original_factory = entrypoint.create_aws_dev_runtime
    calls = []

    def counted_factory(*args):
        calls.append(1)
        return original_factory(*args)

    monkeypatch.setattr(entrypoint, "create_aws_dev_runtime", counted_factory)
    first = _request(private, policy)
    # Mutating the sibling files after cold start cannot replace the frozen in-memory key snapshot.
    (tmp_path / entrypoint.JWKS_SNAPSHOT_FILENAME).write_bytes(b"corrupt after warm initialization")
    second = _request(private, policy, request_id=2)
    assert first["statusCode"] == second["statusCode"] == 200
    assert calls == [1]
    assert entrypoint._CACHED_JWKS_SHA256 == digest
    assert __import__("os").environ[entrypoint.ENV_COGNITO_JWKS_SHA256] == digest

    os.environ[entrypoint.ENV_COGNITO_JWKS_SHA256] = "f" * 64
    changed_digest = entrypoint.handler({}, LambdaContext())
    assert changed_digest == entrypoint._unavailable()
    os.environ[entrypoint.ENV_COGNITO_JWKS_SHA256] = digest
    os.environ[entrypoint.ENV_OWNER_SUBJECT] = "9c6b461d-85ba-4827-9394-3a97b41328db"
    changed_policy = entrypoint.handler({}, LambdaContext())
    assert changed_policy == entrypoint._unavailable()


def test_unknown_rotated_key_fails_closed_as_401_without_reloading_snapshot(isolated_entrypoint, monkeypatch):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path)
    calls = []
    original_factory = entrypoint.create_aws_dev_runtime

    def counted_factory(*args):
        calls.append(1)
        return original_factory(*args)

    monkeypatch.setattr(entrypoint, "create_aws_dev_runtime", counted_factory)
    unknown = _request(private, policy, kid="rotated-key-not-in-snapshot")
    assert unknown["statusCode"] == 401
    assert entrypoint._CACHED_RUNTIME is not None
    assert calls == [1]
    still_unknown = _request(private, policy, kid="another-unknown-kid")
    assert still_unknown["statusCode"] == 401
    assert calls == [1]


def test_runtime_entrypoint_serves_all_synthetic_tools_and_warm_repeated_calls(isolated_entrypoint):
    tmp_path = isolated_entrypoint
    private, policy, _, _, _ = _fixture_bundle(tmp_path)
    date_range = {"from_time": "2026-01-01", "to_time": "2026-02-01"}
    calls = (
        ("get_vehicle_status", {}),
        ("get_vehicle_details", {}),
        ("list_routes", date_range),
        ("get_route_detail", {"route_id": "synthetic-route"}),
        ("get_distance", date_range),
        ("compare_distance_periods", {"period_a": date_range, "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"}}),
        ("get_route_statistics", date_range),
        ("get_distance_breakdown", {**date_range, "group_by": "day"}),
        ("get_route_extremes", date_range),
        ("compare_route_periods", {"period_a": date_range, "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"}}),
    )
    for i, (name, arguments) in enumerate(calls, 1):
        result = _request(private, policy, "tools/call", {"name": name, "arguments": arguments}, i)
        assert result["statusCode"] == 200, name
        assert json.loads(result["body"])["result"]["isError"] is False, name
    first_warm = _request(private, policy, request_id=20)
    second_warm = _request(private, policy, request_id=21)
    assert first_warm["statusCode"] == second_warm["statusCode"] == 200
    assert entrypoint._CACHED_RUNTIME is not None


def test_initialization_errors_emit_no_diagnostics_or_untrusted_values(isolated_entrypoint, capsys):
    import os

    _set_environment(None)
    os.environ[entrypoint.ENV_MAPIT_MCP_ENV] = "prod-private-marker"
    response = entrypoint.handler({"authorization": "Bearer token-private-marker"}, LambdaContext())
    captured = capsys.readouterr()
    assert response == entrypoint._unavailable()
    assert "private-marker" not in response["body"]
    assert "private-marker" not in captured.out
    assert "private-marker" not in captured.err
