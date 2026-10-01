from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa

from mapit import aws_dev_entrypoint as entrypoint
from mapit.aws_dev_runtime import cognito_dev_policy


POOL_ID = "eu-west-1_A1b2C3d4E"
API_ID = "a1b2c3d4e5"
CLIENT_ID = "SyntheticCognitoClient012345"
OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"


class _Context:
    def get_remaining_time_in_millis(self):
        return 30_000


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _write_bundle(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(entrypoint, "__file__", str(tmp_path / "aws_dev_entrypoint.py"))
    monkeypatch.setattr(entrypoint, "_CACHED_RUNTIME", None)
    monkeypatch.setattr(entrypoint, "_CACHED_JWKS_SHA256", None)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    jwks = json.dumps(
        {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": "independent-fixture",
                    "use": "sig",
                    "alg": "RS256",
                    "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
                }
            ]
        },
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(jwks).hexdigest()
    policy = cognito_dev_policy(
        user_pool_id=POOL_ID,
        api_id=API_ID,
        client_id=CLIENT_ID,
        owner_subject=OWNER,
    )
    manifest = json.dumps(
        {
            "issuer": policy.issuer_url,
            "jwks_uri": f"{policy.issuer_url}/.well-known/jwks.json",
            "sha256": digest,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    (tmp_path / entrypoint.JWKS_SNAPSHOT_FILENAME).write_bytes(jwks)
    (tmp_path / entrypoint.JWKS_MANIFEST_FILENAME).write_bytes(manifest)
    monkeypatch.setenv(entrypoint.ENV_MAPIT_MCP_ENV, "dev")
    monkeypatch.setenv(entrypoint.ENV_AWS_REGION, "eu-west-1")
    monkeypatch.setenv(entrypoint.ENV_COGNITO_USER_POOL_ID, POOL_ID)
    monkeypatch.setenv(entrypoint.ENV_API_ID, API_ID)
    monkeypatch.setenv(entrypoint.ENV_COGNITO_CLIENT_ID, CLIENT_ID)
    monkeypatch.setenv(entrypoint.ENV_OWNER_SUBJECT, OWNER)
    monkeypatch.setenv(entrypoint.ENV_COGNITO_JWKS_SHA256, digest)
    return policy, digest


def test_untrusted_path_environment_extras_are_ignored_and_fixed_siblings_are_used(tmp_path, monkeypatch):
    _write_bundle(tmp_path, monkeypatch)
    alternate = tmp_path / "attacker-selected-jwks.json"
    alternate.write_text("not a JWKS snapshot", encoding="utf-8")
    monkeypatch.setenv("MAPIT_COGNITO_JWKS_PATH", str(alternate))
    monkeypatch.setenv("MAPIT_COGNITO_MANIFEST_PATH", str(alternate))
    seen = []
    original = entrypoint._read_fixed_sibling

    def record_fixed_sibling(filename, limit):
        seen.append(filename)
        return original(filename, limit)

    monkeypatch.setattr(entrypoint, "_read_fixed_sibling", record_fixed_sibling)
    response = entrypoint.handler({}, _Context())
    assert entrypoint._CACHED_RUNTIME is not None
    assert seen == [entrypoint.JWKS_SNAPSHOT_FILENAME, entrypoint.JWKS_MANIFEST_FILENAME]
    assert response["statusCode"] != 503


def test_manifest_parse_failure_is_static_and_never_logs_embedded_marker(tmp_path, monkeypatch, capsys):
    _write_bundle(tmp_path, monkeypatch)
    marker = "private-canary-independent-test"
    (tmp_path / entrypoint.JWKS_MANIFEST_FILENAME).write_text(
        '{"issuer":"' + marker + '","issuer":"duplicate"}', encoding="utf-8"
    )
    response = entrypoint.handler({"authorization": marker}, _Context())
    captured = capsys.readouterr()
    assert response == entrypoint._unavailable()
    assert marker not in response["body"]
    assert marker not in captured.out
    assert marker not in captured.err
    assert entrypoint._CACHED_RUNTIME is None


def test_failed_initialization_is_not_negative_cached(tmp_path, monkeypatch):
    _write_bundle(tmp_path, monkeypatch)
    attempts = []

    def fail_without_details(_policy, _digest):
        attempts.append(True)
        raise ValueError("private-canary-independent-test")

    monkeypatch.setattr(entrypoint, "_load_runtime", fail_without_details)
    first = entrypoint.handler({}, _Context())
    second = entrypoint.handler({}, _Context())
    assert first == second == entrypoint._unavailable()
    assert attempts == [True, True]
    assert entrypoint._CACHED_RUNTIME is None
    assert entrypoint._CACHED_JWKS_SHA256 is None
