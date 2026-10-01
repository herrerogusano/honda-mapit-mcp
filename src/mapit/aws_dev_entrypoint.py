"""Fail-closed synthetic-dev Lambda entrypoint backed by fixed public artifacts.

This module does not perform AWS SDK, Cognito discovery, secret-store, MAPIT, or
local credential/session operations. The bundle supplies only a public JWKS
snapshot and its binding manifest as sibling files.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from pathlib import Path
from typing import Any

from .aws_dev_runtime import AwsDevSyntheticRuntime, cognito_dev_policy, create_aws_dev_runtime

ENV_MAPIT_MCP_ENV = "MAPIT_MCP_ENV"
ENV_AWS_REGION = "AWS_REGION"
ENV_COGNITO_USER_POOL_ID = "MAPIT_COGNITO_USER_POOL_ID"
ENV_API_ID = "MAPIT_API_ID"
ENV_COGNITO_CLIENT_ID = "MAPIT_COGNITO_CLIENT_ID"
ENV_OWNER_SUBJECT = "MAPIT_OWNER_SUBJECT"
ENV_COGNITO_JWKS_SHA256 = "MAPIT_COGNITO_JWKS_SHA256"

JWKS_SNAPSHOT_FILENAME = "cognito-public-jwks.json"
JWKS_MANIFEST_FILENAME = "cognito-public-jwks.manifest.json"
MAX_JWKS_SNAPSHOT_BYTES = 32 * 1024
MAX_JWKS_MANIFEST_BYTES = 2 * 1024
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_UNAVAILABLE_BODY = b'{"error":"service_unavailable"}'

_CACHED_RUNTIME: AwsDevSyntheticRuntime | None = None
_CACHED_JWKS_SHA256: str | None = None


def _unavailable() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": _UNAVAILABLE_BODY.decode("ascii"),
        "isBase64Encoded": False,
    }


def _read_fixed_sibling(filename: str, byte_limit: int) -> bytes:
    if filename not in {JWKS_SNAPSHOT_FILENAME, JWKS_MANIFEST_FILENAME}:
        raise ValueError("unsupported artifact")
    directory = Path(__file__).resolve().parent
    artifact_path = directory / filename
    if artifact_path.parent != directory or artifact_path.is_symlink() or not artifact_path.is_file():
        raise ValueError("fixed artifact is unavailable")
    try:
        with artifact_path.open("rb") as artifact:
            raw = artifact.read(byte_limit + 1)
    except OSError:
        raise ValueError("fixed artifact is unavailable") from None
    if len(raw) > byte_limit:
        raise ValueError("fixed artifact exceeds its bound")
    return raw


def _manifest_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate manifest member")
        result[key] = value
    return result


def _reject_manifest_constant(_value: str) -> None:
    raise ValueError("invalid manifest constant")


def _parse_manifest(raw: bytes) -> dict[str, str]:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_JWKS_MANIFEST_BYTES:
        raise ValueError("manifest is outside the allowed size")
    try:
        text = raw.decode("utf-8", errors="strict")
        parsed = json.loads(
            text,
            object_pairs_hook=_manifest_pairs,
            parse_constant=_reject_manifest_constant,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise ValueError("manifest is invalid") from None
    if not isinstance(parsed, dict) or set(parsed) != {"issuer", "jwks_uri", "sha256"}:
        raise ValueError("manifest shape is invalid")
    if not all(isinstance(parsed[name], str) for name in ("issuer", "jwks_uri", "sha256")):
        raise ValueError("manifest field types are invalid")
    return parsed


def _policy_from_environment():
    if os.environ.get(ENV_MAPIT_MCP_ENV) != "dev" or os.environ.get(ENV_AWS_REGION) != "eu-west-1":
        raise ValueError("development runtime environment is unavailable")
    try:
        return cognito_dev_policy(
            user_pool_id=os.environ[ENV_COGNITO_USER_POOL_ID],
            api_id=os.environ[ENV_API_ID],
            client_id=os.environ[ENV_COGNITO_CLIENT_ID],
            owner_subject=os.environ[ENV_OWNER_SUBJECT],
        )
    except (KeyError, TypeError, ValueError):
        raise ValueError("development identity configuration is invalid") from None


def _load_runtime(policy, expected_sha256: str) -> tuple[AwsDevSyntheticRuntime, str]:
    if not isinstance(expected_sha256, str) or not _SHA256_HEX.fullmatch(expected_sha256):
        raise ValueError("expected snapshot digest is invalid")
    raw_jwks = _read_fixed_sibling(JWKS_SNAPSHOT_FILENAME, MAX_JWKS_SNAPSHOT_BYTES)
    raw_manifest = _read_fixed_sibling(JWKS_MANIFEST_FILENAME, MAX_JWKS_MANIFEST_BYTES)
    digest = hashlib.sha256(raw_jwks).hexdigest()
    if not hmac.compare_digest(digest, expected_sha256):
        raise ValueError("snapshot digest does not match configuration")
    manifest = _parse_manifest(raw_manifest)
    expected_jwks_uri = f"{policy.issuer_url}/.well-known/jwks.json"
    if (
        manifest["issuer"] != policy.issuer_url
        or manifest["jwks_uri"] != expected_jwks_uri
        or not _SHA256_HEX.fullmatch(manifest["sha256"])
        or not hmac.compare_digest(manifest["sha256"], digest)
    ):
        raise ValueError("snapshot manifest binding does not match configuration")
    runtime = create_aws_dev_runtime(policy, raw_jwks)
    return runtime, digest


def handler(event: Any, context: Any) -> dict[str, Any]:
    """Synchronous Lambda entrypoint; failures before runtime readiness are constant 503."""
    global _CACHED_RUNTIME, _CACHED_JWKS_SHA256
    try:
        policy = _policy_from_environment()
        expected_sha256 = os.environ.get(ENV_COGNITO_JWKS_SHA256)
        if not isinstance(expected_sha256, str) or not _SHA256_HEX.fullmatch(expected_sha256):
            return _unavailable()
        if _CACHED_RUNTIME is None:
            runtime, digest = _load_runtime(policy, expected_sha256)
            # Publish cache state only after the entire runtime constructed.
            _CACHED_RUNTIME, _CACHED_JWKS_SHA256 = runtime, digest
        elif _CACHED_RUNTIME.policy != policy or not hmac.compare_digest(_CACHED_JWKS_SHA256 or "", expected_sha256):
            return _unavailable()
        return _CACHED_RUNTIME.lambda_handler(event, context)
    except Exception:
        # Do not expose environment values, paths, parser details, or exception text.
        return _unavailable()


__all__ = [
    "ENV_API_ID",
    "ENV_AWS_REGION",
    "ENV_COGNITO_CLIENT_ID",
    "ENV_COGNITO_JWKS_SHA256",
    "ENV_COGNITO_USER_POOL_ID",
    "ENV_MAPIT_MCP_ENV",
    "ENV_OWNER_SUBJECT",
    "JWKS_MANIFEST_FILENAME",
    "JWKS_SNAPSHOT_FILENAME",
    "MAX_JWKS_MANIFEST_BYTES",
    "MAX_JWKS_SNAPSHOT_BYTES",
    "handler",
]
