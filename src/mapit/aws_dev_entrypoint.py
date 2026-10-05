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
import math
import time
from decimal import Decimal, InvalidOperation
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
ENV_EXECUTION_WINDOW_START = "MAPIT_DEV_EXECUTION_START_EPOCH"
ENV_EXECUTION_WINDOW_END = "MAPIT_DEV_EXECUTION_END_EPOCH"

JWKS_SNAPSHOT_FILENAME = "cognito-public-jwks.json"
JWKS_MANIFEST_FILENAME = "cognito-public-jwks.manifest.json"
MAX_JWKS_SNAPSHOT_BYTES = 32 * 1024
MAX_JWKS_MANIFEST_BYTES = 2 * 1024
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_CANONICAL_EPOCH = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
_UNAVAILABLE_BODY = b'{"error":"service_unavailable"}'
_MAX_EXECUTION_WINDOW_SECONDS = Decimal("300")
_ADAPTER_SERIALIZATION_RESERVE_SECONDS = 1.0

_CACHED_RUNTIME: AwsDevSyntheticRuntime | None = None
_CACHED_JWKS_SHA256: str | None = None
_CACHED_WINDOW: tuple[str, str] | None = None


def _clock() -> float:
    """Private test seam; production uses the system UTC epoch clock."""
    return time.time()


class _BoundedContext:
    """Pass a non-increasing Lambda budget capped at the absolute window end."""

    def __init__(self, remaining_ms: int, captured_monotonic: float, window_start: float, window_end: float) -> None:
        self._remaining_ms = remaining_ms
        self._captured_monotonic = captured_monotonic
        self._window_start = window_start
        self._window_end = window_end
        self._last_remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self) -> int:
        elapsed = max(0.0, time.monotonic() - self._captured_monotonic)
        elapsed_ms = math.ceil(elapsed * 1000)
        lambda_remaining = self._remaining_ms - elapsed_ms
        now = _clock()
        if (
            type(now) not in (int, float)
            or not math.isfinite(now)
            or now < self._window_start
            or now >= self._window_end
        ):
            self._last_remaining_ms = 0
            return 0
        window_cap = math.floor((self._window_end - now + _ADAPTER_SERIALIZATION_RESERVE_SECONDS) * 1000)
        self._last_remaining_ms = max(0, min(self._last_remaining_ms, lambda_remaining, window_cap))
        return self._last_remaining_ms


def _epoch_window_from_environment(now: Any) -> tuple[str, str, float, float]:
    start_text = os.environ.get(ENV_EXECUTION_WINDOW_START)
    end_text = os.environ.get(ENV_EXECUTION_WINDOW_END)
    if (
        not isinstance(start_text, str)
        or not isinstance(end_text, str)
        or len(start_text) > 32
        or len(end_text) > 32
        or not _CANONICAL_EPOCH.fullmatch(start_text)
        or not _CANONICAL_EPOCH.fullmatch(end_text)
    ):
        raise ValueError("execution window configuration is invalid")
    try:
        start_decimal = Decimal(start_text)
        end_decimal = Decimal(end_text)
    except InvalidOperation:
        raise ValueError("execution window configuration is invalid") from None
    span = end_decimal - start_decimal
    if span <= 0 or span > _MAX_EXECUTION_WINDOW_SECONDS:
        raise ValueError("execution window span is invalid")
    try:
        clock_is_finite = type(now) in (int, float) and math.isfinite(now)
    except (OverflowError, TypeError, ValueError):
        clock_is_finite = False
    if not clock_is_finite:
        raise ValueError("clock is invalid")
    start, end = float(start_decimal), float(end_decimal)
    if not math.isfinite(start) or not math.isfinite(end):
        raise ValueError("execution window is outside numeric range")
    if now < start or now >= end:
        raise ValueError("execution window is not active")
    return start_text, end_text, start, end


def _capped_context(context: Any, window_start: float, window_end: float) -> _BoundedContext:
    captured_monotonic = time.monotonic()
    try:
        original_ms = context.get_remaining_time_in_millis()
    except Exception:
        raise ValueError("invocation budget is unavailable") from None
    if type(original_ms) is not int or original_ms <= 0:
        raise ValueError("invocation budget is invalid")
    now = _clock()
    if (
        type(now) not in (int, float)
        or not math.isfinite(now)
        or now < window_start
        or now >= window_end
    ):
        raise ValueError("execution window has no remaining budget")
    # The adapter itself reserves one second for response serialization. Add
    # that reserve to its context budget; the dynamic wrapper recomputes this
    # ceiling at dispatch time so wrapper overhead cannot extend the window.
    until_window_plus_reserve = (window_end - now + _ADAPTER_SERIALIZATION_RESERVE_SECONDS) * 1000
    if not math.isfinite(until_window_plus_reserve) or until_window_plus_reserve <= 0:
        raise ValueError("execution window has no remaining budget")
    if math.floor(until_window_plus_reserve) <= 0:
        raise ValueError("execution window has no remaining budget")
    # Keep the pre-read monotonic sample: a slow context getter consumes this
    # same invocation budget and must not cause the value to be overstated.
    return _BoundedContext(original_ms, captured_monotonic, window_start, window_end)


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
    global _CACHED_RUNTIME, _CACHED_JWKS_SHA256, _CACHED_WINDOW
    try:
        start_text, end_text, window_start, window_end = _epoch_window_from_environment(_clock())
        window_binding = (start_text, end_text)
        policy = _policy_from_environment()
        expected_sha256 = os.environ.get(ENV_COGNITO_JWKS_SHA256)
        if not isinstance(expected_sha256, str) or not _SHA256_HEX.fullmatch(expected_sha256):
            return _unavailable()
        if _CACHED_RUNTIME is None:
            runtime, digest = _load_runtime(policy, expected_sha256)
            # Publish cache state only after the entire runtime constructed.
            _CACHED_RUNTIME, _CACHED_JWKS_SHA256, _CACHED_WINDOW = runtime, digest, window_binding
        elif (
            _CACHED_RUNTIME.policy != policy
            or _CACHED_WINDOW != window_binding
            or not hmac.compare_digest(_CACHED_JWKS_SHA256 or "", expected_sha256)
        ):
            return _unavailable()
        dispatch_now = _clock()
        if type(dispatch_now) not in (int, float) or not math.isfinite(dispatch_now) or dispatch_now < float(start_text) or dispatch_now >= window_end:
            return _unavailable()
        bounded_context = _capped_context(context, window_start, window_end)
        before_dispatch = _clock()
        if (
            type(before_dispatch) not in (int, float)
            or not math.isfinite(before_dispatch)
            or before_dispatch < window_start
            or before_dispatch >= window_end
        ):
            return _unavailable()
        result = _CACHED_RUNTIME.lambda_handler(event, bounded_context)
        completed_at = _clock()
        if (
            type(completed_at) not in (int, float)
            or not math.isfinite(completed_at)
            or completed_at < window_start
            or completed_at >= window_end
        ):
            return _unavailable()
        return result
    except Exception:
        # Do not expose environment values, paths, parser details, or exception text.
        return _unavailable()


__all__ = [
    "ENV_API_ID",
    "ENV_AWS_REGION",
    "ENV_COGNITO_CLIENT_ID",
    "ENV_COGNITO_JWKS_SHA256",
    "ENV_COGNITO_USER_POOL_ID",
    "ENV_EXECUTION_WINDOW_END",
    "ENV_EXECUTION_WINDOW_START",
    "ENV_MAPIT_MCP_ENV",
    "ENV_OWNER_SUBJECT",
    "JWKS_MANIFEST_FILENAME",
    "JWKS_SNAPSHOT_FILENAME",
    "MAX_JWKS_MANIFEST_BYTES",
    "MAX_JWKS_SNAPSHOT_BYTES",
    "handler",
]
