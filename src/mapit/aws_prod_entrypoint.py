"""Fail-closed single-owner production Lambda entrypoint.

Only public deployment bindings are read from fixed sibling artifacts. The
refresh token is read per invocation and is never cached or logged. No SDK,
secret read, or network work occurs at import time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import time
from pathlib import Path
from typing import Any, Mapping

from .aws_prod_runtime import CognitoProdPolicy, AwsProdRuntime, create_aws_prod_runtime
from .aws_session_reader import AwsSessionReader
from .cloud_provider import CloudServicesProvider
from .cloud_transport import CloudDirectTransport, validate_cloud_config
from .config import MapitConfig

ENV_FUNCTION = "AWS_LAMBDA_FUNCTION_NAME"
ENV_REGION = "AWS_REGION"
ENV_ENVIRONMENT = "MAPIT_MCP_ENV"
ENV_MANIFEST_SHA256 = "MAPIT_PROD_MANIFEST_SHA256"
REGION = "eu-west-1"
FUNCTION_NAME = "honda-mapit-mcp-prod-handler"
MANIFEST_FILENAME = "mapit-prod.manifest.json"
JWKS_FILENAME = "cognito-public-jwks.json"
MAX_MANIFEST_BYTES = 8 * 1024
MAX_JWKS_BYTES = 32 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_CACHED_RUNTIME: AwsProdRuntime | None = None
_CACHED_MANIFEST_SHA256: str | None = None
_CACHED_SSM_CLIENT: Any | None = None


class _EntryError(ValueError):
    def __init__(self, category: str):
        self.category = category if category in {
            "environment_invalid", "artifact_invalid", "manifest_invalid",
            "configuration_invalid", "runtime_unavailable",
        } else "runtime_unavailable"
        super().__init__(self.category)


def _unavailable() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": '{"error":"service_unavailable"}',
        "isBase64Encoded": False,
    }


def _read_sibling(filename: str, maximum: int) -> bytes:
    if filename not in {MANIFEST_FILENAME, JWKS_FILENAME}:
        raise _EntryError("artifact_invalid")
    root = Path(__file__).resolve().parent
    path = root / filename
    if path.parent != root or path.is_symlink() or not path.is_file():
        raise _EntryError("artifact_invalid")
    try:
        with path.open("rb") as stream:
            raw = stream.read(maximum + 1)
    except OSError:
        raise _EntryError("artifact_invalid") from None
    if not raw or len(raw) > maximum:
        raise _EntryError("artifact_invalid")
    return raw


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _EntryError("manifest_invalid")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise _EntryError("manifest_invalid")


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise _EntryError("manifest_invalid")
    try:
        result = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except _EntryError:
        raise
    except Exception:
        raise _EntryError("manifest_invalid") from None
    if type(result) is not dict:
        raise _EntryError("manifest_invalid")
    expected = {
        "environment", "region", "account_id", "parameter_version", "parameter_tier",
        "user_pool_id", "api_id", "client_id", "owner_subject", "jwks_sha256", "mapit_config",
    }
    if set(result) not in (expected, expected | {"geographic_queries"}):
        raise _EntryError("manifest_invalid")
    if "geographic_queries" in result and result["geographic_queries"] is not True:
        raise _EntryError("manifest_invalid")
    text_fields = expected - {"parameter_version", "mapit_config"}
    if any(type(result[name]) is not str for name in text_fields):
        raise _EntryError("manifest_invalid")
    if (
        result["environment"] != "prod"
        or result["region"] != REGION
        or not _ACCOUNT.fullmatch(result["account_id"])
        or result["account_id"] == "000000000000"
        or type(result["parameter_version"]) is not int
        or result["parameter_version"] != 1
        or result["parameter_tier"] != "Standard"
        or not _SHA256.fullmatch(result["jwks_sha256"])
    ):
        raise _EntryError("manifest_invalid")

    config_data = result["mapit_config"]
    config_fields = {
        "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
        "core_api_url", "geo_api_url", "discovery_enabled", "http_timeout",
    }
    if type(config_data) is not dict or set(config_data) != config_fields:
        raise _EntryError("manifest_invalid")
    if (
        any(type(config_data[name]) is not str for name in config_fields - {"discovery_enabled", "http_timeout"})
        or type(config_data["discovery_enabled"]) is not bool
        or type(config_data["http_timeout"]) not in (int, float)
        or isinstance(config_data["http_timeout"], bool)
        or config_data["http_timeout"] <= 0
        or config_data["http_timeout"] > 2
    ):
        raise _EntryError("manifest_invalid")
    try:
        if not math.isfinite(config_data["http_timeout"]):
            raise _EntryError("manifest_invalid")
    except OverflowError:
        raise _EntryError("manifest_invalid") from None
    try:
        policy = CognitoProdPolicy(
            user_pool_id=result["user_pool_id"], api_id=result["api_id"],
            client_id=result["client_id"], owner_subject=result["owner_subject"],
            request_deadline_seconds=14.0,
        )
        config = MapitConfig(**config_data)
        validate_cloud_config(config)
    except Exception:
        raise _EntryError("configuration_invalid") from None
    # Keep constructor validation canonical: manifest values may not smuggle a
    # dev identity, credentials, discovery setting, or a different MAPIT host.
    if config.discovery_enabled is not False or config.email is not None or config.password is not None:
        raise _EntryError("configuration_invalid")
    result["_validated_policy"] = policy
    result["_validated_config"] = config
    return result


def _validate_environment(environ: Mapping[str, str]) -> str:
    if not isinstance(environ, Mapping):
        raise _EntryError("environment_invalid")
    if (
        environ.get(ENV_FUNCTION) != FUNCTION_NAME
        or environ.get(ENV_REGION) != REGION
        or environ.get(ENV_ENVIRONMENT) != "prod"
    ):
        raise _EntryError("environment_invalid")
    digest = environ.get(ENV_MANIFEST_SHA256)
    if type(digest) is not str or not _SHA256.fullmatch(digest):
        raise _EntryError("environment_invalid")
    return digest


def _make_ssm_client() -> Any:
    # Use only the short-lived credentials supplied to this Lambda execution
    # environment; explicit kwargs prevent boto3 local-profile fallback.
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = os.environ.get("AWS_SESSION_TOKEN")
    if any(type(value) is not str or not value for value in (access_key, secret_key, session_token)):
        raise _EntryError("runtime_unavailable")
    import boto3
    from botocore.config import Config

    config = Config(
        retries={"mode": "standard", "total_max_attempts": 1},
        connect_timeout=1,
        read_timeout=1,
        proxies={},
    )
    return boto3.client(
        "ssm", region_name=REGION, config=config,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )


_ssm_client_factory = _make_ssm_client


def _get_ssm_client() -> Any:
    global _CACHED_SSM_CLIENT
    if _CACHED_SSM_CLIENT is None:
        _CACHED_SSM_CLIENT = _ssm_client_factory()
    return _CACHED_SSM_CLIENT


class _LazySSMClient:
    """Defer role-client initialization until an authenticated token read."""

    def get_parameter(self, **kwargs: Any) -> Any:
        return _get_ssm_client().get_parameter(**kwargs)


def _load_runtime(manifest_raw: bytes, jwks_raw: bytes, manifest_sha: str) -> AwsProdRuntime:
    global _CACHED_RUNTIME, _CACHED_MANIFEST_SHA256
    actual_manifest_sha = hashlib.sha256(manifest_raw).hexdigest()
    if not hmac.compare_digest(actual_manifest_sha, manifest_sha):
        raise _EntryError("manifest_invalid")
    parsed = _parse_manifest(manifest_raw)
    if len(jwks_raw) > MAX_JWKS_BYTES or hashlib.sha256(jwks_raw).hexdigest() != parsed["jwks_sha256"]:
        raise _EntryError("artifact_invalid")
    policy = parsed["_validated_policy"]
    config = parsed["_validated_config"]

    def provider_builder(deadline: float) -> CloudServicesProvider:
        reader = AwsSessionReader(
            _LazySSMClient(), account_id=parsed["account_id"],
            version=parsed["parameter_version"], tier=parsed["parameter_tier"],
        )
        transport = CloudDirectTransport(config, deadline=deadline)
        return CloudServicesProvider(
            config, reader, transport.cognito_json, transport.mapit_request, deadline=deadline,
        )

    runtime_options = {"geographic_queries": True} if parsed.get("geographic_queries") is True else {}
    runtime = create_aws_prod_runtime(
        policy, jwks_raw, provider_builder=provider_builder, **runtime_options,
    )
    _CACHED_RUNTIME = runtime
    _CACHED_MANIFEST_SHA256 = manifest_sha
    return runtime


def handler(event: Any, context: Any) -> dict[str, Any]:
    """Lambda handler; all invalid setup and runtime failures have one response."""
    global _CACHED_RUNTIME, _CACHED_MANIFEST_SHA256
    try:
        env = os.environ
        manifest_sha = _validate_environment(env)
        if _CACHED_RUNTIME is None or _CACHED_MANIFEST_SHA256 != manifest_sha:
            manifest_raw = _read_sibling(MANIFEST_FILENAME, MAX_MANIFEST_BYTES)
            jwks_raw = _read_sibling(JWKS_FILENAME, MAX_JWKS_BYTES)
            runtime = _load_runtime(manifest_raw, jwks_raw, manifest_sha)
        else:
            runtime = _CACHED_RUNTIME
        return runtime.lambda_handler(event, context)
    except Exception:
        return _unavailable()


__all__ = ["FUNCTION_NAME", "MANIFEST_FILENAME", "JWKS_FILENAME", "handler"]
