"""Fail-closed Lambda entrypoint for the invitation-only multiuser MCP.

Configuration comes only from the Lambda environment (docs/multiuser-production.md).
AWS clients are created lazily with the execution role's explicit environment
credentials, one attempt and short timeouts. No AWS call happens at import or
cold start; the only cold-start network access is the pool JWKS fetch.
"""

from __future__ import annotations

import json
import math
import os
import re
import time
import urllib.error
from typing import Any, Callable, Mapping

from .aws_session_reader import AwsSessionReadResult
from .cloud_provider import CloudServicesProvider
from .cloud_transport import CloudDirectTransport, validate_cloud_config
from .config import MapitConfig
from .http_transport import direct_opener
from .multiuser_common import (
    ENVIRONMENTS, REGION, STATUS_ACCEPTED, mcp_url, session_parameter_name, table_name,
    validate_tenant_id,
)
from .multiuser_runtime import (
    JwksCache, MultiuserRuntime, TenantSessionMissing, create_multiuser_runtime,
    fetch_jwks_https, multiuser_policy,
)

ENV_NAMES = (
    "AWS_LAMBDA_FUNCTION_NAME", "AWS_REGION", "MAPIT_MCP_ENV", "MULTIUSER_ISSUER_URL",
    "MULTIUSER_RESOURCE_URL", "MULTIUSER_CLIENT_IDS", "MULTIUSER_USER_POOL_ID",
    "MULTIUSER_TABLE", "MAPIT_CONFIG_JSON", "MULTIUSER_GEOGRAPHY",
)
_POOL_RE = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,64}$")
_RESOURCE_RE = re.compile(r"^https://([a-z0-9]{10})\.execute-api\.eu-west-1\.amazonaws\.com/mcp$")
_CLIENT_RE = re.compile(r"^[A-Za-z0-9]{1,128}$")
_MAX_CONFIG_BYTES = 4096
_MAX_SESSION_BYTES = 4096
_MAX_SCAN_PAGES = 4
_MAX_ERROR_BODY = 4096
_CONFIG_FIELDS = frozenset({
    "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
    "core_api_url", "geo_api_url", "discovery_enabled", "http_timeout",
})
_COGNITO_IDP_URL = f"https://cognito-idp.{REGION}.amazonaws.com/"

_CACHED_RUNTIME: MultiuserRuntime | None = None
_CACHED_SIGNATURE: tuple[str | None, ...] | None = None
_CACHED_CLIENTS: dict[str, Any] = {}


class _EntryError(ValueError):
    """Closed setup failure; never carries environment values."""


def _unavailable() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": '{"error":"service_unavailable"}',
        "isBase64Encoded": False,
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _EntryError("config_invalid")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise _EntryError("config_invalid")


def _parse_mapit_config(raw: Any) -> MapitConfig:
    if type(raw) is not str or not raw or len(raw.encode("utf-8", errors="replace")) > _MAX_CONFIG_BYTES:
        raise _EntryError("config_invalid")
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except _EntryError:
        raise
    except Exception:
        raise _EntryError("config_invalid") from None
    if type(data) is not dict or set(data) != _CONFIG_FIELDS:
        raise _EntryError("config_invalid")
    timeout = data["http_timeout"]
    if (
        any(type(data[name]) is not str for name in _CONFIG_FIELDS - {"discovery_enabled", "http_timeout"})
        or data["discovery_enabled"] is not False
        or isinstance(timeout, bool)
        or type(timeout) not in (int, float)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 2
    ):
        raise _EntryError("config_invalid")
    try:
        config = MapitConfig(**data)
        validate_cloud_config(config)
    except Exception:
        raise _EntryError("config_invalid") from None
    if config.email is not None or config.password is not None or config.discovery_enabled is not False:
        raise _EntryError("config_invalid")
    return config


def _settings(environ: Mapping[str, str]) -> dict[str, Any]:
    if not isinstance(environ, Mapping):
        raise _EntryError("environment_invalid")
    env = environ.get("MAPIT_MCP_ENV")
    if env not in ENVIRONMENTS:
        raise _EntryError("environment_invalid")
    pool = environ.get("MULTIUSER_USER_POOL_ID")
    resource = environ.get("MULTIUSER_RESOURCE_URL")
    clients_raw = environ.get("MULTIUSER_CLIENT_IDS")
    match = _RESOURCE_RE.fullmatch(resource) if type(resource) is str else None
    if (
        environ.get("AWS_REGION") != REGION
        or environ.get("AWS_LAMBDA_FUNCTION_NAME") != f"honda-mapit-mcp-{env}-mcp"
        or type(pool) is not str
        or not _POOL_RE.fullmatch(pool)
        or environ.get("MULTIUSER_ISSUER_URL") != f"https://cognito-idp.{REGION}.amazonaws.com/{pool}"
        or match is None
        or mcp_url(match.group(1)) != resource
        or environ.get("MULTIUSER_TABLE") != table_name(env)
        or environ.get("MULTIUSER_GEOGRAPHY") not in {"0", "1"}
        or type(clients_raw) is not str
    ):
        raise _EntryError("environment_invalid")
    client_ids = tuple(clients_raw.split(","))
    if (
        not 1 <= len(client_ids) <= 4
        or len(set(client_ids)) != len(client_ids)
        or any(not _CLIENT_RE.fullmatch(item) for item in client_ids)
    ):
        raise _EntryError("environment_invalid")
    try:
        policy = multiuser_policy(
            environment=env, user_pool_id=pool, resource_url=resource, client_ids=client_ids,
        )
    except Exception:
        raise _EntryError("environment_invalid") from None
    return {
        "env": env,
        "pool": pool,
        "table": table_name(env),
        "policy": policy,
        "config": _parse_mapit_config(environ.get("MAPIT_CONFIG_JSON")),
        "geography": environ.get("MULTIUSER_GEOGRAPHY") == "1",
    }


def _make_client(service: str) -> Any:
    # Only the execution role's short-lived credentials; explicit kwargs prevent
    # any boto3 profile/IMDS fallback.
    if service not in {"ssm", "dynamodb", "cognito-idp"}:
        raise _EntryError("client_invalid")
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = os.environ.get("AWS_SESSION_TOKEN")
    if any(type(value) is not str or not value for value in (access_key, secret_key, session_token)):
        raise _EntryError("credentials_unavailable")
    import boto3
    from botocore.config import Config

    config = Config(
        retries={"mode": "standard", "total_max_attempts": 1},
        connect_timeout=1,
        read_timeout=2,
        proxies={},
    )
    return boto3.client(
        service, region_name=REGION, config=config,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )


_client_factory: Callable[[str], Any] = _make_client
_jwks_fetcher: Callable[[str], bytes] = fetch_jwks_https


def _client(service: str) -> Any:
    client = _CACHED_CLIENTS.get(service)
    if client is None:
        client = _client_factory(service)
        _CACHED_CLIENTS[service] = client
    return client


def _error_code(exc: BaseException) -> str | None:
    try:
        response = getattr(exc, "response", None)
        code = response.get("Error", {}).get("Code") if isinstance(response, Mapping) else None
    except Exception:
        return None
    return code if type(code) is str else None


class _FixedTokenReader:
    """Adapt one already-read SecureString value to CloudServicesProvider's reader."""

    def __init__(self, value: str, version: int) -> None:
        self._value = value
        self._version = version

    def __repr__(self) -> str:
        return "FixedTokenReader(<redacted>)"

    def read_refresh_token(self, *, deadline: float) -> AwsSessionReadResult:
        if time.monotonic() >= deadline:
            raise RuntimeError("deadline_expired")
        return AwsSessionReadResult(True, "session_read_verified", self._version, "Standard", self._value)


class _RejectionProbe:
    """Opener wrapper that records a Cognito NotAuthorizedException on InitiateAuth.

    CloudDirectTransport discards error bodies, so the only way to tell a
    rejected/revoked MAPIT refresh token from throttling or other 400s is to
    inspect the body here, bounded, before re-raising the unchanged error.
    """

    def __init__(self, inner: Any | None = None) -> None:
        self._inner = inner
        self.rejected = False

    def open(self, request: Any, timeout: float) -> Any:
        opener = self._inner if self._inner is not None else direct_opener()
        try:
            return opener.open(request, timeout=timeout)
        except urllib.error.HTTPError as exc:
            try:
                if (
                    exc.code == 400
                    and request.get_method() == "POST"
                    and request.full_url == _COGNITO_IDP_URL
                    and request.get_header("X-amz-target") == "AWSCognitoIdentityProviderService.InitiateAuth"
                ):
                    body = exc.read(_MAX_ERROR_BODY + 1)
                    if type(body) is bytes and len(body) <= _MAX_ERROR_BODY:
                        kind = json.loads(body.decode("utf-8")).get("__type")
                        if type(kind) is str and (
                            kind == "NotAuthorizedException" or kind.endswith("#NotAuthorizedException")
                        ):
                            self.rejected = True
            except Exception:
                pass
            raise


class _TenantSession:
    """Provider handed to the runtime proxy; exposes the rejection signal."""

    def __init__(self, provider: CloudServicesProvider, probe: _RejectionProbe) -> None:
        self._provider = provider
        self._probe = probe

    def __repr__(self) -> str:
        return "TenantSession(<redacted>)"

    @property
    def session_rejected(self) -> bool:
        return self._probe.rejected is True

    def get(self) -> Any:
        return self._provider.get()


def _build_services_factory(settings: dict[str, Any]) -> Callable[[str, float], Any]:
    env, config = settings["env"], settings["config"]

    def services_factory(tenant_id: str, deadline: float) -> _TenantSession:
        name = session_parameter_name(env, tenant_id)
        if time.monotonic() >= deadline:
            raise RuntimeError("deadline_expired")
        try:
            response = _client("ssm").get_parameter(Name=name, WithDecryption=True)
        except Exception as exc:
            if _error_code(exc) == "ParameterNotFound":
                raise TenantSessionMissing() from None
            raise RuntimeError("session_read_failed") from None
        parameter = response.get("Parameter") if isinstance(response, Mapping) else None
        if not isinstance(parameter, Mapping):
            raise RuntimeError("session_invalid")
        value, version = parameter.get("Value"), parameter.get("Version")
        if (
            parameter.get("Name") != name
            or parameter.get("Type") != "SecureString"
            or type(value) is not str
            or not value
            or len(value.encode("utf-8", errors="replace")) > _MAX_SESSION_BYTES
        ):
            raise RuntimeError("session_invalid")
        version = version if type(version) is int and version > 0 else 1
        probe = _RejectionProbe()
        transport = CloudDirectTransport(config, deadline=deadline, opener=probe)
        provider = CloudServicesProvider(
            config, _FixedTokenReader(value, version), transport.cognito_json,
            transport.mapit_request, deadline=deadline,
        )
        return _TenantSession(provider, probe)

    return services_factory


def _find_email(table: str, tenant_id: str) -> str | None:
    """Return the invitation email for a tenant, None if absent.

    Design choice: the access token carries only the opaque tenant id and the
    Cognito username, while the invitations table is keyed by email. With at
    most ten users per environment a strongly consistent, bounded Scan with a
    tenant filter is cheap and avoids adding the email to tokens or a GSI.
    Requires ``dynamodb:Scan`` on the invitations table. Writes are then
    conditioned on the same tenant id, so a concurrent change cannot redirect them.
    """
    client = _client("dynamodb")
    found: list[str] = []
    start_key = None
    for _ in range(_MAX_SCAN_PAGES):
        kwargs: dict[str, Any] = {
            "TableName": table,
            "ConsistentRead": True,
            "ProjectionExpression": "#e, #t",
            "FilterExpression": "#t = :t",
            "ExpressionAttributeNames": {"#e": "email", "#t": "tenant_id"},
            "ExpressionAttributeValues": {":t": {"S": tenant_id}},
        }
        if start_key is not None:
            kwargs["ExclusiveStartKey"] = start_key
        response = client.scan(**kwargs)
        for item in response.get("Items", []):
            email = item.get("email", {}).get("S")
            if type(email) is str and item.get("tenant_id", {}).get("S") == tenant_id:
                found.append(email)
        start_key = response.get("LastEvaluatedKey")
        if not start_key:
            break
    else:
        raise RuntimeError("scan_incomplete")
    if len(found) > 1:
        raise RuntimeError("tenant_ambiguous")
    return found[0] if found else None


def _attempt(step: Callable[[], Any], ok_codes: frozenset[str] = frozenset()) -> bool:
    try:
        step()
        return True
    except Exception as exc:
        return _error_code(exc) in ok_codes


def _build_account_actions(settings: dict[str, Any]) -> tuple[Callable[[str, str], bool], Callable[[str, str], bool]]:
    env, table, pool = settings["env"], settings["table"], settings["pool"]

    def delete_parameter(tenant_id: str) -> bool:
        return _attempt(
            lambda: _client("ssm").delete_parameter(Name=session_parameter_name(env, tenant_id)),
            frozenset({"ParameterNotFound"}),
        )

    def delete_user(username: str) -> bool:
        return _attempt(
            lambda: _client("cognito-idp").admin_delete_user(UserPoolId=pool, Username=username),
            frozenset({"UserNotFoundException"}),
        )

    def lookup(tenant_id: str) -> tuple[bool, str | None]:
        try:
            return True, _find_email(table, tenant_id)
        except Exception:
            return False, None

    def relink(tenant_id: str, username: str) -> bool:
        validate_tenant_id(tenant_id)
        ok = delete_parameter(tenant_id)
        ok = delete_user(username) and ok
        found, email = lookup(tenant_id)
        if not found:
            return False
        if email is not None:
            now = str(int(time.time()))
            ok = _attempt(lambda: _client("dynamodb").update_item(
                TableName=table,
                Key={"email": {"S": email}},
                UpdateExpression="SET #s = :s, updated_at = :u",
                ConditionExpression="#t = :t",
                ExpressionAttributeNames={"#s": "status", "#t": "tenant_id"},
                ExpressionAttributeValues={":s": {"S": STATUS_ACCEPTED}, ":u": {"N": now}, ":t": {"S": tenant_id}},
            )) and ok
        return ok

    def delete_account(tenant_id: str, username: str) -> bool:
        validate_tenant_id(tenant_id)
        ok = delete_parameter(tenant_id)
        found, email = lookup(tenant_id)
        if not found:
            ok = False
        elif email is not None:
            ok = _attempt(lambda: _client("dynamodb").delete_item(
                TableName=table,
                Key={"email": {"S": email}},
                ConditionExpression="#t = :t",
                ExpressionAttributeNames={"#t": "tenant_id"},
                ExpressionAttributeValues={":t": {"S": tenant_id}},
            ), frozenset({"ConditionalCheckFailedException"})) and ok
        ok = delete_user(username) and ok
        return ok

    return relink, delete_account


def _load_runtime(settings: dict[str, Any]) -> MultiuserRuntime:
    policy = settings["policy"]
    relink, delete_account = _build_account_actions(settings)
    return create_multiuser_runtime(
        policy,
        JwksCache(policy.issuer_url, fetcher=_jwks_fetcher),
        services_factory=_build_services_factory(settings),
        relink=relink,
        delete_account=delete_account,
        geographic_queries=settings["geography"],
    )


def handler(event: Any, context: Any) -> dict[str, Any]:
    """Lambda handler; every setup/runtime failure has one opaque 503 response."""
    global _CACHED_RUNTIME, _CACHED_SIGNATURE
    try:
        environ = os.environ
        signature = tuple(environ.get(name) for name in ENV_NAMES)
        if _CACHED_RUNTIME is None or _CACHED_SIGNATURE != signature:
            runtime = _load_runtime(_settings(environ))
            _CACHED_RUNTIME, _CACHED_SIGNATURE = runtime, signature
        return _CACHED_RUNTIME.lambda_handler(event, context)
    except Exception:
        return _unavailable()


__all__ = ["ENV_NAMES", "handler"]
