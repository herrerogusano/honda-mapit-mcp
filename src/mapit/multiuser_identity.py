"""Identity Lambda for the invitation-only multiuser stack.

One handler serves two event families (see docs/multiuser-production.md):

* Cognito triggers: ``UserMigration_Authentication`` validates the user's
  MAPIT email/password once against MAPIT's Cognito, stores only the MAPIT
  refresh token in SSM and returns the migrated user; ``TokenGeneration_*``
  (Pre Token Generation V2_0) adds the opaque tenant claim to access tokens.
* API Gateway HTTP API v2: ``GET /privacidad``, ``GET/POST /invitacion``.

Nothing is logged and no SDK client or network work happens at import time.
The event (which carries the password) is never logged, printed or embedded in
exception text; every failure maps to a fixed Spanish message.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import math
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl

from . import multiuser_pages as pages
from .cloud_transport import validate_cloud_config
from .config import MapitConfig
from .http_transport import direct_opener, open_direct
try:  # Imported during the Lambda init phase, not inside the handler.
    import boto3 as _boto3
    from botocore.config import Config as _BotoConfig
except ImportError:  # pragma: no cover - optional outside the pinned SDK environment
    _boto3 = None
    _BotoConfig = None

from .multiuser_common import (
    CONSENT_VERSION,
    LOCK_SECONDS,
    MAX_FAILED_LOGINS,
    REGION,
    STATUS_ACCEPTED,
    STATUS_ACTIVE,
    STATUS_INVITED,
    TENANT_ATTRIBUTE,
    TENANT_CLAIM,
    MultiuserError,
    normalize_email,
    session_parameter_name,
    table_name,
    validate_environment,
    validate_tenant_id,
)

# --- user-facing messages (Cognito shows the exception message) -------------

# One message for "not invited" and "wrong MAPIT password" so the sign-in page
# does not reveal which emails are invited.
MSG_BAD_CREDENTIALS = "Email o contraseña de MAPIT incorrectos, o esta cuenta no tiene invitación."
MSG_LOCKED = "Demasiados intentos. Vuelve a probar en 15 minutos."
MSG_GENERIC = "No se ha podido verificar tu cuenta de MAPIT. Inténtalo de nuevo."
MSG_FORGOT_PASSWORD = (
    "Entra con tu contraseña actual de MAPIT. Si la has cambiado, pide al "
    "administrador que reactive tu acceso."
)
_USER_MESSAGES = frozenset({
    MSG_BAD_CREDENTIALS, MSG_LOCKED, MSG_GENERIC, MSG_FORGOT_PASSWORD,
})

# --- limits ------------------------------------------------------------------

# Cognito gives the migration trigger a hard 5 s. Every SDK call is bounded by
# SDK_CONNECT_TIMEOUT + SDK_READ_TIMEOUT (one attempt) and is only started when
# at least SDK_CALL_RESERVE_SECONDS remain before the hard deadline, so the
# worst case stays below 5 s. The MAPIT call must end SDK_CALL_RESERVE_SECONDS
# before the hard deadline (room for at least the item update). Normally both
# post-login calls take milliseconds; if the session put then lacks its
# reserve, sign-in fails generically and a retry is idempotent.
MIGRATION_HARD_LIMIT_SECONDS = 4.6
CONTEXT_SAFETY_SECONDS = 0.3
SDK_CONNECT_TIMEOUT = 0.5
SDK_READ_TIMEOUT = 1.0
SDK_CALL_RESERVE_SECONDS = 1.6
# +0.1 s so a MAPIT call that uses its whole budget still leaves the item
# update its full 1.6 s reserve (float rounding and local work).
POST_LOGIN_RESERVE_SECONDS = SDK_CALL_RESERVE_SECONDS + 0.1
MAX_USERNAME_CHARS = 254
MAPIT_HTTP_TIMEOUT_SECONDS = 2.0
MAX_MAPIT_AUTH_RESPONSE_BYTES = 64 * 1024
MAX_FORM_BYTES = 4 * 1024
MAX_QUERY_CHARS = 2 * 1024
MAX_PASSWORD_CHARS = 256
_READ_CHUNK = 16 * 1024

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{16,128}$")
_REFRESH_RE = re.compile(r"^[\x21-\x7e]{1,8192}$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9]{1,128}$")
_RESOURCE_URL_RE = re.compile(r"^https://[a-z0-9]{10}\.execute-api\.eu-west-1\.amazonaws\.com/mcp$")
_CONFIG_FIELDS = frozenset({
    "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
    "core_api_url", "geo_api_url", "discovery_enabled", "http_timeout",
})
_TOKEN_GENERATION_SOURCES = frozenset({
    "TokenGeneration_HostedAuth", "TokenGeneration_Authentication",
    "TokenGeneration_NewPasswordChallenge", "TokenGeneration_AuthenticateDevice",
    "TokenGeneration_RefreshTokens",
})


class IdentityError(Exception):
    """User-safe failure. The message is one of the fixed MSG_* constants."""


class MapitCredentialsRejected(Exception):
    """MAPIT's Cognito rejected the email/password (NotAuthorized/UserNotFound)."""


class MapitLoginFailed(Exception):
    """Any other MAPIT login failure (transport, timeout, challenge, malformed)."""


class _ConfigInvalid(Exception):
    pass


# --- injectable seams (tests replace these) -------------------------------

_monotonic: Callable[[], float] = time.monotonic
_wall_clock: Callable[[], float] = time.time
_opener_factory: Callable[[], Any] = direct_opener
_CLIENTS: dict[str, Any] = {}


def sdk_config() -> Any:
    """One attempt, 0.5 s connect, 1 s read, no proxies."""
    if _BotoConfig is None:
        raise _ConfigInvalid()
    return _BotoConfig(
        retries={"mode": "standard", "total_max_attempts": 1},
        connect_timeout=SDK_CONNECT_TIMEOUT,
        read_timeout=SDK_READ_TIMEOUT,
        proxies={},
    )


def _make_aws_client(service: str) -> Any:
    """Build a boto3 client from the Lambda's own short-lived credentials only."""
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    session_token = os.environ.get("AWS_SESSION_TOKEN")
    if any(type(value) is not str or not value for value in (access_key, secret_key, session_token)):
        raise _ConfigInvalid()
    if _boto3 is None:
        raise _ConfigInvalid()
    return _boto3.client(
        service, region_name=REGION, config=sdk_config(),
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
    )


def _make_dynamodb_client() -> Any:
    return _make_aws_client("dynamodb")


def _make_ssm_client() -> Any:
    return _make_aws_client("ssm")


_dynamodb_client_factory: Callable[[], Any] = _make_dynamodb_client
_ssm_client_factory: Callable[[], Any] = _make_ssm_client


def _dynamodb() -> Any:
    if "dynamodb" not in _CLIENTS:
        _CLIENTS["dynamodb"] = _dynamodb_client_factory()
    return _CLIENTS["dynamodb"]


def _ssm() -> Any:
    if "ssm" not in _CLIENTS:
        _CLIENTS["ssm"] = _ssm_client_factory()
    return _CLIENTS["ssm"]


def reset_clients() -> None:
    _CLIENTS.clear()
    _PUBLIC_CONFIG_CACHE.clear()


# --- configuration ------------------------------------------------------------

def _environment_name(environ: Mapping[str, str]) -> str:
    try:
        env = validate_environment(environ.get("MAPIT_MCP_ENV", ""))
    except MultiuserError:
        raise _ConfigInvalid() from None
    if environ.get("AWS_REGION") != REGION or environ.get("MULTIUSER_TABLE") != table_name(env):
        raise _ConfigInvalid()
    return env


def _reject_constant(_value: str) -> None:
    raise _ConfigInvalid()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _ConfigInvalid()
        result[key] = value
    return result


def _mapit_config(environ: Mapping[str, str]) -> MapitConfig:
    raw = environ.get("MAPIT_CONFIG_JSON")
    if type(raw) is not str or not raw or len(raw) > 4096:
        raise _ConfigInvalid()
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        if type(data) is not dict or set(data) != _CONFIG_FIELDS:
            raise _ConfigInvalid()
        timeout = data["http_timeout"]
        if type(timeout) not in (int, float) or not math.isfinite(timeout):
            raise _ConfigInvalid()
        config = MapitConfig(**data)
        validate_cloud_config(config)  # pinned region/hosts, discovery off, timeout <= 2 s
    except _ConfigInvalid:
        raise
    except Exception:
        raise _ConfigInvalid() from None
    return config


def public_config_parameter_name(env: str) -> str:
    return f"/honda-mapit-mcp/{validate_environment(env)}/multiuser/public-config"


def _page_settings(environ: Mapping[str, str], env: str) -> dict[str, Any]:
    """Validate the page env vars (no I/O). Client ids come from SSM later."""
    resource_url = environ.get("MULTIUSER_RESOURCE_URL")
    port_raw = environ.get("MULTIUSER_CODEX_CALLBACK_PORT")
    parameter = environ.get("MULTIUSER_PUBLIC_CONFIG_PARAMETER")
    if (
        type(resource_url) is not str or not _RESOURCE_URL_RE.fullmatch(resource_url)
        or type(port_raw) is not str or not re.fullmatch(r"[1-9][0-9]{3,4}", port_raw)
        or not 1024 <= int(port_raw) <= 65535
        or parameter != public_config_parameter_name(env)
    ):
        raise _ConfigInvalid()
    return {"resource_url": resource_url, "codex_callback_port": int(port_raw), "parameter": parameter}


_PUBLIC_CONFIG_CACHE: dict[str, dict[str, Any]] = {}
_PUBLIC_CONFIG_FIELDS = frozenset({"resource_url", "claude_client_id", "codex_client_id", "codex_callback_port"})
MAX_PUBLIC_CONFIG_CHARS = 4096


def _public_config(settings: Mapping[str, Any]) -> dict[str, Any]:
    """Read and strictly parse the public client config once per warm container."""
    name = settings["parameter"]
    cached = _PUBLIC_CONFIG_CACHE.get(name)
    if cached is None:
        try:
            response = _ssm().get_parameter(Name=name, WithDecryption=False)
            parameter = response.get("Parameter") if isinstance(response, Mapping) else None
            raw = parameter.get("Value") if isinstance(parameter, Mapping) else None
            if type(raw) is not str or not raw or len(raw) > MAX_PUBLIC_CONFIG_CHARS:
                raise _ConfigInvalid()
            data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except _ConfigInvalid:
            raise
        except Exception:
            raise _ConfigInvalid() from None
        if (
            type(data) is not dict or set(data) != _PUBLIC_CONFIG_FIELDS
            or type(data["resource_url"]) is not str
            or type(data["claude_client_id"]) is not str
            or not _CLIENT_ID_RE.fullmatch(data["claude_client_id"])
            or type(data["codex_client_id"]) is not str
            or not _CLIENT_ID_RE.fullmatch(data["codex_client_id"])
            or type(data["codex_callback_port"]) is not int
            or not 1024 <= data["codex_callback_port"] <= 65535
        ):
            raise _ConfigInvalid()
        cached = data
        _PUBLIC_CONFIG_CACHE[name] = cached
    # Must agree with the template-provided env vars; otherwise fail closed.
    if (
        cached["resource_url"] != settings["resource_url"]
        or cached["codex_callback_port"] != settings["codex_callback_port"]
    ):
        raise _ConfigInvalid()
    return dict(cached)


def _privacy_contact(environ: Mapping[str, str]) -> str:
    try:
        return normalize_email(environ.get("MULTIUSER_PRIVACY_CONTACT"))
    except MultiuserError:
        raise _ConfigInvalid() from None


# --- DynamoDB item helpers -----------------------------------------------------

def _now() -> int:
    value = _wall_clock()
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise _ConfigInvalid()
    return int(value)


def _s(item: Mapping[str, Any], name: str) -> str | None:
    value = item.get(name)
    if isinstance(value, Mapping) and type(value.get("S")) is str:
        return value["S"]
    return None


def _n(item: Mapping[str, Any], name: str) -> int | None:
    value = item.get(name)
    if isinstance(value, Mapping) and type(value.get("N")) is str and re.fullmatch(r"-?[0-9]{1,20}", value["N"]):
        return int(value["N"])
    return None


def _get_item(env: str, email: str) -> dict[str, Any] | None:
    response = _dynamodb().get_item(
        TableName=table_name(env),
        Key={"email": {"S": email}},
        ConsistentRead=True,
    )
    item = response.get("Item") if isinstance(response, Mapping) else None
    if item is None:
        return None
    if not isinstance(item, Mapping) or _s(item, "email") != email:
        raise _ConfigInvalid()
    return dict(item)


# --- MAPIT USER_PASSWORD_AUTH (single bounded call) ---------------------------

def _read_limited(stream: Any, deadline: float) -> bytes:
    reader = getattr(stream, "read1", None)
    if not callable(reader):
        reader = getattr(stream, "read", None)
    if not callable(reader):
        raise MapitLoginFailed()
    chunks: list[bytes] = []
    total = 0
    while True:
        if _monotonic() >= deadline:
            raise MapitLoginFailed()
        chunk = reader(min(_READ_CHUNK, MAX_MAPIT_AUTH_RESPONSE_BYTES + 1 - total))
        if type(chunk) is not bytes:
            raise MapitLoginFailed()
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > MAX_MAPIT_AUTH_RESPONSE_BYTES:
            raise MapitLoginFailed()
        chunks.append(chunk)


def _parse_json_object(raw: bytes) -> Mapping[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise MapitLoginFailed() from None
    if not isinstance(parsed, Mapping):
        raise MapitLoginFailed()
    return parsed


def _default_mapit_login(config: MapitConfig, email: str, password: str, deadline: float) -> str:
    """One InitiateAuth USER_PASSWORD_AUTH POST to the pinned MAPIT pool.

    Mirrors ``CognitoAuthenticator.authenticate``'s request but stops after the
    user-pool step: only the refresh token is needed here. Direct-only (no
    proxies, no redirects), at most 2 s per socket operation, 64 KiB response.
    Returns the refresh token; raises MapitCredentialsRejected or MapitLoginFailed.
    """
    url = f"https://cognito-idp.{config.region}.amazonaws.com/"
    body = json.dumps({
        "AuthFlow": "USER_PASSWORD_AUTH",
        "ClientId": config.user_pool_client_id,
        "AuthParameters": {"USERNAME": email, "PASSWORD": password},
        "ClientMetadata": {},
    }).encode("utf-8")
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
    }
    remaining = deadline - _monotonic()
    if remaining <= 0.05:
        raise MapitLoginFailed()
    timeout = min(MAPIT_HTTP_TIMEOUT_SECONDS, float(config.http_timeout), remaining)
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    response = None
    try:
        response = open_direct(request, timeout=timeout, opener=_opener_factory())
        status = getattr(response, "status", None)
        if status != 200:
            raise MapitLoginFailed()
        result = _parse_json_object(_read_limited(response, deadline))
    except urllib.error.HTTPError as exc:
        try:
            if exc.code != 400 or exc.fp is None:
                raise MapitLoginFailed() from None
            error = _parse_json_object(_read_limited(exc, deadline))
        except MapitLoginFailed:
            raise MapitLoginFailed() from None
        except Exception:
            raise MapitLoginFailed() from None
        finally:
            try:
                exc.close()
            except Exception:
                pass
        kind = error.get("__type")
        kind = kind.rsplit("#", 1)[-1] if type(kind) is str else ""
        if kind in {"NotAuthorizedException", "UserNotFoundException"}:
            raise MapitCredentialsRejected() from None
        raise MapitLoginFailed() from None
    except (MapitLoginFailed, MapitCredentialsRejected):
        raise
    except Exception:
        raise MapitLoginFailed() from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
    if _monotonic() >= deadline or result.get("ChallengeName"):
        raise MapitLoginFailed()
    auth = result.get("AuthenticationResult")
    refresh = auth.get("RefreshToken") if isinstance(auth, Mapping) else None
    if type(refresh) is not str or not _REFRESH_RE.fullmatch(refresh):
        raise MapitLoginFailed()
    return refresh


_mapit_login: Callable[[MapitConfig, str, str, float], str] = _default_mapit_login


# --- Cognito triggers --------------------------------------------------------------

def _budget_deadline(started: float, context: Any) -> float:
    deadline = started + MIGRATION_HARD_LIMIT_SECONDS
    getter = getattr(context, "get_remaining_time_in_millis", None)
    if callable(getter):
        try:
            remaining_ms = getter()
        except Exception:
            raise _ConfigInvalid() from None
        if type(remaining_ms) not in (int, float) or not math.isfinite(remaining_ms):
            raise _ConfigInvalid()
        deadline = min(deadline, started + remaining_ms / 1000.0 - CONTEXT_SAFETY_SECONDS)
    return deadline


def _require_time(deadline: float) -> None:
    if _monotonic() >= deadline:
        raise IdentityError(MSG_GENERIC)


def _has_sdk_time(deadline: float) -> bool:
    return deadline - _monotonic() >= SDK_CALL_RESERVE_SECONDS


def _require_sdk_time(deadline: float) -> None:
    """Start an SDK call only if its worst case fits before the hard deadline."""
    if not _has_sdk_time(deadline):
        raise IdentityError(MSG_GENERIC)


def _record_failed_login(env: str, email: str, tenant_id: str, now: int, deadline: float) -> bool:
    """Atomically count one MAPIT rejection; returns True when the account locks."""
    _require_sdk_time(deadline)
    response = _dynamodb().update_item(
        TableName=table_name(env),
        Key={"email": {"S": email}},
        UpdateExpression="ADD failed_logins :one SET updated_at = :now",
        ConditionExpression="attribute_exists(email) AND tenant_id = :tid",
        ExpressionAttributeValues={
            ":one": {"N": "1"}, ":now": {"N": str(now)}, ":tid": {"S": tenant_id},
        },
        ReturnValues="UPDATED_NEW",
    )
    attributes = response.get("Attributes") if isinstance(response, Mapping) else None
    count = _n(attributes, "failed_logins") if isinstance(attributes, Mapping) else None
    if count is None or count < MAX_FAILED_LOGINS:
        return False
    if not _has_sdk_time(deadline):
        # Count stays >= MAX_FAILED_LOGINS; the next rejection locks.
        return False
    # Lock and restart the count so the next window allows MAX_FAILED_LOGINS
    # fresh attempts. The condition makes concurrent lockers idempotent.
    try:
        _dynamodb().update_item(
            TableName=table_name(env),
            Key={"email": {"S": email}},
            UpdateExpression="SET locked_until = :until, failed_logins = :zero, updated_at = :now",
            ConditionExpression="attribute_exists(email) AND failed_logins = :count",
            ExpressionAttributeValues={
                ":until": {"N": str(now + LOCK_SECONDS)}, ":zero": {"N": "0"},
                ":now": {"N": str(now)}, ":count": {"N": str(count)},
            },
        )
    except Exception:
        pass
    return True


def _user_migration(event: dict[str, Any], context: Any, started: float, environ: Mapping[str, str]) -> dict[str, Any]:
    try:
        env = _environment_name(environ)
        config = _mapit_config(environ)
        deadline = _budget_deadline(started, context)
        request = event.get("request")
        password = request.get("password") if isinstance(request, Mapping) else None
        if type(password) is not str or not 0 < len(password) <= MAX_PASSWORD_CHARS:
            raise IdentityError(MSG_GENERIC)
        typed = event.get("userName")
        if type(typed) is not str or len(typed) > MAX_USERNAME_CHARS:
            raise IdentityError(MSG_BAD_CREDENTIALS)
        # MAPIT receives the email as typed (trimmed only); our table key is
        # the normalized form.
        mapit_username = typed.strip()
        try:
            email = normalize_email(typed)
        except MultiuserError:
            raise IdentityError(MSG_BAD_CREDENTIALS) from None
        _require_sdk_time(deadline)
        item = _get_item(env, email)
        if item is None:
            raise IdentityError(MSG_BAD_CREDENTIALS)
        status = _s(item, "status")
        tenant_raw = _s(item, "tenant_id")
        try:
            tenant_id = validate_tenant_id(tenant_raw)
        except MultiuserError:
            raise IdentityError(MSG_GENERIC) from None
        if status not in {STATUS_ACCEPTED, STATUS_ACTIVE}:
            raise IdentityError(MSG_BAD_CREDENTIALS)
        now = _now()
        locked_until = _n(item, "locked_until")
        if locked_until is not None and locked_until > now:
            raise IdentityError(MSG_LOCKED)

        try:
            refresh_token = _mapit_login(config, mapit_username, password, deadline - POST_LOGIN_RESERVE_SECONDS)
        except MapitCredentialsRejected:
            locked = _record_failed_login(env, email, tenant_id, _now(), deadline)
            raise IdentityError(MSG_LOCKED if locked else MSG_BAD_CREDENTIALS) from None
        except Exception:
            raise IdentityError(MSG_GENERIC) from None
        if type(refresh_token) is not str or not _REFRESH_RE.fullmatch(refresh_token):
            raise IdentityError(MSG_GENERIC)

        # 1) Conditional item update first: a revoke/relink/lock racing this
        #    sign-in makes it fail before any session is stored.
        _require_sdk_time(deadline)
        now = _now()
        _dynamodb().update_item(
            TableName=table_name(env),
            Key={"email": {"S": email}},
            UpdateExpression=(
                "SET #status = :active, failed_logins = :zero, last_login_at = :now, "
                "updated_at = :now REMOVE locked_until"
            ),
            ConditionExpression=(
                "attribute_exists(email) AND tenant_id = :tid AND #status IN (:accepted, :active) "
                "AND (attribute_not_exists(locked_until) OR locked_until <= :now)"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":active": {"S": STATUS_ACTIVE}, ":accepted": {"S": STATUS_ACCEPTED},
                ":zero": {"N": "0"}, ":now": {"N": str(now)}, ":tid": {"S": tenant_id},
            },
        )
        # 2) Then the session. If this fails the item is active without a
        #    parameter (the MCP reports "no vinculada"); a retry overwrites.
        _require_sdk_time(deadline)
        _ssm().put_parameter(
            Name=session_parameter_name(env, tenant_id),
            Value=refresh_token,
            Type="SecureString",
            Overwrite=True,
            Tier="Standard",
        )
        del refresh_token
        _require_time(deadline)
    except IdentityError:
        raise
    except Exception:
        raise IdentityError(MSG_GENERIC) from None
    # Return the original event shape with only the documented response fields.
    event["response"] = {
        "userAttributes": {
            "email": email,
            "email_verified": "true",
            TENANT_ATTRIBUTE: tenant_id,
        },
        "finalUserStatus": "CONFIRMED",
        "messageAction": "SUPPRESS",
    }
    return event


def _token_generation(event: dict[str, Any]) -> dict[str, Any]:
    """Pre Token Generation V2_0: add the tenant claim to the access token.

    Response shape per
    https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html
    (versions two and three): response.claimsAndScopeOverrideDetails.
    accessTokenGeneration.claimsToAddOrOverride. groupOverrideDetails is
    omitted deliberately (this pool uses no groups).
    """
    request = event.get("request")
    attributes = request.get("userAttributes") if isinstance(request, Mapping) else None
    tenant = attributes.get(TENANT_ATTRIBUTE) if isinstance(attributes, Mapping) else None
    try:
        tenant_id = validate_tenant_id(tenant)
    except MultiuserError:
        raise IdentityError(MSG_GENERIC) from None
    event["response"] = {
        "claimsAndScopeOverrideDetails": {
            "accessTokenGeneration": {
                "claimsToAddOrOverride": {TENANT_CLAIM: tenant_id},
            },
        },
    }
    return event


def _cognito_trigger(event: dict[str, Any], context: Any, started: float) -> dict[str, Any]:
    source = event.get("triggerSource")
    if source == "UserMigration_Authentication":
        return _user_migration(event, context, started, os.environ)
    if source == "UserMigration_ForgotPassword":
        raise IdentityError(MSG_FORGOT_PASSWORD)
    if type(source) is str and source in _TOKEN_GENERATION_SOURCES:
        return _token_generation(event)
    raise IdentityError(MSG_GENERIC)


# --- HTTP API v2 ---------------------------------------------------------------

def _html(status: int, body: str) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
            "content-security-policy": CSP,
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "x-frame-options": "DENY",
        },
        "body": body,
        "isBase64Encoded": False,
    }


class _BadRequest(Exception):
    pass


def _single_fields(pairs: list[tuple[str, str]], allowed: frozenset[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in result:
            raise _BadRequest()
        result[key] = value
    return result


def _invitation_fields(fields: Mapping[str, str]) -> tuple[str, str]:
    token = fields.get("token")
    if type(token) is not str or not _TOKEN_RE.fullmatch(token):
        raise _BadRequest()
    try:
        email = normalize_email(fields.get("email"))
    except MultiuserError:
        raise _BadRequest() from None
    return email, token


def _get_invitation(event: Mapping[str, Any]) -> dict[str, Any]:
    raw = event.get("rawQueryString") or ""
    if type(raw) is not str or len(raw) > MAX_QUERY_CHARS:
        return _html(400, pages.render_invitation_error())
    try:
        pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=bool(raw), max_num_fields=4)
        email, token = _invitation_fields(_single_fields(pairs, frozenset({"email", "token"})))
    except (_BadRequest, ValueError):
        return _html(400, pages.render_invitation_error())
    # Format checks only: nothing here depends on whether the invitation exists.
    return _html(200, pages.render_consent_form(email, token))


def _form_body(event: Mapping[str, Any]) -> dict[str, str]:
    headers = event.get("headers") or {}
    if not isinstance(headers, Mapping):
        raise _BadRequest()
    content_type = None
    for key, value in headers.items():
        if type(key) is str and key.lower() == "content-type":
            content_type = value
    if type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/x-www-form-urlencoded":
        raise _BadRequest()
    body = event.get("body") or ""
    if type(body) is not str or len(body) > 2 * MAX_FORM_BYTES:
        raise _BadRequest()
    if event.get("isBase64Encoded") is True:
        try:
            raw = base64.b64decode(body, validate=True)
        except (binascii.Error, ValueError):
            raise _BadRequest() from None
    else:
        raw = body.encode("utf-8")
    if len(raw) > MAX_FORM_BYTES:
        raise _BadRequest()
    try:
        text = raw.decode("ascii")
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True, max_num_fields=8)
    except (UnicodeError, ValueError):
        raise _BadRequest() from None
    return _single_fields(pairs, frozenset({"email", "token", "consent"}))


def _post_invitation(event: Mapping[str, Any], environ: Mapping[str, str]) -> dict[str, Any]:
    try:
        env = _environment_name(environ)
        settings = _page_settings(environ, env)
    except _ConfigInvalid:
        return _html(503, pages.render_unavailable())
    try:
        fields = _form_body(event)
        if fields.get("consent") != "on":
            raise _BadRequest()
        email, token = _invitation_fields(fields)
        item = _get_item(env, email)
        if item is None:
            raise _BadRequest()
        presented = hashlib.sha256(token.encode("ascii")).hexdigest()
        stored = _s(item, "invite_token_sha256")
        if type(stored) is not str or not re.fullmatch(r"[0-9a-f]{64}", stored):
            raise _BadRequest()
        if not hmac.compare_digest(presented, stored):
            raise _BadRequest()
        now = _now()
        expires = _n(item, "invite_expires_at")
        if expires is None or expires <= now:
            raise _BadRequest()
        current = _s(item, "status")
        if current not in {STATUS_INVITED, STATUS_ACCEPTED, STATUS_ACTIVE}:
            raise _BadRequest()
        # invited -> accepted; accepted and active keep their status (an active
        # user reopening the link only refreshes consent and sees instructions).
        new_status = STATUS_ACCEPTED if current == STATUS_INVITED else current
        _dynamodb().update_item(
            TableName=table_name(env),
            Key={"email": {"S": email}},
            UpdateExpression=(
                "SET #status = :new, consent_at = :now, consent_version = :version, "
                "updated_at = :now"
            ),
            ConditionExpression=(
                "invite_token_sha256 = :hash AND invite_expires_at > :now "
                "AND #status = :current"
            ),
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues={
                ":new": {"S": new_status}, ":current": {"S": current},
                ":now": {"N": str(now)}, ":version": {"S": CONSENT_VERSION},
                ":hash": {"S": stored},
            },
        )
    except Exception:
        return _html(400, pages.render_invitation_error())
    try:
        public = _public_config(settings)
    except Exception:
        return _html(503, pages.render_unavailable())
    return _html(200, pages.render_success(
        public["resource_url"], public["claude_client_id"],
        public["codex_client_id"], public["codex_callback_port"],
    ))


def _http_request(event: Mapping[str, Any]) -> dict[str, Any]:
    context = event.get("requestContext")
    http = context.get("http") if isinstance(context, Mapping) else None
    method = http.get("method") if isinstance(http, Mapping) else None
    path = event.get("rawPath")
    environ = os.environ
    if path == "/privacidad" and method == "GET":
        try:
            _environment_name(environ)
            contact = _privacy_contact(environ)
        except _ConfigInvalid:
            return _html(503, pages.render_unavailable())
        return _html(200, pages.render_privacy(contact))
    if path == "/invitacion" and method in {"GET", "POST"}:
        try:
            _page_settings(environ, _environment_name(environ))
        except _ConfigInvalid:
            return _html(503, pages.render_unavailable())
        if method == "GET":
            return _get_invitation(event)
        return _post_invitation(event, environ)
    return _html(404, pages.render_not_found())


# --- entry point -------------------------------------------------------------------

def handler(event: Any, context: Any) -> dict[str, Any]:
    started = _monotonic()
    if isinstance(event, dict) and "triggerSource" in event:
        message = MSG_GENERIC
        try:
            return _cognito_trigger(event, context, started)
        except IdentityError as exc:
            if exc.args and exc.args[0] in _USER_MESSAGES:
                message = exc.args[0]
        except Exception:
            pass
        # Raised outside the except blocks so the error carries no chained
        # __context__ that could hold request-derived details.
        raise IdentityError(message)
    if isinstance(event, dict) and ("requestContext" in event or "rawPath" in event):
        try:
            return _http_request(event)
        except Exception:
            return _html(503, pages.render_unavailable())
    raise IdentityError(MSG_GENERIC)


__all__ = [
    "CSP", "IdentityError", "MapitCredentialsRejected", "MapitLoginFailed",
    "MSG_BAD_CREDENTIALS", "MSG_LOCKED", "MSG_GENERIC", "sdk_config",
    "MSG_FORGOT_PASSWORD", "handler", "public_config_parameter_name", "reset_clients",
]
