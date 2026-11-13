"""Pass endpoint of the public web mode (function ``web_function_name(env, "pass")``).

Served by the web stack's HTTP API (payload format 2.0) on ``POST /pase``. The
web sends ``{"email": ..., "turnstile": ...}``; this function validates the
Cloudflare Turnstile result and records a short-lived pre-login pass bound to
the keyed email fingerprint. The identity function requires that pass before
it calls MAPIT. Steps, each failing closed with its own fixed code:

1. configuration (environment variables) and the request (exact JSON body);
2. source IP from ``requestContext.http.sourceIp``;
3. configuration row: closed or paused answers like ``/estado`` would, with no
   Cloudflare call;
4. Turnstile ``siteverify`` through an injected transport, with the secret from
   an SSM SecureString (cached in memory), checking ``success``, ``hostname``
   and ``action``; no answer, an odd answer or a missing secret means no pass;
5. used results: conditional ``PutItem`` so a result gives at most one pass;
6. per-IP limit: atomic ``UpdateItem`` capped at ``IP_PASSES_PER_WINDOW``;
7. the pass row: ``attempts_left``, ``issued_at``, ``expires_at``. A new pass
   replaces the old one, which resets the attempts.

The answer never depends on whether an email has used the web. Logs carry one
JSON line per request with the outcome code, the exception class and the AWS
error code only: never the email, IP, result, secret, key or a fingerprint.
CORS is not set here: the HTTP API's CORS configuration adds it.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from . import public_web as web
from .http_transport import direct_opener, open_direct, read_bounded
from .multiuser_common import REGION, MultiuserError, normalize_email, validate_environment

try:  # Imported during the Lambda init phase, not inside the handler.
    import boto3 as _boto3
    from botocore.config import Config as _BotoConfig
except ImportError:  # pragma: no cover - optional outside the pinned SDK environment
    _boto3 = None
    _BotoConfig = None

# --- Contract ---------------------------------------------------------------

PASS_PATH = "/pase"
ENV_VARIABLE = "MAPIT_MCP_ENV"
TABLE_VARIABLE = "MAPIT_WEB_TABLE"
HOSTNAMES_VARIABLE = "MAPIT_WEB_TURNSTILE_HOSTNAMES"   # comma-separated
SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
TURNSTILE_ACTION = "web-pass"          # the widget must be rendered with this action
SITEVERIFY_TIMEOUT_SECONDS = 2.0
MAX_SITEVERIFY_RESPONSE_BYTES = 16 * 1024
MAX_BODY_BYTES = 4 * 1024
MAX_HOSTNAMES = 10
MAX_SECRET_CHARS = 256
IPV6_LIMIT_PREFIX = 64                 # the per-IP limit counts one IPv6 /64 as one IP
SDK_CONNECT_TIMEOUT = 0.5
SDK_READ_TIMEOUT = 1.0
LOG_FIELD = "web_pass_outcome"

# siteverify error codes (Cloudflare server-side validation documentation).
_CLIENT_ERROR_CODES = frozenset({"missing-input-response", "invalid-input-response",
                                 "timeout-or-duplicate"})
_SECRET_ERROR_CODES = frozenset({"missing-input-secret", "invalid-input-secret"})

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                          r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_RESULT_RE = re.compile(r"^[\x21-\x7e]+$")
_SECRET_RE = re.compile(r"^[\x21-\x7e]+$")
# Cloudflare's published dummy secrets accept or reject every result; never in prod.
_DUMMY_SECRET_RE = re.compile(r"^[0-9]x0+AA$")

# Fixed answers. The 200 body is the same for every email.
_BODIES = {
    "issued": (200, {"pase": "emitido", "caduca_en_segundos": web.PASS_TTL_SECONDS}),
    "bad_request": (400, {"error": "peticion_invalida"}),
    "rejected": (403, {"error": "control_no_valido"}),
    "not_found": (404, {"error": "no_encontrado"}),
    "rate_limited": (429, {"error": "demasiados_pases"}),
    "unavailable": (503, {"error": "no_disponible"}),
    "closed": (503, {"estado": "cerrado"}),
    "paused": (503, {"estado": "pausa"}),
}


def turnstile_secret_parameter_name(env: str) -> str:
    """SecureString with the Turnstile secret; outside the swept sessions prefix."""
    return f"{web.web_parameter_root(env)}turnstile-secret"


class PassError(Exception):
    """A closed outcome: ``code`` is logged, ``answer`` selects the fixed body."""

    def __init__(self, code: str, answer: str, *, cause: BaseException | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.answer = answer
        self.cause_type = type(cause).__name__ if cause is not None else None
        self.provider_code = web._provider_code(cause) if cause is not None else None


def _from_web_error(exc: web.PublicWebError, answer: str) -> PassError:
    error = PassError(exc.code, answer)
    error.cause_type, error.provider_code = exc.cause_type, exc.provider_code
    return error


# --- Settings -----------------------------------------------------------------

@dataclass(frozen=True)
class Settings:
    env: str
    table: str
    hostnames: frozenset[str]


def load_settings(environ: Mapping[str, str]) -> Settings:
    try:
        enabled = web.public_mode_enabled(environ)
    except web.PublicWebError:
        enabled = False
    if not enabled:
        raise PassError("pass_mode_disabled", "unavailable")
    try:
        env = validate_environment(environ.get(ENV_VARIABLE, ""))
    except MultiuserError:
        raise PassError("pass_config_invalid", "unavailable") from None
    if environ.get("AWS_REGION") != REGION or environ.get(TABLE_VARIABLE) != web.web_table_name(env):
        raise PassError("pass_config_invalid", "unavailable")
    raw = environ.get(HOSTNAMES_VARIABLE)
    names = raw.split(",") if type(raw) is str else []
    if not 0 < len(names) <= MAX_HOSTNAMES or any(not _HOSTNAME_RE.fullmatch(n) for n in names):
        raise PassError("pass_hostnames_invalid", "unavailable")
    if env == "prod" and "localhost" in names:
        raise PassError("pass_hostnames_invalid", "unavailable")
    return Settings(env=env, table=web.web_table_name(env), hostnames=frozenset(names))


# --- Request ------------------------------------------------------------------

def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError("constant")


def _bad() -> PassError:
    return PassError("request_invalid", "bad_request")


def parse_body(event: Mapping[str, Any]) -> tuple[str, str]:
    """Return ``(email, result)`` or raise the fixed 400."""
    headers = event.get("headers")
    if not isinstance(headers, Mapping):
        raise _bad()
    types = [v for k, v in headers.items() if type(k) is str and k.lower() == "content-type"]
    if len(types) != 1 or type(types[0]) is not str:
        raise _bad()
    media, _, params = types[0].partition(";")
    if media.strip().lower() != "application/json" or params.strip().lower() not in {"", "charset=utf-8"}:
        raise _bad()
    body = event.get("body")
    if type(body) is not str or event.get("isBase64Encoded") is not False:
        raise _bad()
    if not 0 < len(body) <= MAX_BODY_BYTES:
        raise _bad()
    try:
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            raise ValueError("size")
        data = json.loads(body, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise _bad() from None
    if type(data) is not dict or set(data) != {"email", "turnstile"}:
        raise _bad()
    email, result = data["email"], data["turnstile"]
    if type(email) is not str or type(result) is not str:
        raise _bad()
    if not 0 < len(result) <= web.MAX_RESULT_LENGTH or not _RESULT_RE.fullmatch(result):
        raise _bad()
    try:
        normalize_email(email)
    except MultiuserError:
        raise _bad() from None
    return email, result


def source_ip(event: Mapping[str, Any]) -> tuple[str, str]:
    """Return ``(ip for Cloudflare, ip for the limit)``; the limit uses the IPv6 /64."""
    context = event.get("requestContext")
    http = context.get("http") if isinstance(context, Mapping) else None
    value = http.get("sourceIp") if isinstance(http, Mapping) else None
    if type(value) is not str or not 0 < len(value) <= 45:
        raise PassError("source_ip_missing", "unavailable")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise PassError("source_ip_invalid", "unavailable") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if isinstance(address, ipaddress.IPv6Address):
        network = ipaddress.IPv6Network((address, IPV6_LIMIT_PREFIX), strict=False)
        return address.compressed, network.network_address.compressed
    return address.compressed, address.compressed


# --- Turnstile ------------------------------------------------------------------

Transport = Callable[[str, bytes, float, int], tuple[int, bytes]]
"""``(url, form body, timeout seconds, byte ceiling) -> (HTTP status, body)``."""


def default_transport(url: str, body: bytes, timeout: float, limit: int) -> tuple[int, bytes]:
    """Direct HTTPS POST: no proxies, no redirects, bounded read."""
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        response = open_direct(request, timeout=timeout, opener=direct_opener())
    except urllib.error.HTTPError as exc:
        exc.close()
        return exc.code, b""
    try:
        status = getattr(response, "status", None)
        return (status if type(status) is int else 0), read_bounded(response, limit)
    finally:
        response.close()


class SecretStore:
    """Reads the Turnstile secret from SSM once and caches it in memory."""

    def __init__(self, ssm: Any, env: str) -> None:
        self._ssm = ssm
        self._env = env
        self._name = turnstile_secret_parameter_name(env)
        self._secret: str | None = None
        self._lock = threading.Lock()

    def secret(self) -> str:
        with self._lock:
            if self._secret is None:
                self._secret = self._read()
            return self._secret

    def forget(self) -> None:
        with self._lock:
            self._secret = None

    def _read(self) -> str:
        try:
            response = self._ssm.get_parameter(Name=self._name, WithDecryption=True)
        except Exception as exc:
            if web._provider_code(exc) == "ParameterNotFound":
                raise PassError("turnstile_secret_missing", "unavailable", cause=exc) from None
            raise PassError("turnstile_secret_read_failed", "unavailable", cause=exc) from None
        parameter = response.get("Parameter") if isinstance(response, Mapping) else None
        value = parameter.get("Value") if isinstance(parameter, Mapping) else None
        if (not isinstance(parameter, Mapping) or parameter.get("Name") != self._name
                or parameter.get("Type") != "SecureString" or type(value) is not str
                or not 0 < len(value) <= MAX_SECRET_CHARS or not _SECRET_RE.fullmatch(value)):
            raise PassError("turnstile_secret_invalid", "unavailable")
        if self._env == "prod" and _DUMMY_SECRET_RE.fullmatch(value):
            raise PassError("turnstile_secret_invalid", "unavailable")
        return value


def verify_turnstile(transport: Transport, secret: str, result: str, remote_ip: str,
                     hostnames: frozenset[str]) -> None:
    """Accept only a documented success for an allowed hostname and our action."""
    body = urlencode({"secret": secret, "response": result, "remoteip": remote_ip}).encode("ascii")
    try:
        status, raw = transport(SITEVERIFY_URL, body, SITEVERIFY_TIMEOUT_SECONDS,
                                MAX_SITEVERIFY_RESPONSE_BYTES)
    except Exception as exc:
        raise PassError("turnstile_unavailable", "unavailable", cause=exc) from None
    if status != 200:
        raise PassError("turnstile_http_status", "unavailable")
    if type(raw) is not bytes or len(raw) > MAX_SITEVERIFY_RESPONSE_BYTES:
        raise PassError("turnstile_response_too_large", "unavailable")
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        raise PassError("turnstile_response_malformed", "unavailable") from None
    if type(data) is not dict or type(data.get("success")) is not bool:
        raise PassError("turnstile_response_malformed", "unavailable")
    codes = data.get("error-codes", [])
    if type(codes) is not list or any(type(code) is not str for code in codes):
        raise PassError("turnstile_response_malformed", "unavailable")
    if data["success"] is not True:
        if set(codes) & _SECRET_ERROR_CODES:
            raise PassError("turnstile_secret_rejected", "unavailable")
        if codes and set(codes) <= _CLIENT_ERROR_CODES:
            raise PassError("turnstile_rejected", "rejected")
        raise PassError("turnstile_failed_unexpected", "unavailable")
    if codes:
        raise PassError("turnstile_response_malformed", "unavailable")
    hostname = data.get("hostname")
    if type(hostname) is not str or hostname not in hostnames:
        raise PassError("turnstile_hostname_mismatch", "rejected")
    if data.get("action") != TURNSTILE_ACTION:
        raise PassError("turnstile_action_mismatch", "rejected")


# --- Service --------------------------------------------------------------------

def _is_conditional_failure(exc: BaseException) -> bool:
    return web._provider_code(exc) == "ConditionalCheckFailedException"


class PassService:
    def __init__(self, settings: Settings, *, dynamodb: Any, ssm: Any, transport: Transport,
                 clock: Callable[[], float] = time.time) -> None:
        self._settings = settings
        self._dynamodb = dynamodb
        self._keys = web.FingerprintKeyStore(ssm, settings.env)
        self._secrets = SecretStore(ssm, settings.env)
        self._transport = transport
        self._clock = clock

    def _now(self) -> int:
        value = self._clock()
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise PassError("clock_invalid", "unavailable")
        return int(value)

    def issue(self, event: Mapping[str, Any]) -> str:
        """Run every step; return ``"issued"`` or raise :class:`PassError`."""
        email, result = parse_body(event)
        remote_ip, limit_ip = source_ip(event)
        now = self._now()
        self._check_config(now)
        try:
            key = self._keys.key()
        except web.PublicWebError as exc:
            raise _from_web_error(exc, "unavailable") from None
        try:
            email_fp = web.email_fingerprint(key, email)
        except web.PublicWebError:
            raise _bad() from None
        result_fp = web.result_fingerprint(key, result)
        ip_fp = web.ip_fingerprint(key, limit_ip)
        secret = self._secrets.secret()
        try:
            verify_turnstile(self._transport, secret, result, remote_ip, self._settings.hostnames)
        except PassError as exc:
            if exc.code == "turnstile_secret_rejected":
                self._secrets.forget()
            raise
        self._mark_result_used(result_fp, now)
        self._count_ip(ip_fp, now)
        self._write_pass(email_fp, now)
        return "issued"

    def _check_config(self, now: int) -> None:
        try:
            response = self._dynamodb.get_item(
                TableName=self._settings.table, Key=web.config_key(), ConsistentRead=True)
        except Exception as exc:
            raise PassError("config_read_failed", "unavailable", cause=exc) from None
        if not isinstance(response, Mapping):
            raise PassError("config_read_failed", "unavailable")
        config = web.parse_web_config(response.get("Item"))
        if config.source == web.CONFIG_SOURCE_MALFORMED:
            raise PassError("config_malformed", "closed")
        if not config.open:
            raise PassError("web_closed", "closed")
        if not config.accepting(now):
            raise PassError("web_paused", "paused")

    def _mark_result_used(self, result_fp: str, now: int) -> None:
        item = dict(web.used_result_key(result_fp))
        item[web.TTL_ATTRIBUTE] = web.ttl_value(web.used_result_expires_at(now))
        try:
            self._dynamodb.put_item(
                TableName=self._settings.table, Item=item,
                ConditionExpression="attribute_not_exists(#pk)",
                ExpressionAttributeNames={"#pk": web.PARTITION_KEY})
        except Exception as exc:
            if _is_conditional_failure(exc):
                raise PassError("result_reused", "rejected", cause=exc) from None
            raise PassError("result_mark_failed", "unavailable", cause=exc) from None

    def _count_ip(self, ip_fp: str, now: int) -> None:
        window = web.ip_window(now)
        try:
            self._dynamodb.update_item(
                TableName=self._settings.table, Key=web.ip_passes_key(ip_fp, window),
                UpdateExpression="SET #exp = :exp ADD passes :one",
                ConditionExpression="attribute_not_exists(passes) OR passes < :limit",
                ExpressionAttributeNames={"#exp": web.TTL_ATTRIBUTE},
                ExpressionAttributeValues={
                    ":exp": web.ttl_value(web.ip_passes_expires_at(window)),
                    ":one": {"N": "1"}, ":limit": {"N": str(web.IP_PASSES_PER_WINDOW)}})
        except Exception as exc:
            if _is_conditional_failure(exc):
                raise PassError("ip_limit_reached", "rate_limited", cause=exc) from None
            raise PassError("ip_count_failed", "unavailable", cause=exc) from None

    def _write_pass(self, email_fp: str, now: int) -> None:
        item = dict(web.pass_key(email_fp))
        item["attempts_left"] = {"N": str(web.PASS_ATTEMPTS)}
        item["issued_at"] = {"N": str(now)}
        item[web.TTL_ATTRIBUTE] = web.ttl_value(web.pass_expires_at(now))
        try:
            self._dynamodb.put_item(TableName=self._settings.table, Item=item)
        except Exception as exc:
            raise PassError("pass_write_failed", "unavailable", cause=exc) from None


# --- Lambda entry point -------------------------------------------------------------

def response(answer: str) -> dict[str, Any]:
    status, body = _BODIES[answer]
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json; charset=utf-8", "cache-control": "no-store",
                    "x-content-type-options": "nosniff"},
        "body": json.dumps(body, ensure_ascii=False, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def _log_line(code: str, cause_type: str | None = None, provider_code: str | None = None) -> None:
    print(json.dumps({LOG_FIELD: code, "cause_type": cause_type, "provider_code": provider_code},
                     separators=(",", ":")), file=sys.stdout, flush=True)


_log: Callable[[str, str | None, str | None], None] = _log_line
_service_factory: Callable[[Settings], PassService] | None = None
_SERVICES: dict[Settings, PassService] = {}
_SERVICES_LOCK = threading.Lock()


def sdk_config() -> Any:
    """One attempt, 0.5 s connect, 1 s read, no proxies."""
    if _BotoConfig is None:
        raise PassError("sdk_unavailable", "unavailable")
    return _BotoConfig(retries={"mode": "standard", "total_max_attempts": 1},
                       connect_timeout=SDK_CONNECT_TIMEOUT, read_timeout=SDK_READ_TIMEOUT,
                       proxies={})


def _default_service(settings: Settings) -> PassService:
    if _boto3 is None:
        raise PassError("sdk_unavailable", "unavailable")
    config = sdk_config()
    return PassService(settings,
                       dynamodb=_boto3.client("dynamodb", region_name=REGION, config=config),
                       ssm=_boto3.client("ssm", region_name=REGION, config=config),
                       transport=default_transport)


def _service(settings: Settings) -> PassService:
    with _SERVICES_LOCK:
        if settings not in _SERVICES:
            factory = _service_factory or _default_service
            _SERVICES[settings] = factory(settings)
        return _SERVICES[settings]


def reset_services() -> None:
    with _SERVICES_LOCK:
        _SERVICES.clear()


def handle(event: Any, environ: Mapping[str, str]) -> dict[str, Any]:
    error: PassError | None = None
    answer = "unavailable"
    try:
        if not isinstance(event, Mapping):
            raise PassError("event_invalid", "unavailable")
        context = event.get("requestContext")
        http = context.get("http") if isinstance(context, Mapping) else None
        method = http.get("method") if isinstance(http, Mapping) else None
        if event.get("rawPath") != PASS_PATH or method != "POST":
            raise PassError("route_not_found", "not_found")
        answer = _service(load_settings(environ)).issue(event)
    except PassError as exc:
        error, answer = exc, exc.answer
    except Exception as exc:  # never let request-derived text reach the platform log
        error = PassError("pass_internal_error", "unavailable", cause=exc)
        answer = "unavailable"
    if error is None:
        _log("pass_issued", None, None)
    else:
        _log(error.code, error.cause_type, error.provider_code)
    return response(answer)


def handler(event: Any, context: Any) -> dict[str, Any]:
    return handle(event, os.environ)


__all__ = [
    "PASS_PATH", "ENV_VARIABLE", "TABLE_VARIABLE", "HOSTNAMES_VARIABLE", "SITEVERIFY_URL",
    "TURNSTILE_ACTION", "SITEVERIFY_TIMEOUT_SECONDS", "MAX_SITEVERIFY_RESPONSE_BYTES",
    "MAX_BODY_BYTES", "IPV6_LIMIT_PREFIX", "LOG_FIELD", "PassError", "PassService", "SecretStore",
    "Settings", "Transport", "default_transport", "handle", "handler", "load_settings",
    "parse_body", "reset_services", "response", "sdk_config", "source_ip",
    "turnstile_secret_parameter_name", "verify_turnstile",
]
