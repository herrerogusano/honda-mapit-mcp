"""Shared base for the public web mode (stack ``honda-mapit-mcp-{env}-web``).

The public web mode lets anyone with a MAPIT account sign in to the web client
without an invitation, with a cap on distinct people and sessions shorter than
one hour. It runs from the same code as the invitation-only multiuser stack and
is enabled only by ``MAPIT_WEB_MODE=public``, a variable that stack never sets.

This module holds what the identity function, the pass endpoint, the service
and the sweep share: the mode switch, resource names, limits, the row schema of
the single web table, the keyed email/IP/result fingerprint and the parsing of
the configuration row. Nothing here calls AWS at import time; the SSM client is
injected. Error messages are fixed codes and never carry an email, password,
token, IP address, fingerprint or key.

Formats that are hard to undo (changing them resets every count or orphans
existing rows):

* fingerprint: lowercase hex of HMAC-SHA256 over
  ``b"honda-mapit-mcp/web/fingerprint/v1/" + domain + b"\\x00" + value``
  (UTF-8), with ``domain`` one of ``email``, ``ip``, ``result``. The email is
  normalized with :func:`mapit.multiuser_common.normalize_email`, the IP with
  :mod:`ipaddress` (compressed form); a Turnstile result is used verbatim.
* fingerprint key: 32 random bytes, standard base64 with padding, in the
  SecureString parameter :func:`fingerprint_key_parameter_name`.
* table: one partition key ``pk`` (string), no sort key; expiry attribute
  ``expires_at`` (epoch seconds, number) for DynamoDB TTL. See the row table in
  :data:`ROW_KINDS`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import re
import secrets
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .multiuser_common import (
    LOCK_SECONDS,
    MAX_FAILED_LOGINS,
    normalize_email,
    validate_environment,
    validate_tenant_id,
)

# --- Mode switch -----------------------------------------------------------

MODE_VARIABLE = "MAPIT_WEB_MODE"
MODE_PUBLIC = "public"


class PublicWebError(ValueError):
    """Closed failure with a fixed code; never carries user input or secrets.

    ``cause_type`` is the class name of the underlying exception and
    ``provider_code`` the AWS error code when there is one (both safe to log).
    """

    def __init__(self, code: str, *, cause: BaseException | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.cause_type = type(cause).__name__ if cause is not None else None
        self.provider_code = _provider_code(cause) if cause is not None else None


def public_mode_enabled(environ: Mapping[str, str]) -> bool:
    """Absent: invitation mode (False). ``public``: public mode (True).

    Any other value, including an empty string, is a configuration error.
    """
    if MODE_VARIABLE not in environ:
        return False
    if environ[MODE_VARIABLE] == MODE_PUBLIC:
        return True
    raise PublicWebError("web_mode_invalid")


# --- Names -----------------------------------------------------------------

PROJECT = "honda-mapit-mcp"
FUNCTION_ROLES = ("identity", "mcp", "pass", "sweep")


def web_stack_name(env: str) -> str:
    return f"{PROJECT}-{validate_environment(env)}-web"


def web_table_name(env: str) -> str:
    return f"{PROJECT}-{validate_environment(env)}-web-state"


def web_function_name(env: str, role: str) -> str:
    if role not in FUNCTION_ROLES:
        raise PublicWebError("function_role_invalid")
    return f"{PROJECT}-{validate_environment(env)}-web-{role}"


def web_parameter_root(env: str) -> str:
    return f"/{PROJECT}/{validate_environment(env)}/web/"


def web_session_parameter_prefix(env: str) -> str:
    """Prefix of every web MAPIT session parameter; the sweep deletes by age here."""
    return f"{web_parameter_root(env)}sessions/"


def web_session_parameter_name(env: str, tenant_id: str) -> str:
    return f"{web_session_parameter_prefix(env)}{_tenant_arg(tenant_id)}/mapit-refresh-token"


def _tenant_arg(value: object) -> str:
    try:
        return validate_tenant_id(value)
    except ValueError:
        raise PublicWebError("tenant_invalid") from None


def fingerprint_key_parameter_name(env: str) -> str:
    """SecureString with the fingerprint key; outside the swept sessions prefix."""
    return f"{web_parameter_root(env)}fingerprint-key"


# --- Limits (initial values) -----------------------------------------------

DEFAULT_CAP = 100                      # distinct people; 0 in the config row = no cap
DAILY_LOGINS_PER_PERSON = 10
SESSION_CALL_LIMIT = 80                # /mcp calls per session
CALLS_PER_MINUTE = 30                  # /mcp calls per session and minute
BREAKER_REJECTIONS = 20                # MAPIT rejections per window that open the breaker
BREAKER_WINDOW_SECONDS = 10 * 60
BREAKER_OPEN_SECONDS = 15 * 60
PERSON_TTL_SECONDS = 365 * 24 * 3600   # from the last login
ATTEMPTS_TTL_SECONDS = 24 * 3600
SESSION_USAGE_TTL_SECONDS = 2 * 3600
SESSION_MAX_AGE_SECONDS = 55 * 60      # the service refuses older sessions
SWEEP_AGE_SECONDS = 50 * 60            # the sweep deletes users/sessions this old
PASS_TTL_SECONDS = 300
PASS_ATTEMPTS = 3
IP_PASSES_PER_WINDOW = 5
IP_WINDOW_SECONDS = 10 * 60
USED_RESULT_TTL_SECONDS = 10 * 60
MAX_RESULT_LENGTH = 2048               # Turnstile response tokens are at most 2048 characters
FINGERPRINT_KEY_BYTES = 32
# MAX_FAILED_LOGINS (5) and LOCK_SECONDS (15 min) come from multiuser_common.

# --- Table schema ----------------------------------------------------------

PARTITION_KEY = "pk"
TTL_ATTRIBUTE = "expires_at"

KIND_CONFIG = "config"
KIND_PERSON = "person"
KIND_ATTEMPTS = "attempts"
KIND_PASS = "pass"
KIND_RESULT = "result"
KIND_IP = "ip"
KIND_BREAKER = "breaker"
KIND_USAGE = "usage"
KIND_DAY = "day"
KIND_MONTH = "month"

ROW_KINDS: Mapping[str, str] = {
    KIND_CONFIG: "pk 'config'. open, pause_until, cap, occupied, pass_required. "
                 "No expiry.",
    KIND_PERSON: "pk 'person#<email fp>'. First and last login, login count and day, "
                 "consent version and date. Expires PERSON_TTL_SECONDS after the last login.",
    KIND_ATTEMPTS: "pk 'attempts#<email fp>'. Failed-login counter and lock time; exists "
                   "also for emails that never signed in. Expires after ATTEMPTS_TTL_SECONDS.",
    KIND_PASS: "pk 'pass#<email fp>'. Pre-login pass and its remaining attempts. "
               "Expires after PASS_TTL_SECONDS.",
    KIND_RESULT: "pk 'result#<result fp>'. Marks a Turnstile result as used. "
                 "Expires after USED_RESULT_TTL_SECONDS.",
    KIND_IP: "pk 'ip#<ip fp>#<window>'. Passes issued to one IP in one "
             "IP_WINDOW_SECONDS window. Expires one window after the window ends.",
    KIND_BREAKER: "pk 'breaker#<window>'. MAPIT rejections in one BREAKER_WINDOW_SECONDS "
                  "window and its open-until time. Expires BREAKER_OPEN_SECONDS plus one "
                  "window after the window ends.",
    KIND_USAGE: "pk 'usage#<tenant id>'. /mcp call counters of one session. "
                "Expires after SESSION_USAGE_TTL_SECONDS.",
    KIND_DAY: "pk 'day#YYYY-MM-DD' (UTC). Aggregate counts only, no personal data. No expiry.",
    KIND_MONTH: "pk 'month#YYYY-MM' (UTC). Aggregate counts only, no personal data. No expiry.",
}
"""What each row holds and how long it lives.

DynamoDB TTL deletes expired items late (typically within days), so readers
must treat ``expires_at <= now`` as absent instead of relying on the deletion.
"""

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_EPOCH = 2**40
Key = dict[str, dict[str, str]]


def _key(value: str) -> Key:
    return {PARTITION_KEY: {"S": value}}


def _fingerprint_arg(value: object) -> str:
    if type(value) is not str or not _FINGERPRINT_RE.fullmatch(value):
        raise PublicWebError("fingerprint_invalid")
    return value


def _window_arg(value: object) -> int:
    if type(value) is not int or not 0 <= value < _MAX_EPOCH:
        raise PublicWebError("window_invalid")
    return value


def _epoch_arg(value: object) -> int:
    if type(value) is not int or not 0 <= value < _MAX_EPOCH:
        raise PublicWebError("time_invalid")
    return value


def config_key() -> Key:
    return _key(KIND_CONFIG)


def person_key(email_fp: str) -> Key:
    return _key(f"{KIND_PERSON}#{_fingerprint_arg(email_fp)}")


def attempts_key(email_fp: str) -> Key:
    return _key(f"{KIND_ATTEMPTS}#{_fingerprint_arg(email_fp)}")


def pass_key(email_fp: str) -> Key:
    return _key(f"{KIND_PASS}#{_fingerprint_arg(email_fp)}")


def used_result_key(result_fp: str) -> Key:
    return _key(f"{KIND_RESULT}#{_fingerprint_arg(result_fp)}")


def ip_window(now: int) -> int:
    return _epoch_arg(now) // IP_WINDOW_SECONDS


def ip_passes_key(ip_fp: str, window: int) -> Key:
    return _key(f"{KIND_IP}#{_fingerprint_arg(ip_fp)}#{_window_arg(window)}")


def breaker_window(now: int) -> int:
    return _epoch_arg(now) // BREAKER_WINDOW_SECONDS


def breaker_key(window: int) -> Key:
    return _key(f"{KIND_BREAKER}#{_window_arg(window)}")


def session_usage_key(tenant_id: str) -> Key:
    return _key(f"{KIND_USAGE}#{_tenant_arg(tenant_id)}")


def _utc(now: int) -> datetime:
    return datetime.fromtimestamp(_epoch_arg(now), tz=timezone.utc)


def day_key(now: int) -> Key:
    return _key(f"{KIND_DAY}#{_utc(now):%Y-%m-%d}")


def month_key(now: int) -> Key:
    return _key(f"{KIND_MONTH}#{_utc(now):%Y-%m}")


def person_expires_at(last_login: int) -> int:
    return _epoch_arg(last_login) + PERSON_TTL_SECONDS


def attempts_expires_at(now: int) -> int:
    return _epoch_arg(now) + ATTEMPTS_TTL_SECONDS


def pass_expires_at(now: int) -> int:
    return _epoch_arg(now) + PASS_TTL_SECONDS


def used_result_expires_at(now: int) -> int:
    return _epoch_arg(now) + USED_RESULT_TTL_SECONDS


def ip_passes_expires_at(window: int) -> int:
    return (_window_arg(window) + 2) * IP_WINDOW_SECONDS


def breaker_expires_at(window: int) -> int:
    return (_window_arg(window) + 2) * BREAKER_WINDOW_SECONDS + BREAKER_OPEN_SECONDS


def session_usage_expires_at(now: int) -> int:
    return _epoch_arg(now) + SESSION_USAGE_TTL_SECONDS


def ttl_value(expires_at: int) -> dict[str, str]:
    """The ``expires_at`` attribute value in DynamoDB low-level form."""
    return {"N": str(_epoch_arg(expires_at))}


# --- Fingerprints ----------------------------------------------------------

FINGERPRINT_DOMAINS = ("email", "ip", "result")
_FINGERPRINT_LABEL = b"honda-mapit-mcp/web/fingerprint/v1/"


def fingerprint(key: bytes, domain: str, value: str) -> str:
    """Keyed, domain-separated fingerprint (64 lowercase hex characters)."""
    if type(key) is not bytes or len(key) != FINGERPRINT_KEY_BYTES:
        raise PublicWebError("fingerprint_key_invalid")
    if domain not in FINGERPRINT_DOMAINS:
        raise PublicWebError("fingerprint_domain_invalid")
    if type(value) is not str or not value:
        raise PublicWebError("fingerprint_value_invalid")
    message = _FINGERPRINT_LABEL + domain.encode("ascii") + b"\x00" + value.encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def email_fingerprint(key: bytes, email: object) -> str:
    try:
        normalized = normalize_email(email)
    except ValueError:
        raise PublicWebError("email_invalid") from None
    return fingerprint(key, "email", normalized)


def ip_fingerprint(key: bytes, ip: object) -> str:
    if type(ip) is not str:
        raise PublicWebError("ip_invalid")
    try:
        normalized = ipaddress.ip_address(ip).compressed
    except ValueError:
        raise PublicWebError("ip_invalid") from None
    return fingerprint(key, "ip", normalized)


def result_fingerprint(key: bytes, result: object) -> str:
    if type(result) is not str or not 0 < len(result) <= MAX_RESULT_LENGTH:
        raise PublicWebError("result_invalid")
    return fingerprint(key, "result", result)


def _provider_code(exc: BaseException) -> str | None:
    try:
        response = getattr(exc, "response", None)
        code = response.get("Error", {}).get("Code") if isinstance(response, Mapping) else None
    except Exception:
        return None
    return code if type(code) is str and re.fullmatch(r"[A-Za-z0-9.]{1,64}", code) else None


def _encode_key(key: bytes) -> str:
    return base64.b64encode(key).decode("ascii")


def _decode_key(value: object) -> bytes:
    if type(value) is not str or len(value) != 44:
        raise PublicWebError("fingerprint_key_invalid")
    try:
        key = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise PublicWebError("fingerprint_key_invalid") from None
    if len(key) != FINGERPRINT_KEY_BYTES or _encode_key(key) != value:
        raise PublicWebError("fingerprint_key_invalid")
    return key


class FingerprintKeyStore:
    """Loads (or creates once) the fingerprint key from SSM and caches it.

    ``get_parameter`` with decryption; if the parameter does not exist, a new
    key is written with ``Overwrite=False``. If another caller created it
    first (``ParameterAlreadyExists``), the stored key is read again. An
    existing but invalid parameter is never overwritten: it is an error.
    """

    def __init__(self, ssm: Any, env: str, *,
                 token_bytes: Callable[[int], bytes] = secrets.token_bytes) -> None:
        self._ssm = ssm
        self._name = fingerprint_key_parameter_name(env)
        self._token_bytes = token_bytes
        self._key: bytes | None = None
        self._lock = threading.Lock()

    @property
    def parameter_name(self) -> str:
        return self._name

    def key(self) -> bytes:
        with self._lock:
            if self._key is None:
                self._key = self._load_or_create()
            return self._key

    def _read(self) -> bytes | None:
        try:
            response = self._ssm.get_parameter(Name=self._name, WithDecryption=True)
        except Exception as exc:
            if _provider_code(exc) == "ParameterNotFound":
                return None
            raise PublicWebError("fingerprint_key_read_failed", cause=exc) from None
        parameter = response.get("Parameter") if isinstance(response, Mapping) else None
        if (not isinstance(parameter, Mapping) or parameter.get("Name") != self._name
                or parameter.get("Type") != "SecureString"):
            raise PublicWebError("fingerprint_key_invalid")
        return _decode_key(parameter.get("Value"))

    def _load_or_create(self) -> bytes:
        existing = self._read()
        if existing is not None:
            return existing
        candidate = self._token_bytes(FINGERPRINT_KEY_BYTES)
        if type(candidate) is not bytes or len(candidate) != FINGERPRINT_KEY_BYTES:
            raise PublicWebError("fingerprint_key_generation_failed")
        try:
            response = self._ssm.put_parameter(
                Name=self._name, Value=_encode_key(candidate), Type="SecureString",
                Overwrite=False, Tier="Standard",
            )
        except Exception as exc:
            if _provider_code(exc) != "ParameterAlreadyExists":
                raise PublicWebError("fingerprint_key_write_failed", cause=exc) from None
            winner = self._read()
            if winner is None:
                raise PublicWebError("fingerprint_key_unavailable") from None
            return winner
        version = response.get("Version") if isinstance(response, Mapping) else None
        if type(version) is not int or version < 1:
            raise PublicWebError("fingerprint_key_write_unconfirmed")
        return candidate


# --- Configuration row -----------------------------------------------------

CONFIG_SOURCE_DEFAULT = "default"      # row absent
CONFIG_SOURCE_ROW = "row"              # row present and valid
CONFIG_SOURCE_MALFORMED = "malformed"  # row present but invalid: closed
_CONFIG_ATTRIBUTES = frozenset({PARTITION_KEY, "open", "pause_until", "cap", "occupied", "pass_required"})
_NUMBER_RE = re.compile(r"^(0|[1-9][0-9]{0,12})$")


@dataclass(frozen=True)
class WebConfig:
    """Sign-up switch, pause, cap and pass requirement of the public web.

    ``cap == 0`` means no cap. ``pause_until`` is epoch seconds (0 = none).
    """

    open: bool
    pause_until: int
    cap: int
    occupied: int
    pass_required: bool
    source: str

    def accepting(self, now: int) -> bool:
        return self.open and _epoch_arg(now) >= self.pause_until

    def has_room(self) -> bool:
        return self.cap == 0 or self.occupied < self.cap


DEFAULT_WEB_CONFIG = WebConfig(
    open=True, pause_until=0, cap=DEFAULT_CAP, occupied=0, pass_required=True,
    source=CONFIG_SOURCE_DEFAULT)
CLOSED_WEB_CONFIG = WebConfig(
    open=False, pause_until=0, cap=DEFAULT_CAP, occupied=0, pass_required=True,
    source=CONFIG_SOURCE_MALFORMED)


def _bool_attribute(item: Mapping[str, Any], name: str, default: bool) -> bool:
    if name not in item:
        return default
    value = item[name]
    if not isinstance(value, Mapping) or set(value) != {"BOOL"} or type(value["BOOL"]) is not bool:
        raise PublicWebError("config_malformed")
    return value["BOOL"]


def _number_attribute(item: Mapping[str, Any], name: str, default: int) -> int:
    if name not in item:
        return default
    value = item[name]
    if (not isinstance(value, Mapping) or set(value) != {"N"} or type(value["N"]) is not str
            or not _NUMBER_RE.fullmatch(value["N"])):
        raise PublicWebError("config_malformed")
    return int(value["N"])


def parse_web_config(item: object) -> WebConfig:
    """Parse the low-level DynamoDB ``config`` item.

    ``None`` (row absent): the defaults (open, cap 100, pass required). Missing
    attributes take their default, so a row created by an atomic counter update
    stays valid. Unknown attributes, wrong types or a wrong key: closed.
    """
    if item is None:
        return DEFAULT_WEB_CONFIG
    try:
        if not isinstance(item, Mapping) or not set(item) <= _CONFIG_ATTRIBUTES:
            raise PublicWebError("config_malformed")
        if item.get(PARTITION_KEY) != {"S": KIND_CONFIG}:
            raise PublicWebError("config_malformed")
        return WebConfig(
            open=_bool_attribute(item, "open", DEFAULT_WEB_CONFIG.open),
            pause_until=_number_attribute(item, "pause_until", DEFAULT_WEB_CONFIG.pause_until),
            cap=_number_attribute(item, "cap", DEFAULT_WEB_CONFIG.cap),
            occupied=_number_attribute(item, "occupied", DEFAULT_WEB_CONFIG.occupied),
            pass_required=_bool_attribute(item, "pass_required", DEFAULT_WEB_CONFIG.pass_required),
            source=CONFIG_SOURCE_ROW,
        )
    except PublicWebError:
        return CLOSED_WEB_CONFIG


__all__ = [name for name in globals() if (name.isupper() and not name.startswith("_")) or name in {
    "PublicWebError", "public_mode_enabled", "web_stack_name", "web_table_name",
    "web_function_name", "web_parameter_root", "web_session_parameter_prefix",
    "web_session_parameter_name", "fingerprint_key_parameter_name", "config_key", "person_key",
    "attempts_key", "pass_key", "used_result_key", "ip_window", "ip_passes_key",
    "breaker_window", "breaker_key", "session_usage_key", "day_key", "month_key",
    "person_expires_at", "attempts_expires_at", "pass_expires_at", "used_result_expires_at",
    "ip_passes_expires_at", "breaker_expires_at", "session_usage_expires_at", "ttl_value",
    "fingerprint", "email_fingerprint", "ip_fingerprint", "result_fingerprint",
    "FingerprintKeyStore", "WebConfig", "parse_web_config", "Key",
}]
