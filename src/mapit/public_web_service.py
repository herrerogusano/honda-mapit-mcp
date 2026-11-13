"""Public web mode of the ``/mcp`` service (``MAPIT_WEB_MODE=public``).

Per tool call, before any MAPIT read, :meth:`PublicSessionGate.admit`:

1. refuses a session whose login is ``SESSION_MAX_AGE_SECONDS`` old or more,
   using the token's ``auth_time``; the usage row's ``login_at`` is checked in
   the same write, so the older of the two wins. An aged, missing or expired
   session is deleted on the spot (MAPIT session parameter, Cognito user and
   usage row), independently of the sweep;
2. reads the configuration row: a pause (``pause_until`` in the future) stops
   every call; ``open = false`` only closes sign-ups, so sessions already open
   continue; an unreadable or malformed row refuses (closed);
3. counts the call with exactly one conditional ``UpdateItem`` on the usage
   row ``usage#<tenant>``: the row must exist, be unexpired and younger than
   the maximum age, have ``calls < SESSION_CALL_LIMIT`` and fewer than
   ``CALLS_PER_MINUTE`` calls in the current UTC minute. The per-minute counter
   is the attribute ``m<epoch minute>``; the previous minute's attribute is
   removed in the same write. A refused call is not counted.

Usage row written by the identity function at login (shared contract):
``person_fp`` (S, email fingerprint), ``login_at`` (N, epoch s), ``calls``
(N, 0) and ``expires_at`` (N, ``session_usage_expires_at(login_at)``). This
module only adds the ``m<minute>`` attributes.

Every refusal is a :class:`PublicSessionRefused` with a fixed code; nothing
logged or raised carries a token, tenant, username, fingerprint or AWS text.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable, Mapping
from typing import Any

from .multiuser_common import validate_tenant_id
from .public_web import (
    CALLS_PER_MINUTE, PARTITION_KEY, SESSION_CALL_LIMIT, SESSION_MAX_AGE_SECONDS, TTL_ATTRIBUTE,
    CONFIG_SOURCE_MALFORMED, PublicWebError, config_key, parse_web_config, person_key,
    session_usage_key, web_session_parameter_name, web_table_name,
)

# Tools the static web calls (src/service of the web client) plus the two
# account tools. Geographic queries and period comparisons are not exposed.
PUBLIC_READ_TOOLS = ("get_vehicle_status", "get_vehicle_details", "list_routes", "get_route_detail")
PUBLIC_ACCOUNT_TOOLS = ("cerrar_sesion", "borrar_mis_datos")
PUBLIC_TOOLS = PUBLIC_READ_TOOLS + PUBLIC_ACCOUNT_TOOLS

# Refusal codes. The tool error text starts with "<code>: " so the web client
# can tell them apart (it reads the text before the first colon).
REFUSED_EXPIRED = "session_expired"
REFUSED_LIMIT = "session_limit_reached"
REFUSED_RATE = "rate_limited"
REFUSED_PAUSED = "service_paused"
REFUSED_UNAVAILABLE = "service_unavailable"

MSG_PUBLIC_LIMIT = (
    "Has llegado al máximo de consultas de esta sesión. Cierra sesión y vuelve a entrar."
)
MSG_PUBLIC_RATE = "Demasiadas consultas seguidas. Espera un minuto y vuelve a intentarlo."
MSG_PUBLIC_PAUSED = "El servicio está en pausa. Inténtalo de nuevo más tarde."
MSG_LOGOUT_DONE = (
    "Sesión cerrada: se han borrado tu sesión de MAPIT guardada y tu usuario de este servicio."
)
MSG_LOGOUT_FAILED = (
    "No se ha podido cerrar la sesión del todo. Inténtalo de nuevo; si no, se borrará sola "
    "en menos de una hora."
)
MSG_PUBLIC_DELETE_PREVIEW = (
    "No se ha borrado nada. Si llamas a borrar_mis_datos con confirmar=true se borrarán de "
    "inmediato tu sesión de MAPIT guardada (cifrada), tu usuario de este servicio y el registro "
    "de tus entradas (la huella de tu correo, fechas y número de entradas). Tus datos en MAPIT "
    "no se modifican."
)
MSG_PUBLIC_DELETE_DONE = (
    "Hecho: se han borrado tu sesión de MAPIT guardada, tu usuario de este servicio y el "
    "registro de tus entradas. Las próximas peticiones fallarán."
)

_MAX_EPOCH = 2**40
_MINUTE = 60


class PublicSessionRefused(RuntimeError):
    """A call refused before MAPIT; ``code`` is one of the ``REFUSED_*`` values.

    ``step`` names the failing step and ``cause_type``/``provider_code`` the
    underlying exception class and AWS error code; all three are safe to log.
    """

    def __init__(self, code: str, step: str, *, cause: BaseException | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.step = step
        self.cause_type = type(cause).__name__ if cause is not None else None
        self.provider_code = _provider_code(cause) if cause is not None else None


def _provider_code(exc: BaseException) -> str | None:
    # PublicWebError extracts a validated AWS error code (or None) from a cause.
    return PublicWebError("provider_code", cause=exc).provider_code


def _stderr_sink(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


def _log_line(sink: Callable[[str], None], event: str, step: str,
              cause: BaseException | None = None) -> None:
    """One JSON line with fixed words only; a log failure never changes a result."""
    try:
        sink(json.dumps({
            "event": event, "step": step,
            "cause": type(cause).__name__ if cause is not None else None,
            "provider_code": _provider_code(cause) if cause is not None else None,
        }, separators=(",", ":")))
    except Exception:  # noqa: BLE001
        pass


def _number(item: Mapping[str, Any] | None, name: str) -> int | None:
    value = item.get(name) if isinstance(item, Mapping) else None
    if not isinstance(value, Mapping) or set(value) != {"N"} or type(value["N"]) is not str:
        return None
    try:
        number = int(value["N"])
    except ValueError:
        return None
    return number if 0 <= number < _MAX_EPOCH and str(number) == value["N"] else None


def _minute_attribute(minute: int) -> str:
    return f"m{minute}"


class PublicSessionGate:
    """Session age, pause and call limits of the public ``/mcp`` service.

    ``client`` returns a cached boto3 client for ``"ssm"``, ``"dynamodb"`` or
    ``"cognito-idp"``; nothing is called at construction.
    """

    def __init__(self, *, env: str, pool: str, client: Callable[[str], Any],
                 clock: Callable[[], float] = time.time,
                 log: Callable[[str], None] = _stderr_sink) -> None:
        if (not callable(client) or not callable(clock) or not callable(log)
                or type(pool) is not str or not pool):
            raise ValueError("explicit public session gate dependencies required")
        self._env = env
        self._table = web_table_name(env)
        self._pool = pool
        self._client = client
        self._clock = clock
        self._log = log

    def __repr__(self) -> str:
        return "PublicSessionGate(<redacted>)"

    def _now(self) -> int:
        now = self._clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not 0 <= now < _MAX_EPOCH:
            raise PublicSessionRefused(REFUSED_UNAVAILABLE, "clock_invalid")
        return int(now)

    # -- per-call admission -------------------------------------------------

    def admit(self, tenant: str, username: str, auth_time: object) -> None:
        """Return when the call may reach MAPIT; otherwise raise PublicSessionRefused."""
        try:
            self._admit(tenant, username, auth_time)
        except PublicSessionRefused as refused:
            try:
                self._log(json.dumps({
                    "event": "public_call_refused", "code": refused.code, "step": refused.step,
                    "cause": refused.cause_type, "provider_code": refused.provider_code,
                }, separators=(",", ":")))
            except Exception:  # noqa: BLE001
                pass
            raise

    def _admit(self, tenant: str, username: str, auth_time: object) -> None:
        validate_tenant_id(tenant)
        now = self._now()
        if type(auth_time) is not int or not 0 <= auth_time <= now:
            raise PublicSessionRefused(REFUSED_UNAVAILABLE, "auth_time_invalid")
        if now - auth_time >= SESSION_MAX_AGE_SECONDS:
            self._expire(tenant, username)
            raise PublicSessionRefused(REFUSED_EXPIRED, "session_aged")
        self._check_config(now)
        self._count_call(tenant, username, now)

    def _check_config(self, now: int) -> None:
        try:
            response = self._client("dynamodb").get_item(
                TableName=self._table, Key=config_key(), ConsistentRead=True)
        except Exception as exc:
            raise PublicSessionRefused(REFUSED_UNAVAILABLE, "config_read_failed", cause=exc) from None
        item = response.get("Item") if isinstance(response, Mapping) else None
        config = parse_web_config(item)
        if config.source == CONFIG_SOURCE_MALFORMED:
            raise PublicSessionRefused(REFUSED_UNAVAILABLE, "config_malformed")
        if now < config.pause_until:
            raise PublicSessionRefused(REFUSED_PAUSED, "paused")

    def _count_call(self, tenant: str, username: str, now: int) -> None:
        minute = now // _MINUTE
        try:
            self._client("dynamodb").update_item(
                TableName=self._table,
                Key=session_usage_key(tenant),
                UpdateExpression="SET #c = #c + :one, #m = if_not_exists(#m, :zero) + :one REMOVE #p",
                ConditionExpression=(
                    "attribute_exists(#k) AND #e > :now AND #l > :oldest AND #c < :limit "
                    "AND (attribute_not_exists(#m) OR #m < :per_minute)"
                ),
                ExpressionAttributeNames={
                    "#k": PARTITION_KEY, "#e": TTL_ATTRIBUTE, "#l": "login_at", "#c": "calls",
                    "#m": _minute_attribute(minute), "#p": _minute_attribute(minute - 1),
                },
                ExpressionAttributeValues={
                    ":one": {"N": "1"}, ":zero": {"N": "0"}, ":now": {"N": str(now)},
                    ":oldest": {"N": str(now - SESSION_MAX_AGE_SECONDS)},
                    ":limit": {"N": str(SESSION_CALL_LIMIT)},
                    ":per_minute": {"N": str(CALLS_PER_MINUTE)},
                },
                ReturnValuesOnConditionCheckFailure="ALL_OLD",
            )
        except Exception as exc:
            if _provider_code(exc) != "ConditionalCheckFailedException":
                raise PublicSessionRefused(REFUSED_UNAVAILABLE, "usage_write_failed", cause=exc) from None
            response = getattr(exc, "response", None)
            old = response.get("Item") if isinstance(response, Mapping) else None
            self._refuse_from_old(tenant, username, now, minute, old)

    def _refuse_from_old(self, tenant: str, username: str, now: int, minute: int, old: Any) -> None:
        expires_at, login_at = _number(old, TTL_ATTRIBUTE), _number(old, "login_at")
        if (
            not isinstance(old, Mapping)
            or expires_at is None or expires_at <= now
            or login_at is None or now - login_at >= SESSION_MAX_AGE_SECONDS
        ):
            # Missing, expired or aged: the session is no longer valid.
            self._expire(tenant, username)
            raise PublicSessionRefused(REFUSED_EXPIRED, "usage_invalid")
        calls = _number(old, "calls")
        if calls is not None and calls >= SESSION_CALL_LIMIT:
            raise PublicSessionRefused(REFUSED_LIMIT, "session_limit")
        per_minute = _number(old, _minute_attribute(minute))
        if per_minute is not None and per_minute >= CALLS_PER_MINUTE:
            raise PublicSessionRefused(REFUSED_RATE, "minute_limit")
        raise PublicSessionRefused(REFUSED_UNAVAILABLE, "usage_unclassified")

    # -- deletions ------------------------------------------------------------

    def _attempt(self, name: str, step: Callable[[], Any],
                 ok_codes: frozenset[str] = frozenset()) -> bool:
        try:
            step()
            return True
        except Exception as exc:
            if _provider_code(exc) in ok_codes:
                return True
            _log_line(self._log, "public_delete_failed", name, exc)
            return False

    def _delete_session(self, tenant: str, username: str) -> bool:
        """MAPIT session parameter, Cognito user and usage row; idempotent."""
        ok = self._attempt(
            "session_parameter",
            lambda: self._client("ssm").delete_parameter(Name=web_session_parameter_name(self._env, tenant)),
            frozenset({"ParameterNotFound"}),
        )
        ok = self._attempt(
            "cognito_user",
            lambda: self._client("cognito-idp").admin_delete_user(UserPoolId=self._pool, Username=username),
            frozenset({"UserNotFoundException"}),
        ) and ok
        ok = self._attempt(
            "usage_row",
            lambda: self._client("dynamodb").delete_item(TableName=self._table, Key=session_usage_key(tenant)),
        ) and ok
        return ok

    def _expire(self, tenant: str, username: str) -> None:
        self._delete_session(tenant, username)

    def end_session(self, tenant: str, username: str) -> bool:
        """``cerrar_sesion``: delete the session; True when everything is gone."""
        validate_tenant_id(tenant)
        return self._delete_session(tenant, username)

    def delete_account(self, tenant: str, username: str) -> bool:
        """``borrar_mis_datos``: the person row, then the session.

        The person row is found through the usage row's ``person_fp``. If that
        row is missing, expired or the person row cannot be deleted, nothing
        else is deleted and False is returned, so the call can be retried.
        The configuration counter ``occupied`` is not changed here.
        """
        validate_tenant_id(tenant)
        now = self._now()
        try:
            response = self._client("dynamodb").get_item(
                TableName=self._table, Key=session_usage_key(tenant), ConsistentRead=True)
        except Exception as exc:
            _log_line(self._log, "public_delete_failed", "usage_read", exc)
            return False
        item = response.get("Item") if isinstance(response, Mapping) else None
        expires_at = _number(item, TTL_ATTRIBUTE)
        person = item.get("person_fp") if isinstance(item, Mapping) else None
        if expires_at is None or expires_at <= now or not isinstance(person, Mapping) or set(person) != {"S"}:
            _log_line(self._log, "public_delete_failed", "usage_invalid")
            return False
        try:
            key = person_key(person["S"])
        except PublicWebError:
            _log_line(self._log, "public_delete_failed", "person_fp_invalid")
            return False
        if not self._attempt(
                "person_row",
                lambda: self._client("dynamodb").delete_item(TableName=self._table, Key=key)):
            return False
        return self._delete_session(tenant, username)


__all__ = [
    "MSG_LOGOUT_DONE", "MSG_LOGOUT_FAILED", "MSG_PUBLIC_DELETE_DONE", "MSG_PUBLIC_DELETE_PREVIEW",
    "MSG_PUBLIC_LIMIT", "MSG_PUBLIC_PAUSED", "MSG_PUBLIC_RATE", "PUBLIC_ACCOUNT_TOOLS",
    "PUBLIC_READ_TOOLS", "PUBLIC_TOOLS", "PublicSessionGate", "PublicSessionRefused",
    "REFUSED_EXPIRED", "REFUSED_LIMIT", "REFUSED_PAUSED", "REFUSED_RATE", "REFUSED_UNAVAILABLE",
]
