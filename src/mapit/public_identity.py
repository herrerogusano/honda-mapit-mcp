"""Public web mode of the identity Lambda (``MAPIT_WEB_MODE=public``).

Reached only from :mod:`mapit.multiuser_identity` when
:func:`mapit.public_web.public_mode_enabled` is true; with the variable absent
nothing here runs. It serves four Cognito triggers and one HTTP route:

* ``UserMigration_Authentication``: one consistent read of the web table
  (config, person, attempts, pass, breaker), refusals that never call MAPIT
  (closed or paused, breaker open, email locked, no valid pass), the pass
  attempt spent conditionally, one MAPIT login as in invitation mode, then
  either the rejection counters or the MAPIT session under
  :func:`mapit.public_web.web_session_parameter_name` with a random tenant
  followed by the admission (person row, seat, usage row).
  A full cap is checked only after MAPIT accepted the password, so the answer
  never tells whether an email signed in before.
* ``PreAuthentication_Authentication``: the same refusals, before Cognito
  checks the password of a user that still exists.
* ``TokenGeneration_*``: refresh is refused; every other issue counts one
  sign-in per person and day (at most ``DAILY_LOGINS_PER_PERSON``) and the
  day and month aggregates, then adds the tenant claim.
* ``GET /estado``: fixed public JSON, ``abierto``, ``lleno``, ``cerrado`` or
  ``pausa``.

A pass attempt is spent once per sign-in: in the migration before MAPIT is
called, whatever MAPIT answers (the conditional decrement is what lets only
one of several racing migrations through), or in the pre-authentication step
when the user exists (Cognito checks the password itself and no migration
runs). A pre-authentication call for an absent user (``userNotFound``) only
checks the pass, and one for an existing user right after a migration of the
same email (``MIGRATION_SPEND_GRACE_SECONDS``) spends nothing more. Whatever
order Cognito runs the two steps in, one attempt is spent once.

Failures are logged as one JSON line with a fixed step code, the exception
class name and the AWS error code; never the event, email, password, token,
fingerprint or key. User messages are short, provisional Spanish texts.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from . import multiuser_identity as base
from . import multiuser_pages as pages
from . import public_web as web
from .multiuser_common import (
    LOCK_SECONDS,
    MAX_FAILED_LOGINS,
    REGION,
    TENANT_ATTRIBUTE,
    MultiuserError,
    normalize_email,
    validate_environment,
    validate_tenant_id,
)

# Provisional: the consent text of the public web is not final yet.
PUBLIC_CONSENT_VERSION = "web-provisional-1"

MSG_BAD_CREDENTIALS = "Email o contraseña de MAPIT incorrectos."
MSG_START_FROM_WEB = "Empieza desde la web."
MSG_PAUSED = "Ahora no se puede entrar. Vuelve a probar más tarde."
MSG_FULL = "No quedan plazas."
MSG_DAILY_LIMIT = "Has entrado demasiadas veces hoy. Vuelve mañana."
MSG_SESSION_ENDED = "La sesión ha terminado. Vuelve a entrar desde la web."
MSG_FORGOT_PASSWORD = "Entra desde la web con tu contraseña actual de MAPIT."
MSG_LOCKED = base.MSG_LOCKED
MSG_GENERIC = base.MSG_GENERIC
USER_MESSAGES = frozenset({
    MSG_BAD_CREDENTIALS, MSG_START_FROM_WEB, MSG_PAUSED, MSG_FULL, MSG_DAILY_LIMIT,
    MSG_SESSION_ENDED, MSG_FORGOT_PASSWORD, MSG_LOCKED, MSG_GENERIC,
})

STATUS_OPEN = "abierto"
STATUS_FULL = "lleno"
STATUS_CLOSED = "cerrado"
STATUS_PAUSED = "pausa"
STATUS_DEADLINE_SECONDS = 3.0
# Both steps of one sign-in run within one Cognito request (each under 5 s).
MIGRATION_SPEND_GRACE_SECONDS = 10

_LOG = logging.getLogger("mapit.public_identity")
_KEY_STORE = "web_fingerprint_key"
_token_hex: Callable[[int], str] = secrets.token_hex


class _Stop(web.PublicWebError):
    """A refusal or failure of one step: fixed code plus the user message."""

    def __init__(self, code: str, message: str = MSG_GENERIC, cause: BaseException | None = None) -> None:
        super().__init__(code, cause=cause)
        self.message = message
        # ALL_OLD item of a ConditionalCheckFailedException (never logged).
        response = getattr(cause, "response", None)
        self.old_item = response.get("Item") if isinstance(response, Mapping) else None


def _log(trigger: str, code: str, error_type: str | None, provider_code: str | None) -> None:
    _LOG.warning(json.dumps({
        "component": "web_identity", "trigger": trigger, "step": code,
        "error_type": error_type, "provider_code": provider_code,
    }, sort_keys=True))


def _run(trigger: str, step: Callable[..., Any], *args: Any) -> Any:
    try:
        return step(*args)
    except _Stop as exc:
        _log(trigger, exc.code, exc.cause_type, exc.provider_code)
        message = exc.message
    except web.PublicWebError as exc:
        _log(trigger, exc.code, exc.cause_type, exc.provider_code)
        message = MSG_GENERIC
    except Exception as exc:
        _log(trigger, "unexpected", type(exc).__name__, None)
        message = MSG_GENERIC
    # Raised outside the except blocks: no chained context with request data.
    raise base.IdentityError(message)


# --- small helpers -----------------------------------------------------------

def _num(value: int) -> dict[str, str]:
    return {"N": str(value)}


def _day(now: int) -> str:
    return f"{datetime.fromtimestamp(now, tz=timezone.utc):%Y-%m-%d}"


def _environment(environ: Mapping[str, str]) -> str:
    """Public env, region pinned; the invitation table variable must be absent."""
    try:
        env = validate_environment(environ.get("MAPIT_MCP_ENV", ""))
    except MultiuserError:
        raise _Stop("config_invalid") from None
    if environ.get("AWS_REGION") != REGION or "MULTIUSER_TABLE" in environ:
        raise _Stop("config_invalid")
    return env


def _call(step: str, deadline: float, method: Callable[..., Any], **kwargs: Any) -> Any:
    """Start one SDK call only if its worst case fits before the deadline."""
    if not base._has_sdk_time(deadline):
        raise _Stop(f"{step}_no_time")
    try:
        return method(**kwargs)
    except Exception as exc:
        raise _Stop(f"{step}_failed", MSG_GENERIC, exc) from None


def _cancellation(exc: BaseException) -> list[Any] | None:
    """CancellationReasons of a TransactionCanceledException, else None."""
    if web.PublicWebError("x", cause=exc).provider_code != "TransactionCanceledException":
        return None
    reasons = getattr(exc, "response", {}).get("CancellationReasons")
    return reasons if isinstance(reasons, list) else None


def _condition_failed(reasons: list[Any] | None, index: int) -> bool:
    return (reasons is not None and index < len(reasons) and isinstance(reasons[index], Mapping)
            and reasons[index].get("Code") == "ConditionalCheckFailed")


def _email(value: object) -> str:
    try:
        return normalize_email(value)
    except MultiuserError:
        raise _Stop("email_invalid", MSG_START_FROM_WEB) from None


def _email_fp(env: str, email: str, deadline: float) -> str:
    store = base._CLIENTS.get(_KEY_STORE)
    if store is None:
        store = base._CLIENTS[_KEY_STORE] = web.FingerprintKeyStore(base._ssm(), env)
    if not base._has_sdk_time(deadline):
        raise _Stop("fingerprint_key_no_time")
    return web.email_fingerprint(store.key(), email)


# --- the single state read -----------------------------------------------------

def _read(env: str, keys: Mapping[str, web.Key], now: int, deadline: float) -> dict[str, Any]:
    """One consistent BatchGetItem; rows past ``expires_at`` count as absent."""
    table = web.web_table_name(env)
    response = _call("state_read", deadline, base._dynamodb().batch_get_item, RequestItems={
        table: {"Keys": [dict(key) for key in keys.values()], "ConsistentRead": True}})
    if not isinstance(response, Mapping) or response.get("UnprocessedKeys"):
        raise _Stop("state_unprocessed")
    items = (response.get("Responses") or {}).get(table, [])
    wanted = {key[web.PARTITION_KEY]["S"]: name for name, key in keys.items()}
    state: dict[str, Any] = dict.fromkeys(keys)
    for item in items if isinstance(items, list) else [None]:
        pk = base._s(item, web.PARTITION_KEY) if isinstance(item, Mapping) else None
        if pk not in wanted or state[wanted[pk]] is not None:
            raise _Stop("state_malformed")
        name = wanted[pk]
        if name != "config":
            expires = base._n(item, web.TTL_ATTRIBUTE)
            if expires is None:
                raise _Stop("state_malformed")
            if expires <= now:
                continue
        state[name] = item
    return state


def _login_keys(email_fp: str, window: int, *, person: bool) -> dict[str, web.Key]:
    keys = {"config": web.config_key(), "attempts": web.attempts_key(email_fp),
            "pass": web.pass_key(email_fp)}
    if person:
        keys["person"] = web.person_key(email_fp)
    keys.update(_breaker_keys(window))
    return keys


def _breaker_keys(window: int) -> dict[str, web.Key]:
    # The breaker stays open 15 min, so a row of the two previous 10-min windows
    # can still hold an open_until in the future.
    return {f"breaker{i}": web.breaker_key(window - i) for i in range(3)}


def _breaker_open(state: Mapping[str, Any], now: int) -> bool:
    rows = [state[f"breaker{i}"] for i in range(3)]
    if any(row is not None and (base._n(row, "open_until") or 0) > now for row in rows):
        return True
    current = rows[0]
    return current is not None and web.breaker_tripped(max(base._n(current, "rejections") or 0, 0))


def _pass_valid(row: Mapping[str, Any] | None) -> bool:
    # _read already dropped a row past expires_at.
    return row is not None and (base._n(row, "attempts_left") or 0) > 0


def _gate(state: Mapping[str, Any], now: int) -> web.WebConfig:
    """Refusals before MAPIT. A full cap is never checked here."""
    config = web.parse_web_config(state["config"])
    if not config.accepting(now):
        raise _Stop("closed", MSG_PAUSED)
    if _breaker_open(state, now):
        raise _Stop("breaker_open", MSG_PAUSED)
    attempts = state["attempts"]
    if attempts is not None and (base._n(attempts, "locked_until") or 0) > now:
        raise _Stop("locked", MSG_LOCKED)
    if config.pass_required and not _pass_valid(state["pass"]):
        raise _Stop("pass_missing", MSG_START_FROM_WEB)
    return config


def _spend_for_migration(env: str, email_fp: str, now: int, deadline: float) -> None:
    """Spend one pass attempt before MAPIT, whatever MAPIT answers.

    The conditional decrement is the gate: of several migrations racing on a
    pass with one attempt left, only one reaches MAPIT. It also records
    ``migration_spent_at`` so that a pre-authentication step that Cognito may
    run right after this migration does not spend a second attempt.
    """
    try:
        _call("pass_spend", deadline, base._dynamodb().update_item,
              TableName=web.web_table_name(env), Key=web.pass_key(email_fp),
              UpdateExpression="SET attempts_left = attempts_left - :one, migration_spent_at = :now",
              ConditionExpression="attempts_left > :zero AND expires_at > :now",
              ExpressionAttributeValues={":one": _num(1), ":zero": _num(0), ":now": _num(now)})
    except _Stop as exc:
        if exc.provider_code == "ConditionalCheckFailedException":
            raise _Stop("pass_missing", MSG_START_FROM_WEB) from None
        raise


def _spend_for_pre_auth(env: str, email_fp: str, now: int, deadline: float) -> None:
    """Spend one pass attempt for an existing user, unless a migration just did.

    A migration of the same sign-in that ran less than
    ``MIGRATION_SPEND_GRACE_SECONDS`` ago already spent this attempt.
    """
    try:
        _call("pass_spend", deadline, base._dynamodb().update_item,
              TableName=web.web_table_name(env), Key=web.pass_key(email_fp),
              UpdateExpression="SET attempts_left = attempts_left - :one",
              ConditionExpression=("attempts_left > :zero AND expires_at > :now AND "
                                   "(attribute_not_exists(migration_spent_at) OR migration_spent_at < :recent)"),
              ExpressionAttributeValues={":one": _num(1), ":zero": _num(0), ":now": _num(now),
                                         ":recent": _num(now - MIGRATION_SPEND_GRACE_SECONDS)},
              ReturnValuesOnConditionCheckFailure="ALL_OLD")
    except _Stop as exc:
        if exc.provider_code != "ConditionalCheckFailedException":
            raise
        old = getattr(exc, "old_item", None)
        spent = base._n(old, "migration_spent_at") if isinstance(old, Mapping) else None
        expires = base._n(old, web.TTL_ATTRIBUTE) if isinstance(old, Mapping) else None
        if (spent is not None and now - MIGRATION_SPEND_GRACE_SECONDS <= spent <= now
                and expires is not None and expires > now):
            return
        raise _Stop("pass_missing", MSG_START_FROM_WEB) from None


# --- UserMigration_Authentication ------------------------------------------------

def _record_rejection(env: str, email_fp: str, state: Mapping[str, Any],
                      now: int, deadline: float) -> bool:
    """Count one MAPIT rejection once: attempts and breaker in one transaction.

    Returns True when this rejection locks the email. The lock is decided from
    the value read before the login (no extra read); two racing rejections may
    both add instead of locking, and then the next rejection locks. Racing
    migrations are bounded first by the pass (spent before MAPIT) and by the
    function's reserved concurrency.
    """
    table = web.web_table_name(env)
    attempts = state["attempts"]
    failed = (base._n(attempts, "failed_logins") or 0) if attempts is not None else 0
    locks = failed + 1 >= MAX_FAILED_LOGINS
    expires = web.ttl_value(web.attempts_expires_at(now))
    if locks:
        attempts_op = {"UpdateExpression": "SET locked_until = :until, failed_logins = :zero, expires_at = :exp",
                       "ExpressionAttributeValues": {":until": _num(now + LOCK_SECONDS), ":zero": _num(0),
                                                     ":exp": expires}}
    else:
        attempts_op = {"UpdateExpression": "ADD failed_logins :one SET expires_at = :exp",
                       "ExpressionAttributeValues": {":one": _num(1), ":exp": expires}}
    breaker = state["breaker0"]
    rejections = (base._n(breaker, "rejections") or 0) if breaker is not None else 0
    breaker_values = {":one": _num(1), ":exp": web.ttl_value(web.breaker_expires_at(state["window"]))}
    breaker_expression = "ADD rejections :one SET expires_at = :exp"
    if web.breaker_tripped(max(rejections, 0) + 1):
        breaker_expression += ", open_until = :until"
        breaker_values[":until"] = _num(now + web.BREAKER_OPEN_SECONDS)
    _call("rejection_write", deadline, base._dynamodb().transact_write_items, TransactItems=[
        {"Update": {"TableName": table, "Key": web.attempts_key(email_fp), **attempts_op}},
        {"Update": {"TableName": table, "Key": web.breaker_key(state["window"]),
                    "UpdateExpression": breaker_expression, "ExpressionAttributeValues": breaker_values}},
        {"Update": {"TableName": table, "Key": web.day_key(now), "UpdateExpression": "ADD mapit_rejections :one",
                    "ExpressionAttributeValues": {":one": _num(1)}}},
    ])
    return locks


def _admit(env: str, email_fp: str, state: Mapping[str, Any],
           tenant: str, now: int, deadline: float) -> None:
    table = web.web_table_name(env)
    expires = web.ttl_value(web.person_expires_at(now))
    new = state["person"] is None
    if new:
        person_op = {"Put": {"TableName": table, "Item": {
            **web.person_key(email_fp), "first_login_at": _num(now), "last_login_at": _num(now),
            "login_count": _num(0), "consent_version": {"S": PUBLIC_CONSENT_VERSION},
            "consent_at": _num(now), web.TTL_ATTRIBUTE: expires},
            # A row past expires_at that TTL has not deleted yet counts as absent.
            "ConditionExpression": "attribute_not_exists(pk) OR expires_at <= :now",
            "ExpressionAttributeValues": {":now": _num(now)}}}
    else:
        person_op = {"Update": {"TableName": table, "Key": web.person_key(email_fp),
                                "UpdateExpression": "SET last_login_at = :now, expires_at = :exp",
                                "ConditionExpression": "expires_at > :now",
                                "ExpressionAttributeValues": {":now": _num(now), ":exp": expires}}}
    items = [person_op, {"Put": {"TableName": table, "Item": {
        **web.session_usage_key(tenant), "person_fp": {"S": email_fp}, "login_at": _num(now),
        "calls": _num(0), web.TTL_ATTRIBUTE: web.ttl_value(web.session_usage_expires_at(now))},
        "ConditionExpression": "attribute_not_exists(pk)"}}]
    if new:
        # Atomic with the cap stored now (cap 0 = no cap); open and pause were
        # checked on the row read before MAPIT.
        items.append({"Update": web.claim_seat_update(table)})
        items.append({"Update": {"TableName": table, "Key": web.day_key(now),
                                 "UpdateExpression": "ADD new_people :one",
                                 "ExpressionAttributeValues": {":one": _num(1)}}})
    if not base._has_sdk_time(deadline):
        raise _Stop("admit_no_time")
    try:
        base._dynamodb().transact_write_items(TransactItems=items)
    except Exception as exc:
        if new and _condition_failed(_cancellation(exc), 2):
            raise _Stop("cap_full_race", MSG_FULL, exc) from None
        raise _Stop("admit_failed", MSG_GENERIC, exc) from None


def _count_cap_rejection(env: str, now: int, deadline: float) -> None:
    if not base._has_sdk_time(deadline):
        return
    try:
        base._dynamodb().update_item(TableName=web.web_table_name(env), Key=web.day_key(now),
                                     UpdateExpression="ADD cap_rejections :one",
                                     ExpressionAttributeValues={":one": _num(1)})
    except Exception as exc:
        _log("UserMigration_Authentication", "cap_count_failed", type(exc).__name__, None)


def _user_migration(event: dict[str, Any], context: Any, started: float,
                    environ: Mapping[str, str]) -> dict[str, Any]:
    env = _environment(environ)
    try:
        mapit_config = base._mapit_config(environ)
    except Exception:
        raise _Stop("config_invalid") from None
    deadline = base._budget_deadline(started, context)
    request = event.get("request")
    password = request.get("password") if isinstance(request, Mapping) else None
    if type(password) is not str or not 0 < len(password) <= base.MAX_PASSWORD_CHARS:
        raise _Stop("request_invalid")
    typed = event.get("userName")
    if type(typed) is not str or len(typed) > base.MAX_USERNAME_CHARS:
        raise _Stop("email_invalid", MSG_START_FROM_WEB)
    email = _email(typed)
    email_fp = _email_fp(env, email, deadline)
    now = base._now()
    window = web.breaker_window(now)
    state = _read(env, _login_keys(email_fp, window, person=True), now, deadline)
    state["window"] = window
    config = _gate(state, now)
    if config.pass_required:
        _spend_for_migration(env, email_fp, now, deadline)

    try:
        refresh_token = base._mapit_login(mapit_config, typed.strip(), password,
                                          deadline - base.POST_LOGIN_RESERVE_SECONDS)
    except base.MapitCredentialsRejected:
        locked = _record_rejection(env, email_fp, state, base._now(), deadline)
        raise _Stop("mapit_rejected", MSG_LOCKED if locked else MSG_BAD_CREDENTIALS) from None
    except Exception as exc:
        raise _Stop("mapit_failed", MSG_GENERIC, exc) from None
    if type(refresh_token) is not str or not base._REFRESH_RE.fullmatch(refresh_token):
        raise _Stop("mapit_malformed")

    # Only now, with the password proven, may the answer depend on the person.
    now = base._now()
    person = state["person"]
    if person is None and not config.has_room():
        _count_cap_rejection(env, now, deadline)
        raise _Stop("cap_full", MSG_FULL)
    if (person is not None and base._s(person, "login_day") == _day(now)
            and (base._n(person, "login_day_count") or 0) >= web.DAILY_LOGINS_PER_PERSON):
        raise _Stop("daily_limit", MSG_DAILY_LIMIT)
    tenant = validate_tenant_id(_token_hex(16))
    # Session first, admission second. After MAPIT only one SDK call is
    # guaranteed (POST_LOGIN_RESERVE_SECONDS); if the admission then fails or
    # has no time, no seat, person or usage row was written, and the stored
    # session belongs to a random tenant that no token ever carries: the sweep
    # deletes it by age (SWEEP_AGE_SECONDS) like any other session. The reverse
    # order could take a seat for a sign-in that never got its session.
    _call("session_write", deadline, base._ssm().put_parameter,
          Name=web.web_session_parameter_name(env, tenant), Value=refresh_token,
          Type="SecureString", Overwrite=False, Tier="Standard")
    del refresh_token
    _admit(env, email_fp, state, tenant, base._now(), deadline)
    if base._monotonic() >= deadline:
        raise _Stop("deadline_passed")
    event["response"] = {
        "userAttributes": {"email": email, "email_verified": "true", TENANT_ATTRIBUTE: tenant},
        "finalUserStatus": "CONFIRMED",
        "messageAction": "SUPPRESS",
    }
    return event


# --- PreAuthentication_Authentication --------------------------------------------

def _pre_authentication(event: dict[str, Any], context: Any, started: float,
                        environ: Mapping[str, str]) -> dict[str, Any]:
    env = _environment(environ)
    deadline = base._budget_deadline(started, context)
    request = event.get("request")
    if not isinstance(request, Mapping):
        raise _Stop("request_invalid")
    not_found = request.get("userNotFound", False)
    attributes = request.get("userAttributes") or {}
    if type(not_found) is not bool or not isinstance(attributes, Mapping):
        raise _Stop("request_invalid")
    # An existing user carries its email attribute; an absent one only the typed name.
    email = _email(attributes.get("email") if "email" in attributes else event.get("userName"))
    email_fp = _email_fp(env, email, deadline)
    now = base._now()
    state = _read(env, _login_keys(email_fp, web.breaker_window(now), person=False), now, deadline)
    config = _gate(state, now)
    if not not_found and config.pass_required:
        # The user exists: Cognito checks the password and no migration runs,
        # so this attempt is spent here, unless the migration of this same
        # sign-in just spent it.
        _spend_for_pre_auth(env, email_fp, now, deadline)
    event["response"] = {}
    return event


# --- TokenGeneration_* --------------------------------------------------------------

def _count_login(env: str, email_fp: str, now: int, deadline: float) -> None:
    """One sign-in for the person (daily cap) and the day/month aggregates, atomically."""
    table = web.web_table_name(env)
    common = {":one": _num(1), ":now": _num(now), ":today": {"S": _day(now)},
              ":exp": web.ttl_value(web.person_expires_at(now))}
    attempts = (
        ("ADD login_count :one, login_day_count :one SET last_login_at = :now, expires_at = :exp",
         "expires_at > :now AND login_day = :today AND login_day_count < :max",
         {**common, ":max": _num(web.DAILY_LOGINS_PER_PERSON)}),
        ("ADD login_count :one SET login_day = :today, login_day_count = :one, "
         "last_login_at = :now, expires_at = :exp",
         "expires_at > :now AND (attribute_not_exists(login_day) OR login_day <> :today)",
         common),
    )
    aggregates = [{"Update": {"TableName": table, "Key": key, "UpdateExpression": "ADD logins :one",
                              "ExpressionAttributeValues": {":one": _num(1)}}}
                  for key in (web.day_key(now), web.month_key(now))]
    old: Any = None
    for expression, condition, values in attempts:
        if not base._has_sdk_time(deadline):
            raise _Stop("count_no_time")
        person = {"Update": {"TableName": table, "Key": web.person_key(email_fp),
                             "UpdateExpression": expression, "ConditionExpression": condition,
                             "ExpressionAttributeValues": values,
                             "ReturnValuesOnConditionCheckFailure": "ALL_OLD"}}
        try:
            base._dynamodb().transact_write_items(TransactItems=[person, *aggregates])
            return
        except Exception as exc:
            reasons = _cancellation(exc)
            if not _condition_failed(reasons, 0):
                raise _Stop("count_failed", MSG_GENERIC, exc) from None
            old = reasons[0].get("Item")
    expires = base._n(old, web.TTL_ATTRIBUTE) if isinstance(old, Mapping) else None
    if expires is None or expires <= now:
        raise _Stop("person_absent")
    raise _Stop("daily_limit", MSG_DAILY_LIMIT)


def _token_generation(event: dict[str, Any], context: Any, started: float,
                      environ: Mapping[str, str]) -> dict[str, Any]:
    if event.get("triggerSource") == "TokenGeneration_RefreshTokens":
        raise _Stop("refresh_refused", MSG_SESSION_ENDED)
    env = _environment(environ)
    deadline = base._budget_deadline(started, context)
    request = event.get("request")
    attributes = request.get("userAttributes") if isinstance(request, Mapping) else None
    if not isinstance(attributes, Mapping):
        raise _Stop("request_invalid")
    try:
        validate_tenant_id(attributes.get(TENANT_ATTRIBUTE))
    except MultiuserError:
        raise _Stop("tenant_invalid") from None
    email_fp = _email_fp(env, _email(attributes.get("email")), deadline)
    _count_login(env, email_fp, base._now(), deadline)
    return base._token_generation(event)


def cognito_trigger(event: dict[str, Any], context: Any, started: float,
                    environ: Mapping[str, str]) -> dict[str, Any]:
    source = event.get("triggerSource")
    if source == "UserMigration_Authentication":
        return _run(source, _user_migration, event, context, started, environ)
    if source == "PreAuthentication_Authentication":
        return _run(source, _pre_authentication, event, context, started, environ)
    if type(source) is str and source in base._TOKEN_GENERATION_SOURCES:
        return _run(source, _token_generation, event, context, started, environ)
    if source == "UserMigration_ForgotPassword":
        raise base.IdentityError(MSG_FORGOT_PASSWORD)
    _log("unknown", "trigger_unknown", None, None)
    raise base.IdentityError(MSG_GENERIC)


# --- HTTP: GET /estado ----------------------------------------------------------------

def _json(status: int, state: str) -> dict[str, Any]:
    return {
        "statusCode": status,
        "headers": {"content-type": "application/json", "cache-control": "no-store",
                    "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"},
        "body": json.dumps({"estado": state}),
        "isBase64Encoded": False,
    }


def _status(environ: Mapping[str, str]) -> dict[str, Any]:
    try:
        env = _environment(environ)
        now = base._now()
        deadline = base._monotonic() + STATUS_DEADLINE_SECONDS
        state = _read(env, {"config": web.config_key(), **_breaker_keys(web.breaker_window(now))},
                      now, deadline)
    except web.PublicWebError as exc:
        _log("http_status", exc.code, exc.cause_type, exc.provider_code)
        return _json(503, STATUS_PAUSED)
    except Exception as exc:
        _log("http_status", "unexpected", type(exc).__name__, None)
        return _json(503, STATUS_PAUSED)
    config = web.parse_web_config(state["config"])
    if config.source == web.CONFIG_SOURCE_MALFORMED:
        return _json(200, STATUS_PAUSED)
    if not config.open:
        return _json(200, STATUS_CLOSED)
    if not config.accepting(now) or _breaker_open(state, now):
        return _json(200, STATUS_PAUSED)
    return _json(200, STATUS_OPEN if config.has_room() else STATUS_FULL)


def http_request(event: Mapping[str, Any], environ: Mapping[str, str]) -> dict[str, Any]:
    """Only ``GET /estado`` exists; invitation and privacy pages are 404."""
    context = event.get("requestContext")
    http = context.get("http") if isinstance(context, Mapping) else None
    method = http.get("method") if isinstance(http, Mapping) else None
    if event.get("rawPath") == "/estado" and method == "GET":
        return _status(environ)
    return base._html(404, pages.render_not_found())


__all__ = [
    "PUBLIC_CONSENT_VERSION", "USER_MESSAGES", "MSG_BAD_CREDENTIALS", "MSG_START_FROM_WEB",
    "MSG_PAUSED", "MSG_FULL", "MSG_DAILY_LIMIT", "MSG_SESSION_ENDED", "MSG_FORGOT_PASSWORD",
    "STATUS_OPEN", "STATUS_FULL", "STATUS_CLOSED", "STATUS_PAUSED", "MIGRATION_SPEND_GRACE_SECONDS",
    "cognito_trigger", "http_request",
]
