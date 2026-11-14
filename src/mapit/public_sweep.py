"""Sweep of the public web mode (function ``web_function_name(env, "sweep")``).

Runs on a schedule (every 5 minutes) and deletes, by age alone, what a public
login leaves behind:

1. MAPIT session parameters under :func:`web_session_parameter_prefix`,
   listed with ``DescribeParameters`` (metadata only: the value is never read)
   and deleted when their ``LastModifiedDate`` is ``SWEEP_AGE_SECONDS`` or
   older. Only names of the exact form :func:`web_session_parameter_name` are
   deleted; the fingerprint key and anything else is never touched.
2. Users of the web user pool (``ListUsers`` without attributes) whose
   ``UserCreateDate`` is ``SWEEP_AGE_SECONDS`` or older (``AdminDeleteUser``).
   Only the pool whose id comes from :data:`POOL_VARIABLE` is used, and only
   after ``DescribeUserPool`` shows that this id is the pool named
   :func:`web_user_pool_name` for the environment. Otherwise the run deletes
   nothing (sessions included) and fails with ``sweep_pool_mismatch`` or
   ``sweep_pool_check_failed``.

Expired table rows are left to DynamoDB TTL: finding them without a scan is not
possible (their keys are fingerprints or tenant ids the sweep does not know),
and readers already treat ``expires_at <= now`` as absent.

Every run writes one log line in CloudWatch embedded metric format (EMF) with
the age of the oldest item seen, how many items were deleted, and whether the
run failed (``SweepFailed``) or stopped early (``SweepIncomplete``). A failed
run also carries the fixed code :data:`FAILURE_CODE` and one code per failed
step. The line never holds a user name, email, tenant id, parameter name or
token. Deleting something that no longer exists is not an error. The run stops
``DEADLINE_MARGIN_MS`` before the Lambda timeout and leaves the rest for the
next run.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .multiuser_common import REGION, validate_environment, validate_tenant_id
from .public_web import (
    MODE_VARIABLE,
    SWEEP_AGE_SECONDS,
    PublicWebError,
    fingerprint_key_parameter_name,
    public_mode_enabled,
    web_session_parameter_name,
    web_session_parameter_prefix,
    web_stack_name,
    web_table_name,
)
from .public_web import CONFIG_SOURCE_ROW, KIND_PERSON, PARTITION_KEY, TTL_ATTRIBUTE, config_key, parse_web_config

ENV_VARIABLE = "MAPIT_MCP_ENV"
POOL_VARIABLE = "MAPIT_WEB_USER_POOL_ID"

FAILURE_CODE = "web_sweep_failed"
METRIC_NAMESPACE = "honda-mapit-mcp/web"
METRIC_DIMENSION = "Environment"

DEADLINE_MARGIN_MS = 15_000       # each AWS call is bounded to about 3 s
FALLBACK_BUDGET_MS = 45_000       # when the context has no remaining-time method
MAX_SESSION_PAGES = 40            # DescribeParameters: at most 50 per page
MAX_USER_PAGES = 40               # ListUsers: at most 60 per page
SESSION_PAGE_SIZE = 50
USER_PAGE_SIZE = 60
CLOCK_SKEW_SECONDS = 300          # a date further in the future is invalid

RECOUNT_WINDOW_START = 3 * 3600   # seconds after 00:00 UTC
RECOUNT_WINDOW_SECONDS = 300      # one 5-minute run falls in it per day
MAX_RECOUNT_PAGES = 200

_POOL_RE = re.compile(r"^eu-west-1_[0-9A-Za-z]{9,45}$")
_TOKEN_MAX = 4096
_USERNAME_MAX = 128

def web_user_pool_name(env: str) -> str:
    """Name the web template must give its user pool (``UserPoolName``).

    The sweep deletes users only in a pool with exactly this name. It differs
    from the invitation stack pool ``honda-mapit-mcp-{env}-users``.
    """
    return f"{web_stack_name(env)}-users"


def in_recount_window(now: int) -> bool:
    """True for the one daily run that recounts seats (03:00-03:05 UTC)."""
    return 0 <= now % 86400 - RECOUNT_WINDOW_START < RECOUNT_WINDOW_SECONDS


STATUS_OK = "ok"
STATUS_INCOMPLETE = "incomplete"
STATUS_FAILED = "failed"


@dataclass
class SweepResult:
    """Counts only; safe to log."""

    codes: list[str] = field(default_factory=list)
    incomplete: bool = False
    sessions_seen: int = 0
    sessions_deleted: int = 0
    sessions_gone: int = 0
    users_seen: int = 0
    users_deleted: int = 0
    users_gone: int = 0
    invalid_dates: int = 0
    oldest_session_age: int = 0
    oldest_user_age: int = 0
    recount_ran: bool = False
    persons_counted: int = 0
    seats_corrected: int = 0
    recount_conflict: bool = False

    def fail(self, code: str) -> None:
        if code not in self.codes:
            self.codes.append(code)

    @property
    def status(self) -> str:
        if self.codes:
            return STATUS_FAILED
        return STATUS_INCOMPLETE if self.incomplete else STATUS_OK

    @property
    def oldest_age(self) -> int:
        return max(self.oldest_session_age, self.oldest_user_age)


def _provider_code(exc: BaseException) -> str | None:
    return PublicWebError("x", cause=exc).provider_code


def _age(value: object, now: float, result: SweepResult) -> int:
    """Age in whole seconds; a missing, naive or far-future date counts as old."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        result.invalid_dates += 1
        return SWEEP_AGE_SECONDS
    age = now - value.timestamp()
    if age < -CLOCK_SKEW_SECONDS:
        result.invalid_dates += 1
        return SWEEP_AGE_SECONDS
    return max(0, int(age))


def _next_token(response: Mapping[str, Any], key: str, previous: str | None) -> str | None:
    token = response.get(key)
    if token is None:
        return None
    if type(token) is not str or not 0 < len(token) <= _TOKEN_MAX or token == previous:
        raise PublicWebError("page_token_invalid")
    return token


class Sweeper:
    """One sweep run against injected SSM and Cognito clients."""

    def __init__(self, *, env: str, user_pool_id: str, ssm: Any, cognito: Any,
                 now: Callable[[], float], remaining_ms: Callable[[], int],
                 dynamodb: Any = None) -> None:
        self._env = validate_environment(env)
        if type(user_pool_id) is not str or not _POOL_RE.fullmatch(user_pool_id):
            raise PublicWebError("sweep_config_invalid")
        self._pool = user_pool_id
        self._ssm = ssm
        self._cognito = cognito
        self._dynamodb = dynamodb
        self._table = web_table_name(self._env)
        self._now = now
        self._remaining_ms = remaining_ms
        self._prefix = web_session_parameter_prefix(self._env)
        self._protected = fingerprint_key_parameter_name(self._env)

    def _time_left(self) -> bool:
        try:
            return int(self._remaining_ms()) > DEADLINE_MARGIN_MS
        except Exception:
            return False

    def run(self) -> SweepResult:
        result = SweepResult()
        if not self._pool_verified(result):
            return result
        self._sweep_sessions(result)
        self._sweep_users(result)
        if self._dynamodb is not None and in_recount_window(int(self._now())):
            self._recount_seats(result)
        return result

    # --- Daily seat recount ------------------------------------------------

    def _recount_seats(self, result: SweepResult) -> None:
        """Set ``occupied`` to the number of unexpired ``person#`` rows.

        Writes only if the scan finished in time, the config row exists and is
        valid, and ``occupied`` still has the value read before the scan (a
        seat claimed meanwhile makes the write a no-op until the next day).
        """
        now = int(self._now())
        if not self._time_left():
            result.incomplete = True
            return
        try:
            item = self._dynamodb.get_item(
                TableName=self._table, Key=config_key(), ConsistentRead=True).get("Item")
        except Exception:
            result.fail("sweep_recount_read_failed")
            return
        if item is None:
            return  # no row: defaults apply and there is nothing to correct
        if parse_web_config(item).source != CONFIG_SOURCE_ROW:
            result.fail("sweep_recount_config_invalid")
            return
        previous = item.get("occupied")
        count = self._count_persons(result, now)
        if count is None:
            return
        result.recount_ran, result.persons_counted = True, count
        before = int(previous["N"]) if previous is not None else 0
        if count == before:
            return
        if not self._time_left():
            result.incomplete = True
            return
        if previous is None:
            condition, values = "attribute_exists(#pk) AND attribute_not_exists(#occ)", {}
        else:
            condition, values = "attribute_exists(#pk) AND #occ = :prev", {":prev": previous}
        try:
            self._dynamodb.update_item(
                TableName=self._table, Key=config_key(), UpdateExpression="SET #occ = :count",
                ConditionExpression=condition,
                ExpressionAttributeNames={"#pk": PARTITION_KEY, "#occ": "occupied"},
                ExpressionAttributeValues={":count": {"N": str(count)}, **values})
        except Exception as exc:
            if _provider_code(exc) == "ConditionalCheckFailedException":
                result.recount_conflict = True
            else:
                result.fail("sweep_recount_write_failed")
            return
        result.seats_corrected = before - count

    def _count_persons(self, result: SweepResult, now: int) -> int | None:
        total = 0
        start: Any = None
        for _ in range(MAX_RECOUNT_PAGES):
            if not self._time_left():
                result.incomplete = True
                return None
            request: dict[str, Any] = {
                "TableName": self._table, "Select": "COUNT", "ConsistentRead": True,
                # A person row without expires_at is counted (fewer free seats).
                "FilterExpression": "begins_with(#pk, :person) AND "
                                    "(attribute_not_exists(#exp) OR #exp > :now)",
                "ExpressionAttributeNames": {"#pk": PARTITION_KEY, "#exp": TTL_ATTRIBUTE},
                "ExpressionAttributeValues": {":person": {"S": f"{KIND_PERSON}#"},
                                              ":now": {"N": str(now)}},
            }
            if start is not None:
                request["ExclusiveStartKey"] = start
            try:
                response = self._dynamodb.scan(**request)
            except Exception:
                result.fail("sweep_recount_scan_failed")
                return None
            count = response.get("Count") if isinstance(response, Mapping) else None
            following = response.get("LastEvaluatedKey") if isinstance(response, Mapping) else None
            if (type(count) is not int or count < 0
                    or (following is not None and (not isinstance(following, Mapping) or following == start))):
                result.fail("sweep_recount_scan_malformed")
                return None
            total += count
            if following is None:
                return total
            start = following
        result.incomplete = True
        return None

    # --- Pool check --------------------------------------------------------

    def _pool_verified(self, result: SweepResult) -> bool:
        """``DescribeUserPool``: the configured id must be the web pool of this env.

        Any mismatch or failure deletes nothing in this run.
        """
        if not self._time_left():
            result.incomplete = True
            return False
        try:
            response = self._cognito.describe_user_pool(UserPoolId=self._pool)
        except Exception:
            result.fail("sweep_pool_check_failed")
            return False
        pool = response.get("UserPool") if isinstance(response, Mapping) else None
        if not isinstance(pool, Mapping):
            result.fail("sweep_pool_check_failed")
            return False
        if pool.get("Id") != self._pool or pool.get("Name") != web_user_pool_name(self._env):
            result.fail("sweep_pool_mismatch")
            return False
        return True

    # --- Sessions ----------------------------------------------------------

    def session_name(self, name: object) -> str | None:
        """The name if it is exactly a web session parameter of this env, else None."""
        if type(name) is not str or name == self._protected or not name.startswith(self._prefix):
            return None
        tenant = name[len(self._prefix):].split("/", 1)[0]
        try:
            validate_tenant_id(tenant)
        except ValueError:
            return None
        return name if name == web_session_parameter_name(self._env, tenant) else None

    def _list_sessions(self, result: SweepResult) -> list[str]:
        now = self._now()
        old: list[str] = []
        token: str | None = None
        path = self._prefix.rstrip("/")
        for _ in range(MAX_SESSION_PAGES):
            if not self._time_left():
                result.incomplete = True
                return old
            request: dict[str, Any] = {
                "ParameterFilters": [{"Key": "Path", "Option": "Recursive", "Values": [path]}],
                "MaxResults": SESSION_PAGE_SIZE,
            }
            if token is not None:
                request["NextToken"] = token
            try:
                response = self._ssm.describe_parameters(**request)
            except Exception:
                result.fail("sweep_sessions_list_failed")
                return old
            try:
                if not isinstance(response, Mapping) or not isinstance(response.get("Parameters"), list):
                    raise PublicWebError("response_invalid")
                token = _next_token(response, "NextToken", token)
            except PublicWebError:
                result.fail("sweep_sessions_list_malformed")
                return old
            for item in response["Parameters"]:
                name = self.session_name(item.get("Name")) if isinstance(item, Mapping) else None
                if name is None:
                    result.fail("sweep_sessions_unexpected")
                    continue
                result.sessions_seen += 1
                age = _age(item.get("LastModifiedDate"), now, result)
                result.oldest_session_age = max(result.oldest_session_age, age)
                if age >= SWEEP_AGE_SECONDS:
                    old.append(name)
            if token is None:
                return old
        result.incomplete = True
        return old

    def _sweep_sessions(self, result: SweepResult) -> None:
        for name in self._list_sessions(result):
            if not self._time_left():
                result.incomplete = True
                return
            if self.session_name(name) is None:  # defence in depth
                result.fail("sweep_sessions_unexpected")
                continue
            try:
                self._ssm.delete_parameter(Name=name)
                result.sessions_deleted += 1
            except Exception as exc:
                if _provider_code(exc) == "ParameterNotFound":
                    result.sessions_gone += 1
                else:
                    result.fail("sweep_sessions_delete_failed")

    # --- Users -------------------------------------------------------------

    def _list_users(self, result: SweepResult) -> list[str]:
        now = self._now()
        old: list[str] = []
        token: str | None = None
        for _ in range(MAX_USER_PAGES):
            if not self._time_left():
                result.incomplete = True
                return old
            request: dict[str, Any] = {
                "UserPoolId": self._pool, "AttributesToGet": [], "Limit": USER_PAGE_SIZE,
            }
            if token is not None:
                request["PaginationToken"] = token
            try:
                response = self._cognito.list_users(**request)
            except Exception:
                result.fail("sweep_users_list_failed")
                return old
            try:
                if not isinstance(response, Mapping) or not isinstance(response.get("Users"), list):
                    raise PublicWebError("response_invalid")
                token = _next_token(response, "PaginationToken", token)
            except PublicWebError:
                result.fail("sweep_users_list_malformed")
                return old
            for user in response["Users"]:
                username = user.get("Username") if isinstance(user, Mapping) else None
                if type(username) is not str or not 0 < len(username) <= _USERNAME_MAX:
                    result.fail("sweep_users_unexpected")
                    continue
                result.users_seen += 1
                age = _age(user.get("UserCreateDate"), now, result)
                result.oldest_user_age = max(result.oldest_user_age, age)
                if age >= SWEEP_AGE_SECONDS:
                    old.append(username)
            if token is None:
                return old
        result.incomplete = True
        return old

    def _sweep_users(self, result: SweepResult) -> None:
        for username in self._list_users(result):
            if not self._time_left():
                result.incomplete = True
                return
            try:
                self._cognito.admin_delete_user(UserPoolId=self._pool, Username=username)
                result.users_deleted += 1
            except Exception as exc:
                if _provider_code(exc) == "UserNotFoundException":
                    result.users_gone += 1
                else:
                    result.fail("sweep_users_delete_failed")


# --- Metrics and log -------------------------------------------------------

_METRICS = (
    ("OldestItemAgeSeconds", "Seconds"),
    ("OldestSessionAgeSeconds", "Seconds"),
    ("OldestUserAgeSeconds", "Seconds"),
    ("SessionsDeleted", "Count"),
    ("UsersDeleted", "Count"),
    ("SweepFailed", "Count"),
    ("SweepIncomplete", "Count"),
    ("InvalidDates", "Count"),
    ("RecountRan", "Count"),
    ("RecountConflict", "Count"),
)
# Only in the line of a run that finished the daily recount.
_RECOUNT_METRICS = (("PersonsCounted", "Count"), ("SeatsCorrected", "Count"))


def emf_record(result: SweepResult, environment: str, timestamp_ms: int) -> dict[str, Any]:
    """The EMF log object for one run (counts, ages and fixed codes only)."""
    failed = result.status == STATUS_FAILED
    record: dict[str, Any] = {
        "_aws": {
            "Timestamp": timestamp_ms,
            "CloudWatchMetrics": [{
                "Namespace": METRIC_NAMESPACE,
                "Dimensions": [[METRIC_DIMENSION]],
                "Metrics": [{"Name": name, "Unit": unit} for name, unit in
                            _METRICS + (_RECOUNT_METRICS if result.recount_ran else ())],
            }],
        },
        METRIC_DIMENSION: environment,
        "OldestItemAgeSeconds": result.oldest_age,
        "OldestSessionAgeSeconds": result.oldest_session_age,
        "OldestUserAgeSeconds": result.oldest_user_age,
        "SessionsDeleted": result.sessions_deleted,
        "UsersDeleted": result.users_deleted,
        "SweepFailed": 1 if failed else 0,
        "SweepIncomplete": 1 if result.incomplete else 0,
        "InvalidDates": result.invalid_dates,
        "RecountRan": 1 if result.recount_ran else 0,
        "RecountConflict": 1 if result.recount_conflict else 0,
        "event": "web_sweep",
        "status": result.status,
        "codes": list(result.codes),
        "sessions_seen": result.sessions_seen,
        "sessions_already_gone": result.sessions_gone,
        "users_seen": result.users_seen,
        "users_already_gone": result.users_gone,
    }
    if result.recount_ran:
        record["PersonsCounted"] = result.persons_counted
        record["SeatsCorrected"] = result.seats_corrected
    if failed:
        record["error"] = FAILURE_CODE
    return record


# --- Lambda handler --------------------------------------------------------

def _make_client(service: str) -> Any:
    # Only the execution role's short-lived credentials, one attempt, short
    # timeouts; explicit kwargs prevent any profile/IMDS fallback.
    if service not in {"ssm", "cognito-idp", "dynamodb"}:
        raise PublicWebError("client_invalid")
    keys = [os.environ.get(name) for name in
            ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")]
    if any(type(value) is not str or not value for value in keys):
        raise PublicWebError("credentials_unavailable")
    import boto3
    from botocore.config import Config

    config = Config(retries={"mode": "standard", "total_max_attempts": 1},
                    connect_timeout=1, read_timeout=2, proxies={})
    return boto3.client(service, region_name=REGION, config=config, aws_access_key_id=keys[0],
                        aws_secret_access_key=keys[1], aws_session_token=keys[2])


_client_factory: Callable[[str], Any] = _make_client
_emit: Callable[[str], None] = lambda line: print(line, file=sys.stdout, flush=True)  # noqa: E731


def _remaining(context: Any, started: float) -> Callable[[], int]:
    method = getattr(context, "get_remaining_time_in_millis", None)
    if callable(method):
        return lambda: int(method())
    return lambda: int(FALLBACK_BUDGET_MS - (time.monotonic() - started) * 1000)


def _environment_label(environ: Mapping[str, str]) -> str:
    try:
        return validate_environment(environ.get(ENV_VARIABLE))
    except ValueError:
        return "invalid"


def run_sweep(environ: Mapping[str, str], context: Any) -> SweepResult:
    """Validate the configuration, create clients and run once; never raises."""
    started = time.monotonic()
    result = SweepResult()
    try:
        if not public_mode_enabled(environ):
            raise PublicWebError("sweep_config_invalid")
        env = validate_environment(environ.get(ENV_VARIABLE))
        pool = environ.get(POOL_VARIABLE)
        if type(pool) is not str or not _POOL_RE.fullmatch(pool):
            raise PublicWebError("sweep_config_invalid")
    except ValueError:
        result.fail("sweep_config_invalid")
        return result
    try:
        ssm, cognito = _client_factory("ssm"), _client_factory("cognito-idp")
        dynamodb = _client_factory("dynamodb")
    except Exception:
        result.fail("sweep_clients_unavailable")
        return result
    try:
        return Sweeper(env=env, user_pool_id=pool, ssm=ssm, cognito=cognito, now=time.time,
                       remaining_ms=_remaining(context, started), dynamodb=dynamodb).run()
    except Exception:
        result.fail("sweep_internal_error")
        return result


def handler(event: Any, context: Any) -> dict[str, Any]:
    """Scheduled entry point. Returns the status; a failure is logged, not raised."""
    environ = os.environ
    result = run_sweep(environ, context)
    record = emf_record(result, _environment_label(environ), int(time.time() * 1000))
    try:
        _emit(json.dumps(record, separators=(",", ":"), sort_keys=True))
    except Exception:
        pass
    return {"status": result.status, "codes": list(result.codes)}


__all__ = [
    "ENV_VARIABLE", "POOL_VARIABLE", "MODE_VARIABLE", "FAILURE_CODE", "METRIC_NAMESPACE",
    "METRIC_DIMENSION", "DEADLINE_MARGIN_MS", "MAX_SESSION_PAGES", "MAX_USER_PAGES",
    "STATUS_OK", "STATUS_INCOMPLETE", "STATUS_FAILED", "SweepResult", "Sweeper",
    "emf_record", "run_sweep", "handler", "web_user_pool_name", "in_recount_window",
    "RECOUNT_WINDOW_START", "RECOUNT_WINDOW_SECONDS", "MAX_RECOUNT_PAGES",
]
