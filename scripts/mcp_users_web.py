"""Operator commands for the public web stack, called from :mod:`scripts.mcp_users`.

    python -m scripts.mcp_users --env dev web-status
    python -m scripts.mcp_users --env dev web-stats [--days 14] [--months 3]
    python -m scripts.mcp_users --env dev web-config [--cap N] [--open true|false]
        [--pause-until 2026-12-01T18:00:00Z|none] [--pass-required true|false] [--yes]

Names come from :mod:`mapit.public_web` (table, session parameter prefix) and
:func:`mapit.public_sweep.web_user_pool_name` (user pool, found by exact name).
``web-status`` and ``web-stats`` only read. ``web-config`` prints the current
and the new configuration and writes nothing without ``--yes``; it writes one
conditional ``UpdateItem`` that sets only the requested attributes, never
``occupied``, and fails if the row changed since it was read. Output holds
counts, ages and configuration values only: never a user name, email, tenant
id, pool id, parameter name or fingerprint.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

from mapit import public_web as web
from mapit.public_sweep import web_user_pool_name

MAX_CAP = 1_000_000
MAX_DAYS = 62
MAX_MONTHS = 24
MAX_POOL_PAGES = 20
MAX_LIST_PAGES = 40          # same bound as the sweep
PROMISE_SECONDS = 3600       # nothing may live one hour or more
DAY_COUNTERS = ("logins", "new_people", "mapit_rejections", "cap_rejections")
MONTH_COUNTERS = ("logins",)
CONFIG_FIELDS = ("open", "pause_until", "cap", "pass_required")
_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(Z|\+00:00)$")
_COUNTER_RE = re.compile(r"^(0|[1-9][0-9]{0,15})$")


class WebAdminError(RuntimeError):
    """Operator-facing failure without user data."""


def _code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise WebAdminError("expected true or false")


def parse_pause(value: str, now: int) -> int:
    """``none`` gives 0; otherwise an ISO-8601 UTC time in the future."""
    if value == "none":
        return 0
    if not _ISO_RE.fullmatch(value):
        raise WebAdminError("--pause-until must be ISO-8601 UTC (for example 2026-12-01T18:00:00Z) or none")
    try:
        epoch = int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        raise WebAdminError("--pause-until is not a valid time") from None
    if epoch <= now:
        raise WebAdminError("--pause-until is not in the future; use none to lift a pause")
    return epoch


def parse_cap(value: int) -> int:
    if type(value) is not int or not 0 <= value <= MAX_CAP:
        raise WebAdminError(f"--cap must be between 0 (no cap) and {MAX_CAP}")
    return value


def _pause_text(pause_until: int) -> str:
    return "none" if pause_until == 0 else _iso(pause_until)


def describe_config(config: web.WebConfig) -> str:
    cap = "none" if config.cap == 0 else str(config.cap)
    return (f"open={str(config.open).lower()} pause_until={_pause_text(config.pause_until)} cap={cap} "
            f"occupied={config.occupied} pass_required={str(config.pass_required).lower()}")


def public_state(config: web.WebConfig, now: int, breaker_open: bool) -> str:
    """The word ``GET /estado`` would answer for this configuration and breaker."""
    if config.source in (web.CONFIG_SOURCE_MALFORMED, web.CONFIG_SOURCE_READ_FAILED):
        return "pausa"
    if not config.open:
        return "cerrado"
    if not config.accepting(now) or breaker_open:
        return "pausa"
    return "abierto" if config.has_room() else "lleno"


def _number(item: Mapping[str, Any] | None, name: str) -> int | None:
    value = item.get(name) if isinstance(item, Mapping) else None
    if not isinstance(value, Mapping) or set(value) != {"N"} or type(value["N"]) is not str:
        return None
    return int(value["N"]) if _COUNTER_RE.fullmatch(value["N"]) else None


class WebAdmin:
    def __init__(self, env: str, *, dynamodb: Any, cognito: Any, ssm: Any,
                 out: Callable[[str], None], clock: Callable[[], float]) -> None:
        self.env = env
        self.table = web.web_table_name(env)
        self.dynamodb, self.cognito, self.ssm = dynamodb, cognito, ssm
        self.out = out
        self.clock = clock

    def _now(self) -> int:
        return int(self.clock())

    # --- reads ---------------------------------------------------------------

    def _get(self, key: web.Key) -> dict[str, Any] | None:
        response = self.dynamodb.get_item(TableName=self.table, Key=key, ConsistentRead=True)
        if not isinstance(response, Mapping):
            raise WebAdminError("table read returned no response")
        return response.get("Item")

    def _config_item(self) -> tuple[dict[str, Any] | None, web.WebConfig]:
        try:
            item = self._get(web.config_key())
        except WebAdminError:
            raise
        except Exception as error:
            raise WebAdminError(f"config read failed ({_code(error) or type(error).__name__})") from None
        return item, web.parse_web_config(item)

    def _breaker(self, now: int) -> tuple[bool, int]:
        """(open, rejections in the current window), read like the identity function."""
        window = web.breaker_window(now)
        open_ = False
        current = 0
        for back in range(3):
            item = self._get(web.breaker_key(window - back))
            expires = _number(item, web.TTL_ATTRIBUTE)
            if item is None or expires is None or expires <= now:
                continue
            if (_number(item, "open_until") or 0) > now:
                open_ = True
            if back == 0:
                current = _number(item, "rejections") or 0
        return open_ or web.breaker_tripped(current), current

    def _pool_id(self) -> str:
        name = web_user_pool_name(self.env)
        found: list[str] = []
        token = None
        for _ in range(MAX_POOL_PAGES):
            request: dict[str, Any] = {"MaxResults": 60}
            if token:
                request["NextToken"] = token
            response = self.cognito.list_user_pools(**request)
            found += [pool["Id"] for pool in response.get("UserPools", []) if pool.get("Name") == name]
            token = response.get("NextToken")
            if not token:
                break
        else:
            raise WebAdminError("user pool listing did not finish")
        if len(found) != 1:
            raise WebAdminError("web user pool not found" if not found else "more than one web user pool")
        return found[0]

    def _ages(self, dates: list[Any], now: int) -> tuple[int, int | None]:
        ages = [max(0, now - int(date.timestamp())) for date in dates if isinstance(date, datetime)]
        if len(ages) != len(dates):
            raise WebAdminError("listing returned an item without a date")
        return len(ages), (max(ages) if ages else None)

    def _session_dates(self) -> tuple[list[Any], bool]:
        path = web.web_session_parameter_prefix(self.env).rstrip("/")
        dates: list[Any] = []
        token = None
        for _ in range(MAX_LIST_PAGES):
            request: dict[str, Any] = {
                "ParameterFilters": [{"Key": "Path", "Option": "Recursive", "Values": [path]}],
                "MaxResults": 50}
            if token:
                request["NextToken"] = token
            response = self.ssm.describe_parameters(**request)
            dates += [item.get("LastModifiedDate") for item in response.get("Parameters", [])]
            token = response.get("NextToken")
            if not token:
                return dates, True
        return dates, False

    def _user_dates(self, pool_id: str) -> tuple[list[Any], bool]:
        dates: list[Any] = []
        token = None
        for _ in range(MAX_LIST_PAGES):
            request: dict[str, Any] = {"UserPoolId": pool_id, "AttributesToGet": [], "Limit": 60}
            if token:
                request["PaginationToken"] = token
            response = self.cognito.list_users(**request)
            dates += [user.get("UserCreateDate") for user in response.get("Users", [])]
            token = response.get("PaginationToken")
            if not token:
                return dates, True
        return dates, False

    def _age_line(self, label: str, dates: list[Any], complete: bool, now: int) -> bool:
        count, oldest = self._ages(dates, now)
        more = "" if complete else " (listing stopped early: more exist)"
        if oldest is None:
            self.out(f"{label}: 0{more}")
            return complete
        within = oldest < PROMISE_SECONDS
        verdict = "under one hour" if within else "ONE HOUR OR OLDER"
        self.out(f"{label}: {count}{more}, oldest {oldest // 60} min {oldest % 60} s ({verdict})")
        return complete and within

    def status(self) -> bool:
        """Print the read-only state. Returns True when nothing is one hour old or older."""
        now = self._now()
        item, config = self._config_item()
        if config.source == web.CONFIG_SOURCE_MALFORMED:
            names = ", ".join(sorted(item)) if isinstance(item, Mapping) else "-"
            self.out(f"config: MALFORMED (service closed); attributes present: {names}")
        else:
            label = "row" if config.source == web.CONFIG_SOURCE_ROW else "no row, defaults"
            self.out(f"config ({label}): {describe_config(config)}")
        breaker_open, rejections = self._breaker(now)
        self.out(f"breaker: {'OPEN' if breaker_open else 'closed'}; MAPIT rejections in this "
                 f"{web.BREAKER_WINDOW_SECONDS // 60}-min window: {rejections}/{web.BREAKER_REJECTIONS}")
        self.out(f"/estado would answer: {public_state(config, now, breaker_open)}")
        cap = "no cap" if config.cap == 0 else str(config.cap)
        self.out(f"seats occupied: {config.occupied} of {cap}")
        users, users_complete = self._user_dates(self._pool_id())
        ok = self._age_line("users in web pool", users, users_complete, now)
        sessions, sessions_complete = self._session_dates()
        return self._age_line("session parameters", sessions, sessions_complete, now) and ok

    def stats(self, days: int, months: int) -> list[tuple[str, dict[str, int | None]]]:
        if type(days) is not int or not 1 <= days <= MAX_DAYS:
            raise WebAdminError(f"--days must be between 1 and {MAX_DAYS}")
        if type(months) is not int or not 1 <= months <= MAX_MONTHS:
            raise WebAdminError(f"--months must be between 1 and {MAX_MONTHS}")
        now = self._now()
        rows: list[tuple[str, dict[str, int | None]]] = []
        self.out(f"{'day (UTC)':<12} " + " ".join(f"{name:>16}" for name in DAY_COUNTERS))
        for back in range(days):
            key = web.day_key(now - back * 86400)
            values = self._counters(key, DAY_COUNTERS)
            rows.append((key[web.PARTITION_KEY]["S"], values))
            self.out(f"{key[web.PARTITION_KEY]['S'][4:]:<12} "
                     + " ".join(f"{_show(values[name]):>16}" for name in DAY_COUNTERS))
        self.out(f"{'month (UTC)':<12} " + " ".join(f"{name:>16}" for name in MONTH_COUNTERS))
        first = datetime.fromtimestamp(now, tz=timezone.utc).replace(day=1, hour=0, minute=0, second=0)
        for back in range(months):
            year, month = divmod(first.year * 12 + first.month - 1 - back, 12)
            key = web.month_key(int(first.replace(year=year, month=month + 1).timestamp()))
            values = self._counters(key, MONTH_COUNTERS)
            rows.append((key[web.PARTITION_KEY]["S"], values))
            self.out(f"{key[web.PARTITION_KEY]['S'][6:]:<12} "
                     + " ".join(f"{_show(values[name]):>16}" for name in MONTH_COUNTERS))
        return rows

    def _counters(self, key: web.Key, names: tuple[str, ...]) -> dict[str, int | None]:
        item = self._get(key)
        if item is None:
            return dict.fromkeys(names, 0)
        return {name: (_number(item, name) if name in item else 0) for name in names}

    # --- web-config ----------------------------------------------------------

    def configure(self, changes: Mapping[str, Any], *, yes: bool) -> bool:
        """Show current and new values; write only with ``yes``. Returns True if written."""
        if not changes or not set(changes) <= set(CONFIG_FIELDS):
            raise WebAdminError("give at least one of --cap, --open, --pause-until, --pass-required")
        item, current = self._config_item()
        if current.source == web.CONFIG_SOURCE_MALFORMED:
            self.out("current: MALFORMED (service closed)")
        else:
            self.out(f"current: {describe_config(current)}")
        new_item = dict(item) if item is not None else dict(web.config_key())
        for name, value in changes.items():
            new_item[name] = {"BOOL": value} if type(value) is bool else {"N": str(value)}
        new = web.parse_web_config(new_item)
        if new.source != web.CONFIG_SOURCE_ROW:
            raise WebAdminError("the row would stay malformed (unknown attribute or wrong type); "
                                "nothing written")
        self.out(f"new:     {describe_config(new)}")
        if changes.get("pass_required") is False:
            self.out("warning: without the pass, sign-ins reach MAPIT without the anti-bot check")
        if not yes:
            self.out("not written; run again with --yes to write")
            return False
        names: dict[str, str] = {"#pk": web.PARTITION_KEY}
        values: dict[str, Any] = {}
        sets: list[str] = []
        conditions = ["attribute_exists(#pk)" if item is not None else "attribute_not_exists(#pk)"]
        for index, (name, value) in enumerate(sorted(changes.items())):
            names[f"#a{index}"] = name
            values[f":v{index}"] = new_item[name]
            sets.append(f"#a{index} = :v{index}")
            if item is not None and name in item:
                values[f":o{index}"] = item[name]
                conditions.append(f"#a{index} = :o{index}")
            else:
                conditions.append(f"attribute_not_exists(#a{index})")
        try:
            self.dynamodb.update_item(
                TableName=self.table, Key=web.config_key(), UpdateExpression="SET " + ", ".join(sets),
                ConditionExpression=" AND ".join(conditions),
                ExpressionAttributeNames=names, ExpressionAttributeValues=values)
        except Exception as error:
            if _code(error) == "ConditionalCheckFailedException":
                raise WebAdminError("the configuration changed while running; nothing written, run again") from None
            raise
        self.out("written")
        return True


def _show(value: int | None) -> str:
    return "?" if value is None else str(value)
