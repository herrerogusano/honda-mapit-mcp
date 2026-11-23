"""Read-only vehicle selection counts from the MCP Lambda logs.

    python -m scripts.mcp_users --env dev vehicle-stats [--days 7]

Runs one CloudWatch Logs Insights query (``StartQuery`` then
``GetQueryResults``, nothing else) per MCP log group of the environment: the
invitation-only multiuser function and the public web function. The query
counts the ``vehicle_selection`` lines (``docs/phase-1-mcp-contracts.md``,
"Vehicle selection log") and the command prints only aggregated counts per
field value. It never prints a raw log line, a log stream or a request id. A
log group that does not exist is reported as such.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from mapit.multiuser_common import validate_environment
from mapit.public_web import web_function_name
from scripts.build_multiuser_stack import LOG_RETENTION_DAYS, mcp_function_name

MAX_DAYS = LOG_RETENTION_DAYS   # log retention of both stacks
MAX_POLLS = 60
POLL_SECONDS = 1.0
DIMENSIONS = ("vehicles", "excluded", "cancelled", "basis", "outcome", "vehicle_id_given")

# The line is written by json.dumps with a fixed key order (see
# mapit.services._log_vehicle_selection), so one regular expression reads it
# whether or not Logs Insights discovers the JSON fields itself.
QUERY = (
    "filter @message like /\"event\":\"vehicle_selection\"/\n"
    "| parse @message /\"vehicles\":\"(?<vehicles>[0-9+]+)\",\"cancelled\":\"(?<cancelled>[0-9+]+)\","
    "\"excluded\":\"(?<excluded>[0-9+]+)\",\"basis\":\"(?<basis>[a-z_]+)\","
    "\"vehicle_id_given\":(?<vehicle_id_given>true|false),\"outcome\":\"(?<outcome>[a-z_]+)\"/\n"
    "| stats count(*) as events by vehicles, excluded, cancelled, basis, outcome, vehicle_id_given"
)
_ALLOWED = {
    "vehicles": {"0", "1", "2", "3+"},
    "excluded": {"0", "1", "2+"},
    "cancelled": {"0", "1", "2+"},
    "basis": {"dashboard_filter", "legacy_fallback", "none", "not_read"},
    "outcome": {"ok", "selection_required", "not_found", "read_failed"},
    "vehicle_id_given": {"true", "false"},
}


class LogStatsError(RuntimeError):
    """Operator-facing failure without log content."""


def mcp_log_groups(env: str) -> list[tuple[str, str]]:
    env = validate_environment(env)
    return [
        ("multiuser", f"/aws/lambda/{mcp_function_name(env)}"),
        ("public web", f"/aws/lambda/{web_function_name(env, 'mcp')}"),
    ]


def _code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def _rows(results: list[list[dict[str, str]]]) -> list[dict[str, str]]:
    rows = []
    for result in results:
        row = {item.get("field"): item.get("value") for item in result if isinstance(item, dict)}
        rows.append({name: row.get(name) for name in (*DIMENSIONS, "events")})
    return rows


def summarize(rows: list[dict[str, str | None]]) -> tuple[int, dict[str, dict[str, int]]]:
    """Total events and the count per value of each field; unknown values count as ``other``."""
    totals: dict[str, dict[str, int]] = {name: {} for name in DIMENSIONS}
    total = 0
    for row in rows:
        events = row.get("events")
        if not isinstance(events, str) or not events.isdigit():
            raise LogStatsError("query result has an unexpected shape")
        count = int(events)
        total += count
        for name in DIMENSIONS:
            value = row.get(name)
            key = value if value in _ALLOWED[name] else "other"
            totals[name][key] = totals[name].get(key, 0) + count
    return total, totals


class VehicleLogStats:
    def __init__(self, env: str, *, logs: Any, out: Callable[[str], None] = print,
                 clock: Callable[[], float] = time.time, sleep: Callable[[float], None] | None = None) -> None:
        self.env = validate_environment(env)
        self.logs = logs
        self.out = out
        self.clock = clock
        self.sleep = sleep if sleep is not None else time.sleep

    def _query(self, group: str, days: int) -> list[dict[str, str | None]] | None:
        end = int(self.clock())
        try:
            query_id = self.logs.start_query(logGroupName=group, startTime=end - days * 86400, endTime=end,
                                             queryString=QUERY, limit=10000)["queryId"]
        except Exception as error:
            if _code(error) == "ResourceNotFoundException":
                return None
            raise
        for _ in range(MAX_POLLS):
            response = self.logs.get_query_results(queryId=query_id)
            status = response.get("status")
            if status == "Complete":
                return _rows(response.get("results", []))
            if status not in ("Scheduled", "Running"):
                raise LogStatsError(f"query ended with status {status if isinstance(status, str) else '?'}")
            self.sleep(POLL_SECONDS)
        raise LogStatsError("query did not complete in time")

    def stats(self, days: int) -> dict[str, tuple[int, dict[str, dict[str, int]]] | None]:
        if type(days) is not int or not 1 <= days <= MAX_DAYS:
            raise LogStatsError(f"--days must be between 1 and {MAX_DAYS}")
        summaries: dict[str, tuple[int, dict[str, dict[str, int]]] | None] = {}
        for label, group in mcp_log_groups(self.env):
            rows = self._query(group, days)
            if rows is None:
                summaries[label] = None
                self.out(f"{label}: log group not present")
                continue
            total, totals = summarize(rows)
            summaries[label] = (total, totals)
            self.out(f"{label}: {total} vehicle_selection events in the last {days} days")
            for name in DIMENSIONS:
                values = totals[name]
                self.out(f"  {name:<17} " + (", ".join(f"{key}={values[key]}" for key in sorted(values)) or "-"))
        return summaries


__all__ = ["LogStatsError", "MAX_DAYS", "QUERY", "VehicleLogStats", "mcp_log_groups", "summarize"]
