"""Bounded, redacted Phase 2 MCP analytics smoke test."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp import Client  # noqa: E402

from mapit.mcp_server import create_server  # noqa: E402


TOOL_NAMES = (
    "get_route_statistics",
    "get_distance_breakdown",
    "get_route_extremes",
    "compare_route_periods",
)


def build_phase2_periods(now: datetime | None = None) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Return a maximum 31-day window and two adjacent one-day subperiods."""
    instant = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    end = instant.date()
    list_start = end - timedelta(days=31)
    comparison_start = end - timedelta(days=2)
    comparison_split = end - timedelta(days=1)
    period_a = {"from_time": comparison_start.isoformat(), "to_time": comparison_split.isoformat()}
    period_b = {"from_time": comparison_split.isoformat(), "to_time": end.isoformat()}
    return (
        {"from_time": list_start.isoformat(), "to_time": end.isoformat()},
        period_a,
        period_b,
    )


def _default_client_factory() -> Any:
    return Client(create_server(), raise_exceptions=True)


def _failure(tool_name: str, category: str | None = None) -> dict[str, object]:
    return {"success": False, "category": category or f"{tool_name}_failed"}


async def perform_mcp_phase2_smoke(
    *,
    client_factory: Callable[[], Any] | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Call exactly the four Phase 2 tools and return only safe status metadata."""
    factory = client_factory or _default_client_factory
    statuses: dict[str, dict[str, object]] = {}
    outer_category: str | None = None
    try:
        async with factory() as client:
            async def call(tool_name: str, arguments: dict[str, object]) -> tuple[dict[str, object], Mapping[str, object] | None]:
                try:
                    result = await client.call_tool(tool_name, arguments)
                except Exception:
                    return _failure(tool_name), None
                if bool(getattr(result, "is_error", False)):
                    return _failure(tool_name), None
                payload = getattr(result, "structured_content", None)
                if not isinstance(payload, Mapping):
                    return _failure(tool_name, f"{tool_name}_invalid_response"), None
                return {"success": True}, payload

            list_period, period_a, period_b = build_phase2_periods(now)
            statuses["get_route_statistics"], stats_payload = await call(
                "get_route_statistics", list_period
            )
            observed_count = stats_payload.get("observed_route_count") if stats_payload is not None else None
            if statuses["get_route_statistics"].get("success") is True and (
                isinstance(observed_count, bool) or not isinstance(observed_count, int) or observed_count < 1
            ):
                statuses["get_route_statistics"] = _failure(
                    "get_route_statistics", "get_route_statistics_no_routes"
                )
            stats_payload = None

            statuses["get_distance_breakdown"], _ = await call(
                "get_distance_breakdown", {**list_period, "group_by": "month"}
            )
            statuses["get_route_extremes"], _ = await call("get_route_extremes", list_period)
            statuses["compare_route_periods"], _ = await call(
                "compare_route_periods", {"period_a": period_a, "period_b": period_b}
            )
    except Exception:
        outer_category = (
            "mcp_client_close_failed" if len(statuses) == len(TOOL_NAMES) else "mcp_client_failed"
        )
        for tool_name in TOOL_NAMES:
            statuses.setdefault(tool_name, _failure(tool_name))

    ordered = {tool_name: statuses.get(tool_name, _failure(tool_name)) for tool_name in TOOL_NAMES}
    result: dict[str, object] = {
        "success": all(status.get("success") is True for status in ordered.values()),
        "tools": ordered,
    }
    if outer_category is not None:
        result["category"] = outer_category
        result["success"] = False
    return result


def main() -> int:
    try:
        result = asyncio.run(perform_mcp_phase2_smoke())
    except Exception:
        result = {
            "success": False,
            "tools": {tool_name: _failure(tool_name) for tool_name in TOOL_NAMES},
            "category": "mcp_client_failed",
        }
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
