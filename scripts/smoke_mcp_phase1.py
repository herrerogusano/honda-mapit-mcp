"""Bounded, redacted Phase 1 MCP smoke test.

The default entry point uses the real in-memory MCP client and the saved-session
service provider.  Returned tool values are inspected only long enough to find
an in-memory route ID for the optional detail call; no response value is
printed, logged, or persisted.
"""

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
    "get_vehicle_status",
    "get_vehicle_details",
    "list_routes",
    "get_distance",
    "compare_distance_periods",
    "get_route_detail",
)


def build_smoke_periods(now: datetime | None = None) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Return two adjacent one-day periods and the short list period."""
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


def _failure(tool_name: str) -> dict[str, object]:
    return {"success": False, "category": f"{tool_name}_failed"}


def _route_id_from_result(result: Any) -> str | None:
    """Extract one route ID without retaining or returning the response body."""
    if bool(getattr(result, "is_error", False)):
        return None
    payload = getattr(result, "structured_content", None)
    if not isinstance(payload, Mapping):
        return None
    routes = payload.get("routes")
    if not isinstance(routes, list):
        return None
    for route in routes:
        if not isinstance(route, Mapping):
            continue
        route_id = route.get("route_id")
        if isinstance(route_id, str) and route_id.strip():
            return route_id
    return None


async def perform_mcp_smoke(
    *,
    client_factory: Callable[[], Any] | None = None,
    now: datetime | None = None,
) -> dict[str, object]:
    """Call the six Phase 1 tools and return only safe status metadata."""
    factory = client_factory or _default_client_factory
    statuses: dict[str, dict[str, object]] = {}
    outer_category: str | None = None
    try:
        async with factory() as client:
            async def call(tool_name: str, arguments: dict[str, object]) -> tuple[dict[str, object], Any | None]:
                try:
                    result = await client.call_tool(tool_name, arguments)
                except Exception:
                    return _failure(tool_name), None
                if bool(getattr(result, "is_error", False)):
                    return _failure(tool_name), None
                return {"success": True}, result

            list_period, period_a, period_b = build_smoke_periods(now)

            statuses["get_vehicle_status"], _ = await call("get_vehicle_status", {})
            statuses["get_vehicle_details"], _ = await call("get_vehicle_details", {})
            statuses["list_routes"], list_result = await call("list_routes", list_period)
            route_id = _route_id_from_result(list_result) if list_result is not None else None
            list_result = None
            statuses["get_distance"], _ = await call("get_distance", list_period)
            statuses["compare_distance_periods"], _ = await call(
                "compare_distance_periods", {"period_a": period_a, "period_b": period_b}
            )
            if route_id is None:
                statuses["get_route_detail"] = {
                    "success": False,
                    "skipped": True,
                    "category": "get_route_detail_skipped",
                }
            else:
                statuses["get_route_detail"], _ = await call("get_route_detail", {"route_id": route_id})
                route_id = None
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
    if outer_category is not None:
        result["success"] = False
    return result


def main() -> int:
    try:
        result = asyncio.run(perform_mcp_smoke())
    except Exception:
        result = {
            "success": False,
            "tools": {tool_name: _failure(tool_name) for tool_name in TOOL_NAMES},
        }
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
