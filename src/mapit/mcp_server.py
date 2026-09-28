"""Thin MCP adapter for the read-only MAPIT application services."""

from __future__ import annotations

from typing import Callable, TypeVar

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .services import (
    DateRangeInput,
    DistanceComparison,
    DistanceBreakdown,
    DistanceResult,
    GroupBy,
    MapitServices,
    RouteDetail,
    RouteExtremes,
    RouteList,
    RoutePeriodComparison,
    RouteStatistics,
    ServiceError,
    ServiceProvider,
    VehicleDetails,
    VehicleStatus,
)

T = TypeVar("T")
_READ_ONLY_IDEMPOTENT = ToolAnnotations(readOnlyHint=True, idempotentHint=True)


def _safe_call(operation: Callable[[], T]) -> T:
    try:
        return operation()
    except ServiceError as exc:
        raise ToolError(f"{exc.code}: {exc.public_message}") from None


def create_server(provider: ServiceProvider | None = None) -> MCPServer:
    """Build an injectable MCP server; handlers contain no business logic."""
    selected = provider or ServiceProvider()
    server = MCPServer(
        "honda-mapit",
        title="Honda MAPIT (read-only)",
        description="Read-only vehicle status, details, routes and distance summaries from MAPIT.",
        instructions=(
            "All tools are read-only. MAPIT route metric units and route-history completeness are not yet confirmed; "
            "preserve the explicit metadata returned by each tool."
        ),
        version="0.4.0",
    )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_vehicle_status() -> VehicleStatus:
        """Get current or last-known operational state for the selected vehicle."""
        return _safe_call(lambda: selected.get().get_vehicle_status())

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_vehicle_details() -> VehicleDetails:
        """Get stable vehicle, product, plan and dealer metadata."""
        return _safe_call(lambda: selected.get().get_vehicle_details())

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def list_routes(from_time: str, to_time: str) -> RouteList:
        """List normalized routes in an inclusive/exclusive ISO 8601 period of at most 366 days."""
        return _safe_call(lambda: selected.get().list_routes(from_time, to_time))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_route_detail(route_id: str) -> RouteDetail:
        """Get normalized detail and available GeoJSON for one route."""
        return _safe_call(lambda: selected.get().get_route_detail(route_id))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_distance(from_time: str, to_time: str) -> DistanceResult:
        """Sum MAPIT's native distance values for a period of at most 366 days."""
        return _safe_call(lambda: selected.get().get_distance(from_time, to_time))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def compare_distance_periods(period_a: DateRangeInput, period_b: DateRangeInput) -> DistanceComparison:
        """Compare native MAPIT distance totals for two bounded periods."""
        return _safe_call(lambda: selected.get().compare_distance_periods(period_a, period_b))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_route_statistics(from_time: str, to_time: str) -> RouteStatistics:
        """Summarize bounded route distance, count, elapsed duration, and maximum speed."""
        return _safe_call(lambda: selected.get().get_route_statistics(from_time, to_time))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_distance_breakdown(from_time: str, to_time: str, group_by: GroupBy) -> DistanceBreakdown:
        """Group bounded native route distance by UTC day, month, or year."""
        return _safe_call(lambda: selected.get().get_distance_breakdown(from_time, to_time, group_by))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_route_extremes(from_time: str, to_time: str) -> RouteExtremes:
        """Return deterministic bounded route and calendar distance extremes."""
        return _safe_call(lambda: selected.get().get_route_extremes(from_time, to_time))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def compare_route_periods(period_a: DateRangeInput, period_b: DateRangeInput) -> RoutePeriodComparison:
        """Compare bounded route statistics with safe signed changes."""
        return _safe_call(lambda: selected.get().compare_route_periods(period_a, period_b))

    return server


mcp = create_server()


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
