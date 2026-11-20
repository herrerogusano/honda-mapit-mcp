"""Thin MCP adapter for the read-only MAPIT application services."""

from __future__ import annotations

import argparse
from typing import Callable, TypeVar

from mcp.server import MCPServer
from mcp.server.auth.provider import TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .client import metered_tool_call
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
    VehicleIdArgument,
    VehicleList,
    VehicleStatus,
    vehicle_kwargs as _vehicle,
)

T = TypeVar("T")
_READ_ONLY_IDEMPOTENT = ToolAnnotations(readOnlyHint=True, idempotentHint=True)


def _safe_call(tool: str, operation: Callable[[], T]) -> T:
    try:
        with metered_tool_call(tool):
            return operation()
    except ServiceError as exc:
        raise ToolError(f"{exc.code}: {exc.public_message}") from None


def create_server(
    provider: ServiceProvider | None = None,
    *,
    auth_settings: AuthSettings | None = None,
    token_verifier: TokenVerifier | None = None,
    geographic_queries: bool = False,
) -> MCPServer:
    """Build an injectable MCP server; handlers contain no business logic."""
    if (auth_settings is None) != (token_verifier is None):
        raise ValueError("auth_settings and token_verifier must be provided together")
    if auth_settings is not None and provider is None:
        raise ValueError("authenticated server construction requires an explicit provider")
    if type(geographic_queries) is not bool:
        raise ValueError("geographic_queries must be a boolean")
    selected = provider if provider is not None else ServiceProvider()
    server = MCPServer(
        "honda-mapit",
        title="Honda MAPIT (read-only)",
        description="Read-only vehicle status, details, routes and distance summaries from MAPIT.",
        instructions=(
            "All tools are read-only. MAPIT route metric units and route-history completeness are not yet confirmed; "
            "prefer explicitly returned *_km presentation fields, preserve conversion_basis and native-unit metadata, "
            "and never label a native distance as kilometres. Route inference flags are descriptive only, not GPS "
            "accuracy guarantees. An account may have several vehicles: on a vehicle_selection_required error, call "
            "list_vehicles or pick from the error, ask the user when it is unclear, and keep passing the chosen "
            "vehicle_id for the rest of the conversation."
        ),
        version="0.4.0",
        auth=auth_settings,
        token_verifier=token_verifier,
    )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def list_vehicles() -> VehicleList:
        """List the account's vehicles with vehicle_id, model, registration, cancelled flag and status.

        Use it when the user may have several vehicles or after a vehicle_selection_required error. Ask the
        user which vehicle they mean (or pick the obvious one) and keep passing that vehicle_id to every
        vehicle-scoped tool for the rest of the conversation. A cancelled vehicle has no live state: its
        status carries vehicle_cancelled and state_warning.
        """
        return _safe_call("list_vehicles", lambda: selected.get().list_vehicles())

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_vehicle_status(vehicle_id: VehicleIdArgument = None) -> VehicleStatus:
        """Get current or last-known operational state for the selected vehicle."""
        return _safe_call("get_vehicle_status", lambda: selected.get().get_vehicle_status(**_vehicle(vehicle_id)))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_vehicle_details(vehicle_id: VehicleIdArgument = None) -> VehicleDetails:
        """Get stable vehicle, product, plan and dealer metadata."""
        return _safe_call("get_vehicle_details", lambda: selected.get().get_vehicle_details(**_vehicle(vehicle_id)))

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def list_routes(from_time: str, to_time: str, vehicle_id: VehicleIdArgument = None) -> RouteList:
        """List normalized routes with *_km companions where available; inference quality is unknown unless GeoJSON was already present."""
        return _safe_call(
            "list_routes", lambda: selected.get().list_routes(from_time, to_time, **_vehicle(vehicle_id))
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_route_detail(route_id: str, vehicle_id: VehicleIdArgument = None) -> RouteDetail:
        """Get normalized detail, available GeoJSON, explicit *_km presentation, and bounded LineString inference flags."""
        return _safe_call(
            "get_route_detail", lambda: selected.get().get_route_detail(route_id, **_vehicle(vehicle_id))
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_distance(from_time: str, to_time: str, vehicle_id: VehicleIdArgument = None) -> DistanceResult:
        """Sum native distance and provide a UI-correlated, unconfirmed *_km interpretation for a period of at most 366 days."""
        return _safe_call(
            "get_distance", lambda: selected.get().get_distance(from_time, to_time, **_vehicle(vehicle_id))
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def compare_distance_periods(
        period_a: DateRangeInput, period_b: DateRangeInput, vehicle_id: VehicleIdArgument = None
    ) -> DistanceComparison:
        """Compare native totals and additive *_km companions for two bounded periods."""
        return _safe_call(
            "compare_distance_periods",
            lambda: selected.get().compare_distance_periods(period_a, period_b, **_vehicle(vehicle_id)),
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_route_statistics(from_time: str, to_time: str, vehicle_id: VehicleIdArgument = None) -> RouteStatistics:
        """Summarize bounded route distance with *_km companions, count, elapsed duration, and maximum speed."""
        return _safe_call(
            "get_route_statistics",
            lambda: selected.get().get_route_statistics(from_time, to_time, **_vehicle(vehicle_id)),
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_distance_breakdown(
        from_time: str, to_time: str, group_by: GroupBy, vehicle_id: VehicleIdArgument = None
    ) -> DistanceBreakdown:
        """Group bounded native distance and *_km companions by UTC day, month, or year."""
        return _safe_call(
            "get_distance_breakdown",
            lambda: selected.get().get_distance_breakdown(from_time, to_time, group_by, **_vehicle(vehicle_id)),
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def get_route_extremes(from_time: str, to_time: str, vehicle_id: VehicleIdArgument = None) -> RouteExtremes:
        """Return deterministic bounded route and calendar distance extremes with *_km companions."""
        return _safe_call(
            "get_route_extremes",
            lambda: selected.get().get_route_extremes(from_time, to_time, **_vehicle(vehicle_id)),
        )

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def compare_route_periods(
        period_a: DateRangeInput, period_b: DateRangeInput, vehicle_id: VehicleIdArgument = None
    ) -> RoutePeriodComparison:
        """Compare bounded route statistics with safe signed changes."""
        return _safe_call(
            "compare_route_periods",
            lambda: selected.get().compare_route_periods(period_a, period_b, **_vehicle(vehicle_id)),
        )

    if geographic_queries:
        # Optional engine and public-boundary asset are not needed by the
        # ordinary ten-tool/dev package.
        from .geographic_tools import register_geographic_tools

        register_geographic_tools(server, selected)

    return server


mcp = create_server()


def main(argv: list[str] | None = None) -> None:
    """Run stdio MCP; geographic analysis is enabled only by an explicit flag."""
    parser = argparse.ArgumentParser(prog="mapit-mcp")
    parser.add_argument(
        "--geographic-queries",
        action="store_true",
        help="opt in to the bounded public Menorca route-summary tools",
    )
    args = parser.parse_args(argv)
    server = create_server(geographic_queries=args.geographic_queries)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
