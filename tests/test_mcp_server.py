from __future__ import annotations

import pytest
from mcp import Client

from mapit.mcp_server import create_server
from mapit.services import (
    DateRangeInput,
    DistanceComparison,
    DistanceResult,
    Position,
    RouteDetail,
    RouteList,
    ServiceError,
    VehicleDetails,
    VehicleStatus,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


class StubServices:
    def get_vehicle_status(self):
        return VehicleStatus(status="AT_REST", position=Position(), units_confirmed=False)

    def get_vehicle_details(self):
        return VehicleDetails(model="Model")

    def list_routes(self, from_time, to_time):
        return RouteList(
            from_time=from_time,
            to_time=to_time,
            routes=[],
            matched_routes=0,
            returned_routes=0,
            truncated=False,
        )

    def get_route_detail(self, route_id):
        return RouteDetail(route_id=route_id)

    def get_distance(self, from_time, to_time):
        return DistanceResult(from_time=from_time, to_time=to_time, distance=0, route_count=0)

    def compare_distance_periods(self, period_a, period_b):
        first = self.get_distance(period_a.from_time, period_a.to_time)
        second = self.get_distance(period_b.from_time, period_b.to_time)
        return DistanceComparison(period_a=first, period_b=second, absolute_difference=0, percentage_difference=None)


class StubProvider:
    def __init__(self, service=None):
        self.service = service or StubServices()

    def get(self):
        return self.service


@pytest.mark.anyio
async def test_mcp_exposes_exact_phase_one_tool_contract():
    async with Client(create_server(StubProvider()), raise_exceptions=True) as client:
        tools_result = await client.list_tools()

    tools = tools_result.tools
    assert [tool.name for tool in tools] == [
        "get_vehicle_status",
        "get_vehicle_details",
        "list_routes",
        "get_route_detail",
        "get_distance",
        "compare_distance_periods",
    ]
    assert all(tool.annotations is not None for tool in tools)
    assert all(tool.annotations.read_only_hint is True for tool in tools)
    assert all(tool.annotations.idempotent_hint is True for tool in tools)
    list_routes = next(tool for tool in tools if tool.name == "list_routes")
    assert set(list_routes.input_schema["required"]) == {"from_time", "to_time"}
    assert list_routes.output_schema is not None


@pytest.mark.anyio
async def test_mcp_call_returns_structured_content_through_real_protocol():
    async with Client(create_server(StubProvider()), raise_exceptions=True) as client:
        result = await client.call_tool("get_vehicle_status", {})

    assert result.is_error is False
    assert result.structured_content == {
        "status": "AT_REST",
        "speed": None,
        "battery": None,
        "voltage": None,
        "last_communication": None,
        "last_coordinate_update": None,
        "position": {"latitude": None, "longitude": None, "label": None, "gps_accuracy": None},
        "odometer": None,
        "units_confirmed": False,
    }


@pytest.mark.anyio
async def test_mcp_nested_period_contract_is_validated_and_invoked():
    async with Client(create_server(StubProvider()), raise_exceptions=True) as client:
        result = await client.call_tool(
            "compare_distance_periods",
            {
                "period_a": {"from_time": "2026-01-01", "to_time": "2026-02-01"},
                "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"},
            },
        )

    assert result.is_error is False
    assert result.structured_content["percentage_difference"] is None


@pytest.mark.anyio
async def test_service_errors_are_redacted_tool_errors():
    class FailingServices(StubServices):
        def get_route_detail(self, route_id):
            raise ServiceError("not_found", "the requested MAPIT resource was not found")

    async with Client(create_server(StubProvider(FailingServices())), raise_exceptions=True) as client:
        result = await client.call_tool("get_route_detail", {"route_id": "private-route-id"})

    assert result.is_error is True
    rendered = " ".join(block.text for block in result.content if hasattr(block, "text"))
    assert "not_found" in rendered
    assert "private-route-id" not in rendered
