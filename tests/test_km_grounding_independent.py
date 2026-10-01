"""Independent regression probes for bounded distance-claim grounding."""

from mapit.agent import AgentAnswer
from mapit.agent_eval import (
    SyntheticRun,
    _grounded_km_values,
    _unsupported_claim,
)
from mcp import Client
from mapit.mcp_server import create_server
from mapit.services import RouteDetail
import pytest


_BASIS = "ui_correlated_meter_interpretation_unconfirmed"


@pytest.fixture
def anyio_backend():
    return "asyncio"


class _SyntheticServices:
    def get_route_detail(self, route_id):
        return RouteDetail(
            route_id="synthetic-route",
            distance=1200,
            distance_km=1.2,
            has_inferred_segments=True,
            inference_quality_status="inferred_present",
        )


class _SyntheticProvider:
    def get(self):
        return _SyntheticServices()


def test_grounded_km_does_not_turn_whitespace_separated_speed_units_into_distance():
    grounded = {(1.2, False)}

    assert _unsupported_claim("Speed was 1.2 km / h.", grounded) is True
    assert _unsupported_claim("Speed was 1.2 km\t/\th.", grounded) is True


def test_unicode_negative_sign_cannot_be_grounded_by_an_unsigned_distance():
    assert _unsupported_claim("Difference: −1.2 km.", {(1.2, False)}) is True


def test_nested_raw_geojson_distance_key_does_not_ground_a_km_claim():
    record = SyntheticRun(
        answer=AgentAnswer(answer="The value is 1.2 km.", needs_clarification=False),
        used_tool_names=["get_route_detail"],
        tool_calls=[{"name": "get_route_detail", "args": {}}],
        tool_results=[
            {
                "name": "get_route_detail",
                "status": "ok",
                "structured_content": {
                    "conversion_basis": _BASIS,
                    "distance": 1200,
                    "geojson": {
                        "type": "FeatureCollection",
                        "features": [
                            {
                                "type": "Feature",
                                "properties": {"distance_km": 1.2},
                                "geometry": {"type": "Point", "coordinates": [0, 0]},
                            }
                        ],
                    },
                },
            }
        ],
    )

    grounded = _grounded_km_values(record)
    assert (1.2, False) not in grounded
    assert _unsupported_claim(record.answer.answer, grounded) is True


def test_route_list_route_entries_remain_a_valid_grounding_location():
    record = SyntheticRun(
        answer=AgentAnswer(answer="The route was 1.2 km.", needs_clarification=False),
        used_tool_names=["list_routes"],
        tool_calls=[{"name": "list_routes", "args": {}}],
        tool_results=[
            {
                "name": "list_routes",
                "status": "ok",
                "structured_content": {
                    "conversion_basis": _BASIS,
                    "routes": [{"distance": 1200, "distance_km": 1.2}],
                },
            }
        ],
    )

    grounded = _grounded_km_values(record)
    assert (1.2, False) in grounded
    assert _unsupported_claim(record.answer.answer, grounded) is False


def test_nested_statistics_with_conflicting_basis_do_not_ground_km():
    record = SyntheticRun(
        answer=AgentAnswer(answer="Period A was 1.2 km.", needs_clarification=False),
        used_tool_names=["compare_route_periods"],
        tool_calls=[{"name": "compare_route_periods", "args": {}}],
        tool_results=[
            {
                "name": "compare_route_periods",
                "status": "ok",
                "structured_content": {
                    "conversion_basis": _BASIS,
                    "period_a": {
                        "total_distance_km": 1.2,
                        "conversion_basis": "inconsistent_or_unknown",
                    },
                    "period_b": {"total_distance_km": 2.0, "conversion_basis": _BASIS},
                },
            }
        ],
    )

    grounded = _grounded_km_values(record)
    assert (1.2, False) not in grounded
    assert _unsupported_claim(record.answer.answer, grounded) is True


@pytest.mark.anyio
async def test_mcp_protocol_serializes_km_basis_and_inference_indicator():
    async with Client(create_server(_SyntheticProvider()), raise_exceptions=True) as client:
        result = await client.call_tool("get_route_detail", {"route_id": "synthetic-route"})

    assert result.is_error is False
    assert result.structured_content["distance"] == 1200
    assert result.structured_content["distance_km"] == 1.2
    assert result.structured_content["conversion_basis"] == _BASIS
    assert result.structured_content["has_inferred_segments"] is True
