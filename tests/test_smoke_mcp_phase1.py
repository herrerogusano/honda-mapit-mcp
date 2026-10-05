from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from scripts import smoke_mcp_phase1 as smoke


class FakeResult:
    def __init__(self, *, structured_content=None, is_error=False):
        self.structured_content = structured_content
        self.is_error = is_error


class FakeClient:
    def __init__(self, responses, *, close_error=None):
        self.responses = responses
        self.close_error = close_error
        self.calls = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.close_error is not None:
            raise self.close_error
        return False

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        response = self.responses[name]
        if isinstance(response, Exception):
            raise response
        return response


def test_smoke_calls_all_tools_and_never_returns_route_or_period_values():
    route_id = "private-route-id"
    client = FakeClient(
        {
            "get_vehicle_status": FakeResult(structured_content={"status": "private"}),
            "get_vehicle_details": FakeResult(structured_content={"vin": "private-vin"}),
            "list_routes": FakeResult(structured_content={"routes": [{"route_id": route_id}]}),
            "get_distance": FakeResult(structured_content={"distance": 12}),
            "compare_distance_periods": FakeResult(structured_content={"absolute_difference": 1}),
            "get_route_detail": FakeResult(structured_content={"route_id": route_id}),
        }
    )

    result = asyncio.run(
        smoke.perform_mcp_smoke(
            client_factory=lambda: client,
            now=datetime(2026, 9, 28, 12, tzinfo=timezone.utc),
        )
    )

    assert result["success"] is True
    assert [name for name, _ in client.calls] == list(smoke.TOOL_NAMES)
    assert client.calls[2][1] == {"from_time": "2026-08-28", "to_time": "2026-09-28"}
    assert client.calls[4][1] == {
        "period_a": {"from_time": "2026-09-26", "to_time": "2026-09-27"},
        "period_b": {"from_time": "2026-09-27", "to_time": "2026-09-28"},
    }
    assert client.calls[-1][1] == {"route_id": route_id}
    rendered = json.dumps(result)
    assert route_id not in rendered
    assert "private" not in rendered
    assert "2026-09" not in rendered


def test_smoke_marks_route_detail_skipped_when_route_list_has_no_route():
    client = FakeClient(
        {
            "get_vehicle_status": FakeResult(),
            "get_vehicle_details": FakeResult(),
            "list_routes": FakeResult(structured_content={"routes": []}),
            "get_distance": FakeResult(),
            "compare_distance_periods": FakeResult(),
        }
    )

    result = asyncio.run(smoke.perform_mcp_smoke(client_factory=lambda: client))

    assert result["success"] is False
    assert result["tools"]["get_route_detail"] == {
        "success": False,
        "skipped": True,
        "category": "get_route_detail_skipped",
    }
    assert [name for name, _ in client.calls] == [
        "get_vehicle_status",
        "get_vehicle_details",
        "list_routes",
        "get_distance",
        "compare_distance_periods",
    ]


def test_smoke_reduces_tool_errors_to_allowlisted_categories():
    client = FakeClient(
        {
            "get_vehicle_status": FakeResult(is_error=True),
            "get_vehicle_details": RuntimeError("private response body"),
            "list_routes": FakeResult(structured_content={"routes": []}),
            "get_distance": FakeResult(),
            "compare_distance_periods": FakeResult(),
        }
    )

    result = asyncio.run(smoke.perform_mcp_smoke(client_factory=lambda: client))

    assert result["success"] is False
    assert result["tools"]["get_vehicle_status"] == {
        "success": False,
        "category": "get_vehicle_status_failed",
    }
    assert result["tools"]["get_vehicle_details"] == {
        "success": False,
        "category": "get_vehicle_details_failed",
    }
    assert "private response body" not in json.dumps(result)


def test_smoke_fails_when_client_close_fails_after_all_tools_succeed():
    client = FakeClient(
        {
            "get_vehicle_status": FakeResult(),
            "get_vehicle_details": FakeResult(),
            "list_routes": FakeResult(structured_content={"routes": [{"route_id": "private-route"}]}),
            "get_distance": FakeResult(),
            "compare_distance_periods": FakeResult(),
            "get_route_detail": FakeResult(),
        },
        close_error=RuntimeError("private close detail"),
    )

    result = asyncio.run(smoke.perform_mcp_smoke(client_factory=lambda: client))

    assert result["success"] is False
    assert result["category"] == "mcp_client_close_failed"
    assert "private close detail" not in json.dumps(result)
