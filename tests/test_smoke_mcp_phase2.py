from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

from scripts import smoke_mcp_phase2 as smoke


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


def _responses(*, observed_count=1, error_tool=None):
    return {
        "get_route_statistics": FakeResult(
            structured_content={"observed_route_count": observed_count, "private_metric": 10},
            is_error=error_tool == "get_route_statistics",
        ),
        "get_distance_breakdown": FakeResult(
            structured_content={"buckets": [{"bucket": "private-date"}]},
            is_error=error_tool == "get_distance_breakdown",
        ),
        "get_route_extremes": FakeResult(
            structured_content={"longest_route": {"route_id": "private-route"}},
            is_error=error_tool == "get_route_extremes",
        ),
        "compare_route_periods": FakeResult(
            structured_content={"distance_difference": 10},
            is_error=error_tool == "compare_route_periods",
        ),
    }


def test_phase2_smoke_success_calls_exactly_four_tools_and_redacts_values():
    client = FakeClient(_responses())

    result = asyncio.run(
        smoke.perform_mcp_phase2_smoke(
            client_factory=lambda: client,
            now=datetime(2026, 9, 28, 12, tzinfo=timezone.utc),
        )
    )

    assert result["success"] is True
    assert [name for name, _ in client.calls] == list(smoke.TOOL_NAMES)
    assert client.calls[0][1] == {"from_time": "2026-08-28", "to_time": "2026-09-28"}
    assert client.calls[1][1] == {
        "from_time": "2026-08-28",
        "to_time": "2026-09-28",
        "group_by": "month",
    }
    assert client.calls[3][1] == {
        "period_a": {"from_time": "2026-09-26", "to_time": "2026-09-27"},
        "period_b": {"from_time": "2026-09-27", "to_time": "2026-09-28"},
    }
    rendered = json.dumps(result)
    assert "private" not in rendered
    assert "2026-" not in rendered


def test_phase2_smoke_requires_observed_route_for_statistics():
    client = FakeClient(_responses(observed_count=0))

    result = asyncio.run(smoke.perform_mcp_phase2_smoke(client_factory=lambda: client))

    assert result["success"] is False
    assert result["tools"]["get_route_statistics"] == {
        "success": False,
        "category": "get_route_statistics_no_routes",
    }
    assert len(client.calls) == 4


def test_phase2_smoke_reduces_tool_error_without_exception_details():
    client = FakeClient(_responses(error_tool="get_route_extremes"))

    result = asyncio.run(smoke.perform_mcp_phase2_smoke(client_factory=lambda: client))

    assert result["success"] is False
    assert result["tools"]["get_route_extremes"] == {
        "success": False,
        "category": "get_route_extremes_failed",
    }
    assert "private" not in json.dumps(result)


def test_phase2_smoke_fails_on_client_close_failure():
    client = FakeClient(_responses(), close_error=RuntimeError("private close detail"))

    result = asyncio.run(smoke.perform_mcp_phase2_smoke(client_factory=lambda: client))

    assert result["success"] is False
    assert result["category"] == "mcp_client_close_failed"
    assert "private close detail" not in json.dumps(result)
