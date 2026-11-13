"""Offline contract tests for whole-period route reads and the read meter.

The fake MAPIT below implements the route-list contract as this repository
reads it (half-open ``[from, to)`` on ``startedAt``, a byte ceiling per
response, an optional cursor). It proves the code against that reading, not
that MAPIT behaves this way.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import (
    MapitClient,
    MapitHTTPError,
    MapitResponseTooLarge,
    metered_tool_call,
    set_read_meter_sink,
)
from mapit.config import MapitConfig
from mapit.services import DateRangeInput, MapitServices, ServiceError

Z = timezone.utc
SUMMARY = {"vehicles": [{"id": "vehicle-canary", "device": {"state": {}}}]}


def _iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _route(route_id: str, started_at: str, distance: float = 10.0) -> dict:
    start = _iso(started_at)
    return {
        "id": route_id,
        "startedAt": started_at,
        "endedAt": (start + timedelta(minutes=30)).isoformat().replace("+00:00", "Z"),
        "distance": distance,
        "maxSpeed": 40 + distance,
        "avgSpeed": 20,
        "complete": True,
    }


class FakeMapit:
    """Service-level fake: routes filtered by ``[from, to)`` on ``startedAt``."""

    def __init__(self, routes, *, max_routes_per_response=None, cursor_over=None, fail=None, reverse=False):
        self.routes = list(routes)
        self.max_routes = max_routes_per_response
        self.cursor_over = cursor_over
        self.fail = fail or {}
        self.reverse = reverse
        self.windows: list[tuple[str, str]] = []
        self.core_calls = 0

    def get_core(self, path, *, params=None, max_response_bytes=None):
        self.core_calls += 1
        assert path == "/v1/account-summary"
        return SUMMARY

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        assert path == "/v1/routes"
        assert max_response_bytes == 2 * 1024 * 1024
        window = (params["from"], params["to"])
        self.windows.append(window)
        if window in self.fail:
            raise self.fail[window]
        start, end = _iso(params["from"]), _iso(params["to"])
        data = [route for route in self.routes if start <= _iso(route["startedAt"]) < end]
        if self.reverse:
            data.reverse()
        if self.max_routes is not None and len(data) > self.max_routes:
            raise MapitResponseTooLarge()
        payload = {"data": data}
        if self.cursor_over is not None and len(data) > self.cursor_over:
            payload["lastEvaluatedKey"] = {"id": "cursor-canary"}
        return payload


class ForcedMonthlyMapit(FakeMapit):
    """Answers every multi-month window as too large: reproduces month-by-month reads."""

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        start, end = _iso(params["from"]), _iso(params["to"])
        next_month = (start.replace(day=1) + timedelta(days=32)).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        if end > next_month:
            self.windows.append((params["from"], params["to"]))
            raise MapitResponseTooLarge()
        return super().get_geo(path, params=params, max_response_bytes=max_response_bytes)


# Routes at every month edge of the first half of 2026, plus one route per month.
EDGE_ROUTES = [
    _route("jan-first-instant", "2026-01-01T00:00:00Z", 1),
    _route("jan-mid", "2026-01-15T08:00:00Z", 2),
    _route("jan-last-ms", "2026-01-31T23:59:59.999Z", 3),
    _route("feb-first-instant", "2026-02-01T00:00:00Z", 4),
    _route("feb-mid", "2026-02-14T09:00:00Z", 5),
    _route("mar-first-instant", "2026-03-01T00:00:00Z", 6),
    _route("mar-last-ms", "2026-03-31T23:59:59.999Z", 7),
    _route("apr-first-instant", "2026-04-01T00:00:00Z", 8),
    _route("may-mid", "2026-05-20T10:00:00Z", 9),
    _route("jun-last-ms", "2026-06-30T23:59:59.999Z", 10),
    _route("jul-first-instant-outside", "2026-07-01T00:00:00Z", 11),
    _route("dec-last-ms-outside", "2025-12-31T23:59:59.999Z", 12),
]
INSIDE_IDS = sorted(route["id"] for route in EDGE_ROUTES if "outside" not in route["id"])
SEMESTER = ("2026-01-01", "2026-07-01")
MONTHS_2026_H1 = [
    ("2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"),
    ("2026-02-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z"),
    ("2026-03-01T00:00:00.000Z", "2026-04-01T00:00:00.000Z"),
    ("2026-04-01T00:00:00.000Z", "2026-05-01T00:00:00.000Z"),
    ("2026-05-01T00:00:00.000Z", "2026-06-01T00:00:00.000Z"),
    ("2026-06-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"),
]


def _all_outputs(services: MapitServices) -> dict:
    a = DateRangeInput(from_time="2026-01-01", to_time="2026-04-01")
    b = DateRangeInput(from_time="2026-04-01", to_time="2026-07-01")
    return {
        "list": services.list_routes(*SEMESTER).model_dump(mode="json"),
        "distance": services.get_distance(*SEMESTER).model_dump(mode="json"),
        "statistics": services.get_route_statistics(*SEMESTER).model_dump(mode="json"),
        "breakdown": services.get_distance_breakdown(*SEMESTER, "month").model_dump(mode="json"),
        "extremes": services.get_route_extremes(*SEMESTER).model_dump(mode="json"),
        "compare_distance": services.compare_distance_periods(a, b).model_dump(mode="json"),
        "compare_routes": services.compare_route_periods(a, b).model_dump(mode="json"),
    }


def test_period_that_fits_is_one_read_with_the_whole_window():
    mapit = FakeMapit(EDGE_ROUTES)

    result = MapitServices(mapit).list_routes(*SEMESTER)

    assert mapit.core_calls == 1
    assert mapit.windows == [("2026-01-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z")]
    assert sorted(route.route_id for route in result.routes) == INSIDE_IDS


@pytest.mark.parametrize(
    "mapit",
    [
        FakeMapit(EDGE_ROUTES),
        FakeMapit(EDGE_ROUTES, reverse=True),
        FakeMapit(EDGE_ROUTES, max_routes_per_response=4),
        FakeMapit(EDGE_ROUTES, max_routes_per_response=3, reverse=True),
        FakeMapit(EDGE_ROUTES, cursor_over=3),
    ],
    ids=["one-read", "one-read-newest-first", "split", "split-twice-newest-first", "cursor-split"],
)
def test_every_tool_output_matches_month_by_month_reads(mapit):
    expected = _all_outputs(MapitServices(ForcedMonthlyMapit(EDGE_ROUTES)))

    assert _all_outputs(MapitServices(mapit)) == expected


def test_month_by_month_reference_really_reads_each_month():
    mapit = ForcedMonthlyMapit(EDGE_ROUTES)

    MapitServices(mapit).list_routes(*SEMESTER)

    assert [window for window in mapit.windows if window in MONTHS_2026_H1] == MONTHS_2026_H1


def test_edges_neither_duplicate_nor_drop_a_route():
    mapit = FakeMapit(EDGE_ROUTES, max_routes_per_response=3)

    result = MapitServices(mapit).list_routes(*SEMESTER)

    ids = [route.route_id for route in result.routes]
    assert len(ids) == len(set(ids))
    assert sorted(ids) == INSIDE_IDS
    assert result.matched_routes == len(INSIDE_IDS)
    assert [route.route_id for route in result.routes][:3] == ["jan-first-instant", "jan-mid", "jan-last-ms"]


def test_oversized_period_splits_in_halves_and_again_oldest_first():
    # Jan-Jun: 10 routes; Jan-Mar: 7; Apr-Jun: 3; Jan: 3; Feb-Mar: 4.
    mapit = FakeMapit(EDGE_ROUTES, max_routes_per_response=4)

    MapitServices(mapit).list_routes(*SEMESTER)

    assert mapit.windows == [
        ("2026-01-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"),  # 10 > 4: split
        ("2026-01-01T00:00:00.000Z", "2026-04-01T00:00:00.000Z"),  # 7 > 4: split again
        ("2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"),  # 3: fits
        ("2026-02-01T00:00:00.000Z", "2026-04-01T00:00:00.000Z"),  # 4: fits
        ("2026-04-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"),  # 3: fits
    ]


def test_split_preserves_partial_month_edges_of_the_request():
    mapit = ForcedMonthlyMapit([])

    MapitServices(mapit).list_routes("2026-01-15T12:00:00Z", "2026-03-02T06:00:00Z")

    assert mapit.windows == [
        ("2026-01-15T12:00:00.000Z", "2026-03-02T06:00:00.000Z"),  # refused: split
        ("2026-01-15T12:00:00.000Z", "2026-02-01T00:00:00.000Z"),
        ("2026-02-01T00:00:00.000Z", "2026-03-02T06:00:00.000Z"),  # refused: split
        ("2026-02-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z"),
        ("2026-03-01T00:00:00.000Z", "2026-03-02T06:00:00.000Z"),
    ]


def test_one_month_over_the_ceiling_still_fails_like_month_by_month():
    mapit = FakeMapit(EDGE_ROUTES, max_routes_per_response=2)

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes("2026-01-01", "2026-03-01")

    assert error.value.code == "response_too_large"
    assert mapit.windows == [
        ("2026-01-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z"),
        ("2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"),  # 3 routes, one month: no further split
    ]


def test_single_month_period_over_the_ceiling_is_one_read_and_fails():
    mapit = FakeMapit(EDGE_ROUTES, max_routes_per_response=1)

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes("2026-01-01", "2026-02-01")

    assert error.value.code == "response_too_large"
    assert len(mapit.windows) == 1


def test_cursor_on_a_multi_month_window_splits_and_on_one_month_fails_closed():
    mapit = FakeMapit(EDGE_ROUTES, cursor_over=2)

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes("2026-01-01", "2026-03-01")

    assert error.value.code == "pagination_unsupported"
    assert "cursor-canary" not in str(error.value)
    assert mapit.windows == [
        ("2026-01-01T00:00:00.000Z", "2026-03-01T00:00:00.000Z"),
        ("2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z"),
    ]


def test_empty_period_is_one_read_and_empty_results():
    mapit = FakeMapit([])
    services = MapitServices(mapit)

    listed = services.list_routes(*SEMESTER)
    distance = services.get_distance(*SEMESTER)

    assert listed.routes == [] and listed.matched_routes == 0 and listed.truncated is False
    assert distance.distance == 0 and distance.route_count == 0
    assert len(mapit.windows) == 2  # one route read per tool call


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (MapitHTTPError(503, "https://geo.invalid/"), "mapit_unavailable"),
        (MapitHTTPError(429, "https://geo.invalid/"), "rate_limited"),
        (MapitHTTPError(401, "https://geo.invalid/"), "authentication_failed"),
    ],
)
def test_error_in_a_later_chunk_fails_the_whole_call(failure, code):
    failing_window = ("2026-04-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z")
    mapit = FakeMapit(EDGE_ROUTES, max_routes_per_response=7, fail={failing_window: failure})

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes(*SEMESTER)

    assert error.value.code == code
    assert mapit.windows[-1] == failing_window


def test_invalid_shape_in_a_chunk_is_not_split():
    class BadShape(FakeMapit):
        def get_geo(self, path, *, params=None, max_response_bytes=None):
            super().get_geo(path, params=params, max_response_bytes=max_response_bytes)
            return {"rows": []}

    mapit = BadShape(EDGE_ROUTES)

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes(*SEMESTER)

    assert error.value.code == "invalid_response"
    assert len(mapit.windows) == 1


def test_maximum_period_needs_at_most_two_reads_per_month_minus_one():
    # Every multi-month window is refused: 13 month windows -> 2*13-1 route reads.
    mapit = ForcedMonthlyMapit([])

    MapitServices(mapit).list_routes("2025-01-15", "2026-01-16")

    assert len(mapit.windows) == 25


# --- Read meter -------------------------------------------------------------

NOW = datetime.now(Z) + timedelta(hours=1)


def _session(refresh=None):
    return MapitSession(
        "id-token-test", "access-test", "refresh-test", NOW + timedelta(hours=1),
        TemporaryCredentials("AKIA_TEST", "secret-test", "session-test", NOW + timedelta(hours=1)), refresh,
    )


def _wire_client(transport, refresh=None):
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    return MapitClient(config, _session(refresh), transport=transport)


class WireMapit:
    def __init__(self, routes=(), *, auth_failures=0):
        self.routes = list(routes)
        self.gets = 0
        self.auth_failures = auth_failures

    def __call__(self, method, url, headers):
        assert method == "GET"
        self.gets += 1
        if self.auth_failures:
            self.auth_failures -= 1
            raise MapitHTTPError(401, url)
        if url.endswith("/v1/account-summary"):
            return json.dumps(SUMMARY).encode()
        if "/v1/routes?" in url:
            return json.dumps({"data": self.routes}).encode()
        return json.dumps(_route("route-canary", "2026-03-01T10:00:00Z")).encode()


@pytest.fixture
def log_lines():
    lines: list[str] = []
    set_read_meter_sink(lines.append)
    yield lines
    set_read_meter_sink(None)


def test_meter_counts_every_get_and_logs_only_counts(log_lines):
    wire = WireMapit([_route("route-canary", "2026-02-01T10:00:00Z")])
    services = MapitServices(_wire_client(wire))

    with metered_tool_call("list_routes") as meter:
        services.list_routes(*SEMESTER)

    assert meter.reads == wire.gets == 2
    assert [json.loads(line) for line in log_lines] == [
        {"event": "mapit_reads", "tool": "list_routes", "reads": 2, "outcome": "ok"}
    ]
    assert "canary" not in log_lines[0] and "2026" not in log_lines[0]


def test_meter_counts_auth_recovery_retry_and_errors(log_lines):
    wire = WireMapit(auth_failures=1)
    services = MapitServices(_wire_client(wire, refresh=lambda current: None))

    with metered_tool_call("get_vehicle_status"):
        services.get_vehicle_status()
    with pytest.raises(ServiceError):
        with metered_tool_call("get_vehicle_details"):
            wire.auth_failures = 2
            services.get_vehicle_details()

    assert [json.loads(line) for line in log_lines] == [
        {"event": "mapit_reads", "tool": "get_vehicle_status", "reads": 2, "outcome": "ok"},
        {"event": "mapit_reads", "tool": "get_vehicle_details", "reads": 2, "outcome": "error"},
    ]


def test_reads_outside_a_tool_call_are_not_counted_or_logged(log_lines):
    wire = WireMapit()
    MapitServices(_wire_client(wire)).get_vehicle_status()

    assert wire.gets == 1
    assert log_lines == []


def test_a_failing_log_sink_never_changes_the_tool_result():
    def broken(line):
        raise OSError("closed stream")

    set_read_meter_sink(broken)
    try:
        with metered_tool_call("get_vehicle_status") as meter:
            MapitServices(_wire_client(WireMapit())).get_vehicle_status()
    finally:
        set_read_meter_sink(None)
    assert meter.reads == 1


@pytest.mark.parametrize(
    ("name", "run", "reads"),
    [
        ("get_vehicle_status", lambda s: s.get_vehicle_status(), 1),
        ("get_vehicle_details", lambda s: s.get_vehicle_details(), 2),
        ("get_route_detail", lambda s: s.get_route_detail("route-canary"), 2),
        ("list_routes", lambda s: s.list_routes(*SEMESTER), 2),
        ("list_routes_366_days", lambda s: s.list_routes("2025-01-15", "2026-01-16"), 2),
        ("get_distance", lambda s: s.get_distance(*SEMESTER), 2),
        ("get_route_statistics", lambda s: s.get_route_statistics(*SEMESTER), 2),
        ("get_distance_breakdown", lambda s: s.get_distance_breakdown(*SEMESTER, "month"), 2),
        ("get_route_extremes", lambda s: s.get_route_extremes(*SEMESTER), 2),
        (
            "compare_distance_periods",
            lambda s: s.compare_distance_periods(
                DateRangeInput(from_time="2025-07-01", to_time="2026-01-01"),
                DateRangeInput(from_time="2026-01-01", to_time="2026-07-01"),
            ),
            4,
        ),
        (
            "compare_route_periods",
            lambda s: s.compare_route_periods(
                DateRangeInput(from_time="2025-07-01", to_time="2026-01-01"),
                DateRangeInput(from_time="2026-01-01", to_time="2026-07-01"),
            ),
            4,
        ),
    ],
)
def test_reads_per_tool_when_each_period_fits(log_lines, name, run, reads):
    wire = WireMapit()
    with metered_tool_call(name) as meter:
        run(MapitServices(_wire_client(wire)))

    assert meter.reads == wire.gets == reads


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_mcp_tool_calls_log_their_own_name_and_read_count(log_lines):
    from mcp import Client

    from mapit.mcp_server import create_server

    class Provider:
        def get(self):
            return MapitServices(_wire_client(WireMapit()))

    async with Client(create_server(Provider())) as client:
        await client.call_tool("get_vehicle_status", {})
        await client.call_tool("list_routes", {"from_time": SEMESTER[0], "to_time": SEMESTER[1]})
        failed = await client.call_tool("list_routes", {"from_time": "bad", "to_time": SEMESTER[1]})

    assert failed.is_error
    assert [json.loads(line) for line in log_lines] == [
        {"event": "mapit_reads", "tool": "get_vehicle_status", "reads": 1, "outcome": "ok"},
        {"event": "mapit_reads", "tool": "list_routes", "reads": 2, "outcome": "ok"},
        {"event": "mapit_reads", "tool": "list_routes", "reads": 0, "outcome": "error"},
    ]
