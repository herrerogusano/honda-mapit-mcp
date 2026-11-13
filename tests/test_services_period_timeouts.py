"""Offline tests for read timeouts on whole-period route reads.

A read timeout on a multi-month window falls back to that window's single
months; on one month the former error stands. Connection failures and HTTP
errors never split. These fakes encode the contract as this repository reads
it; they do not prove how MAPIT behaves.
"""

from __future__ import annotations

import json
import urllib.error

import pytest

from mapit.client import (
    MapitHTTPError,
    MapitResponseTooLarge,
    MapitTimeout,
    MapitTransportError,
    metered_tool_call,
    set_read_meter_sink,
)
from mapit.cloud_transport import CloudDirectTransport
from mapit.services import MapitServices, ServiceError

from test_cloud_transport import Clock, FakeOpener, FakeResponse, _config
from test_services_period_reads import (
    EDGE_ROUTES,
    MONTHS_2026_H1,
    SEMESTER,
    SUMMARY,
    FakeMapit,
    ForcedMonthlyMapit,
    _all_outputs,
    _iso,
    _wire_client,
)

WHOLE_SEMESTER = ("2026-01-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z")


def _months(window: tuple[str, str]) -> int:
    start, end = _iso(window[0]), _iso(window[1])
    return (end.year - start.year) * 12 + end.month - start.month + (1 if end.day > 1 or end.hour else 0)


class SlowMapit(FakeMapit):
    """Times out on every window spanning more than ``max_months`` months."""

    def __init__(self, routes, *, max_months=1, slow_windows=(), **kwargs):
        super().__init__(routes, **kwargs)
        self.max_months = max_months
        self.slow_windows = set(slow_windows)

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        window = (params["from"], params["to"])
        if window in self.slow_windows or _months(window) > self.max_months:
            self.windows.append(window)
            raise MapitTimeout()
        return super().get_geo(path, params=params, max_response_bytes=max_response_bytes)


def test_timeout_on_a_multi_month_window_falls_back_to_its_months():
    mapit = SlowMapit(EDGE_ROUTES)

    MapitServices(mapit).list_routes(*SEMESTER)

    assert mapit.windows == [WHOLE_SEMESTER, *MONTHS_2026_H1]


def test_timeout_fallback_output_matches_month_by_month_reads():
    expected = _all_outputs(MapitServices(ForcedMonthlyMapit(EDGE_ROUTES)))

    assert _all_outputs(MapitServices(SlowMapit(EDGE_ROUTES))) == expected
    assert _all_outputs(MapitServices(SlowMapit(EDGE_ROUTES, max_months=2, reverse=True))) == expected


def test_timeout_on_one_month_fails_as_before():
    mapit = SlowMapit(EDGE_ROUTES, max_months=0)

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes("2026-01-01", "2026-02-01")

    assert error.value.code == "mapit_unavailable"
    assert mapit.windows == [("2026-01-01T00:00:00.000Z", "2026-02-01T00:00:00.000Z")]


def test_timeout_on_a_month_after_fallback_stops_the_whole_call():
    mapit = SlowMapit(EDGE_ROUTES, slow_windows={MONTHS_2026_H1[1]})

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes(*SEMESTER)

    assert error.value.code == "mapit_unavailable"
    assert mapit.windows == [WHOLE_SEMESTER, MONTHS_2026_H1[0], MONTHS_2026_H1[1]]


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        (MapitHTTPError(503, "https://geo.invalid/"), "mapit_unavailable"),
        (MapitHTTPError(504, "https://geo.invalid/"), "mapit_unavailable"),
        (MapitTransportError(), "mapit_unavailable"),
    ],
    ids=["503", "504", "connection"],
)
def test_server_or_connection_error_on_a_multi_month_window_fails_without_split(failure, code):
    mapit = FakeMapit(EDGE_ROUTES, fail={WHOLE_SEMESTER: failure})

    with pytest.raises(ServiceError) as error:
        MapitServices(mapit).list_routes(*SEMESTER)

    assert error.value.code == code
    assert mapit.windows == [WHOLE_SEMESTER]


def test_timeout_inside_a_size_split_falls_back_only_for_that_half():
    first_quarter = ("2026-01-01T00:00:00.000Z", "2026-04-01T00:00:00.000Z")
    second_quarter = ("2026-04-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z")
    mapit = SlowMapit(EDGE_ROUTES, max_months=6, slow_windows={first_quarter}, max_routes_per_response=7)
    mapit.routes = [*EDGE_ROUTES, *[dict(r, id=r["id"] + "-copy") for r in EDGE_ROUTES[:1]]]

    result = MapitServices(mapit).list_routes(*SEMESTER)

    assert mapit.windows == [WHOLE_SEMESTER, first_quarter, *MONTHS_2026_H1[:3], second_quarter]
    assert len(result.routes) == 11


def test_worst_case_timeouts_on_the_maximum_period_cost_one_plus_months_reads():
    mapit = SlowMapit([])

    MapitServices(mapit).list_routes("2025-01-15", "2026-01-16")

    assert len(mapit.windows) == 1 + 13


# --- Classification of timeouts in the transports ------------------------------


def _wire(raise_for_routes):
    calls = []

    def transport(method, url, headers):
        calls.append(url)
        if "/v1/routes?" in url and raise_for_routes(url):
            raise TimeoutError("timed out")
        if url.endswith("/v1/account-summary"):
            return json.dumps(SUMMARY).encode()
        return json.dumps({"data": []}).encode()

    return transport, calls


def test_meter_counts_the_timeout_fallback_reads():
    lines = []
    set_read_meter_sink(lines.append)
    try:
        transport, calls = _wire(lambda url: "from=2026-01-01" in url and "to=2026-07-01" in url)
        with metered_tool_call("list_routes") as meter:
            MapitServices(_wire_client(transport)).list_routes(*SEMESTER)
    finally:
        set_read_meter_sink(None)

    assert meter.reads == len(calls) == 1 + 1 + 6
    assert json.loads(lines[0]) == {"event": "mapit_reads", "tool": "list_routes", "reads": 8, "outcome": "ok"}


@pytest.mark.parametrize(
    ("raised", "expected"),
    [
        (TimeoutError("timed out"), MapitTimeout),
        (urllib.error.URLError(TimeoutError("connect timed out")), MapitTransportError),
        (ConnectionResetError(), MapitTransportError),
    ],
    ids=["read-timeout", "connect-timeout", "reset"],
)
def test_client_classifies_only_read_timeouts_as_timeouts(monkeypatch, raised, expected):
    import mapit.client as client_module

    def injected(method, url, headers):
        raise raised

    def direct(request, *, timeout):
        raise raised

    for client in (_wire_client(injected), _wire_client(None)):
        monkeypatch.setattr(client_module, "open_direct", direct)
        with pytest.raises(MapitTransportError) as error:
            client.get_core("/v1/account-summary")
        assert type(error.value) is expected


def test_cloud_transport_timeout_at_full_read_timeout_is_a_timeout():
    transport = CloudDirectTransport(_config(http_timeout=2.0), deadline=20.0,
                                     opener=FakeOpener(TimeoutError("timed out")), monotonic=Clock(10))

    with pytest.raises(MapitTimeout):
        transport.mapit_request("GET", "https://geo.prod.mapit.me/v1/routes", {})


def test_cloud_transport_body_read_timeout_is_a_timeout():
    class SlowBody(FakeResponse):
        def read1(self, size):
            raise TimeoutError("timed out")

    transport = CloudDirectTransport(_config(http_timeout=2.0), deadline=20.0,
                                     opener=FakeOpener(SlowBody()), monotonic=Clock(10))

    with pytest.raises(MapitTimeout):
        transport.mapit_request("GET", "https://geo.prod.mapit.me/v1/routes", {})


@pytest.mark.parametrize(
    ("raised", "deadline"),
    [
        (TimeoutError("timed out"), 10.25),  # socket timeout cut short by the request deadline
        (urllib.error.URLError(TimeoutError("connect timed out")), 20.0),
        (ConnectionResetError(), 20.0),
    ],
    ids=["deadline-capped", "connect-timeout", "reset"],
)
def test_cloud_transport_other_failures_stay_plain_transport_errors(raised, deadline):
    transport = CloudDirectTransport(_config(http_timeout=2.0), deadline=deadline,
                                     opener=FakeOpener(raised), monotonic=Clock(10))

    with pytest.raises(MapitTransportError) as error:
        transport.mapit_request("GET", "https://geo.prod.mapit.me/v1/routes", {})
    assert type(error.value) is MapitTransportError


def test_size_limit_still_wins_over_timeout_classification():
    mapit = FakeMapit(EDGE_ROUTES, fail={WHOLE_SEMESTER: MapitResponseTooLarge()})

    MapitServices(mapit).list_routes(*SEMESTER)

    assert mapit.windows[1] == ("2026-01-01T00:00:00.000Z", "2026-04-01T00:00:00.000Z")
