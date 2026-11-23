"""The ``vehicle_selection`` log line: one per tool call, bucketed counts only.

Synthetic account summaries only (``tests/multi_vehicle_fixtures.py``).
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any

import pytest
from mcp import Client

from tests import multi_vehicle_fixtures as fx
from mapit.client import MapitTransportError, metered_tool_call, set_read_meter_sink
from mapit.mcp_server import create_server
from mapit.services import DateRangeInput, MapitServices, ServiceError, ServiceProvider

PERIOD = ("2026-03-01", "2026-04-01")
A = DateRangeInput(from_time="2026-03-01", to_time="2026-04-01")
B = DateRangeInput(from_time="2026-04-01", to_time="2026-05-01")
AREA = {"type": "Polygon", "coordinates": [[[-10.0, 30.0], [10.0, 30.0], [10.0, 50.0], [-10.0, 50.0], [-10.0, 30.0]]]}
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)

FIELDS = {"event", "tool", "vehicles", "cancelled", "excluded", "basis", "vehicle_id_given", "outcome"}
ENUMS = {
    "vehicles": {"0", "1", "2", "3+"},
    "cancelled": {"0", "1", "2+"},
    "excluded": {"0", "1", "2+"},
    "basis": {"dashboard_filter", "legacy_fallback", "none", "not_read"},
    "vehicle_id_given": {True, False},
    "outcome": {"ok", "selection_required", "not_found", "read_failed", "error"},
}

VEHICLE_TOOLS = {
    "get_vehicle_status": lambda s, **kw: s.get_vehicle_status(**kw),
    "get_vehicle_details": lambda s, **kw: s.get_vehicle_details(**kw),
    "list_routes": lambda s, **kw: s.list_routes(*PERIOD, **kw),
    "get_route_detail": lambda s, **kw: s.get_route_detail("route-synthetic-1", **kw),
    "get_distance": lambda s, **kw: s.get_distance(*PERIOD, **kw),
    "compare_distance_periods": lambda s, **kw: s.compare_distance_periods(A, B, **kw),
    "get_route_statistics": lambda s, **kw: s.get_route_statistics(*PERIOD, **kw),
    "get_distance_breakdown": lambda s, **kw: s.get_distance_breakdown(*PERIOD, "day", **kw),
    "get_route_extremes": lambda s, **kw: s.get_route_extremes(*PERIOD, **kw),
    "compare_route_periods": lambda s, **kw: s.compare_route_periods(A, B, **kw),
    "geographic_summary": lambda s, **kw: s.get_geographic_summary(*PERIOD, AREA, **kw),
    "summer_geographic_summary": lambda s, **kw: s.get_summer_geographic_summary(AREA, 2026, now=NOW, **kw),
}


def _private_values(summary: dict[str, Any]) -> set[str]:
    """Every identifier and free-text value of a synthetic account summary."""
    values = {summary["account"]["id"]}
    for item in summary["vehicles"]:
        if not isinstance(item, dict):
            continue
        for key in ("id", "model", "registrationNumber"):
            if isinstance(item.get(key), str):
                values.add(item[key])
        if isinstance(item.get("device"), dict):
            if isinstance(item["device"].get("id"), str):
                values.add(item["device"]["id"])
            values.add(item["device"]["state"]["location"])
        if isinstance(item.get("subscription"), dict) and item["subscription"]["id"]:
            values.add(item["subscription"]["id"])
        if isinstance(item.get("dealerData"), dict):
            values.add(item["dealerData"]["name"])
    return values


class FailingClient(fx.FakeClient):
    def get_core(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("core", path, params))
        raise MapitTransportError()


@pytest.fixture
def lines():
    captured: list[str] = []
    set_read_meter_sink(captured.append)
    yield captured
    set_read_meter_sink(None)


def selection_lines(captured: list[str]) -> list[dict[str, Any]]:
    records = [json.loads(line) for line in captured]
    return [record for record in records if record["event"] == "vehicle_selection"]


def run_tool(tool: str, client: fx.FakeClient, call, **kwargs):
    with metered_tool_call(tool):
        return call(MapitServices(client), **kwargs)


def expected(tool, vehicles, cancelled, excluded, basis, given, outcome):
    return {"event": "vehicle_selection", "tool": tool, "vehicles": vehicles, "cancelled": cancelled,
            "excluded": excluded, "basis": basis, "vehicle_id_given": given, "outcome": outcome}


# --- one line per scenario ----------------------------------------------------------------------

SCENARIOS = [
    # (name, fixture, tool, kwargs, expected buckets, raised code)
    ("one vehicle", fx.ONE, "list_vehicles", {}, ("1", "0", "0", "dashboard_filter", False, "ok"), None),
    ("two active listed", fx.TWO_ACTIVE, "list_vehicles", {}, ("2", "0", "0", "dashboard_filter", False, "ok"), None),
    ("two active, no id", fx.TWO_ACTIVE, "get_distance", {},
     ("2", "0", "0", "dashboard_filter", False, "selection_required"), "vehicle_selection_required"),
    ("active and cancelled", fx.ACTIVE_AND_CANCELLED, "list_vehicles", {},
     ("2", "1", "0", "dashboard_filter", False, "ok"), None),
    ("sold without device", fx.SOLD_AND_ACTIVE, "get_vehicle_status", {},
     ("1", "0", "1", "dashboard_filter", False, "ok"), None),
    ("pending", fx.PENDING_AND_ACTIVE, "list_routes", {}, ("1", "0", "1", "dashboard_filter", False, "ok"), None),
    ("legacy fallback", fx.LEGACY_ONLY, "get_distance", {}, ("1", "0", "1", "legacy_fallback", False, "ok"), None),
    ("legacy id only", fx.LEGACY_ID_ONLY, "list_vehicles", {}, ("1", "0", "0", "legacy_fallback", False, "ok"), None),
    ("none", fx.NOTHING, "get_vehicle_status", {}, ("0", "0", "0", "none", False, "not_found"), "vehicle_not_found"),
    ("empty account", fx.EMPTY, "list_vehicles", {}, ("0", "0", "0", "none", False, "not_found"), "vehicle_not_found"),
    ("explicit vehicle_id ok", fx.TWO_ACTIVE, "get_distance", {"vehicle_id": "veh-b"},
     ("2", "0", "0", "dashboard_filter", True, "ok"), None),
    ("unknown vehicle_id", fx.TWO_ACTIVE, "get_vehicle_status", {"vehicle_id": "veh-zzz"},
     ("2", "0", "0", "dashboard_filter", True, "not_found"), "vehicle_not_found"),
    ("sold vehicle_id", fx.SOLD_AND_ACTIVE, "list_routes", {"vehicle_id": "veh-sold"},
     ("1", "0", "1", "dashboard_filter", True, "not_found"), "vehicle_not_found"),
    ("malformed vehicle_id", fx.TWO_ACTIVE, "get_vehicle_status", {"vehicle_id": " "},
     ("0", "0", "0", "not_read", True, "not_found"), "vehicle_not_found"),
    ("many vehicles", fx.many(5), "list_vehicles", {}, ("3+", "0", "0", "dashboard_filter", False, "ok"), None),
]
CALLS = {"list_vehicles": lambda s, **kw: s.list_vehicles(**kw), **VEHICLE_TOOLS}


@pytest.mark.parametrize(("name", "fixture", "tool", "kwargs", "buckets", "code"), SCENARIOS,
                         ids=[scenario[0] for scenario in SCENARIOS])
def test_each_scenario_logs_exactly_one_line(lines, name, fixture, tool, kwargs, buckets, code):
    client = fx.FakeClient(fixture)
    if code is None:
        run_tool(tool, client, CALLS[tool], **kwargs)
    else:
        with pytest.raises(ServiceError) as error:
            run_tool(tool, client, CALLS[tool], **kwargs)
        assert error.value.code == code
        # Refused before any route, detail or geo read, as before this change.
        assert all(kind == "core" and path == "/v1/account-summary" for kind, path, _ in client.calls)
    assert selection_lines(lines) == [expected(tool, *buckets)]
    # The selection line comes before the read count line of the same call.
    assert [json.loads(line)["event"] for line in lines] == ["vehicle_selection", "mapit_reads"]


def test_account_summary_read_failure_logs_read_failed(lines):
    client = FailingClient(fx.ONE)
    with pytest.raises(ServiceError) as error:
        run_tool("get_vehicle_status", client, CALLS["get_vehicle_status"])
    assert error.value.code == "mapit_unavailable"
    assert selection_lines(lines) == [expected("get_vehicle_status", "0", "0", "0", "not_read", False, "read_failed")]


@pytest.mark.parametrize("tool", sorted(VEHICLE_TOOLS))
@pytest.mark.parametrize(("kwargs", "outcome"), [({}, "selection_required"), ({"vehicle_id": "veh-b"}, "ok"),
                                                 ({"vehicle_id": "veh-zzz"}, "not_found")])
def test_every_vehicle_scoped_tool_logs_one_line(lines, tool, kwargs, outcome):
    client = fx.FakeClient(fx.TWO_ACTIVE, routes=[])
    if outcome == "ok":
        run_tool(tool, client, VEHICLE_TOOLS[tool], **kwargs)
    else:
        with pytest.raises(ServiceError):
            run_tool(tool, client, VEHICLE_TOOLS[tool], **kwargs)
        assert [path for _, path, _ in client.calls] == ["/v1/account-summary"]
    assert selection_lines(lines) == [
        expected(tool, "2", "0", "0", "dashboard_filter", "vehicle_id" in kwargs, outcome)
    ]


def test_every_line_has_the_fixed_shape(lines):
    for _, fixture, tool, kwargs, _, code in SCENARIOS:
        try:
            run_tool(tool, fx.FakeClient(fixture), CALLS[tool], **kwargs)
        except ServiceError:
            assert code is not None
    records = selection_lines(lines)
    assert len(records) == len(SCENARIOS)
    for record in records:
        assert set(record) == FIELDS
        for name, allowed in ENUMS.items():
            assert record[name] in allowed


def test_nothing_is_logged_outside_a_tool_call(lines):
    service = MapitServices(fx.FakeClient(fx.TWO_ACTIVE))
    service.list_vehicles()
    with pytest.raises(ServiceError):
        service.get_vehicle_status()
    assert lines == []


def test_a_failing_log_sink_never_changes_the_result():
    def broken(_line):
        raise OSError("sink down")

    expected_result = MapitServices(fx.FakeClient(fx.ONE)).list_vehicles()
    set_read_meter_sink(broken)
    try:
        with metered_tool_call("list_vehicles"):
            result = MapitServices(fx.FakeClient(fx.ONE)).list_vehicles()
        with pytest.raises(ServiceError) as error:
            with metered_tool_call("get_distance"):
                MapitServices(fx.FakeClient(fx.TWO_ACTIVE)).get_distance(*PERIOD)
    finally:
        set_read_meter_sink(None)
    assert result == expected_result
    assert error.value.code == "vehicle_selection_required"


# --- bucket edges -------------------------------------------------------------------------------


def _active(index, **kwargs):
    return fx.vehicle(f"veh-e{index}", device_id=f"device-e{index}", subscription=f"sub-e{index}", **kwargs)


def _sold(index):
    return fx.vehicle(f"veh-s{index}", device=False)


@pytest.mark.parametrize(("summary", "buckets"), [
    (fx.summary(_active(0), _active(1)), ("2", "0", "0")),
    (fx.summary(_active(0), _active(1), _active(2)), ("3+", "0", "0")),
    (fx.summary(_active(0, cancelled=True), _active(1, cancelled=True)), ("2", "2+", "0")),
    (fx.summary(*[_active(i, cancelled=True) for i in range(3)]), ("3+", "2+", "0")),
    (fx.summary(_active(0), _sold(1), _sold(2)), ("1", "0", "2+")),
    (fx.summary(_active(0), _sold(1), _sold(2), _sold(3)), ("1", "0", "2+")),
    (fx.summary(_active(0), _sold(1), _active(2, pending=True)), ("1", "0", "2+")),
], ids=["2 active", "3 active", "2 cancelled", "3 cancelled", "2 excluded", "3 excluded", "sold and pending"])
def test_bucket_edges(lines, summary, buckets):
    run_tool("list_vehicles", fx.FakeClient(summary), CALLS["list_vehicles"])
    vehicles, cancelled, excluded = buckets
    assert selection_lines(lines) == [
        expected("list_vehicles", vehicles, cancelled, excluded, "dashboard_filter", False, "ok")
    ]


# --- logging failures never change results ------------------------------------------------------


def test_a_failure_while_preparing_the_line_never_changes_the_result(lines, monkeypatch):
    import mapit.services as services_module

    expected_result = MapitServices(fx.FakeClient(fx.ONE)).list_vehicles()

    def broken(*_args):
        raise RuntimeError("bucket failed")

    monkeypatch.setattr(services_module, "_bucket", broken)
    result = run_tool("list_vehicles", fx.FakeClient(fx.ONE), CALLS["list_vehicles"])
    assert result == expected_result
    with pytest.raises(ServiceError) as error:
        run_tool("get_distance", fx.FakeClient(fx.TWO_ACTIVE), CALLS["get_distance"])
    assert error.value.code == "vehicle_selection_required"
    with pytest.raises(ServiceError) as error:
        run_tool("get_vehicle_status", fx.FakeClient(fx.TWO_ACTIVE), CALLS["get_vehicle_status"], vehicle_id=" ")
    assert error.value.code == "vehicle_not_found"
    # No selection line, but the read meter lines are still written.
    assert selection_lines(lines) == []
    assert [json.loads(line)["event"] for line in lines] == ["mapit_reads"] * 3


# --- concurrent tool calls ----------------------------------------------------------------------


class SlowStream:
    """Records every write call; sleeps inside write so unlocked writers overlap."""

    def __init__(self):
        self.writes: list[str] = []
        self.active = 0
        self.overlaps = 0

    def write(self, text):
        self.active += 1
        if self.active > 1:
            self.overlaps += 1
        time.sleep(0.0005)
        self.writes.append(text)
        self.active -= 1
        return len(text)

    def flush(self):
        pass


def test_concurrent_tool_calls_write_whole_lines_one_at_a_time(monkeypatch):
    stream = SlowStream()
    monkeypatch.setattr(sys, "stderr", stream)
    set_read_meter_sink(None)  # the real stderr sink

    def worker(fixture, tool):
        for _ in range(20):
            try:
                run_tool(tool, fx.FakeClient(fixture), CALLS[tool])
            except ServiceError:
                pass

    threads = [threading.Thread(target=worker, args=args)
               for args in ((fx.ONE, "list_vehicles"), (fx.TWO_ACTIVE, "get_distance"))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert stream.overlaps == 0
    # 2 threads x 20 calls x (selection line + read meter line), one write each.
    assert len(stream.writes) == 80
    for chunk in stream.writes:
        assert chunk.endswith("\n") and chunk.count("\n") == 1
        assert set(json.loads(chunk)) in (FIELDS, {"event", "tool", "reads", "outcome"})


# --- no vehicle data anywhere in the logs -------------------------------------------------------

PRIVATE_FIXTURES = [fx.ONE, fx.TWO_ACTIVE, fx.ACTIVE_AND_CANCELLED, fx.SOLD_AND_ACTIVE, fx.PENDING_AND_ACTIVE,
                    fx.LEGACY_ONLY]


def test_service_layer_logs_carry_no_vehicle_data(lines, caplog):
    caplog.set_level(logging.DEBUG)
    private: set[str] = set()
    for _, fixture, tool, kwargs, _, _ in SCENARIOS:
        private |= _private_values(fixture) - set(kwargs.values())
        try:
            run_tool(tool, fx.FakeClient(fixture), CALLS[tool], **kwargs)
        except ServiceError:
            pass
    output = "\n".join(lines) + "\n" + caplog.text
    assert selection_lines(lines)
    for value in private:
        assert value not in output, value
    # The vehicle_id the caller passed is not echoed into our lines either.
    for line in lines:
        assert "veh-" not in line and "SYN" not in line


@pytest.mark.anyio
async def test_mcp_end_to_end_logs_carry_no_vehicle_data(caplog, capfd):
    """Default stderr sink and the SDK's own logging at DEBUG, through the MCP client."""
    caplog.set_level(logging.DEBUG)
    passed = {"veh-cancelled", "veh-active", "veh-zzz"}
    for fixture in PRIVATE_FIXTURES:
        provider = ServiceProvider(lambda fixture=fixture: MapitServices(fx.FakeClient(fixture)))
        async with Client(create_server(provider, geographic_queries=True), raise_exceptions=True) as client:
            await client.call_tool("list_vehicles", {})
            await client.call_tool("get_vehicle_status", {})
            await client.call_tool("get_vehicle_details", {})
            await client.call_tool("get_distance", {"from_time": PERIOD[0], "to_time": PERIOD[1]})
            await client.call_tool("get_vehicle_status", {"vehicle_id": "veh-cancelled"})
            await client.call_tool("list_routes", {"from_time": PERIOD[0], "to_time": PERIOD[1],
                                                   "vehicle_id": "veh-active"})
            await client.call_tool("get_vehicle_status", {"vehicle_id": "veh-zzz"})
    stderr = capfd.readouterr().err
    records = [json.loads(line) for line in stderr.splitlines() if line.startswith('{"event":"vehicle_selection"')]
    assert len(records) == 7 * len(PRIVATE_FIXTURES)
    assert all(set(record) == FIELDS for record in records)
    # Our own lines never carry a vehicle_id, even one the caller passed.
    for line in stderr.splitlines():
        if line.startswith('{"event":'):
            assert "veh-" not in line and "SYN" not in line and "device-" not in line
    private: set[str] = set()
    for fixture in PRIVATE_FIXTURES:
        private |= _private_values(fixture) - passed
    # Models, registrations, device and subscription ids, account id and
    # location never reach any log: ours (stderr) or the SDK's (logging).
    for value in private:
        assert value not in caplog.text, value
        assert value not in stderr, value
