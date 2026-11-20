"""Multi-vehicle selection: eligibility, list_vehicles, vehicle_id and fallbacks.

Synthetic account summaries only (``tests/multi_vehicle_fixtures.py``).
"""

from __future__ import annotations

import hashlib
import json
import logging

import pydantic_core
import pytest
from mcp import Client
from mcp.server.mcpserver.exceptions import ToolError

from tests import multi_vehicle_fixtures as fx
from mapit.client import set_read_meter_sink
from mapit.mcp_server import create_server
from mapit.services import (
    CANCELLED_STATE_WARNING,
    DateRangeInput,
    MapitServices,
    ServiceError,
    ServiceProvider,
)

PERIOD = ("2026-03-01", "2026-04-01")
A = DateRangeInput(from_time="2026-03-01", to_time="2026-04-01")
B = DateRangeInput(from_time="2026-04-01", to_time="2026-05-01")
AREA = {"type": "Polygon", "coordinates": [[[-10.0, 30.0], [10.0, 30.0], [10.0, 50.0], [-10.0, 50.0], [-10.0, 30.0]]]}

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
    "get_geographic_summary": lambda s, **kw: s.get_geographic_summary(*PERIOD, AREA, **kw),
}

# Recorded from the code before this change (origin/develop) with the same
# fixtures: sha256 of the MCP text content and the vehicle id each tool read.
BEFORE = {
    "compare_distance_periods": "1265bdb65230b9933b82450738cbfa331eb8e0d821ff5caf376c2d45a65e874e",
    "compare_route_periods": "9e0c2d136f8af503c8360713152659cf40be68b736aa8d0adbf6a757ee6d187e",
    "get_distance": "8b3a442064b54194a8d807532e59936998e61c8bc305929f46a3b609b810e4b5",
    "get_distance_breakdown": "bc85ed22287d5ca00740d19f117b3bfae149b623fda489e281243a12b615269b",
    "get_route_detail": "61e95c2decc6801888ddab1df7c182cd9e657388a0204e83eeaa0dcb33993f3f",
    "get_route_extremes": "d1ae3cc66f211486f205d973cd5872d46bd4df81162b8146eec2cc15103c69b7",
    "get_route_statistics": "e5e974fb006376aa66cc7d94adaab9f074a3dd7cdf291e026e8ddee53a82c8ba",
    "get_vehicle_details": "563674efe4dccd4061dc0881cc8a5e3c8b6cb223277b46ed0d01d0514378a116",
    "get_vehicle_status": "9f2d6ced82fc40f368f5b84c3731434377519dd79e366462860800be24189bc0",
    "list_routes": "db04a341fcbe6ed6654f3cab10ef7858d8cc366d23efee384f8598001776ad7c",
}
BEFORE_STATUS_TEXT = """{
  "status": "AT_REST",
  "speed": 0.0,
  "battery": 77.0,
  "voltage": 12.4,
  "last_communication": 1000.0,
  "last_coordinate_update": 900.0,
  "position": {
    "latitude": 40.0,
    "longitude": -3.0,
    "label": "Synthetic Town",
    "gps_accuracy": 1.2
  },
  "odometer": 1234.0,
  "units_confirmed": false
}"""


def services(summary):
    client = fx.FakeClient(summary)
    return MapitServices(client), client


def summary_reads(client) -> int:
    return sum(1 for kind, path, _ in client.calls if kind == "core" and path == "/v1/account-summary")


# --- single-vehicle accounts are unchanged -----------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected_vehicle"),
    [("ONE", "veh-one"), ("LEGACY_ONLY", "veh-legacy-device"), ("SOLD_AND_ACTIVE", "veh-current")],
)
@pytest.mark.parametrize("tool", sorted(BEFORE))
def test_single_vehicle_outputs_are_byte_identical_to_before(fixture, expected_vehicle, tool):
    service, client = services(getattr(fx, fixture))
    result = VEHICLE_TOOLS[tool](service)
    text = pydantic_core.to_json(result, fallback=str, indent=2).decode()
    assert hashlib.sha256(text.encode()).hexdigest() == BEFORE[tool]
    assert set(client.route_vehicle_ids()) <= {expected_vehicle}
    if tool != "get_vehicle_status":
        assert set(client.route_vehicle_ids()) == {expected_vehicle}


def test_single_vehicle_status_text_and_structured_content_unchanged():
    service, _ = services(fx.ONE)
    status = service.get_vehicle_status()
    assert pydantic_core.to_json(status, fallback=str, indent=2).decode() == BEFORE_STATUS_TEXT
    assert status.model_dump(mode="json", by_alias=True) == json.loads(BEFORE_STATUS_TEXT)


def test_explicit_vehicle_id_on_single_vehicle_account_gives_the_same_output():
    implicit, _ = services(fx.ONE)
    explicit, client = services(fx.ONE)
    assert explicit.list_routes(*PERIOD, vehicle_id="veh-one") == implicit.list_routes(*PERIOD)
    assert client.route_vehicle_ids() == ["veh-one"]


# --- eligibility filter -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "expected_ids", "basis"),
    [
        ("ONE", ["veh-one"], "mapit_dashboard_filter"),
        ("TWO_ACTIVE", ["veh-a", "veh-b"], "mapit_dashboard_filter"),
        ("ACTIVE_AND_CANCELLED", ["veh-active", "veh-cancelled"], "mapit_dashboard_filter"),
        ("SOLD_AND_ACTIVE", ["veh-current"], "mapit_dashboard_filter"),
        ("PENDING_AND_ACTIVE", ["veh-ready"], "mapit_dashboard_filter"),
        ("NO_SUBSCRIPTION_AND_ACTIVE", ["veh-paid"], "mapit_dashboard_filter"),
        ("EMPTY_SUBSCRIPTION_ID", ["veh-paid"], "mapit_dashboard_filter"),
        ("SAME_MODEL", ["veh-x", "veh-y"], "mapit_dashboard_filter"),
        ("LEGACY_ONLY", ["veh-legacy-device"], "legacy_single_vehicle_fallback"),
        ("LEGACY_ID_ONLY", ["veh-legacy-only"], "legacy_single_vehicle_fallback"),
    ],
)
def test_list_vehicles_applies_the_dashboard_filter_with_one_read(fixture, expected_ids, basis):
    service, client = services(getattr(fx, fixture))
    listing = service.list_vehicles()
    assert [entry.vehicle_id for entry in listing.vehicles] == expected_ids
    assert listing.vehicle_count == len(expected_ids)
    assert listing.selection_required is (len(expected_ids) > 1)
    assert listing.selection_basis == basis
    assert client.calls == [("core", "/v1/account-summary", None)]


def test_list_vehicles_entry_fields_and_cancelled_status():
    service, _ = services(fx.ACTIVE_AND_CANCELLED)
    active, cancelled = service.list_vehicles().vehicles
    assert (active.model, active.registration, active.cancelled) == ("SYNTH-125", "0001SYN", False)
    assert (cancelled.model, cancelled.registration, cancelled.cancelled) == ("SYNTH-300", "0003SYN", True)
    assert active.status.status == "AT_REST" and active.status.vehicle_cancelled is None
    assert "vehicle_cancelled" not in active.status.model_dump(mode="json")
    assert cancelled.status.vehicle_cancelled is True
    assert cancelled.status.state_warning == CANCELLED_STATE_WARNING
    assert cancelled.status.status == "PARKED"  # last stored value, flagged as not live


def test_duplicate_vehicle_ids_are_listed_once():
    service, _ = services(fx.summary(fx.vehicle("veh-dup"), fx.vehicle("veh-dup", model="OTHER")))
    listing = service.list_vehicles()
    assert [(entry.vehicle_id, entry.model) for entry in listing.vehicles] == [("veh-dup", "SYNTH-125")]
    assert service.get_vehicle_status().status == "AT_REST"


@pytest.mark.parametrize("fixture", ["NOTHING", "EMPTY"])
def test_no_vehicle_at_all_is_vehicle_not_found(fixture):
    service, _ = services(getattr(fx, fixture))
    for call in (service.list_vehicles, service.get_vehicle_status, lambda: service.list_routes(*PERIOD)):
        with pytest.raises(ServiceError) as error:
            call()
        assert error.value.code == "vehicle_not_found"


# --- several vehicles without vehicle_id ----------------------------------------------------


@pytest.mark.parametrize("fixture", ["TWO_ACTIVE", "ACTIVE_AND_CANCELLED", "SAME_MODEL"])
@pytest.mark.parametrize("tool", sorted(VEHICLE_TOOLS))
def test_several_vehicles_without_vehicle_id_require_selection(fixture, tool):
    # The previous rule silently used the first vehicle; this must now fail.
    service, client = services(getattr(fx, fixture))
    with pytest.raises(ServiceError) as error:
        VEHICLE_TOOLS[tool](service)
    assert error.value.code == "vehicle_selection_required"
    assert client.route_vehicle_ids() == []  # no route or detail read for a guessed vehicle
    # MCP frameworks log tool error text: no identifier, model or registration in it.
    message = error.value.public_message
    for vehicle in getattr(fx, fixture)["vehicles"]:
        assert vehicle["id"] not in message
        assert vehicle["model"] not in message
        assert vehicle["registrationNumber"] not in message


def test_selection_message_gives_count_and_points_to_list_vehicles():
    service, _ = services(fx.many(13))
    with pytest.raises(ServiceError) as error:
        service.get_distance(*PERIOD)
    message = error.value.public_message
    assert "13 vehicles" in message and "list_vehicles" in message
    assert "Keep using the chosen vehicle_id" in message
    assert "vehicle_id=" not in message
    long_text = fx.summary(
        fx.vehicle("veh-1", model="M" * 500 + "\n\x1b", registration="R" * 500),
        fx.vehicle("veh-2"),
    )
    service, _ = services(long_text)
    with pytest.raises(ServiceError) as error:
        service.get_distance(*PERIOD)
    assert "MMM" not in error.value.public_message and "RRR" not in error.value.public_message
    assert "\n" not in error.value.public_message and "\x1b" not in error.value.public_message


def test_null_device_id_is_excluded_when_another_vehicle_is_eligible():
    # device object present but device.id null, with a valid subscription:
    # the dashboard filter drops it, so the other vehicle is used without asking.
    service, client = services(
        fx.summary(
            fx.vehicle("veh-nulldevice", device_id=None, registration="0009SYN"),
            fx.vehicle("veh-ok", model="SYNTH-750", registration="0002SYN"),
        )
    )
    assert [entry.vehicle_id for entry in service.list_vehicles().vehicles] == ["veh-ok"]
    service.list_routes(*PERIOD)
    assert client.route_vehicle_ids() == ["veh-ok"]
    with pytest.raises(ServiceError) as error:
        service.get_vehicle_status(vehicle_id="veh-nulldevice")
    assert error.value.code == "vehicle_not_found"


# --- explicit vehicle_id --------------------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(VEHICLE_TOOLS))
@pytest.mark.parametrize("chosen", ["veh-a", "veh-b"])
def test_vehicle_id_selects_that_vehicle(tool, chosen):
    service, client = services(fx.TWO_ACTIVE)
    VEHICLE_TOOLS[tool](service, vehicle_id=chosen)
    assert set(client.route_vehicle_ids()) <= {chosen}
    if tool != "get_vehicle_status":
        assert set(client.route_vehicle_ids()) == {chosen}


def test_vehicle_id_reads_the_chosen_vehicle_state():
    service, _ = services(fx.ACTIVE_AND_CANCELLED)
    assert service.get_vehicle_status(vehicle_id="veh-active").status == "AT_REST"
    cancelled = service.get_vehicle_status(vehicle_id="veh-cancelled")
    assert cancelled.status == "PARKED" and cancelled.vehicle_cancelled is True
    assert cancelled.state_warning == CANCELLED_STATE_WARNING


@pytest.mark.parametrize("tool", ["list_routes", "get_distance", "get_vehicle_details", "get_route_detail"])
def test_cancelled_vehicle_is_selectable_for_routes_distance_and_details(tool):
    service, client = services(fx.ACTIVE_AND_CANCELLED)
    VEHICLE_TOOLS[tool](service, vehicle_id="veh-cancelled")
    assert set(client.route_vehicle_ids()) == {"veh-cancelled"}


@pytest.mark.parametrize(
    ("fixture", "vehicle_id"),
    [
        ("TWO_ACTIVE", "veh-unknown"),
        ("SOLD_AND_ACTIVE", "veh-sold"),  # present in MAPIT but not eligible
        ("PENDING_AND_ACTIVE", "veh-pending"),
        ("NO_SUBSCRIPTION_AND_ACTIVE", "veh-nosub"),
        ("LEGACY_ONLY", "veh-legacy-nodevice"),  # fallback offers only its one vehicle
        ("EMPTY", "veh-one"),
    ],
)
def test_vehicle_id_not_eligible_is_vehicle_not_found(fixture, vehicle_id):
    service, client = services(getattr(fx, fixture))
    with pytest.raises(ServiceError) as error:
        service.list_routes(*PERIOD, vehicle_id=vehicle_id)
    assert error.value.code == "vehicle_not_found"
    assert client.route_vehicle_ids() == []


@pytest.mark.parametrize("vehicle_id", ["", "   ", "x" * 257, 7, ["veh-a"]])
def test_malformed_vehicle_id_is_refused_before_any_read(vehicle_id):
    service, client = services(fx.TWO_ACTIVE)
    with pytest.raises(ServiceError) as error:
        service.get_vehicle_status(vehicle_id=vehicle_id)
    assert error.value.code == "vehicle_not_found"
    assert client.calls == []


def test_fallback_vehicle_is_selectable_by_its_id():
    service, client = services(fx.LEGACY_ONLY)
    service.list_routes(*PERIOD, vehicle_id="veh-legacy-device")
    assert client.route_vehicle_ids() == ["veh-legacy-device"]


def test_summer_geographic_summary_forwards_vehicle_id():
    client = fx.FakeClient(fx.TWO_ACTIVE, routes=[])
    service = MapitServices(client)
    from datetime import datetime, timezone

    service.get_summer_geographic_summary(AREA, 2026, vehicle_id="veh-b", now=datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert set(client.route_vehicle_ids()) == {"veh-b"}
    with pytest.raises(ServiceError) as error:
        service.get_summer_geographic_summary(AREA, 2026, now=datetime(2026, 10, 1, tzinfo=timezone.utc))
    assert error.value.code == "vehicle_selection_required"


def test_comparisons_read_both_periods_for_the_same_vehicle():
    service, client = services(fx.TWO_ACTIVE)
    service.compare_distance_periods(A, B, vehicle_id="veh-b")
    service.compare_route_periods(A, B, vehicle_id="veh-b")
    assert client.route_vehicle_ids() == ["veh-b"] * 4
    assert summary_reads(client) == 4


# --- MCP surface ----------------------------------------------------------------------------------


@pytest.mark.anyio
async def test_mcp_list_vehicles_and_vehicle_id_end_to_end(caplog):
    caplog.set_level(logging.INFO)
    client_double = fx.FakeClient(fx.TWO_ACTIVE)
    provider = ServiceProvider(lambda: MapitServices(client_double))
    async with Client(create_server(provider), raise_exceptions=True) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        assert tools["list_vehicles"].input_schema.get("properties", {}) == {}
        assert tools["list_vehicles"].annotations.read_only_hint is True
        for name, tool in tools.items():
            if name != "list_vehicles":
                assert "vehicle_id" in tool.input_schema["properties"]
                assert "vehicle_id" not in tool.input_schema.get("required", [])
        listing = await client.call_tool("list_vehicles", {})
        assert [item["vehicle_id"] for item in listing.structured_content["vehicles"]] == ["veh-a", "veh-b"]
        assert listing.structured_content["selection_required"] is True
        refused = await client.call_tool("get_distance", {"from_time": PERIOD[0], "to_time": PERIOD[1]})
        assert refused.is_error is True
        assert "vehicle_selection_required: " in refused.content[0].text
        chosen = await client.call_tool(
            "get_distance", {"from_time": PERIOD[0], "to_time": PERIOD[1], "vehicle_id": "veh-b"}
        )
        assert chosen.is_error is False
        unknown = await client.call_tool("get_vehicle_status", {"vehicle_id": "veh-zzz"})
        assert unknown.is_error is True and "vehicle_not_found: " in unknown.content[0].text
    assert set(client_double.route_vehicle_ids()) == {"veh-b"}
    # The SDK logs tool error text at INFO: the selection error must not leak vehicle data.
    for vehicle in fx.TWO_ACTIVE["vehicles"]:
        for value in (vehicle["model"], vehicle["registrationNumber"]):
            assert value not in caplog.text
    assert "vehicle_selection_required" in caplog.text


@pytest.mark.anyio
async def test_mcp_single_vehicle_structured_content_unchanged():
    provider = ServiceProvider(lambda: MapitServices(fx.FakeClient(fx.ONE)))
    async with Client(create_server(provider), raise_exceptions=True) as client:
        result = await client.call_tool("get_vehicle_status", {})
    assert result.structured_content == json.loads(BEFORE_STATUS_TEXT)


@pytest.mark.anyio
async def test_read_meter_lines_never_carry_vehicle_data():
    lines: list[str] = []
    set_read_meter_sink(lines.append)
    try:
        provider = ServiceProvider(lambda: MapitServices(fx.FakeClient(fx.ACTIVE_AND_CANCELLED)))
        async with Client(create_server(provider), raise_exceptions=True) as client:
            await client.call_tool("list_vehicles", {})
            await client.call_tool("get_vehicle_status", {})
            await client.call_tool("get_vehicle_status", {"vehicle_id": "veh-cancelled"})
            await client.call_tool("list_routes", {"from_time": PERIOD[0], "to_time": PERIOD[1], "vehicle_id": "veh-active"})
    finally:
        set_read_meter_sink(None)
    assert len(lines) == 4
    for line in lines:
        assert set(json.loads(line)) == {"event", "tool", "reads", "outcome"}
        for secret in ("veh-", "SYNTH", "SYN", "device-", "sub-"):
            assert secret not in line


# --- local distance ledger ------------------------------------------------------------------


def test_ledger_import_stops_with_a_category_for_several_vehicles(tmp_path):
    from tests.test_history_runtime import FakeClient as HistoryClient, _run_import, _route

    class TwoVehicles(HistoryClient):
        def get_core(self, path, *, max_response_bytes):
            self.calls.append(("core", path, {}, max_response_bytes))
            return fx.TWO_ACTIVE

    client = TwoVehicles([_route()])
    result, client, secrets_store, secure_calls = _run_import(tmp_path / "history", None, client=client)
    assert result == {"success": False, "category": "vehicle_selection_required", "facts_committed": False,
                      "private_values_printed": False}
    assert [call[0] for call in client.calls] == ["core"]
    assert secure_calls == [] and secrets_store.load_key_calls == []
    assert not (tmp_path / "history").exists()


def test_ledger_import_keeps_working_for_one_eligible_vehicle(tmp_path):
    from tests.test_history_runtime import FakeClient as HistoryClient, _run_import, _route

    class OneVehicle(HistoryClient):
        def get_core(self, path, *, max_response_bytes):
            self.calls.append(("core", path, {}, max_response_bytes))
            return fx.ACTIVE_AND_CANCELLED | {"vehicles": [fx.ACTIVE_AND_CANCELLED["vehicles"][0]]}

    result, client, _, _ = _run_import(tmp_path / "history", [_route(complete=False)], client=OneVehicle([_route(complete=False)]))
    assert result["success"] is True and result["category"] == "success"
    assert [call[2].get("vehicleId") for call in client.calls if call[0] == "geo"] == ["veh-active"]
