"""Synthetic account-summary vehicles shaped like the anonymized schema.

Every identifier, model and registration here is invented; nothing comes from
a real account. The module has no ``mapit`` import so the same fixtures can be
fed to an older checkout to record its outputs.
"""

from __future__ import annotations

import copy
from typing import Any

_STATE = {
    "status": "AT_REST",
    "speed": 0,
    "battery": 77,
    "voltage": 12.4,
    "lastTs": 1000,
    "lastCoordTs": 900,
    "lat": 40.0,
    "lng": -3.0,
    "location": "Synthetic Town",
    "hdop": 1.2,
    "odometer": None,
}


def vehicle(
    vehicle_id: str | None,
    *,
    model: str = "SYNTH-125",
    registration: str = "0000SYN",
    device: bool = True,
    device_id: Any = "device-synthetic",
    pending: Any = False,
    subscription: Any = "subscription-synthetic",
    cancelled: bool = False,
    status: str = "AT_REST",
    km: float = 1234.0,
) -> dict[str, Any]:
    """One synthetic vehicle; ``subscription=None`` drops the subscription object."""
    item: dict[str, Any] = {
        "model": model,
        "registrationNumber": registration,
        "cancelled": cancelled,
        "pending": pending,
        "km": km,
        "product": "connected",
        "dealerData": {"name": "Synthetic Dealer", "shop": {"telephone": "+00 000", "openingHours": ["Mo-Fr"]}},
    }
    if vehicle_id is not None:
        item["id"] = vehicle_id
    if device:
        state = copy.deepcopy(_STATE)
        state["status"] = status
        item["device"] = {"id": device_id, "model": "MapitDevice", "state": state}
    else:
        item["device"] = None
    if subscription is not None:
        item["subscription"] = {"id": subscription, "cancelled": cancelled, "autoRenew": not cancelled}
    return item


def summary(*vehicles: dict[str, Any]) -> dict[str, Any]:
    return {"account": {"id": "account-synthetic"}, "vehicles": list(vehicles)}


ONE = summary(vehicle("veh-one", model="SYNTH-125", registration="0001SYN"))
TWO_ACTIVE = summary(
    vehicle("veh-a", model="SYNTH-125", registration="0001SYN"),
    vehicle("veh-b", model="SYNTH-750", registration="0002SYN", device_id="device-b", subscription="sub-b"),
)
ACTIVE_AND_CANCELLED = summary(
    vehicle("veh-active", model="SYNTH-125", registration="0001SYN"),
    vehicle("veh-cancelled", model="SYNTH-300", registration="0003SYN", cancelled=True, device_id="device-c",
            subscription="sub-c", status="PARKED"),
)
# Sold or transferred: the MAPIT device moved away, so the vehicle has no device.
SOLD_AND_ACTIVE = summary(
    vehicle("veh-sold", model="SYNTH-300", registration="0003SYN", device=False),
    vehicle("veh-current", model="SYNTH-750", registration="0002SYN"),
)
PENDING_AND_ACTIVE = summary(
    vehicle("veh-pending", pending=True, device_id="device-p"),
    vehicle("veh-ready", model="SYNTH-750", registration="0002SYN"),
)
NO_SUBSCRIPTION_AND_ACTIVE = summary(
    vehicle("veh-nosub", subscription=None, device_id="device-n"),
    vehicle("veh-paid", model="SYNTH-750", registration="0002SYN"),
)
EMPTY_SUBSCRIPTION_ID = summary(
    vehicle("veh-emptysub", subscription="", device_id="device-e"),
    vehicle("veh-paid", model="SYNTH-750", registration="0002SYN"),
)
SAME_MODEL = summary(
    vehicle("veh-x", model="SYNTH-125", registration="1111SYN"),
    vehicle("veh-y", model="SYNTH-125", registration="2222SYN", device_id="device-y", subscription="sub-y"),
)
# Nothing passes the dashboard filter (no subscription, null device id), but the
# previous rule still finds a vehicle with a device.
LEGACY_ONLY = summary(
    vehicle("veh-legacy-nodevice", device=False, subscription=None),
    vehicle("veh-legacy-device", device_id=None, subscription=None),
)
LEGACY_ID_ONLY = summary(vehicle("veh-legacy-only", device=False, subscription=None))
NOTHING = summary(vehicle(None), {"model": "no id"}, "not-a-mapping")
EMPTY = summary()


def many(count: int) -> dict[str, Any]:
    return summary(*[
        vehicle(f"veh-{index:02d}", model=f"SYNTH-{index:02d}", registration=f"{index:04d}SYN",
                device_id=f"device-{index:02d}", subscription=f"sub-{index:02d}")
        for index in range(count)
    ])


VEHICLE_DETAIL = {
    "id": "veh-one",
    "model": "SYNTH-125",
    "registrationNumber": "0001SYN",
    "vin": "SYNTHVIN0000000001",
    "km": 456,
    "products": ["product-a"],
    "productPlanName": "plan",
    "branch": "branch",
}

ROUTE = {
    "id": "route-synthetic-1",
    "distance": 12000,
    "startedAt": "2026-03-01T10:00:00Z",
    "endedAt": "2026-03-01T11:00:00Z",
    "complete": True,
    "avgSpeed": 30,
    "maxSpeed": 60,
    "startTz": "Europe/Madrid",
    "odometerStart": 100,
    "odometerEnd": 112,
}


class FakeClient:
    """GET-only double: one account summary, one vehicle detail, fixed routes."""

    def __init__(self, account_summary: dict[str, Any], *, routes: list[dict[str, Any]] | None = None):
        self.summary = account_summary
        self.routes = [ROUTE] if routes is None else routes
        self.calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def get_core(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("core", path, params))
        if path == "/v1/account-summary":
            return copy.deepcopy(self.summary)
        if path.startswith("/v1/vehicles/"):
            return copy.deepcopy(VEHICLE_DETAIL)
        raise AssertionError("unexpected core path")

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("geo", path, params))
        if path == "/v1/routes":
            return {"data": copy.deepcopy(self.routes)}
        if "/routes/" in path:
            return copy.deepcopy({**ROUTE, "merged": False, "geoJSON": {"type": "FeatureCollection", "features": []}})
        raise AssertionError("unexpected geo path")

    def route_vehicle_ids(self) -> list[str]:
        ids = [params["vehicleId"] for kind, path, params in self.calls if kind == "geo" and path == "/v1/routes"]
        ids += [path.split("/")[3] for kind, path, _ in self.calls if kind == "geo" and "/routes/" in path]
        ids += [path.split("/")[3] for kind, path, _ in self.calls if kind == "core" and path.startswith("/v1/vehicles/")]
        return ids
