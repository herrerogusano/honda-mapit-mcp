"""One redacted July-2025 availability read, not an exhaustive history scan."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for search_path in (ROOT, ROOT / "src"):
    if str(search_path) not in sys.path:
        sys.path.insert(0, str(search_path))

from scripts.probe_route_completion_flags import (
    CompletionCounters, CompletionTransport, MAX_RESPONSE_BYTES,
    MapitClient, ManagedSession, SessionManager, _local_store, _select_vehicle_id,
)
from scripts.probe_monthly_measurement import MeasurementBudgetExceeded

START = datetime(2025, 7, 1, tzinfo=timezone.utc)
END = datetime(2025, 8, 1, tzinfo=timezone.utc)


class AvailabilityCounters(CompletionCounters):
    def reserve_wire(self, kind: str) -> None:
        if kind == "geo" and self.geo_wire >= 2:
            raise MeasurementBudgetExceeded
        super().reserve_wire(kind)


def classify(payload):
    """Emit presence only after checking every returned start belongs to July."""
    if (not isinstance(payload, dict) or not isinstance(payload.get("data"), list)
            or "lastEvaluatedKey" in payload or len(payload["data"]) > 10_000):
        raise ValueError("invalid_response")
    for route in payload["data"]:
        if not isinstance(route, dict) or not isinstance(route.get("startedAt"), str):
            raise ValueError("invalid_response")
        start = datetime.fromisoformat(route["startedAt"].replace("Z", "+00:00"))
        if start.tzinfo is None or start.utcoffset() is None or not START <= start.astimezone(timezone.utc) < END:
            raise ValueError("invalid_response")
    return bool(payload["data"])


def perform(*, store=None, manager_factory=SessionManager, client_factory=None):
    result = {"success": False, "category": "availability_failed", "window": "july_2025",
              "routes_observed": None, "pre_august_history_observed": None,
              "coverage": "UNKNOWN", "core_logical_reads": 0, "geo_logical_reads": 0,
              "core_wire_gets": 0, "geo_wire_gets": 0}
    counters = AvailabilityCounters()
    payload = context = client = None
    try:
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            result["category"] = "credential_store_failed"
            return result
        context = manager_factory(store=selected_store).login_saved()
        if not isinstance(context, ManagedSession):
            result["category"] = "session_failed"
            return result
        counters.start_window()
        client = client_factory(context, counters) if client_factory else MapitClient(
            context.config, context.session, transport=CompletionTransport(context.config, counters))
        result["core_logical_reads"] = 1
        summary = client.get_core("/v1/account-summary", max_response_bytes=MAX_RESPONSE_BYTES)
        counters.check_time()
        vehicle = _select_vehicle_id(summary)
        if vehicle is None:
            raise ValueError("invalid_response")
        summary = None
        result["geo_logical_reads"] = 1
        payload = client.get_geo("/v1/routes", params={"vehicleId": vehicle,
            "from": "2025-07-01T00:00:00.000Z", "to": "2025-08-01T00:00:00.000Z"},
            max_response_bytes=MAX_RESPONSE_BYTES)
        counters.check_time()
        observed = classify(payload)
        result.update(success=True, category="success", routes_observed=observed,
                      pre_august_history_observed=True if observed else None, coverage="PARTIAL")
    except Exception:
        pass  # Never expose provider/identifier/path/credential exception text.
    finally:
        result["core_wire_gets"] = counters.core_wire
        result["geo_wire_gets"] = counters.geo_wire
        payload = context = client = None
    return result


if __name__ == "__main__":
    result = perform()
    print(json.dumps(result, allow_nan=False))
    raise SystemExit(0 if result["success"] else 1)
