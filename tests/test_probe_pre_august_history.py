import json
from datetime import datetime, timedelta, timezone

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.config import MapitConfig
from mapit.session import ManagedSession

from scripts import probe_pre_august_history as probe


def test_presence_requires_all_returned_starts_in_july_and_aware():
    assert probe.classify({"data": [{"startedAt": "2025-07-20T00:00:00Z"}]}) is True
    assert probe.classify({"data": []}) is False
    for timestamp in ("2025-08-01T00:00:00Z", "2025-06-30T00:00:00Z", "2025-07-20", "secret-invalid"):
        with pytest.raises(ValueError):
            probe.classify({"data": [{"startedAt": timestamp}]})


def test_ambiguous_envelopes_and_pagination_fail_closed():
    for payload in ({}, {"data": [], "lastEvaluatedKey": None}, {"data": [None]}, {"data": [{}]}):
        with pytest.raises(ValueError):
            probe.classify(payload)


def test_wire_budget_rejects_third_geo_attempt_before_increment():
    counters = probe.AvailabilityCounters(clock=lambda: 0)
    counters.start_window()
    counters.reserve_wire("geo")
    counters.reserve_wire("geo")
    with pytest.raises(probe.MeasurementBudgetExceeded):
        counters.reserve_wire("geo")
    assert counters.geo_wire == 2


def _managed_context():
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    session = MapitSession(
        "private-id-token", "private-access-token", "private-refresh-token", expires,
        TemporaryCredentials("private-access-key", "private-secret-key", "private-session-token", expires),
    )
    return ManagedSession(MapitConfig(), session)


class Manager:
    def __init__(self, context, **_kwargs):
        self.context = context

    def login_saved(self):
        return self.context


class FakeClient:
    def __init__(self, context, counters, routes):
        self.context = context
        self.counters = counters
        self.routes = routes
        self.calls = []

    def get_core(self, path, *, max_response_bytes):
        self.counters.reserve_wire("core")
        self.calls.append(("core", path, None, max_response_bytes))
        return {"vehicles": [{"id": "private-vehicle-id", "device": {"state": {}}}]}

    def get_geo(self, path, *, params, max_response_bytes):
        self.counters.reserve_wire("geo")
        self.calls.append(("geo", path, dict(params), max_response_bytes))
        return {"data": self.routes}


def _run(routes):
    context = _managed_context()
    holder = {}

    def client_factory(received_context, counters):
        client = FakeClient(received_context, counters, routes)
        holder["client"] = client
        return client

    result = probe.perform(
        store=object(),
        manager_factory=lambda **kwargs: Manager(context),
        client_factory=client_factory,
    )
    return result, holder["client"]


def test_runner_uses_one_exact_july_read_and_empty_result_stays_unknown():
    result, client = _run([])

    assert result["success"] is True and result["category"] == "success"
    assert result["window"] == "july_2025"
    assert result["routes_observed"] is False
    assert result["pre_august_history_observed"] is None
    assert result["coverage"] == "PARTIAL"
    assert (result["core_logical_reads"], result["core_wire_gets"]) == (1, 1)
    assert (result["geo_logical_reads"], result["geo_wire_gets"]) == (1, 1)
    assert [call[0] for call in client.calls] == ["core", "geo"]
    assert client.calls[0][1] == "/v1/account-summary"
    assert client.calls[0][3] == probe.MAX_RESPONSE_BYTES
    assert client.calls[1][1] == "/v1/routes"
    assert client.calls[1][2] == {
        "vehicleId": "private-vehicle-id",
        "from": "2025-07-01T00:00:00.000Z",
        "to": "2025-08-01T00:00:00.000Z",
    }
    assert client.calls[1][3] == probe.MAX_RESPONSE_BYTES


def test_runner_emits_presence_only_and_suppresses_private_values():
    private_timestamp = "2025-07-20T02:03:04Z"
    routes = [{
        "id": "private-route-id",
        "startedAt": private_timestamp,
        "endedAt": "2025-07-20T02:33:04Z",
        "distance": 123.456,
        "coordinates": [[1.234, 5.678]],
    }]
    result, _client = _run(routes)

    assert result["success"] is True
    assert result["routes_observed"] is True
    assert result["pre_august_history_observed"] is True
    encoded = json.dumps(result, ensure_ascii=True)
    for private in ("private-route-id", private_timestamp, "123.456", "1.234", "5.678"):
        assert private not in encoded


def test_runner_failure_text_is_redacted_and_fixed_result_schema():
    context = _managed_context()

    class FailingClient(FakeClient):
        def get_core(self, path, *, max_response_bytes):
            self.counters.reserve_wire("core")
            raise RuntimeError("private route id and signed URL https://secret.invalid/token")

    result = probe.perform(
        store=object(),
        manager_factory=lambda **kwargs: Manager(context),
        client_factory=lambda received_context, counters: FailingClient(received_context, counters, []),
    )

    assert result["success"] is False
    assert result["category"] == "availability_failed"
    assert result["geo_logical_reads"] == result["geo_wire_gets"] == 0
    assert set(result) == {
        "success", "category", "window", "routes_observed", "pre_august_history_observed",
        "coverage", "core_logical_reads", "geo_logical_reads", "core_wire_gets", "geo_wire_gets",
    }
    encoded = json.dumps(result, ensure_ascii=True)
    assert "private route id" not in encoded and "secret.invalid" not in encoded


def test_route_array_cap_is_enforced_before_reporting_presence():
    with pytest.raises(ValueError):
        probe.classify({"data": [{"startedAt": "2025-07-20T00:00:00Z"}] * 10_001})
