from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitClient
from mapit.config import MapitConfig
from mapit.session import ManagedSession
from scripts import probe_route_completion_flags as probe


NOW = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
ACCOUNT = "private-account-must-not-print"
VEHICLE = "private-vehicle-must-not-print"
ROUTE = "private-route-must-not-print"


def _route(route_id=ROUTE, *, complete=True, **extra):
    return {
        "id": route_id,
        "startedAt": "2026-01-08T04:00:00Z",
        "endedAt": "2026-01-08T04:30:00Z",
        "distance": 8.0,
        "complete": complete,
        **extra,
    }


def _context(config=None):
    current = datetime.now(timezone.utc) + timedelta(hours=1)
    session = MapitSession(
        "id-token-private",
        "access-token-private",
        "refresh-token-private",
        current,
        TemporaryCredentials("access-key-private", "secret-key-private", "session-token-private", current),
    )
    return ManagedSession(config or MapitConfig(), session)


class Manager:
    def __init__(self, context=None, error=None, **_kwargs):
        self.context = context
        self.last_error_category = error

    def login_saved(self):
        return self.context


class FakeClient:
    def __init__(self, counters, replies):
        self.counters = counters
        self.replies = list(replies)
        self.calls = []
        self.transport = None

    def get_core(self, path, *, max_response_bytes):
        self.calls.append(("core", path, {}, max_response_bytes))
        if len(self.calls) > 1:
            raise AssertionError("only one account-summary operation is allowed")
        return {"vehicles": [{"id": VEHICLE, "device": {"state": {}}}]}

    def get_geo(self, path, *, params, max_response_bytes):
        self.calls.append(("geo", path, dict(params), max_response_bytes))
        reply = self.replies.pop(0)
        if isinstance(reply, BaseException):
            raise reply
        return reply


class CountingFakeTransport(probe.CompletionTransport):
    def __init__(self, config, counters, replies, *, geo_403_count=0):
        super().__init__(config, counters)
        self.replies = list(replies)
        self.geo_403_count = geo_403_count
        self.geo_wire_calls = 0
        self.urls = []

    def __call__(self, method, url, headers):
        parsed = urlparse(url)
        kind = "core" if parsed.netloc.lower() == urlparse(self.config.core_api_url).netloc.lower() else "geo"
        self.counters.reserve_wire(kind)
        self.urls.append(url)
        if kind == "core":
            return json.dumps({"vehicles": [{"id": VEHICLE, "device": {"state": {}}}]}).encode()
        self.geo_wire_calls += 1
        if self.geo_wire_calls <= self.geo_403_count:
            raise urllib.error.HTTPError(url, 403, "fake forbidden", {}, None)
        payload = self.replies.pop(0)
        return json.dumps(payload).encode()


def _run(replies, *, now=NOW, client_factory=None, manager=None):
    context = _context()
    manager = manager or Manager(context)
    client_holder = {}

    def factory(config, session, counters):
        client = client_factory(config, session, counters) if client_factory else FakeClient(counters, replies)
        client_holder["client"] = client
        return client

    result = probe.perform_route_completion_probe(
        store=object(),
        manager_factory=lambda **kwargs: manager,
        client_factory=factory,
        now=now,
    )
    return result, client_holder.get("client")


def test_analyzer_distinguishes_classes_and_false_old_completed_route_counterexample():
    evidence = probe.analyze_route_payload(
        {"data": [_route(complete=False, endedAt="2026-01-01T00:00:00Z", startedAt="2025-12-20T00:00:00Z")]},
        NOW,
    )
    assert evidence.complete_class == "all_false"
    assert evidence.false_end_older_24h is True
    assert evidence.false_start_older_7d is True
    assert evidence.false_positive_distance is True
    assert evidence.false_inferred_feature is False
    assert evidence.false_starts_at_last_known is False

    for rows, expected in [([], "empty"), ([_route(complete=True)], "all_true"),
                           ([_route(complete=False)], "all_false"),
                           ([_route(complete=True), _route("r2", complete=False)], "mixed"),
                           ([_route() | {"complete": "false"}], "unknown")]:
        assert probe.analyze_route_payload({"data": rows}, NOW).complete_class == expected


def test_three_variants_share_current_utc_month_and_output_only_safe_metadata():
    complete_true = _route(complete=True)
    complete_false = _route(
        complete=False,
        endedAt="2025-12-01T00:00:00Z",
        startedAt="2025-11-01T00:00:00Z",
        geoJSON={"features": [{"type": "Feature", "properties": {"inferred": True}}]},
        startsAtLastKnown=True,
    )
    replies = [{"data": [complete_true]}, {"data": [complete_false]}, {"data": [complete_true]}]
    result, client = _run(replies)

    assert frozenset(result) == probe.OUTPUT_KEYS
    assert result["success"] is True and result["category"] == "success"
    assert (result["core_logical_reads"], result["core_wire_gets"]) == (1, 1)
    assert (result["geo_logical_reads"], result["geo_wire_gets"]) == (3, 3)
    assert result["window"] == "current_utc_month" and result["coverage"] == "PARTIAL"
    assert result["complete_class"] == {"omitted": "all_true", "false": "all_false", "true": "all_true"}
    assert result["false_has_valid_past_end_older_24h"] is True
    assert result["false_has_past_start_older_7d"] is True
    assert result["false_has_positive_native_distance"] is True
    assert result["false_has_inferred_feature"] is True
    assert result["false_has_starts_at_last_known"] is True
    assert result["omitted_vs_false_id_set"] == "same"
    assert result["omitted_vs_false_same_fact_signature"] is False
    assert result["omitted_vs_true_id_set"] == "same"
    assert result["omitted_vs_true_same_fact_signature"] is True
    assert [call[2].get("includeInProgress") for call in client.calls if call[0] == "geo"] == [None, "false", "true"]
    geo_params = [call[2] for call in client.calls if call[0] == "geo"]
    assert all("limit" not in params and set(params) == {"vehicleId", "from", "to", *( ["includeInProgress"] if "includeInProgress" in params else [])} for params in geo_params)
    assert all(params["from"] == "2026-01-01T00:00:00.000Z" and params["to"] == "2026-02-01T00:00:00.000Z" for params in geo_params)
    serialized = json.dumps(result)
    for private in (ACCOUNT, VEHICLE, ROUTE, "2026-01-01", "8.0", "endedAt"):
        assert private not in serialized


def test_false_end_counterexample_requires_coherent_valid_timestamps():
    evidence = probe.analyze_route_payload(
        {"data": [_route(complete=False, startedAt="2026-01-10T00:00:00Z", endedAt="2026-01-01T00:00:00Z")]},
        NOW,
    )
    assert evidence.false_end_older_24h is False
    evidence = probe.analyze_route_payload(
        {"data": [_route(complete=False, startedAt="not-a-time", endedAt="2026-01-01T00:00:00Z")]},
        NOW,
    )
    assert evidence.false_end_older_24h is False


def test_real_mapit_client_uses_only_one_builtin_403_recovery_and_string_query_values():
    replies = [{"data": [_route()]}, {"data": [_route()]}, {"data": [_route()]}]
    context = _context()
    refresh_calls = []
    context.session._refresh_callback = lambda _session: refresh_calls.append(True)
    holders = {}

    def factory(config, session, counters):
        transport = CountingFakeTransport(config, counters, replies, geo_403_count=1)
        client = MapitClient(config, session, transport=transport)
        holders["transport"] = transport
        return client

    result, _ = _run(replies, client_factory=factory, manager=Manager(context))
    assert result["success"] is True
    assert result["geo_logical_reads"] == 3
    assert result["geo_wire_gets"] == 4
    assert len(refresh_calls) == 1
    params = [parse_qs(urlparse(url).query) for url in holders["transport"].urls if "/routes" in url]
    assert [query.get("includeInProgress", [None])[0] for query in params] == [None, None, "false", "true"]


def test_real_mapit_client_stops_after_one_builtin_recovery_attempt():
    context = _context()
    context.session._refresh_callback = lambda _session: None
    holders = {}

    def factory(config, session, counters):
        transport = CountingFakeTransport(config, counters, [], geo_403_count=2)
        client = MapitClient(config, session, transport=transport)
        holders["transport"] = transport
        return client

    result, _ = _run([], client_factory=factory, manager=Manager(context))
    assert result["category"] == "routes_list_http_403"
    assert result["geo_logical_reads"] == 1
    assert result["geo_wire_gets"] == 2
    assert len(holders["transport"].urls) == 3  # one Core, then exactly two Geo attempts


@pytest.mark.parametrize(
    ("bad_payload", "expected"),
    [
        ({"unexpected": []}, "routes_list_invalid"),
        ({"data": {}}, "routes_list_invalid"),
        ({"data": [], "lastEvaluatedKey": None}, "pagination_unsupported"),
        ({"data": [_route(), _route()]}, "routes_list_invalid"),
        ({"data": [{"id": "x" * 257}]}, "routes_list_invalid"),
        ({"data": [{"id": "\ud800"}]}, "routes_list_invalid"),
        ({"data": [None]}, "routes_list_invalid"),
    ],
)
def test_invalid_or_paginated_variant_stops_before_next_request(bad_payload, expected):
    result, client = _run([{"data": [_route()]}, bad_payload, {"data": [_route()]}])
    assert result["category"] == expected
    assert result["success"] is False
    assert [call[0] for call in client.calls] == ["core", "geo", "geo"]
    assert result["geo_logical_reads"] == 2
    assert result["complete_class"]["false"] == "unknown"


def test_response_too_large_and_http_errors_are_redacted_and_stop_sequential_probe():
    for failure, category in [
        (probe.MapitResponseTooLarge(), "routes_list_response_too_large"),
        (probe.MapitHTTPError(429, "https://private.example/path?secret=1"), "routes_list_http_429"),
    ]:
        result, client = _run([{"data": [_route()]}, failure, {"data": [_route()]}])
        assert result["category"] == category
        assert result["geo_logical_reads"] == 2
        assert len(client.calls) == 3
        assert "private.example" not in json.dumps(result)
        assert "secret" not in json.dumps(result)


def test_missing_session_and_manager_errors_are_fixed_categories_without_error_text():
    for manager, expected in [(Manager(None), "session_missing"), (Manager(None, "credential_store_failed"), "credential_store_failed")]:
        result = probe.perform_route_completion_probe(store=object(), manager_factory=lambda **kwargs: manager, now=NOW)
        assert result["category"] == expected
        assert result["core_logical_reads"] == result["geo_logical_reads"] == 0
        assert frozenset(result) == probe.OUTPUT_KEYS

    class BrokenManager(Manager):
        def login_saved(self):
            raise RuntimeError("private-token-and-account-id")

    result = probe.perform_route_completion_probe(store=object(), manager_factory=lambda **kwargs: BrokenManager(), now=NOW)
    assert result["category"] == "session_failed"
    assert "private-token" not in json.dumps(result)


def test_route_count_cap_and_untrusted_values_are_validated_before_classification():
    with pytest.raises(OverflowError):
        probe.analyze_route_payload({"data": [{"id": str(i)} for i in range(probe.MAX_ROUTE_COUNT + 1)]}, NOW)
    for route_id in ("", "  ", "é" * 129):
        with pytest.raises(ValueError):
            probe.analyze_route_payload({"data": [{"id": route_id}]}, NOW)


def test_utc_window_handles_december_rollover_and_counter_caps_are_fail_closed():
    result, client = _run(
        [{"data": [_route()]}, {"data": [_route()]}, {"data": [_route()]}],
        now=datetime(2026, 12, 31, 23, 30, tzinfo=timezone.utc),
    )
    assert result["success"] is True
    geo_params = [call[2] for call in client.calls if call[0] == "geo"]
    assert all(params["from"] == "2026-12-01T00:00:00.000Z" and params["to"] == "2027-01-01T00:00:00.000Z" for params in geo_params)

    counters = probe.CompletionCounters(clock=lambda: 0.0)
    counters.start_window()
    for _ in range(probe.MAX_GEO_WIRE_GETS):
        counters.reserve_wire("geo")
    with pytest.raises(probe.MeasurementBudgetExceeded):
        counters.reserve_wire("geo")
    core_counters = probe.CompletionCounters(clock=lambda: 0.0)
    for _ in range(probe.MAX_CORE_WIRE_GETS):
        core_counters.reserve_wire("core")
    with pytest.raises(probe.MeasurementBudgetExceeded):
        core_counters.reserve_wire("core")


def test_expired_measurement_clock_stops_without_geo_and_categories_are_closed():
    ticks = iter([0.0, 181.0, 181.0, 181.0])
    counter = probe.CompletionCounters(clock=lambda: next(ticks, 181.0))
    counter.start_window()
    with pytest.raises(probe.MeasurementTimeExceeded):
        counter.check_time()

    ticks = iter([0.0, 181.0])
    context = _context()
    client_holder = {}

    def factory(config, session, counters):
        client = FakeClient(counters, [])
        client_holder["client"] = client
        return client

    result = probe.perform_route_completion_probe(
        store=object(),
        manager_factory=lambda **kwargs: Manager(context),
        client_factory=factory,
        now=NOW,
        perf_counter=lambda: next(ticks, 181.0),
    )
    assert result["category"] == "time_limit_exceeded"
    assert result["core_wire_gets"] == 0
    assert client_holder["client"].calls == []

    for failure, category in [
        (probe.MeasurementBudgetExceeded(), "budget_exceeded"),
        (probe.MeasurementTimeExceeded(), "time_limit_exceeded"),
    ]:
        result, client = _run([{"data": [_route()]}, failure, {"data": [_route()]}])
        assert result["category"] == category
        assert result["geo_logical_reads"] == 2
        assert len(client.calls) == 3
