from __future__ import annotations

import json
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from mapit.auth import CognitoHTTPError, MapitSession, SessionRefreshError, TemporaryCredentials, UnsupportedCognitoChallenge
from mapit.client import MapitHTTPError, MapitResponseError, MapitResponseTooLarge, MapitTransportError
from mapit.config import MapitConfig
from mapit.session import ManagedSession, SessionManagerError
from scripts import probe_monthly_measurement as probe


SECRET = "vehicle-secret-id"


def _session(refreshes: list[int] | None = None) -> MapitSession:
    now = datetime.now(timezone.utc)
    callback = (lambda _session: refreshes.append(1)) if refreshes is not None else None
    return MapitSession(
        "id-token-private",
        "access-token-private",
        "refresh-token-private",
        now + timedelta(hours=2),
        TemporaryCredentials("access-private", "secret-private", "session-private", now + timedelta(hours=2)),
        callback,
    )


class SavedManager:
    def __init__(self, context: ManagedSession | None, **_: object) -> None:
        self.context = context

    def login_saved(self):
        return self.context


def _context(refreshes: list[int] | None = None) -> ManagedSession:
    return ManagedSession(MapitConfig(), _session(refreshes))


class RecordingClient:
    def __init__(self, *, failure: tuple[str, Exception] | None = None, responses=None, clock=None) -> None:
        self.failure = failure
        self.responses = list(responses or [{"data": []}] * 6)
        self.calls: list[tuple[str, dict, int]] = []
        self.clock = clock

    def get_core(self, path, *, max_response_bytes):
        assert path == "/v1/account-summary"
        if self.failure and self.failure[0] == "core":
            raise self.failure[1]
        if self.clock is not None:
            self.clock[0] += 181
        return {"vehicles": [{"id": SECRET, "device": {}}]}

    def get_geo(self, path, *, params, max_response_bytes):
        self.calls.append((path, dict(params), max_response_bytes))
        if self.failure and self.failure[0] == f"geo{len(self.calls)}":
            raise self.failure[1]
        if self.failure and self.failure[0] == "geo" and len(self.calls) == 1:
            raise self.failure[1]
        return self.responses.pop(0)


def _run(client, *, now=None, clock=None):
    context = _context()
    return probe.perform_monthly_measurement(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda _config, _session: client,
        now=now,
        perf_counter=(lambda: clock[0]) if clock is not None else (lambda: 0.0),
    )


def test_success_is_six_logical_reads_without_limit_and_only_fixed_redacted_output():
    client = RecordingClient(responses=[{"data": [{"id": f"r{i}"}]} for i in range(5)] + [{"data": [{"id": "control"}]}])

    result = _run(client, now=datetime(2026, 1, 17, 12, tzinfo=timezone.utc))

    assert result["success"] is True
    assert result["core_logical_reads"] == result["core_wire_gets"] == 1
    assert result["geo_logical_reads"] == result["geo_wire_gets"] == 6
    assert result["successful_repetitions"] == 5
    assert result["coverage_class"] == "PARTIAL"
    assert result["monthly_control_class"] == "disjoint"
    assert result["response_size_bucket"] == "unknown"
    assert all("limit" not in params for _, params, _ in client.calls)
    assert all(params["from"] == "2026-01-01T00:00:00.000Z" for _, params, _ in client.calls[:5])
    assert client.calls[-1][1]["from"] == "2025-12-01T00:00:00.000Z"
    assert all(size == probe.MAX_RESPONSE_BYTES for _, _, size in client.calls)
    assert set(result) == probe.OUTPUT_KEYS
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    ("stage", "error", "expected"),
    [
        ("core", MapitHTTPError(401, f"https://core.invalid/{SECRET}"), "account_summary_http_401"),
        ("core", MapitHTTPError(403, "https://private.invalid/path"), "account_summary_http_403"),
        ("core", MapitHTTPError(429, "https://private.invalid/path"), "account_summary_http_429"),
        ("core", MapitResponseTooLarge(), "account_summary_response_too_large"),
        ("core", MapitTransportError("body-secret"), "account_summary_transport_failed"),
        ("core", SessionRefreshError("token-secret"), "session_failed"),
        ("core", CognitoHTTPError(400), "session_failed"),
        ("core", SessionManagerError("credential_store_failed"), "credential_store_failed"),
        ("geo", MapitHTTPError(401, f"https://geo.invalid/{SECRET}"), "routes_list_http_401"),
        ("geo", MapitHTTPError(403, "https://private.invalid/path"), "routes_list_http_403"),
        ("geo", MapitHTTPError(429, "https://private.invalid/path"), "routes_list_http_429"),
        ("geo", MapitResponseTooLarge(), "routes_list_response_too_large"),
        ("geo", MapitResponseError("raw body private"), "routes_list_invalid"),
        ("geo", MapitTransportError("private exception"), "routes_list_transport_failed"),
    ],
)
def test_failure_categories_are_allowlisted_and_counts_consume_attempt(stage, error, expected):
    client = RecordingClient(failure=(stage, error))

    result = _run(client)

    assert result["success"] is False
    assert result["category"] == expected
    assert result["category"] in probe.CATEGORIES
    assert result["error_categories"] == [expected]
    assert SECRET not in json.dumps(result)
    if stage == "geo":
        assert result["geo_logical_reads"] == result["geo_wire_gets"] == 1
        assert result["successful_repetitions"] == 0


def test_partial_repetitions_and_error_category_survive_later_failure():
    class PartialClient(RecordingClient):
        def get_geo(self, path, *, params, max_response_bytes):
            self.calls.append((path, dict(params), max_response_bytes))
            if len(self.calls) == 3:
                raise MapitHTTPError(429, "https://secret.invalid/?route=" + SECRET)
            return {"data": []}

    result = _run(PartialClient())

    assert result["category"] == "routes_list_http_429"
    assert result["successful_repetitions"] == 2
    assert result["geo_logical_reads"] == result["geo_wire_gets"] == 3
    assert result["monthly_control_class"] == "unknown"
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize("bad_route", [{}, {"id": None}, {"id": 1}, {"id": "   "}, {"id": "x" * 257}])
def test_structurally_invalid_route_id_fails_closed(bad_route):
    client = RecordingClient(responses=[{"data": [bad_route]}])

    result = _run(client)

    assert result["success"] is False
    assert result["category"] == "routes_list_invalid"
    assert result["geo_logical_reads"] == result["geo_wire_gets"] == 1
    assert result["successful_repetitions"] == 0


def test_empty_month_response_is_valid_and_classified_empty():
    result = _run(RecordingClient())

    assert result["success"] is True
    assert result["successful_repetitions"] == 5
    assert result["monthly_control_class"] == "empty"


@pytest.mark.parametrize("cap_name, cap, expected_geo", [("MAX_GEO_WIRE_GETS", 2, 2), ("MAX_GEO_LOGICAL_READS", 2, 2)])
def test_injected_client_caps_stop_before_next_geo_dispatch(monkeypatch, cap_name, cap, expected_geo):
    monkeypatch.setattr(probe, cap_name, cap)
    client = RecordingClient()

    result = _run(client)

    assert result["category"] == "budget_exceeded"
    assert result["geo_logical_reads"] == expected_geo
    assert result["geo_wire_gets"] == expected_geo
    assert len(client.calls) == expected_geo
    assert result["successful_repetitions"] == expected_geo


def test_measurement_deadline_stops_before_geo_after_slow_account_call():
    clock = [0.0]
    client = RecordingClient(clock=clock)
    context = _context()
    result = probe.perform_monthly_measurement(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda _config, _session: client,
        perf_counter=lambda: clock[0],
    )

    assert result["category"] == "time_limit_exceeded"
    assert result["core_wire_gets"] == 1
    assert result["geo_logical_reads"] == result["geo_wire_gets"] == 0
    assert client.calls == []


@pytest.mark.parametrize("mode", ["oversized", "deadline"])
def test_chunked_response_read_is_bounded_and_checks_deadline(monkeypatch, mode):
    clock = [0.0]
    context = _context()

    class Response:
        def __init__(self, raw: bytes, *, is_geo: bool = False) -> None:
            self.raw = raw
            self.position = 0
            self.is_geo = is_geo
            self.read_sizes: list[int] = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read1(self, amount: int) -> bytes:
            self.read_sizes.append(amount)
            part = self.raw[self.position : self.position + amount]
            self.position += len(part)
            if mode == "deadline" and self.is_geo and part:
                clock[0] = 181
            return part

    class Opener:
        def __init__(self) -> None:
            self.responses: list[Response] = []

        def open(self, request, timeout):
            if "core.prod.mapit.me" in request.full_url:
                response = Response(b'{"vehicles":[{"id":"ephemeral","device":{}}]}')
            elif mode == "oversized":
                response = Response(b"x" * (probe.MAX_RESPONSE_BYTES + 1), is_geo=True)
            else:
                response = Response(b'{"data":[]}', is_geo=True)
            self.responses.append(response)
            return response

    opener = Opener()
    monkeypatch.setattr(probe, "_NO_REDIRECT_OPENER", opener)
    result = probe.perform_monthly_measurement(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda config, session, counters: __import__("mapit.client", fromlist=["MapitClient"]).MapitClient(
            config, session, transport=probe.BoundedMapitTransport(config, counters)
        ),
        perf_counter=lambda: clock[0],
    )

    geo_response = opener.responses[-1]
    assert geo_response.read_sizes
    assert max(geo_response.read_sizes) <= 64 * 1024
    assert len(geo_response.read_sizes) == 1 if mode == "deadline" else len(geo_response.read_sizes) > 1
    if mode == "oversized":
        assert result["category"] == "routes_list_response_too_large"
        assert result["response_size_bucket"] == ">2MiB"
        assert result["geo_wire_gets"] == 1
    else:
        assert result["category"] == "time_limit_exceeded"
        assert result["geo_wire_gets"] == 1
        assert result["geo_logical_reads"] == 1


def test_probe_stdout_never_contains_http_url_or_exception_details(monkeypatch, capsys):
    result = _run(RecordingClient(failure=("core", MapitHTTPError(403, f"https://private.invalid/{SECRET}", "private-body"))))
    monkeypatch.setattr(probe, "perform_monthly_measurement", lambda: result)

    assert probe.main() == 1
    output = capsys.readouterr().out
    assert SECRET not in output
    assert "private.invalid" not in output
    assert "private-body" not in output
    assert json.loads(output)["category"] == "account_summary_http_403"


def test_bounded_transport_rejects_non_get_before_dispatch(monkeypatch):
    counters = probe.MeasurementCounters()
    transport = probe.BoundedMapitTransport(MapitConfig(), counters)

    class NoDispatch:
        def open(self, *_args, **_kwargs):
            pytest.fail("non-GET method reached HTTP opener")

    monkeypatch.setattr(probe, "_NO_REDIRECT_OPENER", NoDispatch())
    with pytest.raises(MapitTransportError):
        transport("POST", "https://geo.prod.mapit.me/v1/routes", {})
    assert counters.core_wire == counters.geo_wire == 0


@pytest.mark.parametrize(
    ("last_error", "expected"),
    [
        (None, "session_missing"),
        ("credential_store_failed", "credential_store_failed"),
        ("discovery_failed", "session_failed"),
        ("authentication_failed", "session_failed"),
        ("authentication_rejected", "session_failed"),
        ("secret-from-manager", "session_failed"),
    ],
)
def test_missing_saved_session_uses_only_safe_manager_category(last_error, expected):
    class MissingManager:
        last_error_category = last_error

        def __init__(self, **kwargs):
            pass

        def login_saved(self):
            return None

    result = probe.perform_monthly_measurement(store=object(), manager_factory=MissingManager)

    assert result["category"] == expected
    assert result["core_wire_gets"] == result["geo_wire_gets"] == 0
    assert "secret-from-manager" not in json.dumps(result)


@pytest.mark.parametrize(
    ("status", "target", "success", "expected_core", "expected_geo"),
    [
        (401, "core", True, 2, 6),
        (403, "geo", True, 1, 7),
        (401, "geo", False, 1, 2),
        (403, "core", False, 2, 0),
    ],
)
def test_real_mapit_client_auth_recovery_is_one_wire_retry_only(status, target, success, expected_core, expected_geo, monkeypatch):
    refreshes: list[int] = []
    context = _context(refreshes)

    class Response:
        def __init__(self, raw: bytes) -> None:
            self.raw = raw
            self.position = 0

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self, amount=-1):
            if amount < 0:
                amount = len(self.raw) - self.position
            part = self.raw[self.position : self.position + amount]
            self.position += len(part)
            return part

    class Opener:
        def __init__(self):
            self.calls: list[str] = []
            self.target_calls = 0

        def open(self, request, timeout):
            self.calls.append(request.full_url)
            is_target = (target == "core" and "core.prod.mapit.me" in request.full_url) or (
                target == "geo" and "geo.prod.mapit.me" in request.full_url
            )
            if is_target:
                self.target_calls += 1
            if is_target and (self.target_calls == 1 or not success):
                raise urllib.error.HTTPError(request.full_url, status, "private-body", {}, None)
            if "core.prod.mapit.me" in request.full_url:
                raw = b'{"vehicles":[{"id":"vehicle-secret-id","device":{}}]}'
            else:
                raw = b'{"data":[]}'
            return Response(raw)

    opener = Opener()
    monkeypatch.setattr(probe, "_NO_REDIRECT_OPENER", opener)
    result = probe.perform_monthly_measurement(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda config, session, counters: __import__("mapit.client", fromlist=["MapitClient"]).MapitClient(
            config, session, transport=probe.BoundedMapitTransport(config, counters)
        ),
    )

    assert result["success"] is success, result
    assert result["core_wire_gets"] == expected_core
    assert result["geo_wire_gets"] == expected_geo
    assert result["core_wire_gets"] <= probe.MAX_CORE_WIRE_GETS
    assert result["geo_wire_gets"] <= probe.MAX_GEO_WIRE_GETS
    assert len(opener.calls) == expected_core + expected_geo
    assert len(refreshes) == 1
    if not success:
        expected = f"{'account_summary' if target == 'core' else 'routes_list'}_http_{status}"
        assert result["category"] == expected
        assert result["geo_logical_reads"] == (0 if target == "core" else 1)
    else:
        assert result["response_size_bucket"] == "<64KiB"
    assert SECRET not in json.dumps(result)


@pytest.mark.parametrize(
    ("status", "refresh_error", "expected"),
    [
        (401, SessionRefreshError("refresh token private"), "session_failed"),
        (403, CognitoHTTPError(400), "session_failed"),
        (403, UnsupportedCognitoChallenge("challenge-private"), "session_failed"),
        (401, SessionManagerError("credential_store_failed"), "credential_store_failed"),
    ],
)
def test_auth_recovery_failure_is_safe_and_does_not_dispatch_a_retry(status, refresh_error, expected, monkeypatch):
    session = _session()

    def fail_refresh(_session):
        raise refresh_error

    session._refresh_callback = fail_refresh
    context = ManagedSession(MapitConfig(), session)

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read1(self, _amount):
            return b""

    class Opener:
        def __init__(self):
            self.calls = 0

        def open(self, request, timeout):
            self.calls += 1
            raise urllib.error.HTTPError(request.full_url, status, "private-body", {}, None)

    opener = Opener()
    monkeypatch.setattr(probe, "_NO_REDIRECT_OPENER", opener)
    result = probe.perform_monthly_measurement(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda config, saved_session, counters: __import__("mapit.client", fromlist=["MapitClient"]).MapitClient(
            config, saved_session, transport=probe.BoundedMapitTransport(config, counters)
        ),
    )

    assert result["success"] is False
    assert result["category"] == expected
    assert result["error_categories"] == [expected]
    assert result["core_wire_gets"] == opener.calls == 1
    assert result["geo_wire_gets"] == 0
    serialized = json.dumps(result)
    assert "private" not in serialized
    assert "400" not in serialized


@pytest.mark.parametrize(
    ("value", "expected"),
    [(-1, "<1"), (0.999, "<1"), (1, "1-5"), (5, "5-15"), (15, ">=15")],
)
def test_latency_buckets(value, expected):
    assert probe._latency_bucket(value) == expected


def test_size_bucket_and_month_boundaries_are_coarse_and_utc():
    assert probe._size_bucket(0) == "<64KiB"
    assert probe._size_bucket(64 * 1024) == "64-256KiB"
    assert probe._size_bucket(2 * 1024 * 1024) == "1-2MiB"
    assert probe._size_bucket(2 * 1024 * 1024 + 1) == ">2MiB"
    start, next_start, previous_start, previous_end = probe._month_bounds(datetime(2024, 3, 1, tzinfo=timezone(timedelta(hours=2))))
    assert (start.isoformat(), next_start.isoformat(), previous_start.isoformat(), previous_end.isoformat()) == (
        "2024-02-01T00:00:00+00:00",
        "2024-03-01T00:00:00+00:00",
        "2024-01-01T00:00:00+00:00",
        "2024-02-01T00:00:00+00:00",
    )


def test_monthly_control_overlap_and_empty_are_ephemeral_classes():
    assert probe._control_class([{"same"}] * 5, {"same"}) == "overlap"
    assert probe._control_class([set()] * 5, {"control"}) == "empty"
