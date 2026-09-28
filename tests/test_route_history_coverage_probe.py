from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitHTTPError, MapitResponseError, MapitResponseTooLarge, MapitTransportError
from mapit.config import MapitConfig
from mapit.session import ManagedSession, SessionManagerError
from scripts import probe_route_history_coverage as probe


def _session() -> MapitSession:
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    return MapitSession("id-token", "access-token", "refresh-token", now, TemporaryCredentials("access", "secret", "session", now))


class SavedManager:
    def __init__(self, context: ManagedSession | None, category: str | None = None, **_: object) -> None:
        self.context = context
        self.last_error_category = category

    def login_saved(self):
        return self.context


class RecordingClient:
    def __init__(self, summary=None, responses=None, error=None):
        self.summary = summary if summary is not None else {"vehicles": [{"id": "vehicle/one", "device": {}}]}
        self.responses = list(responses or [])
        self.error = error
        self.calls: list[tuple[str, dict, int]] = []

    def get_core(self, path):
        assert path == "/v1/account-summary"
        return self.summary

    def get_geo(self, path, *, params, max_response_bytes):
        self.calls.append((path, dict(params), max_response_bytes))
        if self.error is not None:
            raise self.error
        return self.responses.pop(0)


def _run(tmp_path: Path, client: RecordingClient, *, context=None, category=None):
    context = context or ManagedSession(MapitConfig(), _session())
    return probe.perform_route_history_coverage_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, category, **kwargs),
        client_factory=lambda config, session: client,
    )


def _route(route_id: str, started_at: str):
    return {"id": route_id, "startedAt": started_at, "lat": 1.2, "distance": 4}


def test_started_at_offsets_and_naive_values_are_classified_in_utc():
    assert probe._month(probe._parse_started_at("2026-03-01T00:30:00+01:00")) == "2026-02"
    assert probe._month(probe._parse_started_at("2026-03-01T00:30:00")) == "2026-03"


def test_exact_unfiltered_and_control_calls_complete_for_returned_response(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-01-15T12:00:00Z"), _route("r2", "2026-03-20T12:00:00+00:00"), _route("r3", "2026-03-01T00:00:00Z")]},
            {"data": [_route("r1", "2026-01-20T00:00:00Z")]},
            {"data": [_route("r2", "2026-03-20T12:00:00Z"), _route("r3", "2026-03-01T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)

    assert result == {
        "success": True,
        "region": "eu-west-1",
        "route_count_observed": 3,
        "oldest_month_observed": "2026-01",
        "newest_month_observed": "2026-03",
        "pagination_metadata_observed": False,
        "coverage_class": "COMPLETE_FOR_RETURNED_RESPONSE",
    }
    assert client.calls == [
        ("/v1/routes", {"vehicleId": "vehicle/one"}, probe.MAX_RESPONSE_BYTES),
        (
            "/v1/routes",
            {"vehicleId": "vehicle/one", "from": "2026-01-01T00:00:00.000Z", "to": "2026-02-01T00:00:00.000Z"},
            probe.MAX_RESPONSE_BYTES,
        ),
        (
            "/v1/routes",
            {"vehicleId": "vehicle/one", "from": "2026-03-01T00:00:00.000Z", "to": "2026-04-01T00:00:00.000Z"},
            probe.MAX_RESPONSE_BYTES,
        ),
    ]
    assert not list(tmp_path.iterdir())
    assert "r1" not in json.dumps(result)


def test_same_month_uses_one_control_request(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-03-01T00:00:00Z"), _route("r2", "2026-03-30T00:00:00Z")]},
            {"data": [_route("r1", "2026-03-10T00:00:00Z"), _route("r2", "2026-03-30T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)
    assert result["coverage_class"] == "COMPLETE_FOR_RETURNED_RESPONSE"
    assert result["route_count_observed"] == 2
    assert len(client.calls) == 2


def test_control_subset_is_partial_even_without_pagination_metadata(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-03-01T00:00:00Z"), _route("r2", "2026-03-30T00:00:00Z")]},
            {"data": [_route("r1", "2026-03-10T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)
    assert result["coverage_class"] == "PARTIAL"


def test_duplicate_base_id_is_partial_and_skips_controls(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-03-01T00:00:00Z"), _route("r1", "2026-03-02T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)
    assert result["coverage_class"] == "PARTIAL"
    assert len(client.calls) == 1


def test_duplicate_control_id_is_partial(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-03-01T00:00:00Z")]},
            {"data": [_route("r1", "2026-03-02T00:00:00Z"), _route("r1", "2026-03-03T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)
    assert result["coverage_class"] == "PARTIAL"


def test_control_route_outside_base_set_is_partial(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("base", "2026-03-01T00:00:00Z")]},
            {"data": [_route("not-in-base", "2026-03-02T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)
    assert result["coverage_class"] == "PARTIAL"
    assert "not-in-base" not in json.dumps(result)


def test_pagination_metadata_is_name_only_and_partial(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-03-01T00:00:00Z")], "lastEvaluatedKey": {"secret": "token"}},
            {"data": [_route("r1", "2026-03-02T00:00:00Z")]},
        ]
    )
    result = _run(tmp_path, client)
    assert result["pagination_metadata_observed"] is True
    assert result["coverage_class"] == "PARTIAL"
    assert "token" not in json.dumps(result)


def test_control_pagination_metadata_is_reported_without_exposing_value(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [_route("r1", "2026-03-01T00:00:00Z")]},
            {"data": [_route("r1", "2026-03-02T00:00:00Z")], "cursor": "secret-cursor"},
        ]
    )
    result = _run(tmp_path, client)
    assert result["pagination_metadata_observed"] is True
    assert result["coverage_class"] == "PARTIAL"
    assert "secret-cursor" not in json.dumps(result)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ({"data": []}, "UNKNOWN"),
        ({"data": "not-an-array"}, "UNKNOWN"),
        ({"wrong": []}, "UNKNOWN"),
        ({"data": [{"id": "r1", "startedAt": "bad-date"}]}, "UNKNOWN"),
        ({"data": [{"startedAt": "2026-03-01T00:00:00Z"}]}, "PARTIAL"),
    ],
)
def test_invalid_or_empty_base_is_safe_and_never_controls(tmp_path, response, expected):
    client = RecordingClient(responses=[response])
    result = _run(tmp_path, client)
    assert result["coverage_class"] == expected
    assert len(client.calls) == 1
    assert result["oldest_month_observed"] is None if expected == "UNKNOWN" else True


def test_response_limit_fails_closed_before_comparison(tmp_path):
    client = RecordingClient(error=MapitResponseTooLarge())
    result = _run(tmp_path, client)
    assert result == {"success": False, "region": "eu-west-1", "error": "response_too_large"}


def test_no_session_makes_zero_data_calls(tmp_path):
    class NoDataClient:
        def __init__(self, *_):
            raise AssertionError("client must not be created")

    result = probe.perform_route_history_coverage_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None),
        client_factory=NoDataClient,
    )
    assert result["error"] == "session_missing"
    assert not list(tmp_path.iterdir())


def test_manager_error_and_transport_errors_are_sanitized(tmp_path):
    class FailingManager:
        def __init__(self, **kwargs):
            pass

        def login_saved(self):
            raise SessionManagerError("authentication_rejected")

    result = probe.perform_route_history_coverage_probe(store=object(), manager_factory=FailingManager)
    assert result["error"] == "authentication_rejected"

    for error, expected in [
        (MapitHTTPError(429, "https://secret.invalid/routes?vehicleId=secret"), "rate_limited"),
        (MapitTransportError("https://secret.invalid/body-secret"), "transport_failed"),
        (MapitResponseError("body-secret"), "invalid_response"),
    ]:
        result = _run(tmp_path, RecordingClient(error=error))
        assert result["error"] == expected
        assert "secret" not in json.dumps(result)
