from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitHTTPError, MapitResponseError, MapitTransportError
from mapit.config import MapitConfig
from mapit.session import ManagedSession
from scripts import probe_route_history_filters as probe


class MadridLike(tzinfo):
    """Small deterministic DST zone for tests without a system tzdata file."""

    def utcoffset(self, dt):
        return timedelta(hours=2 if dt is not None and 4 <= dt.month <= 10 else 1)

    def dst(self, dt):
        return timedelta(hours=1 if dt is not None and 4 <= dt.month <= 10 else 0)

    def tzname(self, dt):
        return "MADT" if self.dst(dt) else "MAST"


def _session() -> MapitSession:
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    return MapitSession(
        id_token="id-token",
        access_token="access-token",
        refresh_token="refresh-token",
        token_expiration=now,
        credentials=TemporaryCredentials("access", "secret", "session", now),
    )


class SavedManager:
    def __init__(self, context: ManagedSession | None, category: str | None = None, **_: object) -> None:
        self.context = context
        self.last_error_category = category

    def login_saved(self):
        return self.context


class RecordingClient:
    def __init__(self, *, summary=None, responses=None, error=None):
        self.summary = summary if summary is not None else {"vehicles": [{"id": "vehicle/one", "device": {}}]}
        self.responses = list(responses or [{"data": []}, {"data": []}])
        self.error = error
        self.calls: list[tuple[str, str, dict | None]] = []

    def get_core(self, path):
        self.calls.append(("core", path, None))
        if self.error and self.error[0] == "account":
            raise self.error[1]
        return self.summary

    def get_geo(self, path, *, params):
        self.calls.append(("geo", path, dict(params)))
        window_calls = len([call for call in self.calls if call[0] == "geo"])
        if self.error and self.error[0] == "window" and window_calls == 1:
            raise self.error[1]
        if self.error and self.error[0] == "second_window" and window_calls == 2:
            raise self.error[1]
        return self.responses.pop(0)


def _run(tmp_path: Path, client: RecordingClient, *, now=None, context=None, category=None):
    context = context or ManagedSession(MapitConfig(), _session())
    return probe.perform_route_history_filters_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, category, **kwargs),
        client_factory=lambda config, session: client,
        clock=(lambda: now) if now is not None else None,
    )


def test_month_windows_match_local_calendar_and_dst():
    madrid = MadridLike()
    windows = probe.build_month_windows(datetime(2026, 11, 15, 12, tzinfo=madrid))
    assert windows == [
        ("2026-10-31T23:00:00.000Z", "2026-11-30T23:00:00.000Z"),
        ("2026-09-30T22:00:00.000Z", "2026-10-31T23:00:00.000Z"),
    ]


def test_month_windows_cross_year_and_summer_dst():
    madrid = MadridLike()
    windows = probe.build_month_windows(datetime(2026, 1, 10, 12, tzinfo=madrid))
    assert windows == [
        ("2025-12-31T23:00:00.000Z", "2026-01-31T23:00:00.000Z"),
        ("2025-11-30T23:00:00.000Z", "2025-12-31T23:00:00.000Z"),
    ]


def test_default_clock_uses_operating_system_local_boundaries(monkeypatch):
    calls = []
    original = probe._month_start

    def wrapped(year, month, tzinfo, *, system_local):
        calls.append(system_local)
        return original(year, month, tzinfo, system_local=system_local)

    monkeypatch.setattr(probe, "_month_start", wrapped)
    windows = probe.build_month_windows()
    assert len(windows) == 2
    assert calls == [True, True, True, True]
    assert all(value.endswith("Z") for window in windows for value in window)


def test_exact_two_requests_and_no_data_persistence(tmp_path):
    client = RecordingClient(
        responses=[
            {"data": [{"id": "secret-route"}], "lastEvaluatedKey": {"token": "secret"}},
            {"data": [{"id": "other-secret"}]},
        ]
    )
    result = _run(tmp_path, client, now=datetime(2026, 9, 28, tzinfo=timezone.utc))

    assert result == {
        "success": True,
        "region": "eu-west-1",
        "windows_checked": 2,
        "last_evaluated_key_observed": True,
    }
    assert client.calls == [
        ("core", "/v1/account-summary", None),
        (
            "geo",
            "/v1/routes",
            {
                "vehicleId": "vehicle/one",
                "limit": 1,
                "from": "2026-09-01T00:00:00.000Z",
                "to": "2026-10-01T00:00:00.000Z",
            },
        ),
        (
            "geo",
            "/v1/routes",
            {
                "vehicleId": "vehicle/one",
                "limit": 1,
                "from": "2026-08-01T00:00:00.000Z",
                "to": "2026-09-01T00:00:00.000Z",
            },
        ),
    ]
    rendered = json.dumps(result)
    assert "secret" not in rendered
    assert not list(tmp_path.iterdir())


def test_no_session_makes_zero_data_calls(tmp_path):
    class NoDataClient:
        def __init__(self, *_):
            raise AssertionError("data client must not be created")

    result = probe.perform_route_history_filters_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None, None, **kwargs),
        client_factory=NoDataClient,
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "session_missing"}
    assert not list(tmp_path.iterdir())


def test_session_manager_error_is_safe(tmp_path):
    from mapit.session import SessionManagerError

    class FailingManager:
        last_error_category = "authentication_rejected"

        def __init__(self, **kwargs):
            pass

        def login_saved(self):
            raise SessionManagerError("authentication_rejected")

    result = probe.perform_route_history_filters_probe(
        store=object(), manager_factory=FailingManager
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "authentication_rejected"}
    assert not list(tmp_path.iterdir())


def test_missing_vehicle_stops_before_geo(tmp_path):
    client = RecordingClient(summary={"vehicles": [{"id": ""}, {"id": 4}]})
    result = _run(tmp_path, client)
    assert result["error"] == "route_history_missing_vehicle"
    assert client.calls == [("core", "/v1/account-summary", None)]


def test_second_window_failure_does_not_make_extra_requests(tmp_path):
    client = RecordingClient(error=("second_window", MapitHTTPError(418, "https://secret.invalid/second")))
    result = _run(tmp_path, client)
    assert result["error"] == "route_history_http_error"
    assert len([call for call in client.calls if call[0] == "geo"]) == 2


def test_http_category_rejects_boolean_status():
    assert probe._http_category("window", True) == "route_history_http_error"


@pytest.mark.parametrize(
    ("exception", "expected"),
    [
        (MapitHTTPError(403, "https://secret.invalid/routes?vehicleId=secret"), "route_history_http_403"),
        (MapitTransportError("https://secret.invalid"), "route_history_transport_failed"),
        (MapitResponseError("body secret"), "route_history_invalid_response"),
    ],
)
def test_window_failures_are_sanitized(tmp_path, exception, expected):
    client = RecordingClient(error=("window", exception))
    result = _run(tmp_path, client)
    assert result["error"] == expected
    rendered = json.dumps(result)
    assert "secret" not in rendered
    assert "secret.invalid" not in rendered


def test_malformed_response_is_invalid_and_stops_after_one_window(tmp_path):
    client = RecordingClient(responses=[{"unexpected": "secret"}, {"data": []}])
    result = _run(tmp_path, client)
    assert result["error"] == "route_history_invalid_response"
    assert len([call for call in client.calls if call[0] == "geo"]) == 1


def test_account_failure_is_sanitized(tmp_path):
    client = RecordingClient(error=("account", MapitHTTPError(401, "https://secret.invalid/account")))
    result = _run(tmp_path, client)
    assert result["error"] == "account_summary_http_401"
    assert "secret.invalid" not in json.dumps(result)
