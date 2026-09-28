from __future__ import annotations

import json
from pathlib import Path

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitHTTPError, MapitResponseError, MapitTransportError
from mapit.config import MapitConfig
from mapit.session import ManagedSession
from scripts import probe_route_detail as probe


def _session() -> MapitSession:
    from datetime import datetime, timezone

    return MapitSession(
        id_token="id-token",
        access_token="access-token",
        refresh_token="refresh-token",
        token_expiration=datetime.now(timezone.utc),
        credentials=TemporaryCredentials(
            access_key_id="access",
            secret_access_key="secret",
            session_token="session",
            expiration=datetime.now(timezone.utc),
        ),
    )


class SavedManager:
    def __init__(self, context: ManagedSession | None, category: str | None = None, **_: object) -> None:
        self.context = context
        self.last_error_category = category

    def login_saved(self):
        return self.context


class RecordingClient:
    def __init__(self, summary, routes, detail=None, *, error=None):
        self.summary = summary
        self.routes = routes
        self.detail = detail if detail is not None else {"route": {"name": "hidden", "coordinates": [1, 2]}}
        self.error = error
        self.calls: list[tuple[str, str, dict | None]] = []

    def get_core(self, path):
        self.calls.append(("core", path, None))
        if isinstance(self.error, tuple) and self.error[0] == "account":
            raise self.error[1]
        return self.summary

    def get_geo(self, path, *, params):
        self.calls.append(("geo", path, dict(params)))
        if path == "/v1/routes":
            if isinstance(self.error, tuple) and self.error[0] == "list":
                raise self.error[1]
            return self.routes
        if isinstance(self.error, tuple) and self.error[0] == "detail":
            raise self.error[1]
        return self.detail


def _run(tmp_path: Path, client: RecordingClient, *, context: ManagedSession | None = None, category=None):
    context = context or ManagedSession(MapitConfig(), _session())
    return probe.perform_route_detail_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, category, **kwargs),
        client_factory=lambda config, session: client,
        save_path=tmp_path / "route-detail.schema.json",
    )


def test_exact_bounded_calls_and_strict_segment_encoding(tmp_path):
    client = RecordingClient(
        {"vehicles": [{"id": "first", "device": None}, {"id": "vehicle/one", "device": {}}]},
        {"data": [{"id": ""}, {"id": "route one?"}], "next": "must-not-follow"},
        {"route": {"name": "secret", "number": 42}},
    )

    result = _run(tmp_path, client)

    assert result["success"] is True
    assert client.calls == [
        ("core", "/v1/account-summary", None),
        ("geo", "/v1/routes", {"vehicleId": "vehicle/one", "limit": 1}),
        (
            "geo",
            "/v1/vehicles/vehicle%2Fone/routes/route%20one%3F",
            {"includeStats": "true"},
        ),
    ]
    saved = json.loads((tmp_path / "route-detail.schema.json").read_text(encoding="utf-8"))
    text = json.dumps(saved)
    assert "secret" not in text
    assert "vehicle/one" not in text
    assert "route one?" not in text
    assert "next" not in text


def test_saved_session_missing_makes_zero_data_calls(tmp_path):
    class NoDataClient:
        def __init__(self, *_):
            raise AssertionError("data client must not be created")

    result = probe.perform_route_detail_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None, None, **kwargs),
        client_factory=NoDataClient,
        save_path=tmp_path / "out.json",
    )

    assert result == {"success": False, "region": "eu-west-1", "error": "session_missing"}
    assert not (tmp_path / "out.json").exists()


def test_saved_session_error_is_safe(tmp_path):
    result = probe.perform_route_detail_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None, "credential_store_failed", **kwargs),
        save_path=tmp_path / "out.json",
    )
    assert result["error"] == "credential_store_failed"
    assert "refresh" not in json.dumps(result)


def test_missing_vehicle_stops_before_geo(tmp_path):
    client = RecordingClient({"vehicles": [{"id": ""}, {"id": 12}]}, {"data": [{"id": "route"}]})
    result = _run(tmp_path, client)
    assert result["error"] == "route_detail_missing_vehicle"
    assert client.calls == [("core", "/v1/account-summary", None)]


def test_missing_route_stops_before_detail(tmp_path):
    client = RecordingClient({"vehicles": [{"id": "vehicle"}]}, {"data": [{"id": ""}, {"id": None}]})
    result = _run(tmp_path, client)
    assert result["error"] == "route_detail_missing_route"
    assert client.calls == [
        ("core", "/v1/account-summary", None),
        ("geo", "/v1/routes", {"vehicleId": "vehicle", "limit": 1}),
    ]


@pytest.mark.parametrize(
    ("where", "exception", "expected"),
    [
        ("account", MapitHTTPError(401, "https://secret.invalid/token"), "account_summary_http_401"),
        ("list", MapitHTTPError(429, "https://secret.invalid/routes?token=secret"), "routes_list_http_429"),
        ("detail", MapitHTTPError(503, "https://secret.invalid/detail"), "route_detail_http_5xx"),
        ("account", MapitTransportError("https://secret.invalid"), "account_summary_transport_failed"),
        ("list", MapitResponseError("body contains secret"), "routes_list_invalid_response"),
        ("detail", MapitTransportError("https://secret.invalid"), "route_detail_transport_failed"),
    ],
)
def test_request_failures_are_sanitized(tmp_path, where, exception, expected):
    client = RecordingClient(
        {"vehicles": [{"id": "vehicle"}]},
        {"data": [{"id": "route"}]},
        error=(where, exception),
    )
    result = _run(tmp_path, client)
    assert result["error"] == expected
    rendered = json.dumps(result)
    assert "secret" not in rendered
    assert "secret.invalid" not in rendered


def test_schema_and_persist_failures_are_categorized(tmp_path, monkeypatch):
    client = RecordingClient({"vehicles": [{"id": "vehicle"}]}, {"data": [{"id": "route"}]})
    monkeypatch.setattr(probe, "schema_only", lambda value: (_ for _ in ()).throw(ValueError("secret")))
    result = _run(tmp_path, client)
    assert result["error"] == "route_detail_schema_failed"

    monkeypatch.setattr(probe, "schema_only", lambda value: {"type": "object", "fields": {"safe": {"type": "string"}}})
    monkeypatch.setattr(probe, "atomic_write_schema", lambda schema, path: (_ for _ in ()).throw(OSError("secret")))
    result = _run(tmp_path, client)
    assert result["error"] == "route_detail_persist_failed"
