from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitHTTPError, MapitResponseError, MapitResponseTooLarge, MapitTransportError
from mapit.config import MapitConfig
from mapit.session import ManagedSession
from scripts import probe_route_input_sufficiency as probe


def _session() -> MapitSession:
    now = datetime.now(timezone.utc)
    return MapitSession(
        id_token="id-token",
        access_token="access-token",
        refresh_token="refresh-token",
        token_expiration=now,
        credentials=TemporaryCredentials(
            access_key_id="access",
            secret_access_key="secret",
            session_token="session",
            expiration=now,
        ),
    )


def _detail():
    return {
        "id": "detail-secret",
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [{
                "type": "Feature",
                "properties": {"name": "secret-name", "timestamps": [1, 2]},
                "geometry": {"type": "LineString", "coordinates": [[-3.7, 40.4], [-3.701, 40.401, 77]]},
            }],
        },
        "startedAt": "secret-time",
    }


class SavedManager:
    def __init__(self, context, category=None, **_):
        self.context = context
        self.last_error_category = category

    def login_saved(self):
        return self.context


class RecordingClient:
    def __init__(self, detail=None, error=None):
        self.detail = detail if detail is not None else _detail()
        self.error = error
        self.calls = []

    def get_core(self, path, **kwargs):
        self.calls.append(("core", path, None))
        if isinstance(self.error, tuple) and self.error[0] == "account":
            raise self.error[1]
        return {"vehicles": [{"id": "vehicle/one", "device": {}}]}

    def get_geo(self, path, *, params, **kwargs):
        self.calls.append(("geo", path, dict(params)))
        if isinstance(self.error, tuple) and self.error[0] == path:
            raise self.error[1]
        if path == "/v1/routes":
            return {"data": [{"id": "route one?"}]}
        return self.detail


def _run(client, *, context=None, category=None):
    context = context or ManagedSession(MapitConfig(), _session())
    return probe.perform_route_input_sufficiency_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, category, **kwargs),
        client_factory=lambda config, session: client,
    )


def test_exact_three_logical_reads_and_encoded_detail_without_leakage():
    client = RecordingClient()
    result = _run(client)
    assert result["success"] is True
    assert client.calls == [
        ("core", "/v1/account-summary", None),
        ("geo", "/v1/routes", {"vehicleId": "vehicle/one", "limit": 1}),
        ("geo", "/v1/vehicles/vehicle%2Fone/routes/route%20one%3F", {"includeStats": "true"}),
    ]
    rendered = json.dumps(result)
    for sentinel in ("vehicle/one", "route one?", "secret-name", "secret-time", "detail-secret"):
        assert sentinel not in rendered


def test_missing_saved_session_makes_zero_data_calls():
    class NoDataClient:
        def __init__(self, *_):
            raise AssertionError("client must not be built")

    result = probe.perform_route_input_sufficiency_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None, "session_missing", **kwargs),
        client_factory=NoDataClient,
    )
    assert result["success"] is False and result["category"] == "session_missing"


def test_missing_route_stops_before_detail():
    class MissingRouteClient(RecordingClient):
        def get_geo(self, path, *, params, **kwargs):
            self.calls.append(("geo", path, dict(params)))
            return {"data": []}

    client = MissingRouteClient()
    result = _run(client)
    assert result["category"] == "routes_list_missing_route"
    assert len(client.calls) == 2


@pytest.mark.parametrize(
    ("where", "exception", "expected"),
    [
        ("account", MapitHTTPError(401, "https://secret.invalid"), "account_summary_http_401"),
        ("/v1/routes", MapitTransportError("secret"), "routes_list_transport_failed"),
        ("/v1/vehicles/vehicle%2Fone/routes/route%20one%3F", MapitResponseError("body secret"), "route_detail_invalid_response"),
        ("/v1/vehicles/vehicle%2Fone/routes/route%20one%3F", MapitResponseTooLarge(), "route_detail_response_too_large"),
    ],
)
def test_request_failures_are_safe(where, exception, expected):
    client = RecordingClient(error=(where, exception))
    result = _run(client)
    assert result["success"] is False and result["category"] == expected
    assert "secret" not in json.dumps(result)


def test_detail_unknown_shape_fails_closed_without_raw_data():
    client = RecordingClient(detail={"geoJSON": {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": "Polygon", "coordinates": []}}]}})
    result = _run(client)
    assert result["category"] == "route_input_unsupported_geometry"
    assert "Polygon" not in json.dumps(result)
