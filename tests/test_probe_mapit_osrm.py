from __future__ import annotations

import json
import io
import urllib.request
import urllib.error
from datetime import datetime, timezone

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.config import MapitConfig
from mapit.session import ManagedSession
from scripts import probe_mapit_osrm as probe
from scripts import probe_local_osrm_fixture as local_probe


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


def _detail(*, coordinates=None):
    return {
        "id": "detail-secret",
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [
                {"type": "Feature", "geometry": {"type": "Point", "coordinates": [2.1, 41.3]}},
                {
                    "type": "Feature",
                    "geometry": {
                        "type": "LineString",
                        "coordinates": coordinates or [[2.10, 41.30, 900], [2.11, 41.31, 901]],
                    },
                },
            ],
        },
        "startedAt": "secret-time",
    }


def _match_response():
    return {
        "code": "Ok",
        "matchings": [{"confidence": 0.72, "legs": [{"annotation": {}, "steps": [{"name": "private"}]}]}],
        "tracepoints": [{"matchings_index": 0}, {"matchings_index": 0}],
    }


class SavedManager:
    def __init__(self, context, **_):
        self.context = context

    def login_saved(self):
        return self.context


class RecordingClient:
    def __init__(self, *, detail=None, missing_route=False, error=None):
        self.detail = detail if detail is not None else _detail()
        self.missing_route = missing_route
        self.error = error
        self.calls = []

    def get_core(self, path, **kwargs):
        self.calls.append(("core", path, None, kwargs))
        if self.error is not None and self.error[0] == "account":
            raise self.error[1]
        return {"vehicles": [{"id": "vehicle/secret", "device": {}}]}

    def get_geo(self, path, *, params, **kwargs):
        self.calls.append(("geo", path, dict(params), kwargs))
        if self.error is not None and self.error[0] == path:
            raise self.error[1]
        if path == "/v1/routes":
            return {"data": [] if self.missing_route else [{"id": "route secret?"}]}
        return self.detail


def _run(client, *, base_url="http://127.0.0.1:5000", osrm_transport=None, context=None):
    context = context or ManagedSession(MapitConfig(), _session())
    return probe.perform_mapit_osrm_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda config, session: client,
        osrm_transport=osrm_transport or (lambda method, url, timeout: _match_response()),
        osrm_base_url=base_url,
    )


def test_exact_three_mapit_reads_then_one_local_match_and_fixed_output():
    client = RecordingClient()
    osrm_calls = []

    def osrm_transport(method, url, timeout):
        osrm_calls.append((method, url, timeout))
        return _match_response()

    result = _run(client, osrm_transport=osrm_transport)
    assert result["category"] == "matched"
    assert set(result) == probe.OUTPUT_KEYS
    assert [(kind, path, params) for kind, path, params, _ in client.calls] == [
        ("core", "/v1/account-summary", None),
        ("geo", "/v1/routes", {"vehicleId": "vehicle/secret", "limit": 1}),
        ("geo", "/v1/vehicles/vehicle%2Fsecret/routes/route%20secret%3F", {"includeStats": "true"}),
    ]
    assert len(osrm_calls) == 1
    assert "/match/v1/driving/" in osrm_calls[0][1]
    assert "tidy=false" in osrm_calls[0][1]
    rendered = json.dumps(result)
    for sentinel in ("vehicle/secret", "route secret?", "detail-secret", "secret-time", "2.1", "41.3", "private"):
        assert sentinel not in rendered


def test_third_ordinate_is_discarded_and_not_sent_to_osrm():
    client = RecordingClient(detail=_detail(coordinates=[[2.10, 41.30, 987654321], [2.11, 41.31, 987654322]]))
    calls = []
    result = _run(client, osrm_transport=lambda method, url, timeout: calls.append(url) or _match_response())
    assert result["category"] == "matched"
    assert result["stage_category"] == "success"
    assert "987654321" not in calls[0]
    assert "987654322" not in calls[0]


def test_missing_saved_session_makes_zero_mapit_and_osrm_calls():
    called = []
    result = probe.perform_mapit_osrm_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None, **kwargs),
        client_factory=lambda *_: (_ for _ in ()).throw(AssertionError("client must not be built")),
        osrm_transport=lambda *args: called.append(args),
    )
    assert result["category"] == "engine_unavailable"
    assert result["stage_category"] == "session_missing"
    assert called == []


def test_missing_route_stops_before_detail_or_osrm():
    client = RecordingClient(missing_route=True)
    called = []
    result = _run(client, osrm_transport=lambda *args: called.append(args))
    assert result["category"] == "invalid_input"
    assert result["stage_category"] == "routes_list_invalid"
    assert len(client.calls) == 2
    assert called == []


@pytest.mark.parametrize(
    ("where", "expected"),
    [("account", "account_summary_too_large"), ("/v1/routes", "routes_list_too_large")],
)
def test_account_and_list_size_failures_keep_stage_category(where, expected):
    client = RecordingClient(error=(where, probe.MapitResponseTooLarge()))
    result = _run(client)
    assert result["category"] == "resource_limit"
    assert result["stage_category"] == expected


def test_more_than_500_coordinates_is_resource_limit_without_osrm_call():
    coordinates = [[2.1 + (index % 10) * 0.001, 41.3 + (index // 10) * 0.0001] for index in range(501)]
    client = RecordingClient(detail=_detail(coordinates=coordinates))
    called = []
    result = _run(client, osrm_transport=lambda *args: called.append(args))
    assert result["category"] == "resource_limit"
    assert result["stage_category"] == "route_detail_too_large"
    assert called == []


def test_bbox_and_local_endpoint_fail_closed_before_osrm():
    outside = RecordingClient(detail=_detail(coordinates=[[2.1, 41.3], [3.0, 41.31]]))
    called = []
    result = _run(outside, osrm_transport=lambda *args: called.append(args))
    assert result["category"] == "invalid_input"
    assert result["stage_category"] == "outside_bbox"
    assert called == []
    result = _run(RecordingClient(), base_url="http://localhost:5000", osrm_transport=lambda *args: called.append(args))
    assert result["category"] == "invalid_input"
    assert result["stage_category"] == "matcher_invalid"
    assert called == []


def test_osrm_failure_is_fixed_and_redacted():
    result = _run(RecordingClient(), osrm_transport=lambda *args: (_ for _ in ()).throw(OSError("signed URL secret")))
    assert result["category"] == "engine_unavailable"
    assert set(result) == probe.OUTPUT_KEYS
    assert "secret" not in json.dumps(result)


def test_local_osrm_http_400_nomatch_body_is_classified(monkeypatch):
    body = json.dumps({"code": "NoMatch", "matchings": [], "tracepoints": []}).encode()

    class Opener:
        def open(self, *_args, **_kwargs):
            raise urllib.error.HTTPError("http://127.0.0.1:5000/match", 400, "NoMatch", {}, io.BytesIO(body))

    monkeypatch.setattr(probe, "_NO_REDIRECT_OPENER", Opener())
    client = RecordingClient()
    result = _run(client, osrm_transport=probe._local_osrm_transport)
    assert result["category"] == "no_match"
    assert result["stage_category"] == "matcher_no_match"


def test_local_fixture_opener_has_empty_proxy_configuration(monkeypatch):
    assert local_probe._NO_PROXY_HANDLER.proxies == {}
    monkeypatch.setattr(urllib.request, "getproxies", lambda: {"http": "http://proxy.invalid:9999"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), local_probe._NoRedirectHandler)
    assert not any(handler.__class__.__name__ == "ProxyHandler" for handler in opener.handlers)
