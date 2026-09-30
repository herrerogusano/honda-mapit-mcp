from __future__ import annotations

import json

import pytest

from mapit.osrm import OUTPUT_KEYS
from scripts import probe_local_osrm_fixture as probe_module
from scripts.probe_local_osrm_fixture import run_local_osrm_fixture_probe


def _route_response():
    return {
        "code": "Ok",
        "routes": [{"geometry": {"type": "LineString", "coordinates": [[7.4, 43.7], [7.401, 43.701], [7.402, 43.702]]}}],
    }


def _match_response():
    return {
        "code": "Ok",
        "matchings": [{"confidence": 0.72, "legs": [{"annotation": {"nodes": [1, 2]}, "steps": [{"name": "Private Street"}]}]}],
        "tracepoints": [{"matchings_index": 0}, {"matchings_index": 0}],
        "coordinates": [[7.4, 43.7]],
    }


def test_probe_calls_only_route_then_match_and_returns_redacted_result():
    calls = []

    def transport(method, url, timeout):
        calls.append((method, url, timeout))
        return _route_response() if "/route/" in url else _match_response()

    result = run_local_osrm_fixture_probe(transport=transport)
    assert result["category"] == "matched"
    assert set(result) == OUTPUT_KEYS
    assert [call[0] for call in calls] == ["GET", "GET"]
    assert "/route/v1/driving/" in calls[0][1]
    assert "/match/v1/driving/" in calls[1][1]
    assert "7.4165000,43.7304000;7.4320000,43.7420000" in calls[0][1]
    match_coordinates = calls[1][1].split("/match/v1/driving/", 1)[1].split("?", 1)[0]
    assert len(match_coordinates.split(";")) <= 12
    rendered = json.dumps(result)
    for sentinel in ("Private Street", "7.4", "43.7", "coordinates", "route"):
        assert sentinel not in rendered


def test_probe_rejects_non_loopback_before_transport():
    called = []
    result = run_local_osrm_fixture_probe(base_url="http://example.com:5000", transport=lambda *args: called.append(args))
    assert result["category"] == "invalid_input"
    assert called == []


@pytest.mark.parametrize("base_url", [
    "http://localhost:5000",
    "http://example.com:5000",
    "http://user:pass@127.0.0.1:5000",
])
def test_probe_accepts_only_literal_loopback_without_external_transport(base_url):
    called = []
    result = run_local_osrm_fixture_probe(base_url=base_url, transport=lambda *args: called.append(args))
    assert result["category"] == "invalid_input"
    assert called == []


def test_ipv6_loopback_literal_is_allowed():
    calls = []

    def transport(method, url, timeout):
        calls.append(url)
        return _route_response() if "/route/" in url else _match_response()

    result = run_local_osrm_fixture_probe(base_url="http://[::1]:5000", transport=transport)
    assert result["category"] == "matched"
    assert calls[0].startswith("http://[::1]:5000/")


def test_redirect_handler_rejects_redirect_without_following(monkeypatch):
    request = probe_module.Request("http://127.0.0.1:5000")
    assert probe_module._NoRedirectHandler().redirect_request(request, object(), "http://example.com/") is None

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def getcode(self):
            return 302

        def read(self, _):
            raise AssertionError("redirect body must not be read")

    class Opener:
        def __init__(self):
            self.calls = 0

        def open(self, *_args, **_kwargs):
            self.calls += 1
            return Response()

    opener = Opener()
    monkeypatch.setattr(probe_module, "_NO_REDIRECT_OPENER", opener)
    with pytest.raises(probe_module._ProbeError) as caught:
        probe_module._urllib_transport("GET", "http://127.0.0.1:5000/route", 1.0)
    assert caught.value.category == "engine_unavailable"
    assert opener.calls == 1


def test_probe_fails_safe_for_route_shape_or_oversized_payload():
    result = run_local_osrm_fixture_probe(transport=lambda *_: {"code": "Ok", "routes": []})
    assert result["category"] == "invalid_input"
    result = run_local_osrm_fixture_probe(transport=lambda *_: b"x" * (2 * 1024 * 1024 + 1))
    assert result["category"] == "resource_limit"
    deep = None
    for _ in range(20):
        deep = [deep]
    result = run_local_osrm_fixture_probe(transport=lambda *_: {"code": "Ok", "routes": deep})
    assert result["category"] == "resource_limit"


def test_probe_hard_caps_long_route_sampling_at_twelve_points():
    route = {
        "code": "Ok",
        "routes": [{"geometry": {"type": "LineString", "coordinates": [[7.4 + i / 1000, 43.7 + i / 1000] for i in range(30)]}}],
    }
    calls = []

    def transport(method, url, timeout):
        calls.append(url)
        return route if "/route/" in url else _match_response()

    result = run_local_osrm_fixture_probe(transport=transport)
    assert result["category"] == "matched"
    match_coordinates = calls[1].split("/match/v1/driving/", 1)[1].split("?", 1)[0]
    assert len(match_coordinates.split(";")) == 12


def test_probe_maps_transport_failure_to_engine_unavailable_without_detail():
    result = run_local_osrm_fixture_probe(transport=lambda *_: (_ for _ in ()).throw(OSError("secret URL/body")))
    assert result["category"] == "engine_unavailable"
    assert "secret" not in json.dumps(result)
    assert result["raw_discarded"] is True
