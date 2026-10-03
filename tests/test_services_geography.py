from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from mapit.services import MapitServices, ServiceError


SQUARE = {"type": "Polygon", "coordinates": [[[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]]}


def feature(kind, coordinates, inferred=False):
    return {
        "type": "Feature",
        "properties": {"inferred": inferred, "label": "never-retain-this"},
        "geometry": {"type": kind, "coordinates": coordinates},
    }


def route(route_id, started, distance, geojson, *, flags=False):
    return {"id": route_id, "startedAt": started, "distance": distance, "geoJSON": geojson}


class GeoClient:
    def __init__(self, payloads):
        self.payloads = list(payloads)
        self.calls = []

    def get_core(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("core", path, params))
        return {"vehicles": [{"id": "vehicle-in-memory"}]}

    def get_geo(self, path, *, params=None, max_response_bytes=None):
        self.calls.append(("geo", path, params))
        assert path == "/v1/routes"
        return self.payloads.pop(0) if self.payloads else {"data": []}


def fc(*features):
    return {"type": "FeatureCollection", "features": list(features)}


def test_geographic_summary_classifies_embedded_geometry_without_detail_gets():
    payload = {
        "data": [
            route("private-id-inside", "2026-01-10T00:00:00Z", 1000, fc(feature("LineString", [[1, 1], [3, 3]], True))),
            route("private-id-out", "2026-01-11T00:00:00Z", 2000, fc(feature("LineString", [[5, 1], [6, 3]]))),
            route("private-id-cross", "2026-01-12T00:00:00Z", 3000, fc(feature("LineString", [[-1, 2], [5, 2]]))),
            route("private-id-unknown", "2026-01-13T00:00:00Z", 4000, fc(feature("Point", [1, 1]))),
        ]
    }
    client = GeoClient([payload])
    result = MapitServices(client).get_geographic_summary("2026-01-01", "2026-02-01", SQUARE)

    assert result.matched_routes == 4
    assert (result.fully_inside_routes, result.outside_routes, result.crossing_routes, result.unknown_routes) == (1, 1, 1, 1)
    assert result.fully_inside_distance == 1000
    assert result.fully_inside_distance_km == 1
    assert result.inferred_marked_inside_routes == 1
    assert result.not_marked_inferred_inside_routes == 0
    assert result.inference_unknown_inside_routes == 0
    assert result.completeness == "unverified"
    assert len([call for call in client.calls if call[0] == "geo"]) == 1
    assert not any("/routes/" in str(call) for call in client.calls)
    rendered = result.model_dump_json()
    assert "private-id" not in rendered
    assert "never-retain-this" not in rendered
    assert '"features"' not in rendered
    assert '"geometry"' not in rendered
    assert "area_geojson" not in rendered


def test_geojson_is_reduced_to_coordinates_only_before_retention(monkeypatch):
    import mapit.services as services_module

    captured = []
    original = services_module.classify_route_geojson_with_work

    def inspect(geojson, area, **kwargs):
        captured.append(geojson)
        return original(geojson, area, **kwargs)

    monkeypatch.setattr(services_module, "classify_route_geojson_with_work", inspect)
    payload = {"data": [route("private", "2026-01-10T00:00:00Z", 1, fc(feature("LineString", [[1, 1], [2, 2]])))]}
    MapitServices(GeoClient([payload])).get_geographic_summary("2026-01-01", "2026-02-01", SQUARE)

    assert captured
    assert "properties" not in captured[0]["features"][0]
    assert "label" not in json.dumps(captured)


@pytest.mark.parametrize(
    ("started_at", "code"),
    [
        ("2026-01-01", "invalid_route_timestamp"),
        ("2026-02-01T00:00:00Z", "route_outside_requested_interval"),
        ("2025-12-31T23:59:59Z", "route_outside_requested_interval"),
        ("2026-01-10T00:00:00", "invalid_route_timestamp"),
    ],
)
def test_new_path_requires_aware_start_within_half_open_interval(started_at, code):
    payload = {"data": [route("private", started_at, 5, fc(feature("LineString", [[1, 1], [2, 2]])))]}
    with pytest.raises(ServiceError) as error:
        MapitServices(GeoClient([payload])).get_geographic_summary("2026-01-01", "2026-02-01", SQUARE)
    assert error.value.code == code


def test_invalid_first_window_fact_stops_before_later_month_get():
    first = {"data": [route("private", "2026-03-01T00:00:00Z", 1, fc(feature("LineString", [[1, 1], [2, 2]])))]}
    client = GeoClient([first, {"data": []}])
    with pytest.raises(ServiceError) as error:
        MapitServices(client).get_geographic_summary("2026-01-01", "2026-03-01", SQUARE)
    assert error.value.code == "route_outside_requested_interval"
    assert len([call for call in client.calls if call[0] == "geo"]) == 1


@pytest.mark.parametrize("distance", [None, -1, float("inf"), float("nan")])
def test_new_path_rejects_invalid_distance_for_any_route(distance):
    payload = {"data": [route("private", "2026-01-10T00:00:00Z", distance, fc(feature("Point", [8, 8])))]}
    with pytest.raises(ServiceError) as error:
        MapitServices(GeoClient([payload])).get_geographic_summary("2026-01-01", "2026-02-01", SQUARE)
    assert error.value.code == "distance_unavailable"


def test_invalid_area_and_too_wide_period_stop_before_network():
    client = GeoClient([])
    service = MapitServices(client)
    with pytest.raises(ServiceError) as invalid_area:
        service.get_geographic_summary("2026-01-01", "2026-02-01", {"type": "Point"})
    assert invalid_area.value.code == "unsupported_area"
    with pytest.raises(ServiceError) as wide:
        service.get_geographic_summary("2026-01-01", "2026-04-10", SQUARE)
    assert wide.value.code == "geographic_period_too_large"
    assert client.calls == []


def test_geometry_caps_fail_the_whole_request_not_a_partial_summary(monkeypatch):
    import mapit.services as services_module

    monkeypatch.setattr(services_module, "MAX_GEOGRAPHIC_BATCH_OPERATIONS", 1)
    payload = {"data": [route("private", "2026-01-10T00:00:00Z", 1, fc(feature("LineString", [[1, 1], [2, 2]])))]}
    with pytest.raises(ServiceError) as error:
        MapitServices(GeoClient([payload])).get_geographic_summary("2026-01-01", "2026-02-01", SQUARE)
    assert error.value.code == "geometry_budget_exceeded"


def test_compiled_area_route_cap_stops_before_requesting_next_month():
    pytest.importorskip("shapely")
    from shapely.geometry import box
    from shapely import prepare

    from mapit.geography_engine import PreparedPublicArea, _PREPARED_AREA_TOKEN

    geometry = box(0, 0, 4, 4)
    prepare(geometry)
    area = PreparedPublicArea(
        geometry=geometry,
        source_version="synthetic-test",
        feature_count=1,
        vertex_count=5,
        ring_count=1,
        _validation_token=_PREPARED_AREA_TOKEN,
    )
    coordinates = [[1 + (index % 2) * 0.001, 1] for index in range(4_097)]
    first = {"data": [route("oversized", "2026-01-10T00:00:00Z", 1, fc(feature("LineString", coordinates)))]}
    client = GeoClient([first, {"data": []}])
    with pytest.raises(ServiceError) as error:
        MapitServices(client).get_geographic_summary(
            "2026-01-01", "2026-03-01", area, "ign_menorca_municipalities_union_2026_10_03"
        )
    assert error.value.code == "geometry_budget_exceeded"
    assert len([call for call in client.calls if call[0] == "geo"]) == 1


def test_summer_convenience_uses_fixed_utc_bounds_and_fails_closed_on_area():
    client = GeoClient([{"data": []}])
    result = MapitServices(client).get_summer_geographic_summary(
        SQUARE,
        now=datetime(2025, 12, 31, 23, 30, tzinfo=timezone.utc),
    )
    assert result.from_time == "2026-05-31T22:00:00.000Z"
    assert result.to_time == "2026-08-31T22:00:00.000Z"
    calls = [call for call in client.calls if call[0] == "geo"]
    assert calls[0][2]["from"] == result.from_time
    assert calls[-1][2]["to"] == result.to_time
