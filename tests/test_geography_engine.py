from __future__ import annotations

import pytest

shapely = pytest.importorskip("shapely")
if shapely.__version__ != "2.1.2":
    pytest.skip("geographic engine contract is pinned to Shapely 2.1.2", allow_module_level=True)

from shapely import prepare
from shapely.geometry import Polygon, box

from mapit.geography import classify_route_geojson, validate_area
from mapit.geography_engine import (
    MENORCA_GEOJSON_MAX_BYTES,
    MENORCA_GEOJSON_SHA256,
    GeographyEngineError,
    PreparedPublicArea,
    _PREPARED_AREA_TOKEN,
    classify_public_area_route,
    load_frozen_menorca_area,
)


def synthetic_area(geometry):
    prepare(geometry)
    return PreparedPublicArea(
        geometry=geometry,
        source_version="synthetic-test",
        feature_count=1,
        vertex_count=5,
        ring_count=1,
        _validation_token=_PREPARED_AREA_TOKEN,
    )


def route(*features):
    return {"type": "FeatureCollection", "features": list(features)}


def line(coordinates, inferred=False):
    return {
        "type": "Feature",
        "properties": {"inferred": inferred, "private_label": "discarded"},
        "geometry": {"type": "LineString", "coordinates": coordinates},
    }


def test_prepared_engine_matches_pure_core_for_polygon_and_hole_cases():
    area_doc = {
        "type": "Polygon",
        "coordinates": [
            [[0, 0], [6, 0], [6, 6], [0, 6], [0, 0]],
            [[2, 2], [4, 2], [4, 4], [2, 4], [2, 2]],
        ],
    }
    engine = synthetic_area(Polygon(area_doc["coordinates"][0], [area_doc["coordinates"][1]]))
    cases = [
        route(line([[1, 1], [1.5, 1.5]], inferred=True)),
        route(line([[8, 8], [9, 9]])),
        route(line([[1, 3], [5, 3]])),
        route(line([[2.5, 3], [3.5, 3]])),
        route({"type": "Feature", "geometry": {"type": "Point", "coordinates": [1, 1]}}),
    ]
    pure = validate_area(area_doc)
    for value in cases:
        assert classify_public_area_route(value, engine) == classify_route_geojson(value, pure)


def test_inferred_flag_and_properties_never_change_engine_classification():
    area = synthetic_area(box(0, 0, 4, 4))
    assert classify_public_area_route(route(line([[1, 1], [3, 3]], True)), area) == "fully_inside"
    assert classify_public_area_route(route(line([[1, 1], [3, 3]], False)), area) == "fully_inside"


def test_engine_boundary_contact_matches_pure_boundary_inclusion():
    area = synthetic_area(box(0, 0, 4, 4))
    value = route(line([[0, 0], [4, 0]]))
    assert classify_public_area_route(value, area) == "fully_inside"
    assert classify_public_area_route(value, area) == classify_route_geojson(
        value,
        validate_area({"type": "Polygon", "coordinates": [[[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]]}),
    )


def test_engine_point_tangency_matches_pure_outside_classification():
    area = synthetic_area(box(0, 0, 4, 4))
    value = route(line([[-1, 1], [1, -1]]))
    pure_area = validate_area(
        {"type": "Polygon", "coordinates": [[[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]]]}
    )
    assert classify_public_area_route(value, area) == "outside"
    assert classify_public_area_route(value, area) == classify_route_geojson(value, pure_area)


def test_engine_uses_bounded_predicates_for_many_crossings_without_intersection_output(monkeypatch):
    area = synthetic_area(box(0, 0, 4, 4))
    coordinates = [(-1 + index * 6 / 1999, 2 + (0.2 if index % 2 else -0.2)) for index in range(2000)]

    def no_intersection_materialization(*_args, **_kwargs):
        raise AssertionError("route classification must not materialize an intersection geometry")

    monkeypatch.setattr(type(area.geometry), "intersection", no_intersection_materialization)
    assert classify_public_area_route(route(line(coordinates)), area) == "crossing"


def test_engine_rejects_single_route_above_compiled_coordinate_cap():
    area = synthetic_area(box(0, 0, 4, 4))
    coordinates = [[1 + (index % 2) * 0.001, 1] for index in range(4_097)]
    with pytest.raises(GeographyEngineError) as error:
        classify_public_area_route(route(line(coordinates)), area)
    assert error.value.category == "geometry_budget_exceeded"


def test_repository_boundary_asset_loads_only_from_exact_public_digest():
    from importlib import resources

    raw = resources.files("mapit").joinpath("data", "menorca-ign-20261003.geojson").read_bytes()
    area = load_frozen_menorca_area(raw)
    assert area.feature_count == 8
    assert area.vertex_count == 24_750
    assert area.ring_count == 111
    rendered = repr(area)
    assert "coordinates" not in rendered


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, "unknown"),
        (route({"type": "Feature", "geometry": {"type": "Point", "coordinates": [1, 1]}}), "unknown"),
        (route(line([[1, 1], [float("nan"), 2]])), "unknown"),
        (route(line([[1, 1], [2, 2]]), line([[8, 8], [9, 9]])), "crossing"),
    ],
)
def test_engine_fails_closed_for_malformed_or_mixed_route_geometry(value, expected):
    assert classify_public_area_route(value, synthetic_area(box(0, 0, 4, 4))) == expected


def test_prepared_area_repr_never_includes_coordinates():
    area = synthetic_area(box(100.25, 20.75, 103.5, 22.25))
    rendered = repr(area)
    assert "synthetic-test" in rendered
    assert "100.25" not in rendered
    assert "20.75" not in rendered


def test_prepared_area_cannot_be_constructed_from_untrusted_geometry():
    with pytest.raises(GeographyEngineError) as error:
        PreparedPublicArea(geometry=box(0, 0, 1, 1))
    assert error.value.category == "prepared_area_must_be_loaded_from_frozen_asset"


def test_frozen_loader_rejects_fixture_digest_before_json_or_engine_use(monkeypatch):
    import mapit.geography_engine as engine_module

    def must_not_prepare(_):
        raise AssertionError("digest mismatch must be rejected before parsing/preparation")

    monkeypatch.setattr(engine_module, "_prepare_collection", must_not_prepare)
    with pytest.raises(GeographyEngineError) as error:
        load_frozen_menorca_area(b"{}")
    assert error.value.category == "public_asset_digest_mismatch"


def test_frozen_loader_rejects_wrong_type_and_oversize_without_coordinate_output():
    with pytest.raises(GeographyEngineError) as wrong_type:
        load_frozen_menorca_area("{}")
    assert wrong_type.value.category == "public_asset_size_invalid"
    with pytest.raises(GeographyEngineError) as oversized:
        load_frozen_menorca_area(b" " * (MENORCA_GEOJSON_MAX_BYTES + 1))
    assert oversized.value.category == "public_asset_size_invalid"


def test_frozen_digest_is_fixed_lowercase_sha256():
    assert len(MENORCA_GEOJSON_SHA256) == 64
    assert MENORCA_GEOJSON_SHA256 == MENORCA_GEOJSON_SHA256.lower()
    assert all(character in "0123456789abcdef" for character in MENORCA_GEOJSON_SHA256)
