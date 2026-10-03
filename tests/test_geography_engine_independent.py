"""Independent cross-checks for the optional prepared public-boundary engine."""

from __future__ import annotations

import pytest

shapely = pytest.importorskip("shapely")
if shapely.__version__ != "2.1.2":
    pytest.skip("geographic engine contract is pinned to Shapely 2.1.2", allow_module_level=True)

from pathlib import Path

from shapely import prepare
from shapely.geometry import MultiPolygon, Polygon

from mapit.geography import classify_route_geojson, validate_area
from mapit.geography_engine import (
    MENORCA_AREA_VERSION,
    MENORCA_GEOJSON_MAX_BYTES,
    MENORCA_GEOJSON_SHA256,
    PreparedPublicArea,
    _PREPARED_AREA_TOKEN,
    classify_public_area_route,
    load_frozen_menorca_area,
)


def _area(geometry):
    prepare(geometry)
    return PreparedPublicArea(
        geometry=geometry,
        source_version="independent-synthetic",
        feature_count=1,
        vertex_count=5,
        ring_count=1,
        _validation_token=_PREPARED_AREA_TOKEN,
    )


def _route(kind, coordinates, inferred=None):
    properties = {"inferred": inferred, "label": "private-geometry-canary"}
    return {
        "type": "FeatureCollection",
        "features": [{
            "type": "Feature",
            "properties": properties,
            "geometry": {"type": kind, "coordinates": coordinates},
        }],
    }


@pytest.mark.parametrize(
    ("area_geometry", "area_doc", "route_doc"),
    [
        (
            Polygon([[0, 0], [4, 0], [4, 4], [3, 4], [3, 1], [1, 1], [1, 4], [0, 4], [0, 0]]),
            {"type": "Polygon", "coordinates": [[[0, 0], [4, 0], [4, 4], [3, 4], [3, 1], [1, 1], [1, 4], [0, 4], [0, 0]]]},
            _route("LineString", [[0.5, 3.5], [3.5, 3.5]], True),
        ),
        (
            Polygon([[0, 0], [6, 0], [6, 6], [0, 6], [0, 0]], [[[2, 2], [4, 2], [4, 4], [2, 4], [2, 2]]]),
            {"type": "Polygon", "coordinates": [[[0, 0], [6, 0], [6, 6], [0, 6], [0, 0]], [[2, 2], [4, 2], [4, 4], [2, 4], [2, 2]]]},
            _route("LineString", [[1, 3], [5, 3]], False),
        ),
        (
            MultiPolygon([
                Polygon([[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]),
                Polygon([[3, 0], [4, 0], [4, 1], [3, 1], [3, 0]]),
            ]),
            {"type": "MultiPolygon", "coordinates": [
                [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]],
                [[[3, 0], [4, 0], [4, 1], [3, 1], [3, 0]]],
            ]},
            {"type": "FeatureCollection", "features": [{
                "type": "Feature", "geometry": {"type": "MultiLineString", "coordinates": [
                    [[0.2, 0.2], [0.8, 0.8]], [[3.2, 0.2], [3.8, 0.8]],
                ]},
            }]},
        ),
    ],
)
def test_engine_matches_pure_classifier_for_concavity_holes_and_multipolygon_union(
    area_geometry, area_doc, route_doc
):
    engine_area = _area(area_geometry)
    expected = classify_route_geojson(route_doc, validate_area(area_doc))
    assert classify_public_area_route(route_doc, engine_area) == expected


def test_frozen_packaged_asset_loads_from_exact_digest_and_preserves_topology():
    asset = Path(__file__).parents[1] / "src" / "mapit" / "data" / "menorca-ign-20261003.geojson"
    size = asset.stat().st_size
    assert 0 < size <= MENORCA_GEOJSON_MAX_BYTES
    raw = asset.read_bytes()
    assert len(raw) == size
    import hashlib

    assert hashlib.sha256(raw).hexdigest() == MENORCA_GEOJSON_SHA256
    prepared = load_frozen_menorca_area(raw)
    assert prepared.source_version == MENORCA_AREA_VERSION
    assert prepared.feature_count == 8
    assert prepared.vertex_count == 24_750
    assert prepared.ring_count == 111
    assert prepared.geometry.geom_type == "MultiPolygon"
    assert prepared.geometry.is_valid
    # The public union remains polygonal and exposes only aggregate counts in
    # repr; synthetic hole semantics are checked separately above.
    assert "39." not in repr(prepared)
    assert "4." not in repr(prepared)
