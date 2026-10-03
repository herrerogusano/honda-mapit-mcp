"""Independent topology edge cases for the bounded geography classifier."""

from __future__ import annotations

import pytest

from mapit.geography import GeographyError, classify_route_geojson, validate_area


def _polygon(ring, *holes):
    return {"type": "Polygon", "coordinates": [ring, *holes]}


def _track(kind, coordinates):
    return {
        "type": "FeatureCollection",
        "features": [{"type": "Feature", "geometry": {"type": kind, "coordinates": coordinates}}],
    }


def test_concavity_exit_between_inside_endpoints_is_crossing():
    concave = _polygon(
        [[0, 0], [4, 0], [4, 4], [3, 4], [3, 1], [1, 1], [1, 4], [0, 4], [0, 0]]
    )
    route = _track("LineString", [[0.5, 3.5], [3.5, 3.5]])
    assert classify_route_geojson(route, validate_area(concave)) == "crossing"


def test_multiline_parts_in_disconnected_polygon_union_are_fully_inside():
    two_islands = {
        "type": "MultiPolygon",
        "coordinates": [
            [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]],
            [[[3, 0], [4, 0], [4, 1], [3, 1], [3, 0]]],
        ],
    }
    route = _track("MultiLineString", [[[0.2, 0.2], [0.8, 0.8]], [[3.2, 0.2], [3.8, 0.8]]])
    assert classify_route_geojson(route, validate_area(two_islands)) == "fully_inside"


def test_hole_boundary_is_included_but_hole_interior_is_not():
    donut = _polygon(
        [[0, 0], [6, 0], [6, 6], [0, 6], [0, 0]],
        [[2, 2], [4, 2], [4, 4], [2, 4], [2, 2]],
    )
    area = validate_area(donut)
    boundary_track = _track("LineString", [[2, 2.5], [2, 3.5]])
    hole_track = _track("LineString", [[2.5, 3], [3.5, 3]])
    assert classify_route_geojson(boundary_track, area) == "fully_inside"
    assert classify_route_geojson(hole_track, area) == "outside"


def test_adjacent_ring_edges_cannot_backtrack_over_each_other():
    backtracking = _polygon([[0, 0], [3, 0], [1, 0], [3, 2], [0, 2], [0, 0]])
    with pytest.raises(GeographyError):
        validate_area(backtracking)
