from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mapit.geography import GeographyError, classify_route_geojson, summer_window_utc, validate_area


def polygon(coordinates):
    return {"type": "Polygon", "coordinates": [coordinates]}


def square_geojson():
    return polygon([[0, 0], [4, 0], [4, 4], [0, 4], [0, 0]])


def track(*positions):
    return {
        "type": "FeatureCollection",
        "features": [
            {
                "type": "Feature",
                "properties": {"inferred": False},
                "geometry": {"type": "LineString", "coordinates": [list(position) for position in positions]},
            }
        ],
    }


@pytest.mark.parametrize(
    ("geojson", "expected"),
    [
        (track((1, 1), (3, 3)), "fully_inside"),
        (track((5, 1), (6, 3)), "outside"),
        (track((-1, 2), (5, 2)), "crossing"),
        (track((0, 0), (4, 0)), "fully_inside"),  # boundary contact counts as covered
        (track((-1, 1), (1, -1)), "outside"),  # a point-only tangency has no inside interval
    ],
)
def test_line_classification(geojson, expected):
    assert classify_route_geojson(geojson, validate_area(square_geojson())) == expected


def test_polygon_hole_is_not_counted_as_inside_and_route_is_crossing():
    area = polygon(
        [
            [0, 0], [6, 0], [6, 6], [0, 6], [0, 0],
        ]
    )
    area["coordinates"].append([[2, 2], [4, 2], [4, 4], [2, 4], [2, 2]])
    validated = validate_area(area)

    assert classify_route_geojson(track((1, 3), (5, 3)), validated) == "crossing"
    assert classify_route_geojson(track((2.5, 3), (3.5, 3)), validated) == "outside"


def test_multipolygon_gap_between_inside_endpoints_is_crossing():
    multipolygon = {
        "type": "MultiPolygon",
        "coordinates": [
            [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]],
            [[[3, 0], [4, 0], [4, 1], [3, 1], [3, 0]]],
        ],
    }
    assert classify_route_geojson(track((0.5, 0.5), (3.5, 0.5)), validate_area(multipolygon)) == "crossing"


@pytest.mark.parametrize(
    "geojson",
    [
        None,
        {"type": "FeatureCollection", "features": []},
        {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": "Point", "coordinates": [1, 1]}}]},
        {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": "LineString", "coordinates": [[1, 1], [float("nan"), 2]]}}]},
        {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": "Polygon", "coordinates": []}}]},
    ],
)
def test_missing_or_unsupported_route_geometry_is_unknown(geojson):
    assert classify_route_geojson(geojson, validate_area(square_geojson())) == "unknown"


@pytest.mark.parametrize(
    "area",
    [
        None,
        {"type": "Point", "coordinates": [1, 2]},
        polygon([[0, 0], [4, 4], [0, 4], [4, 0], [0, 0]]),  # self-intersecting
        polygon([[179, 0], [-179, 0], [-179, 1], [179, 1], [179, 0]]),  # antimeridian
    ],
)
def test_bad_or_unsupported_area_fails_closed(area):
    with pytest.raises(GeographyError):
        validate_area(area)


def test_area_vertex_budget_precedes_expensive_topology_validation():
    ring = [[1, 1]] * 400  # Aggregate limit is checked before ring topology.
    area = {"type": "MultiPolygon", "coordinates": [[ring] for _ in range(6)]}
    with pytest.raises(GeographyError) as error:
        validate_area(area)
    assert error.value.category == "area_too_complex"


def test_area_coordinates_are_not_in_repr():
    area = validate_area(square_geojson())
    assert "ValidatedArea" in repr(area)
    assert "vertex_count=5" in repr(area)
    assert "0.0" not in repr(area)


def test_work_cap_returns_unknown_without_partial_inside_claim():
    assert classify_route_geojson(track((1, 1), (3, 3)), validate_area(square_geojson()), max_segment_edge_tests=1) == "unknown"


@pytest.mark.parametrize(
    ("year", "expected"),
    [
        (2026, ("2026-05-31T22:00:00.000Z", "2026-08-31T22:00:00.000Z")),
        (2002, ("2002-05-31T22:00:00.000Z", "2002-08-31T22:00:00.000Z")),
        (2031, ("2031-05-31T22:00:00.000Z", "2031-08-31T22:00:00.000Z")),
    ],
)
def test_summer_window_is_explicit_fixed_cest_interval(year, expected):
    assert summer_window_utc(year) == expected


def test_summer_window_infers_calendar_year_safely_near_utc_year_boundary():
    assert summer_window_utc(now=datetime(2025, 12, 31, 23, 30, tzinfo=timezone.utc)) == summer_window_utc(2026)
    assert summer_window_utc(now=datetime(2026, 1, 1, 0, 30, tzinfo=timezone.utc)) == summer_window_utc(2026)


@pytest.mark.parametrize("year", [True, 2001, 2032, 2026.0])
def test_summer_window_rejects_unsupported_years(year):
    with pytest.raises(GeographyError) as error:
        summer_window_utc(year)
    assert error.value.category == "unsupported_summer_year"


def test_summer_window_rejects_naive_clock():
    with pytest.raises(GeographyError) as error:
        summer_window_utc(now=datetime(2026, 1, 1))
    assert error.value.category == "invalid_clock"
