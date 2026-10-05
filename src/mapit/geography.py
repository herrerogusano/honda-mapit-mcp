"""Bounded, conservative planar classification for route GeoJSON.

This module does not geocode, clip tracks, infer roads, or retain coordinates.
Coordinates are interpreted as longitude/latitude in a local planar test;
the result describes only the supplied source geometry, not physical coverage.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Literal, Mapping

AreaRelation = Literal["fully_inside", "outside", "crossing", "unknown"]

MAX_AREA_POLYGONS = 16
MAX_AREA_RINGS = 64
MAX_AREA_VERTICES = 2048
MAX_RING_VERTICES = 512
MAX_ROUTE_FEATURES = 4096
MAX_ROUTE_COORDINATES = 100_000
MAX_ROUTE_SEGMENT_EDGE_TESTS = 2_000_000
MAX_GEOGRAPHIC_ROUTE_FEATURES = 10_000
MAX_GEOGRAPHIC_ROUTE_COORDINATES = 100_000
_EPSILON = 1e-12


class GeographyError(ValueError):
    """Safe, fixed-category input error for geographic requests."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


Point = tuple[float, float]
Ring = tuple[Point, ...]
Polygon = tuple[Ring, ...]


@dataclass(frozen=True, repr=False)
class ValidatedArea:
    """Validated polygon coordinates, deliberately omitted from repr/output."""

    polygons: tuple[Polygon, ...] = field(repr=False)
    vertex_count: int
    source: Literal["caller_supplied_geojson"] = "caller_supplied_geojson"

    def __repr__(self) -> str:
        return f"ValidatedArea(source={self.source!r}, vertex_count={self.vertex_count})"


def _finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _position(value: Any) -> Point:
    if not isinstance(value, (list, tuple)) or len(value) not in (2, 3):
        raise GeographyError("invalid_area")
    if any(not _finite_number(item) for item in value):
        raise GeographyError("invalid_area")
    longitude, latitude = float(value[0]), float(value[1])
    if not -180 <= longitude <= 180 or not -90 <= latitude <= 90:
        raise GeographyError("invalid_area")
    return longitude, latitude


def _cross(a: Point, b: Point, c: Point) -> float:
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def _on_segment(point: Point, start: Point, end: Point) -> bool:
    if abs(_cross(start, end, point)) > _EPSILON:
        return False
    return (
        min(start[0], end[0]) - _EPSILON <= point[0] <= max(start[0], end[0]) + _EPSILON
        and min(start[1], end[1]) - _EPSILON <= point[1] <= max(start[1], end[1]) + _EPSILON
    )


def _segments_intersect(a: Point, b: Point, c: Point, d: Point) -> bool:
    ab_c, ab_d = _cross(a, b, c), _cross(a, b, d)
    cd_a, cd_b = _cross(c, d, a), _cross(c, d, b)
    if ((ab_c > _EPSILON and ab_d < -_EPSILON) or (ab_c < -_EPSILON and ab_d > _EPSILON)) and (
        (cd_a > _EPSILON and cd_b < -_EPSILON) or (cd_a < -_EPSILON and cd_b > _EPSILON)
    ):
        return True
    return (
        abs(ab_c) <= _EPSILON and _on_segment(c, a, b)
        or abs(ab_d) <= _EPSILON and _on_segment(d, a, b)
        or abs(cd_a) <= _EPSILON and _on_segment(a, c, d)
        or abs(cd_b) <= _EPSILON and _on_segment(b, c, d)
    )


def _signed_area(ring: Ring) -> float:
    return sum(
        ring[index][0] * ring[index + 1][1] - ring[index + 1][0] * ring[index][1]
        for index in range(len(ring) - 1)
    ) / 2.0


def _point_in_ring(point: Point, ring: Ring) -> tuple[bool, bool, int]:
    """Return (inside, boundary), using an even/odd ray crossing test."""
    inside = False
    x, y = point
    operations = 0
    for index in range(len(ring) - 1):
        operations += 1
        a, b = ring[index], ring[index + 1]
        if _on_segment(point, a, b):
            return True, True, operations
        if (a[1] > y) != (b[1] > y):
            intersection_x = (b[0] - a[0]) * (y - a[1]) / (b[1] - a[1]) + a[0]
            if x < intersection_x:
                inside = not inside
    return inside, False, operations


def _ring_edges(ring: Ring):
    for index in range(len(ring) - 1):
        yield ring[index], ring[index + 1]


def _parse_ring(value: Any) -> Ring:
    if not isinstance(value, list) or not 4 <= len(value) <= MAX_RING_VERTICES + 1:
        raise GeographyError("invalid_area")
    ring = tuple(_position(item) for item in value)
    if ring[0] != ring[-1] or len(set(ring[:-1])) < 3:
        raise GeographyError("invalid_area")
    # Reject antimeridian-wrap edges: a planar lon/lat interpretation is unsafe there.
    if any(abs(right[0] - left[0]) > 180 for left, right in _ring_edges(ring)):
        raise GeographyError("unsupported_area")
    if abs(_signed_area(ring)) <= _EPSILON:
        raise GeographyError("invalid_area")
    edges = list(_ring_edges(ring))
    for first in range(len(edges)):
        for second in range(first + 1, len(edges)):
            if second == first + 1 or (first == 0 and second == len(edges) - 1):
                continue
            if _segments_intersect(*edges[first], *edges[second]):
                raise GeographyError("invalid_area")
    return ring


def _parse_polygon(value: Any) -> Polygon:
    if not isinstance(value, list) or not value or len(value) > MAX_AREA_RINGS:
        raise GeographyError("invalid_area")
    rings = tuple(_parse_ring(item) for item in value)
    shell = rings[0]
    for hole in rings[1:]:
        inside, boundary, _ = _point_in_ring(hole[0], shell)
        if not inside or boundary:
            raise GeographyError("invalid_area")
        if any(_segments_intersect(*outer, *inner) for outer in _ring_edges(shell) for inner in _ring_edges(hole)):
            raise GeographyError("invalid_area")
    for first in range(1, len(rings)):
        for second in range(first + 1, len(rings)):
            if _point_in_ring(rings[first][0], rings[second])[0] or _point_in_ring(rings[second][0], rings[first])[0]:
                raise GeographyError("invalid_area")
            if any(
                _segments_intersect(*left, *right)
                for left in _ring_edges(rings[first])
                for right in _ring_edges(rings[second])
            ):
                raise GeographyError("invalid_area")
    return rings


def validate_area(
    geojson: Any,
    *,
    source: str = "caller_supplied_geojson",
) -> ValidatedArea:
    """Validate a bounded caller-provided Polygon or MultiPolygon."""
    if source != "caller_supplied_geojson":
        raise GeographyError("unsupported_area_source")
    if not isinstance(geojson, Mapping):
        raise GeographyError("invalid_area")
    kind = geojson.get("type")
    coordinates = geojson.get("coordinates")
    if kind == "Polygon":
        raw_polygons = [coordinates]
    elif kind == "MultiPolygon":
        raw_polygons = coordinates
    else:
        raise GeographyError("unsupported_area")
    if not isinstance(raw_polygons, list) or not 1 <= len(raw_polygons) <= MAX_AREA_POLYGONS:
        raise GeographyError("invalid_area")
    # Enforce the aggregate vertex budget before the quadratic self-intersection
    # checks. This also keeps pathological many-small-ring inputs inexpensive.
    raw_ring_count = 0
    raw_vertex_count = 0
    for raw_polygon in raw_polygons:
        if not isinstance(raw_polygon, list) or not raw_polygon or len(raw_polygon) > MAX_AREA_RINGS:
            raise GeographyError("invalid_area")
        raw_ring_count += len(raw_polygon)
        if raw_ring_count > MAX_AREA_RINGS:
            raise GeographyError("area_too_complex")
        for raw_ring in raw_polygon:
            if not isinstance(raw_ring, list) or not 4 <= len(raw_ring) <= MAX_RING_VERTICES + 1:
                raise GeographyError("invalid_area")
            raw_vertex_count += len(raw_ring)
            if raw_vertex_count > MAX_AREA_VERTICES:
                raise GeographyError("area_too_complex")
    polygons = tuple(_parse_polygon(item) for item in raw_polygons)
    vertex_count = sum(len(ring) for polygon in polygons for ring in polygon)
    if vertex_count > MAX_AREA_VERTICES:
        raise GeographyError("area_too_complex")
    return ValidatedArea(polygons=polygons, vertex_count=vertex_count)


def _point_in_polygon(point: Point, polygon: Polygon) -> tuple[bool, int]:
    in_shell, shell_boundary, operations = _point_in_ring(point, polygon[0])
    if shell_boundary:
        return True, operations
    if not in_shell:
        return False, operations
    for hole in polygon[1:]:
        in_hole, hole_boundary, checked = _point_in_ring(point, hole)
        operations += checked
        if hole_boundary:
            return True, operations  # GeoJSON boundary is included in the classified area.
        if in_hole:
            return False, operations
    return True, operations


def _point_in_area(point: Point, area: ValidatedArea) -> tuple[bool, int]:
    operations = 0
    for polygon in area.polygons:
        inside, checked = _point_in_polygon(point, polygon)
        operations += checked
        if inside:
            return True, operations
    return False, operations


def _segment_intersection_parameters(a: Point, b: Point, c: Point, d: Point) -> tuple[float, ...]:
    """Return track parameters where a segment meets a boundary edge."""
    rx, ry = b[0] - a[0], b[1] - a[1]
    sx, sy = d[0] - c[0], d[1] - c[1]
    denominator = rx * sy - ry * sx
    qx, qy = c[0] - a[0], c[1] - a[1]
    if abs(denominator) > _EPSILON:
        t = (qx * sy - qy * sx) / denominator
        u = (qx * ry - qy * rx) / denominator
        if -_EPSILON <= t <= 1 + _EPSILON and -_EPSILON <= u <= 1 + _EPSILON:
            return (min(1.0, max(0.0, t)),)
        return ()
    if abs(qx * ry - qy * rx) > _EPSILON:
        return ()
    length_squared = rx * rx + ry * ry
    if length_squared <= _EPSILON:
        return ()
    values = []
    for point in (c, d):
        t = ((point[0] - a[0]) * rx + (point[1] - a[1]) * ry) / length_squared
        if -_EPSILON <= t <= 1 + _EPSILON:
            values.append(min(1.0, max(0.0, t)))
    return tuple(values)


def _interpolate(start: Point, end: Point, fraction: float) -> Point:
    return (start[0] + (end[0] - start[0]) * fraction, start[1] + (end[1] - start[1]) * fraction)


def _route_lines(
    geojson: Any,
    *,
    max_coordinates: int,
) -> tuple[tuple[list[tuple[Point, ...]], int] | None, int]:
    if not isinstance(geojson, Mapping) or geojson.get("type") != "FeatureCollection":
        return None, 0
    features = geojson.get("features")
    if not isinstance(features, list) or not features or len(features) > MAX_ROUTE_FEATURES:
        return None, 0
    lines: list[tuple[Point, ...]] = []
    coordinate_count = 0
    for feature in features:
        if not isinstance(feature, Mapping) or feature.get("type") != "Feature":
            return None, coordinate_count
        geometry = feature.get("geometry")
        if not isinstance(geometry, Mapping):
            return None, coordinate_count
        kind = geometry.get("type")
        if kind == "Point":
            # Point markers are not evidence of the driven track.
            point = geometry.get("coordinates")
            try:
                _position(point)
            except GeographyError:
                return None, coordinate_count
            continue
        if kind == "LineString":
            raw_lines = [geometry.get("coordinates")]
        elif kind == "MultiLineString":
            raw_lines = geometry.get("coordinates")
        else:
            return None, coordinate_count
        if not isinstance(raw_lines, list) or not raw_lines or len(raw_lines) > MAX_ROUTE_FEATURES:
            return None, coordinate_count
        for raw_line in raw_lines:
            if not isinstance(raw_line, list) or len(raw_line) < 2:
                return None, coordinate_count
            coordinate_count += len(raw_line)
            if coordinate_count > min(MAX_ROUTE_COORDINATES, max_coordinates):
                return None, coordinate_count
            try:
                line = tuple(_position(item) for item in raw_line)
            except GeographyError:
                return None, coordinate_count
            if any(abs(right[0] - left[0]) > 180 for left, right in zip(line, line[1:])):
                return None, coordinate_count
            lines.append(line)
    if not lines:
        return None, coordinate_count
    return (lines, coordinate_count), coordinate_count


def sanitize_route_geojson(
    geojson: Any,
    *,
    remaining_features: int,
    remaining_coordinates: int,
) -> tuple[dict[str, Any] | None, int, int]:
    """Copy only bounded geometry positions, dropping labels and other properties."""
    if type(remaining_features) is not int or remaining_features < 1:
        raise GeographyError("geometry_too_complex")
    if type(remaining_coordinates) is not int or remaining_coordinates < 1:
        raise GeographyError("geometry_too_complex")
    if not isinstance(geojson, Mapping) or geojson.get("type") != "FeatureCollection":
        return None, 0, 0
    features = geojson.get("features")
    if not isinstance(features, list):
        return None, 0, 0
    if len(features) > min(MAX_ROUTE_FEATURES, remaining_features):
        raise GeographyError("geometry_too_complex")
    output: list[dict[str, Any]] = []
    coordinates_seen = 0
    for feature in features:
        if not isinstance(feature, Mapping) or feature.get("type") != "Feature":
            return None, len(features), coordinates_seen
        geometry = feature.get("geometry")
        if not isinstance(geometry, Mapping):
            return None, len(features), coordinates_seen
        kind = geometry.get("type")
        coordinates = geometry.get("coordinates")
        if kind == "Point":
            try:
                point = _position(coordinates)
            except GeographyError:
                return None, len(features), coordinates_seen
            coordinates_seen += 1
            if coordinates_seen > min(MAX_ROUTE_COORDINATES, remaining_coordinates):
                raise GeographyError("geometry_too_complex")
            clean_coordinates: Any = point
        elif kind == "LineString":
            raw_lines = [coordinates]
            as_multi = False
        elif kind == "MultiLineString":
            raw_lines = coordinates
            as_multi = True
        else:
            # Polygonal/unknown route shapes have no agreed track semantics.
            return None, len(features), coordinates_seen
        if kind in {"LineString", "MultiLineString"}:
            if not isinstance(raw_lines, list) or not raw_lines or len(raw_lines) > MAX_ROUTE_FEATURES:
                return None, len(features), coordinates_seen
            parsed_lines: list[list[Point]] = []
            for raw_line in raw_lines:
                if not isinstance(raw_line, list) or len(raw_line) < 2:
                    return None, len(features), coordinates_seen
                coordinates_seen += len(raw_line)
                if coordinates_seen > min(MAX_ROUTE_COORDINATES, remaining_coordinates):
                    raise GeographyError("geometry_too_complex")
                try:
                    parsed = [_position(item) for item in raw_line]
                except GeographyError:
                    return None, len(features), coordinates_seen
                if any(abs(right[0] - left[0]) > 180 for left, right in zip(parsed, parsed[1:])):
                    return None, len(features), coordinates_seen
                parsed_lines.append(parsed)
            clean_coordinates = parsed_lines if as_multi else parsed_lines[0]
        output.append(
            {
                "type": "Feature",
                "geometry": {"type": kind, "coordinates": clean_coordinates},
            }
        )
    return {"type": "FeatureCollection", "features": output}, len(features), coordinates_seen


def classify_route_geojson_with_work(
    geojson: Any,
    area: ValidatedArea,
    *,
    max_segment_edge_tests: int = MAX_ROUTE_SEGMENT_EDGE_TESTS,
    max_coordinates: int = MAX_ROUTE_COORDINATES,
) -> tuple[AreaRelation, int, int]:
    """Internal classifier result also reports bounded work and coordinates."""
    if type(max_coordinates) is not int or max_coordinates < 1:
        return "unknown", 0, 0
    parsed, coordinates_seen = _route_lines(geojson, max_coordinates=max_coordinates)
    if parsed is None or type(max_segment_edge_tests) is not int or max_segment_edge_tests < 1:
        return "unknown", 0, coordinates_seen
    lines, coordinate_count = parsed
    operations = 0
    saw_inside = False
    saw_outside = False
    for line in lines:
        for start, end in zip(line, line[1:]):
            parameters = [0.0, 1.0]
            for polygon in area.polygons:
                for ring in polygon:
                    for edge_start, edge_end in _ring_edges(ring):
                        operations += 1
                        if operations > max_segment_edge_tests:
                            return "unknown", operations, coordinate_count
                        intersections = _segment_intersection_parameters(start, end, edge_start, edge_end)
                        parameters.extend(intersections)
            parameters.sort()
            unique: list[float] = []
            for value in parameters:
                if not unique or abs(value - unique[-1]) > _EPSILON:
                    unique.append(value)
            # Classifying each open interval catches a segment whose endpoints
            # are both inside while it leaves a concavity or crosses a hole.
            for lower, upper in zip(unique, unique[1:]):
                midpoint = _interpolate(start, end, (lower + upper) / 2.0)
                inside, checked = _point_in_area(midpoint, area)
                operations += checked
                if operations > max_segment_edge_tests:
                    return "unknown", operations, coordinate_count
                if inside:
                    saw_inside = True
                else:
                    saw_outside = True
                if saw_inside and saw_outside:
                    return "crossing", operations, coordinate_count
            if len(unique) == 1:  # defensive; normally endpoints ensure at least two
                inside, checked = _point_in_area(start, area)
                operations += checked
                if operations > max_segment_edge_tests:
                    return "unknown", operations, coordinate_count
                if inside:
                    saw_inside = True
                else:
                    saw_outside = True
    if saw_inside and not saw_outside:
        return "fully_inside", operations, coordinate_count
    if saw_outside and not saw_inside:
        return "outside", operations, coordinate_count
    return "unknown", operations, coordinate_count


def classify_route_geojson(
    geojson: Any,
    area: ValidatedArea,
    *,
    max_segment_edge_tests: int = MAX_ROUTE_SEGMENT_EDGE_TESTS,
) -> AreaRelation:
    """Classify source LineStrings without clipping or storing their geometry."""
    relation, _, _ = classify_route_geojson_with_work(
        geojson,
        area,
        max_segment_edge_tests=max_segment_edge_tests,
    )
    return relation


def summer_window_utc(year: int | None = None, *, now: Any = None) -> tuple[str, str]:
    """Return June–September CEST bounds under an explicitly fixed EU rule.

    This is a project-specific summer reporting window, not a general Europe/
    Madrid timezone implementation. Supported calendar years are 2002–2031.
    """
    from datetime import datetime, timedelta, timezone

    if year is None:
        current = now if now is not None else datetime.now(timezone.utc)
        if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
            raise GeographyError("invalid_clock")
        try:
            year = (current.astimezone(timezone.utc) + timedelta(hours=1)).year
        except (OverflowError, ValueError):
            raise GeographyError("invalid_clock") from None
    if type(year) is not int or not 2002 <= year <= 2031:
        raise GeographyError("unsupported_summer_year")
    # June 1 and September 1 fall inside the EU summer-time period. The
    # fixed +02 offset denotes the selected project window only.
    start = datetime(year, 6, 1, tzinfo=timezone(timedelta(hours=2))).astimezone(timezone.utc)
    end = datetime(year, 9, 1, tzinfo=timezone(timedelta(hours=2))).astimezone(timezone.utc)
    return start.isoformat(timespec="milliseconds").replace("+00:00", "Z"), end.isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
