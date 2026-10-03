"""Optional exact-topology engine for the frozen public Menorca boundary.

Shapely is imported only when this module's preparation/classification APIs are
called. The loader accepts bytes supplied by a separate explicit asset loader;
it performs no filesystem or network access itself. No repair, simplification,
or route-geometry persistence is performed here.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from typing import Any, Mapping

from .geography import GeographyError, sanitize_route_geojson

MENORCA_AREA_VERSION = "ign-menorca-2026-10-03-epsg4258-to-4326-v3"
MENORCA_GEOJSON_SHA256 = "1e75a0c988fe13c2917487bf6b9834bd6aa4f48af5117b6ed216901be09b33cd"
MENORCA_GEOJSON_MAX_BYTES = 1024 * 1024
MENORCA_FEATURE_CODES = frozenset(
    {
        "34040707002",
        "34040707015",
        "34040707064",
        "34040707037",
        "34040707902",
        "34040707023",
        "34040707032",
        "34040707052",
    }
)
MENORCA_EXPECTED_VERTICES = 24_750
MENORCA_EXPECTED_RINGS = 111
MAX_ENGINE_ROUTE_FEATURES = 4096
MAX_ENGINE_ROUTE_COORDINATES = 4_096
_PREPARED_AREA_TOKEN = object()


class GeographyEngineError(ValueError):
    """Safe fixed-category error raised while preparing the public boundary."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _no_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GeographyEngineError("duplicate_json_key")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise GeographyEngineError("invalid_json_number")


def _position(value: Any) -> tuple[float, float]:
    if not isinstance(value, list) or len(value) not in (2, 3):
        raise GeographyEngineError("invalid_public_geometry")
    if any(isinstance(part, bool) or not isinstance(part, (int, float)) for part in value):
        raise GeographyEngineError("invalid_public_geometry")
    try:
        numeric = tuple(float(part) for part in value)
    except OverflowError:
        raise GeographyEngineError("invalid_public_geometry") from None
    if any(not math.isfinite(part) for part in numeric):
        raise GeographyEngineError("invalid_public_geometry")
    longitude, latitude = numeric[:2]
    if not -180 <= longitude <= 180 or not -90 <= latitude <= 90:
        raise GeographyEngineError("invalid_public_geometry")
    return longitude, latitude


def _geometry_rings(geometry: Any) -> tuple[list[list[tuple[float, float]]], int]:
    if not isinstance(geometry, Mapping):
        raise GeographyEngineError("invalid_public_geometry")
    kind = geometry.get("type")
    coordinates = geometry.get("coordinates")
    if kind == "Polygon":
        raw_polygons = [coordinates]
    elif kind == "MultiPolygon":
        raw_polygons = coordinates
    else:
        raise GeographyEngineError("invalid_public_geometry")
    if not isinstance(raw_polygons, list) or not raw_polygons:
        raise GeographyEngineError("invalid_public_geometry")
    rings: list[list[tuple[float, float]]] = []
    vertex_count = 0
    for polygon in raw_polygons:
        if not isinstance(polygon, list) or not polygon:
            raise GeographyEngineError("invalid_public_geometry")
        for raw_ring in polygon:
            if not isinstance(raw_ring, list) or len(raw_ring) < 4:
                raise GeographyEngineError("invalid_public_geometry")
            vertex_count += len(raw_ring)
            if vertex_count > MENORCA_EXPECTED_VERTICES:
                raise GeographyEngineError("public_vertex_count_mismatch")
            ring = [_position(point) for point in raw_ring]
            if ring[0] != ring[-1]:
                raise GeographyEngineError("invalid_public_geometry")
            if any(abs(right[0] - left[0]) > 180 for left, right in zip(ring, ring[1:])):
                raise GeographyEngineError("unsupported_public_geometry")
            rings.append(ring)
            if len(rings) > MENORCA_EXPECTED_RINGS:
                raise GeographyEngineError("public_ring_count_mismatch")
    return rings, vertex_count


def _load_shapely():
    try:
        import shapely
        from shapely.geometry import LineString, shape
        from shapely import covers, disjoint, is_empty, is_valid, union_all
    except Exception:
        raise GeographyEngineError("geometry_engine_unavailable") from None
    version = getattr(shapely, "__version__", "")
    if not isinstance(version, str) or version != "2.1.2":
        raise GeographyEngineError("geometry_engine_version_unsupported")
    return shapely, LineString, shape, covers, disjoint, is_empty, is_valid, union_all


@dataclass(frozen=True, repr=False, init=False)
class PreparedPublicArea:
    """Prepared public polygon union; the actual coordinates never enter repr."""

    geometry: Any = field(repr=False, compare=False)
    source_version: str = MENORCA_AREA_VERSION
    feature_count: int = 8
    vertex_count: int = MENORCA_EXPECTED_VERTICES
    ring_count: int = MENORCA_EXPECTED_RINGS
    _validation_token: object = field(repr=False, compare=False)

    def __init__(
        self,
        *,
        geometry: Any,
        source_version: str = MENORCA_AREA_VERSION,
        feature_count: int = 8,
        vertex_count: int = MENORCA_EXPECTED_VERTICES,
        ring_count: int = MENORCA_EXPECTED_RINGS,
        _validation_token: object | None = None,
    ) -> None:
        if _validation_token is not _PREPARED_AREA_TOKEN:
            raise GeographyEngineError("prepared_area_must_be_loaded_from_frozen_asset")
        object.__setattr__(self, "geometry", geometry)
        object.__setattr__(self, "source_version", source_version)
        object.__setattr__(self, "feature_count", feature_count)
        object.__setattr__(self, "vertex_count", vertex_count)
        object.__setattr__(self, "ring_count", ring_count)
        object.__setattr__(self, "_validation_token", _validation_token)

    def __repr__(self) -> str:
        return (
            f"PreparedPublicArea(source_version={self.source_version!r}, "
            f"feature_count={self.feature_count}, vertex_count={self.vertex_count}, ring_count={self.ring_count})"
        )


def is_valid_prepared_public_area(value: Any) -> bool:
    """Check the unforgeable loader token before any upstream request."""
    return isinstance(value, PreparedPublicArea) and value._validation_token is _PREPARED_AREA_TOKEN


def _prepare_collection(data: Any) -> PreparedPublicArea:
    if not isinstance(data, Mapping) or data.get("type") != "FeatureCollection":
        raise GeographyEngineError("public_feature_collection_invalid")
    features = data.get("features")
    if not isinstance(features, list) or len(features) != len(MENORCA_FEATURE_CODES):
        raise GeographyEngineError("public_feature_count_mismatch")
    seen_codes: set[str] = set()
    geometries = []
    vertices = rings = 0
    _, _, shape, _, _, is_empty, is_valid, union_all = _load_shapely()
    for feature in features:
        if not isinstance(feature, Mapping) or feature.get("type") != "Feature":
            raise GeographyEngineError("public_feature_invalid")
        properties = feature.get("properties")
        code = properties.get("nationalCode") if isinstance(properties, Mapping) else None
        if not isinstance(code, str) or code not in MENORCA_FEATURE_CODES or code in seen_codes:
            raise GeographyEngineError("public_feature_code_mismatch")
        seen_codes.add(code)
        geometry_data = feature.get("geometry")
        feature_rings, feature_vertices = _geometry_rings(geometry_data)
        if vertices + feature_vertices > MENORCA_EXPECTED_VERTICES or rings + len(feature_rings) > MENORCA_EXPECTED_RINGS:
            raise GeographyEngineError("public_geometry_count_mismatch")
        try:
            geometry = shape(geometry_data)
        except Exception:
            raise GeographyEngineError("public_geometry_invalid") from None
        if bool(is_empty(geometry)) or not bool(is_valid(geometry)):
            raise GeographyEngineError("public_geometry_invalid")
        vertices += feature_vertices
        # Count rings from the bounded parser rather than trusting library internals.
        rings += len(feature_rings)
        if vertices > MENORCA_EXPECTED_VERTICES or rings > MENORCA_EXPECTED_RINGS:
            raise GeographyEngineError("public_geometry_count_mismatch")
        geometries.append(geometry)
    if seen_codes != MENORCA_FEATURE_CODES:
        raise GeographyEngineError("public_feature_code_mismatch")
    if vertices != MENORCA_EXPECTED_VERTICES or rings != MENORCA_EXPECTED_RINGS:
        raise GeographyEngineError("public_geometry_count_mismatch")
    union = union_all(geometries)
    if bool(is_empty(union)) or not bool(is_valid(union)) or union.geom_type != "MultiPolygon":
        raise GeographyEngineError("public_union_invalid")
    # Shapely 2.x prepare() modifies the geometry in place and returns None.
    shapely, *_ = _load_shapely()
    try:
        shapely.prepare(union)
    except Exception:
        raise GeographyEngineError("public_geometry_prepare_failed") from None
    return PreparedPublicArea(geometry=union, _validation_token=_PREPARED_AREA_TOKEN)


def load_frozen_menorca_area(raw_bytes: bytes) -> PreparedPublicArea:
    """Validate and prepare the pinned 8-municipality public GeoJSON bytes.

    The caller explicitly supplies the asset. No file lookup or HTTP request is
    performed. The SHA-256 pins the exact approved conversion output.
    """
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) > MENORCA_GEOJSON_MAX_BYTES:
        raise GeographyEngineError("public_asset_size_invalid")
    if hashlib.sha256(raw_bytes).hexdigest() != MENORCA_GEOJSON_SHA256:
        raise GeographyEngineError("public_asset_digest_mismatch")
    try:
        data = json.loads(raw_bytes.decode("utf-8"), object_pairs_hook=_no_duplicate_object, parse_constant=_reject_constant)
    except GeographyEngineError:
        raise
    except Exception:
        raise GeographyEngineError("public_asset_json_invalid") from None
    return _prepare_collection(data)


def _route_lines(geojson: Any):
    try:
        cleaned, _, _ = sanitize_route_geojson(
            geojson,
            remaining_features=MAX_ENGINE_ROUTE_FEATURES,
            remaining_coordinates=MAX_ENGINE_ROUTE_COORDINATES,
        )
    except GeographyError as exc:
        if exc.category == "geometry_too_complex":
            raise GeographyEngineError("geometry_budget_exceeded") from None
        return None
    if cleaned is None:
        return None
    _, LineString, _, _, _, is_empty, is_valid, _ = _load_shapely()
    lines = []
    for feature in cleaned["features"]:
        geometry = feature["geometry"]
        kind = geometry["type"]
        if kind == "Point":
            continue
        coordinates = geometry["coordinates"]
        raw_lines = coordinates if kind == "MultiLineString" else [coordinates]
        for positions in raw_lines:
            try:
                line = LineString(positions)
                if bool(is_empty(line)) or not bool(is_valid(line)):
                    return None
            except Exception:
                return None
            lines.append(line)
    return lines or None


def classify_public_area_route(geojson: Any, area: PreparedPublicArea) -> str:
    """Classify route lines by exact prepared covers/disjoint predicates."""
    if not isinstance(area, PreparedPublicArea) or area._validation_token is not _PREPARED_AREA_TOKEN:
        return "unknown"
    lines = _route_lines(geojson)
    if lines is None:
        return "unknown"
    _, _, _, covers, disjoint, _, _, _ = _load_shapely()
    try:
        line_relations: list[str] = []
        for line in lines:
            if bool(covers(area.geometry, line)):
                line_relations.append("inside")
            elif bool(disjoint(area.geometry, line)):
                line_relations.append("outside")
            else:
                # DE-9IM avoids constructing a potentially huge intersection
                # geometry.  In polygon/line order, relation[0] is interior /
                # interior and relation[3] is polygon-boundary / line-interior.
                # A point-only tangent has dimension 0, unlike any positive-
                # length contact or traversal (dimension 1).
                relation = area.geometry.relate(line)
                if not isinstance(relation, str) or len(relation) != 9:
                    return "unknown"
                if relation[0] == "1" or relation[3] == "1":
                    line_relations.append("crossing")
                elif relation[0] in "F0" and relation[3] in "F0":
                    line_relations.append("outside")
                else:
                    return "unknown"
        if all(relation == "inside" for relation in line_relations):
            return "fully_inside"
        if all(relation == "outside" for relation in line_relations):
            return "outside"
        return "crossing"
    except Exception:
        return "unknown"
