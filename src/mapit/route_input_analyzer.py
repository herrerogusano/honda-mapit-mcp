"""Pure, value-free analysis of one MAPIT route-detail payload.

The analyzer deliberately retains no route values in its result.  It accepts
only the small GeoJSON subset documented by the Phase 6 research note and
raises a stable error for malformed, oversized, or unsupported structures.
"""

from __future__ import annotations

import math
from typing import Any, Iterable

MAX_FEATURES = 4096
MAX_NODES = 100_000

GEOMETRY_CLASSES = frozenset({"Point", "LineString", "other"})
SHAPE_CLASSES = frozenset({"scalar", "pair-like", "nested", "invalid", "unknown"})
DIMENSION_CLASSES = frozenset({"2", "3", "other", "unknown"})
DENSITY_BANDS = frozenset({"none", "few", "many"})
GAP_BANDS = frozenset({"none", "short", "medium", "long", "unknown"})
NAME_BANDS = frozenset({"none", "few", "many"})
COVERAGE_CLASSES = frozenset({"all", "partial", "none", "unknown"})
INPUT_SUFFICIENCY = frozenset({"insufficient", "candidate", "candidate_with_time"})
SAFE_CATEGORIES = frozenset({"success", "invalid_structure", "oversized", "unsupported_geometry"})

OUTPUT_KEYS = frozenset(
    {
        "success",
        "category",
        "geometry_classes",
        "coordinate_shape_classes",
        "coordinate_dimension_classes",
        "wgs84_range_valid",
        "point_density_band",
        "max_consecutive_gap_distance_band",
        "distinct_name_band",
        "distinct_label_band",
        "inferred_coverage_class",
        "per_point_time_present",
        "per_point_accuracy_present",
        "per_point_heading_present",
        "per_point_speed_present",
        "input_sufficiency",
    }
)


class RouteInputAnalysisError(ValueError):
    """Stable category for fail-closed route-input analysis failures."""

    def __init__(self, category: str = "invalid_structure") -> None:
        self.category = category if category in SAFE_CATEGORIES else "invalid_structure"
        super().__init__(self.category)


def _empty_result(*, category: str, success: bool = False) -> dict[str, Any]:
    return {
        "success": success,
        "category": category,
        "geometry_classes": [],
        "coordinate_shape_classes": [],
        "coordinate_dimension_classes": [],
        "wgs84_range_valid": False,
        "point_density_band": "none",
        "max_consecutive_gap_distance_band": "unknown",
        "distinct_name_band": "none",
        "distinct_label_band": "none",
        "inferred_coverage_class": "unknown",
        "per_point_time_present": False,
        "per_point_accuracy_present": False,
        "per_point_heading_present": False,
        "per_point_speed_present": False,
        "input_sufficiency": "insufficient",
    }


class _Budget:
    def __init__(self) -> None:
        self.nodes = 0

    def take(self, amount: int = 1) -> None:
        self.nodes += amount
        if self.nodes > MAX_NODES:
            raise RouteInputAnalysisError("oversized")


def _band(count: int) -> str:
    if count == 0:
        return "none"
    return "few" if count <= 3 else "many"


def _density(count: int) -> str:
    if count == 0:
        return "none"
    return "few" if count <= 16 else "many"


def _finite_number(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _coordinate(value: Any, budget: _Budget) -> tuple[float, ...]:
    budget.take()
    if not isinstance(value, list):
        raise RouteInputAnalysisError("invalid_structure")
    if len(value) < 2:
        raise RouteInputAnalysisError("invalid_structure")
    budget.take(len(value))
    if len(value) > 3 or not all(_finite_number(item) for item in value):
        raise RouteInputAnalysisError("invalid_structure")
    # A third ordinate is intentionally opaque: it is never interpreted as time.
    return tuple(float(item) for item in value)


def _haversine_meters(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    radius = 6_371_000.0
    lon1, lat1 = math.radians(left[0]), math.radians(left[1])
    lon2, lat2 = math.radians(right[0]), math.radians(right[1])
    # Use the shortest longitude arc so crossings near +/-180 degrees do not
    # look like a globe-spanning gap.
    dlon = (lon2 - lon1 + math.pi) % (2 * math.pi) - math.pi
    dlat = lat2 - lat1
    a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    return radius * 2 * math.asin(min(1.0, math.sqrt(a)))


def _gap_band(max_gap: float | None) -> str:
    if max_gap is None:
        return "none"
    if max_gap <= 100.0:
        return "short"
    if max_gap <= 1000.0:
        return "medium"
    return "long"


def _properties(feature: dict[str, Any], budget: _Budget) -> dict[str, Any]:
    value = feature.get("properties")
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RouteInputAnalysisError("invalid_structure")
    budget.take(len(value) + 1)
    return value


def _metadata_flags(properties: dict[str, Any], point_count: int) -> tuple[set[str], bool | None]:
    aliases = {
        "time": {"time", "timestamp", "timestamps", "pointtime", "point_time", "recordedat", "recorded_at"},
        "accuracy": {"accuracy", "accuracies", "hdop", "precision", "radius", "radii"},
        "heading": {"heading", "headings", "bearing", "bearings"},
        "speed": {"speed", "speeds", "velocity", "velocities"},
    }
    present: set[str] = set()
    inferred: bool | None = None
    for raw_key, value in properties.items():
        if not isinstance(raw_key, str):
            raise RouteInputAnalysisError("invalid_structure")
        key = raw_key.lower()
        if isinstance(value, (str, bytes)) and len(value) > 4096:
            raise RouteInputAnalysisError("oversized")
        if isinstance(value, (list, dict)) and len(value) > MAX_FEATURES:
            raise RouteInputAnalysisError("oversized")
        if key == "inferred":
            if type(value) is not bool:
                raise RouteInputAnalysisError("invalid_structure")
            inferred = value
        for kind, names in aliases.items():
            if key not in names or value is None:
                continue
            if point_count == 1 or (isinstance(value, list) and len(value) == point_count):
                present.add(kind)
    return present, inferred


def analyze_route_input(payload: Any) -> dict[str, Any]:
    """Return fixed-schema, redacted geometry sufficiency metadata."""
    budget = _Budget()
    if not isinstance(payload, dict):
        raise RouteInputAnalysisError()
    budget.take(len(payload) + 1)
    geo = payload.get("geoJSON")
    if not isinstance(geo, dict):
        raise RouteInputAnalysisError("invalid_structure")
    budget.take(len(geo) + 1)
    geo_type = geo.get("type")
    if not isinstance(geo_type, str):
        raise RouteInputAnalysisError("invalid_structure")
    feature_entries: list[tuple[str, dict[str, Any], Any]] = []
    if geo_type == "FeatureCollection":
        features = geo.get("features")
        if not isinstance(features, list):
            raise RouteInputAnalysisError()
        if len(features) > MAX_FEATURES:
            raise RouteInputAnalysisError("oversized")
        for feature in features:
            if not isinstance(feature, dict) or feature.get("type") != "Feature":
                raise RouteInputAnalysisError("invalid_structure")
            geometry = feature.get("geometry")
            if not isinstance(geometry, dict):
                raise RouteInputAnalysisError("invalid_structure")
            geometry_type = geometry.get("type")
            if not isinstance(geometry_type, str):
                raise RouteInputAnalysisError("invalid_structure")
            feature_entries.append((geometry_type, feature, geometry.get("coordinates")))
    elif geo_type in {"Feature", "Point", "LineString"}:
        if geo_type == "Feature":
            geometry = geo.get("geometry")
            if not isinstance(geometry, dict):
                raise RouteInputAnalysisError()
            geometry_type = geometry.get("type")
            if not isinstance(geometry_type, str):
                raise RouteInputAnalysisError("invalid_structure")
            feature_entries.append((geometry_type, geo, geometry.get("coordinates")))
        else:
            feature_entries.append((geo_type, geo, geo.get("coordinates")))
    else:
        raise RouteInputAnalysisError("unsupported_geometry")

    geometry_classes: set[str] = set()
    shapes: set[str] = set()
    dimensions: set[str] = set()
    observed_stream: list[tuple[float, ...]] = []
    all_points: list[tuple[float, ...]] = []
    range_valid = True
    names: set[str] = set()
    labels: set[str] = set()
    inferred_values: list[bool] = []
    metadata = {"time": False, "accuracy": False, "heading": False, "speed": False}

    for geometry_type, feature, coordinates in feature_entries:
        budget.take()
        if not isinstance(geometry_type, str):
            raise RouteInputAnalysisError("invalid_structure")
        if geometry_type not in {"Point", "LineString"}:
            geometry_classes.add("other")
            raise RouteInputAnalysisError("unsupported_geometry")
        geometry_classes.add(geometry_type)
        if geometry_type == "Point":
            point = _coordinate(coordinates, budget)
            sequence = [point]
            shapes.add("pair-like")
        else:
            if not isinstance(coordinates, list) or not coordinates:
                raise RouteInputAnalysisError("invalid_structure")
            budget.take(len(coordinates))
            sequence = [_coordinate(item, budget) for item in coordinates]
            shapes.add("nested")
        for point in sequence:
            dimensions.add(str(len(point)) if len(point) in (2, 3) else "other")
            if not (-180.0 <= point[0] <= 180.0 and -90.0 <= point[1] <= 90.0):
                range_valid = False
        # This is the observed stream: feature order, then coordinate order
        # within each feature. Gaps at feature boundaries are intentional.
        observed_stream.extend(sequence)
        all_points.extend(sequence)
        properties = _properties(feature, budget)
        for key, target in (("name", names), ("label", labels)):
            value = properties.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise RouteInputAnalysisError("invalid_structure")
                if len(value) > 4096:
                    raise RouteInputAnalysisError("oversized")
                if value.strip():
                    target.add(value.strip())
        present, inferred = _metadata_flags(properties, len(sequence))
        for kind in present:
            metadata[kind] = True
        if inferred is not None:
            inferred_values.append(inferred)

    max_gap: float | None = None
    if range_valid:
        for left, right in zip(observed_stream, observed_stream[1:]):
            gap = _haversine_meters(left, right)
            max_gap = gap if max_gap is None else max(max_gap, gap)
    coverage = "unknown"
    if inferred_values:
        coverage = "all" if all(inferred_values) else "none" if not any(inferred_values) else "partial"
    result = _empty_result(category="success", success=True)
    result.update(
        {
            "geometry_classes": sorted(geometry_classes),
            "coordinate_shape_classes": sorted(shapes),
            "coordinate_dimension_classes": sorted(dimensions, key=lambda value: {"2": 0, "3": 1, "other": 2, "unknown": 3}[value]),
            "wgs84_range_valid": bool(all_points) and range_valid,
            "point_density_band": _density(len(all_points)),
            "max_consecutive_gap_distance_band": _gap_band(max_gap) if range_valid else "unknown",
            "distinct_name_band": _band(len(names)),
            "distinct_label_band": _band(len(labels)),
            "inferred_coverage_class": coverage,
            "per_point_time_present": metadata["time"],
            "per_point_accuracy_present": metadata["accuracy"],
            "per_point_heading_present": metadata["heading"],
            "per_point_speed_present": metadata["speed"],
            "input_sufficiency": "insufficient" if not all_points or not range_valid else "candidate_with_time" if metadata["time"] else "candidate",
        }
    )
    return result


def safe_analyze_route_input(payload: Any) -> dict[str, Any]:
    """Convert analyzer failures to the same fixed, value-free output shape."""
    try:
        return analyze_route_input(payload)
    except (RouteInputAnalysisError, TypeError, ValueError, OverflowError, KeyError, IndexError) as exc:
        category = exc.category if isinstance(exc, RouteInputAnalysisError) else "invalid_structure"
        result = _empty_result(category=category)
        if category == "oversized":
            result["max_consecutive_gap_distance_band"] = "unknown"
        return result


# Descriptive aliases keep the pure API discoverable without adding another
# implementation path.
analyze_route_input_sufficiency = analyze_route_input
safe_analyze_route_input_sufficiency = safe_analyze_route_input


__all__ = [
    "analyze_route_input",
    "DIMENSION_CLASSES",
    "GAP_BANDS",
    "GEOMETRY_CLASSES",
    "INPUT_SUFFICIENCY",
    "OUTPUT_KEYS",
    "RouteInputAnalysisError",
    "analyze_route_input_sufficiency",
    "safe_analyze_route_input",
    "safe_analyze_route_input_sufficiency",
]
