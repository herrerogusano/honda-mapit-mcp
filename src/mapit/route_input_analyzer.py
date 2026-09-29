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
GAP_SOURCES = frozenset({"none", "inside_linestring", "between_features", "point_stream", "multiple", "unknown"})
NAME_ORDER_PATTERNS = frozenset({"stable", "repeating", "transitions_present", "unknown"})
LINESTRING_GAP_DISTRIBUTIONS = frozenset({"none", "short", "medium", "long", "mixed", "unknown"})
NAME_BANDS = frozenset({"none", "few", "many"})
COVERAGE_CLASSES = frozenset({"all", "partial", "none", "unknown"})
INPUT_SUFFICIENCY = frozenset({"insufficient", "candidate", "candidate_with_time"})
THIRD_ORDINATE_CLASSES = frozenset({"absent", "present_opaque", "unknown"})
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
        "max_gap_within_linestring_band",
        "max_gap_between_features_band",
        "max_gap_point_stream_band",
        "max_consecutive_gap_source",
        "feature_count_band_by_geometry",
        "coordinate_density_band_by_geometry",
        "name_presence_band_by_geometry",
        "label_presence_band_by_geometry",
        "distinct_name_band_by_geometry",
        "distinct_label_band_by_geometry",
        "inferred_coverage_class_by_geometry",
        "feature_order_name_pattern",
        "linestring_gap_distribution_band",
        "feature_boundary_gap_band",
        "point_stream_gap_band",
        "distinct_name_band",
        "distinct_label_band",
        "inferred_coverage_class",
        "per_point_time_present",
        "per_point_accuracy_present",
        "per_point_heading_present",
        "per_point_speed_present",
        "input_sufficiency",
        "third_ordinate_class",
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
        "max_gap_within_linestring_band": "unknown",
        "max_gap_between_features_band": "unknown",
        "max_gap_point_stream_band": "unknown",
        "max_consecutive_gap_source": "unknown",
        "feature_count_band_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "coordinate_density_band_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "name_presence_band_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "label_presence_band_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "distinct_name_band_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "distinct_label_band_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "inferred_coverage_class_by_geometry": {"Point": "unknown", "LineString": "unknown"},
        "feature_order_name_pattern": "unknown",
        "linestring_gap_distribution_band": "unknown",
        "feature_boundary_gap_band": "unknown",
        "point_stream_gap_band": "unknown",
        "distinct_name_band": "none",
        "distinct_label_band": "none",
        "inferred_coverage_class": "unknown",
        "per_point_time_present": False,
        "per_point_accuracy_present": False,
        "per_point_heading_present": False,
        "per_point_speed_present": False,
        "input_sufficiency": "insufficient",
        "third_ordinate_class": "unknown",
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


def _max_gap_band(gaps: list[float]) -> str:
    return _gap_band(max(gaps)) if gaps else "none"


def _per_geometry_band(counts: dict[str, int]) -> dict[str, str]:
    return {geometry_type: _band(counts[geometry_type]) for geometry_type in ("Point", "LineString")}


def _per_geometry_density(counts: dict[str, int]) -> dict[str, str]:
    return {geometry_type: _density(counts[geometry_type]) for geometry_type in ("Point", "LineString")}


def _coverage(values: list[bool]) -> str:
    if not values:
        return "unknown"
    return "all" if all(values) else "none" if not any(values) else "partial"


def _name_order_pattern(names: list[str | None]) -> str:
    if not names or any(name is None for name in names) or len(names) < 2:
        return "unknown"
    concrete = [name for name in names if name is not None]
    if len(set(concrete)) == 1:
        return "stable"
    if len(set(concrete)) < len(concrete):
        return "repeating"
    return "transitions_present"


def _linestring_gap_distribution(gaps: list[float], *, range_valid: bool) -> str:
    if not range_valid:
        return "unknown"
    bands = {_gap_band(gap) for gap in gaps}
    if not bands:
        return "none"
    return next(iter(bands)) if len(bands) == 1 else "mixed"


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
    observed_features: list[tuple[str, list[tuple[float, ...]]]] = []
    all_points: list[tuple[float, ...]] = []
    range_valid = True
    names: set[str] = set()
    labels: set[str] = set()
    feature_counts = {"Point": 0, "LineString": 0}
    coordinate_counts = {"Point": 0, "LineString": 0}
    names_by_geometry = {"Point": set(), "LineString": set()}
    labels_by_geometry = {"Point": set(), "LineString": set()}
    name_presence_counts = {"Point": 0, "LineString": 0}
    label_presence_counts = {"Point": 0, "LineString": 0}
    inferred_by_geometry = {"Point": [], "LineString": []}
    feature_names: list[str | None] = []
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
        feature_counts[geometry_type] += 1
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
        coordinate_counts[geometry_type] += len(sequence)
        observed_stream.extend(sequence)
        observed_features.append((geometry_type, sequence))
        all_points.extend(sequence)
        properties = _properties(feature, budget)
        feature_name: str | None = None
        for key, target in (("name", names), ("label", labels)):
            value = properties.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise RouteInputAnalysisError("invalid_structure")
                if len(value) > 4096:
                    raise RouteInputAnalysisError("oversized")
                if value.strip():
                    target.add(value.strip())
                    if key == "name":
                        feature_name = value.strip()
                        names_by_geometry[geometry_type].add(feature_name)
                        name_presence_counts[geometry_type] += 1
                    else:
                        labels_by_geometry[geometry_type].add(value.strip())
                        label_presence_counts[geometry_type] += 1
        feature_names.append(feature_name)
        present, inferred = _metadata_flags(properties, len(sequence))
        for kind in present:
            metadata[kind] = True
        if inferred is not None:
            inferred_values.append(inferred)
            inferred_by_geometry[geometry_type].append(inferred)

    within_linestring_gaps: list[float] = []
    between_feature_gaps: list[float] = []
    point_stream_gaps: list[float] = []
    if range_valid:
        for geometry_type, sequence in observed_features:
            if geometry_type == "LineString":
                within_linestring_gaps.extend(
                    _haversine_meters(left, right) for left, right in zip(sequence, sequence[1:])
                )
        for (left_type, left_sequence), (right_type, right_sequence) in zip(
            observed_features, observed_features[1:]
        ):
            gap = _haversine_meters(left_sequence[-1], right_sequence[0])
            if left_type == right_type == "Point":
                point_stream_gaps.append(gap)
            else:
                between_feature_gaps.append(gap)
        ordered_stream_gaps = [
            _haversine_meters(left, right) for left, right in zip(observed_stream, observed_stream[1:])
        ]
        max_gap = max(ordered_stream_gaps) if ordered_stream_gaps else None
    else:
        max_gap = None

    if not range_valid:
        gap_source = "unknown"
    else:
        source_maxima = {
            source: max(gaps)
            for source, gaps in (
                ("inside_linestring", within_linestring_gaps),
                ("between_features", between_feature_gaps),
                ("point_stream", point_stream_gaps),
            )
            if gaps
        }
        if not source_maxima:
            gap_source = "none"
        else:
            largest_gap = max(source_maxima.values())
            tied_sources = [source for source, value in source_maxima.items() if value == largest_gap]
            gap_source = tied_sources[0] if len(tied_sources) == 1 else "multiple"
    third_ordinate_class = "present_opaque" if "3" in dimensions else "absent"
    feature_count_by_geometry = _per_geometry_band(feature_counts)
    coordinate_density_by_geometry = _per_geometry_density(coordinate_counts)
    name_presence_by_geometry = _per_geometry_band(name_presence_counts)
    label_presence_by_geometry = _per_geometry_band(label_presence_counts)
    distinct_name_by_geometry = _per_geometry_band(
        {geometry_type: len(names_by_geometry[geometry_type]) for geometry_type in ("Point", "LineString")}
    )
    distinct_label_by_geometry = _per_geometry_band(
        {geometry_type: len(labels_by_geometry[geometry_type]) for geometry_type in ("Point", "LineString")}
    )
    inferred_coverage_by_geometry = {
        geometry_type: _coverage(inferred_by_geometry[geometry_type]) for geometry_type in ("Point", "LineString")
    }
    linestring_distribution = _linestring_gap_distribution(within_linestring_gaps, range_valid=range_valid)
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
            "max_gap_within_linestring_band": _max_gap_band(within_linestring_gaps) if range_valid else "unknown",
            "max_gap_between_features_band": _max_gap_band(between_feature_gaps) if range_valid else "unknown",
            "max_gap_point_stream_band": _max_gap_band(point_stream_gaps) if range_valid else "unknown",
            "max_consecutive_gap_source": gap_source,
            "feature_count_band_by_geometry": feature_count_by_geometry,
            "coordinate_density_band_by_geometry": coordinate_density_by_geometry,
            "name_presence_band_by_geometry": name_presence_by_geometry,
            "label_presence_band_by_geometry": label_presence_by_geometry,
            "distinct_name_band_by_geometry": distinct_name_by_geometry,
            "distinct_label_band_by_geometry": distinct_label_by_geometry,
            "inferred_coverage_class_by_geometry": inferred_coverage_by_geometry,
            "feature_order_name_pattern": _name_order_pattern(feature_names),
            "linestring_gap_distribution_band": linestring_distribution,
            "feature_boundary_gap_band": _max_gap_band(between_feature_gaps) if range_valid else "unknown",
            "point_stream_gap_band": _max_gap_band(point_stream_gaps) if range_valid else "unknown",
            "distinct_name_band": _band(len(names)),
            "distinct_label_band": _band(len(labels)),
            "inferred_coverage_class": coverage,
            "per_point_time_present": metadata["time"],
            "per_point_accuracy_present": metadata["accuracy"],
            "per_point_heading_present": metadata["heading"],
            "per_point_speed_present": metadata["speed"],
            "input_sufficiency": "insufficient" if not all_points or not range_valid else "candidate_with_time" if metadata["time"] else "candidate",
            "third_ordinate_class": third_ordinate_class,
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
    "GAP_SOURCES",
    "GEOMETRY_CLASSES",
    "INPUT_SUFFICIENCY",
    "LINESTRING_GAP_DISTRIBUTIONS",
    "NAME_ORDER_PATTERNS",
    "OUTPUT_KEYS",
    "RouteInputAnalysisError",
    "THIRD_ORDINATE_CLASSES",
    "analyze_route_input_sufficiency",
    "safe_analyze_route_input",
    "safe_analyze_route_input_sufficiency",
]
