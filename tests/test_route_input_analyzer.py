from __future__ import annotations

import json

import pytest

from mapit.route_input_analyzer import (
    DIMENSION_CLASSES,
    GAP_BANDS,
    GAP_SOURCES,
    GEOMETRY_CLASSES,
    INPUT_SUFFICIENCY,
    OUTPUT_KEYS,
    RouteInputAnalysisError,
    THIRD_ORDINATE_CLASSES,
    analyze_route_input,
    safe_analyze_route_input,
)


def _detail(*, coordinates=None, properties=None, geometry_type="LineString"):
    coordinates = coordinates if coordinates is not None else [[-3.7000, 40.4000], [-3.7005, 40.4005, 123.0]]
    return {
        "id": "route-secret",
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [{
                "type": "Feature",
                "properties": properties or {},
                "geometry": {"type": geometry_type, "coordinates": coordinates},
            }],
        },
        "startedAt": "private-timestamp",
    }


def test_output_is_fixed_schema_and_all_values_are_allowlisted():
    result = analyze_route_input(
        _detail(
            properties={
                "name": "Sensitive street",
                "label": "Private label",
                "inferred": True,
                "timestamps": [1, 2],
                "accuracy": [3, 4],
                "heading": [5, 6],
                "speed": [7, 8],
            }
        )
    )
    assert set(result) == OUTPUT_KEYS
    assert result["success"] is True and result["category"] == "success"
    assert set(result["geometry_classes"]) <= GEOMETRY_CLASSES
    assert set(result["coordinate_dimension_classes"]) <= DIMENSION_CLASSES
    assert result["max_consecutive_gap_distance_band"] in GAP_BANDS
    assert result["max_gap_within_linestring_band"] in GAP_BANDS
    assert result["max_gap_between_features_band"] in GAP_BANDS
    assert result["max_gap_point_stream_band"] in GAP_BANDS
    assert result["max_consecutive_gap_source"] in GAP_SOURCES
    assert result["third_ordinate_class"] in THIRD_ORDINATE_CLASSES
    assert result["input_sufficiency"] in INPUT_SUFFICIENCY
    assert json.dumps(result, ensure_ascii=True).find("Sensitive") == -1
    assert "private-timestamp" not in json.dumps(result)
    assert result["per_point_time_present"] is True
    assert result["per_point_accuracy_present"] is True
    assert result["per_point_heading_present"] is True
    assert result["per_point_speed_present"] is True
    assert result["third_ordinate_class"] == "present_opaque"


def test_third_ordinate_is_dimension_only_not_timestamp():
    result = analyze_route_input(_detail(coordinates=[[-3.7, 40.4, 1700000000], [-3.701, 40.401, 12]]))
    assert result["coordinate_dimension_classes"] == ["3"]
    assert result["per_point_time_present"] is False
    assert result["input_sufficiency"] == "candidate"
    assert result["third_ordinate_class"] == "present_opaque"


def test_point_and_linestring_shapes_and_wgs84_range():
    point = analyze_route_input(_detail(coordinates=[-3.7, 40.4], geometry_type="Point"))
    assert point["coordinate_shape_classes"] == ["pair-like"]
    assert point["point_density_band"] == "few"
    invalid = analyze_route_input(_detail(coordinates=[[181.0, 40.4], [182.0, 40.5]]))
    assert invalid["wgs84_range_valid"] is False
    assert invalid["input_sufficiency"] == "insufficient"
    assert invalid["max_consecutive_gap_distance_band"] == "unknown"


def test_gap_and_name_label_inferred_bands_are_value_free():
    features = []
    for index in range(4):
        features.append(
            {
                "type": "Feature",
                "properties": {"name": f"name-{index}", "label": f"label-{index}", "inferred": index % 2 == 0},
                "geometry": {"type": "Point", "coordinates": [-3.0 + index, 40.0]},
            }
        )
    result = analyze_route_input({"geoJSON": {"type": "FeatureCollection", "features": features}})
    assert result["point_density_band"] == "few"
    assert result["distinct_name_band"] == "many"
    assert result["distinct_label_band"] == "many"
    assert result["inferred_coverage_class"] == "partial"
    assert result["max_consecutive_gap_distance_band"] == "long"
    assert result["max_gap_within_linestring_band"] == "none"
    assert result["max_gap_between_features_band"] == "long"
    assert result["max_gap_point_stream_band"] == "long"
    assert result["max_consecutive_gap_source"] == "point_stream"
    assert all(value not in json.dumps(result) for value in ("name-0", "label-0"))


def test_ordered_point_features_include_feature_boundaries_in_gap_band():
    payload = {
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [
                {"type": "Feature", "geometry": {"type": "Point", "coordinates": [0, 0]}},
                {"type": "Feature", "geometry": {"type": "Point", "coordinates": [0, 0.1]}},
            ],
        }
    }
    result = analyze_route_input(payload)
    assert result["max_consecutive_gap_distance_band"] == "long"


def test_antimeridian_uses_shortest_longitude_arc():
    payload = _detail(coordinates=[[179.999, 0], [-179.999, 0]])
    result = analyze_route_input(payload)
    assert result["max_consecutive_gap_distance_band"] == "medium"


def test_gap_provenance_is_inside_linestring_when_no_feature_boundary_exists():
    result = analyze_route_input(_detail(coordinates=[[0, 0], [0, 0.0005]]))
    assert result["max_gap_within_linestring_band"] == "short"
    assert result["max_gap_between_features_band"] == "none"
    assert result["max_gap_point_stream_band"] == "none"
    assert result["max_consecutive_gap_source"] == "inside_linestring"


def test_gap_provenance_separates_feature_boundary_from_line_internal_gap():
    payload = {
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [
                {"type": "Feature", "geometry": {"type": "Point", "coordinates": [0, 0]}},
                {"type": "Feature", "geometry": {"type": "LineString", "coordinates": [[0, 0.1]]}},
            ],
        }
    }
    result = analyze_route_input(payload)
    assert result["max_gap_within_linestring_band"] == "none"
    assert result["max_gap_between_features_band"] == "long"
    assert result["max_gap_point_stream_band"] == "none"
    assert result["max_consecutive_gap_source"] == "between_features"


def test_gap_provenance_marks_mixed_sources_without_values():
    payload = {
        "geoJSON": {
            "type": "FeatureCollection",
            "features": [
                {"type": "Feature", "geometry": {"type": "LineString", "coordinates": [[0, 0], [0, 0.0005]]}},
                {"type": "Feature", "geometry": {"type": "Point", "coordinates": [0, 0.1]}},
            ],
        }
    }
    result = analyze_route_input(payload)
    assert result["max_gap_within_linestring_band"] == "short"
    assert result["max_gap_between_features_band"] == "long"
    assert result["max_gap_point_stream_band"] == "none"
    assert result["max_consecutive_gap_source"] == "multiple"
    assert "0.1" not in json.dumps(result)


@pytest.mark.parametrize(
    "payload,category",
    [
        ([], "invalid_structure"),
        ({}, "invalid_structure"),
        ({"geoJSON": []}, "invalid_structure"),
        ({"geoJSON": {"type": []}}, "invalid_structure"),
        ({"geoJSON": {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": [], "coordinates": [0, 0]}}]}}, "invalid_structure"),
        ({"geoJSON": {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": "Polygon", "coordinates": []}}]}}, "unsupported_geometry"),
        (_detail(coordinates=[[1, 2, 3, 4], [2, 3, 4, 5]]), "invalid_structure"),
        ({"geoJSON": {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": None}]}}, "invalid_structure"),
    ],
)
def test_malformed_or_unknown_shapes_fail_closed(payload, category):
    with pytest.raises(RouteInputAnalysisError) as exc_info:
        analyze_route_input(payload)
    assert exc_info.value.category == category
    result = safe_analyze_route_input(payload)
    assert result["success"] is False and result["category"] == category
    assert set(result) == OUTPUT_KEYS


def test_oversized_feature_collection_fails_closed():
    payload = {"geoJSON": {"type": "FeatureCollection", "features": []}}
    payload["geoJSON"]["features"] = [
        {"type": "Feature", "geometry": {"type": "Point", "coordinates": [0, 0]}}
        for _ in range(4097)
    ]
    result = safe_analyze_route_input(payload)
    assert result["success"] is False and result["category"] == "oversized"


def test_empty_collection_is_safe_candidate_failure_without_values():
    result = analyze_route_input({"geoJSON": {"type": "FeatureCollection", "features": []}})
    assert result["success"] is True
    assert result["input_sufficiency"] == "insufficient"
    assert json.dumps(result).find("geoJSON") == -1


@pytest.mark.parametrize("payload", [[], {}, {"geoJSON": []}, {"geoJSON": {"type": "FeatureCollection", "features": [{"type": "Feature", "geometry": {"type": {}}}]}}])
def test_safe_analyzer_always_returns_fixed_schema_for_malformed_json_shapes(payload):
    result = safe_analyze_route_input(payload)
    assert set(result) == OUTPUT_KEYS
    assert result["success"] is False
    assert result["category"] == "invalid_structure"
