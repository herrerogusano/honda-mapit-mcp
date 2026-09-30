from __future__ import annotations

import json

import pytest

from mapit.osrm import (
    CATEGORIES,
    CONFIDENCE_BANDS,
    MATCHING_COUNT_BANDS,
    OUTPUT_KEYS,
    TRACEPOINT_COVERAGE_BANDS,
    classify_match_json,
    classify_match_response,
)


def _match(**overrides):
    payload = {
        "code": "Ok",
        "matchings": [{
            "confidence": 0.72,
            "legs": [{"annotation": {"nodes": [1, 2]}, "steps": [{"name": "Synthetic Avenue"}]}],
        }],
        "tracepoints": [{"matchings_index": 0}, {"matchings_index": 0}],
    }
    payload.update(overrides)
    return payload


def test_match_classifier_has_fixed_redacted_schema_and_expected_fixture_result():
    result = classify_match_response(_match())
    assert set(result) == OUTPUT_KEYS
    assert result == {
        "engine": "osrm-local",
        "category": "matched",
        "code_ok": True,
        "matching_count_band": "few",
        "tracepoint_coverage_band": "all",
        "confidence_band": "medium",
        "steps_present": True,
        "annotations_present": True,
        "names_present": True,
        "raw_discarded": True,
    }
    assert "Synthetic Avenue" not in json.dumps(result)


@pytest.mark.parametrize(
    ("payload", "category"),
    [
        ({"code": "NoMatch", "tracepoints": [], "matchings": []}, "no_match"),
        ({"code": "InvalidQuery"}, "invalid_input"),
        ({"code": "TooBig"}, "resource_limit"),
        ({"code": "Ok", "matchings": [], "tracepoints": []}, "no_match"),
    ],
)
def test_classifier_categories_are_allowlisted(payload, category):
    result = classify_match_response(payload)
    assert result["category"] == category
    assert result["category"] in CATEGORIES
    assert set(result) == OUTPUT_KEYS
    assert result["raw_discarded"] is True


def test_partial_tracepoints_and_confidence_bands():
    result = classify_match_response(_match(tracepoints=[None, {"matchings_index": 0}, {"matchings_index": None}]))
    assert result["category"] == "partial"
    assert result["tracepoint_coverage_band"] == "partial"
    assert result["confidence_band"] == "medium"


def test_real_schema_null_tracepoint_empty_step_name_and_leg_annotation():
    result = classify_match_response(_match(
        tracepoints=[None, {"matchings_index": 0}],
        matchings=[{
            "confidence": 0.72,
            "legs": [{"annotation": {"duration": [1.0]}, "steps": [{"name": ""}]}],
        }],
    ))
    assert result["category"] == "partial"
    assert result["tracepoint_coverage_band"] == "partial"
    assert result["annotations_present"] is True
    assert result["names_present"] is False


def test_optional_match_metadata_is_safe_and_unknown_without_values():
    result = classify_match_response({"code": "Ok", "matchings": [{"legs": []}], "tracepoints": []})
    assert result["category"] == "partial"
    assert result["matching_count_band"] in MATCHING_COUNT_BANDS
    assert result["tracepoint_coverage_band"] in TRACEPOINT_COVERAGE_BANDS
    assert result["confidence_band"] == "unknown"
    assert all(result[key] is False for key in ("steps_present", "annotations_present", "names_present"))


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"code": "Ok", "matchings": {}, "tracepoints": []},
        {"code": "Ok", "matchings": [{}], "tracepoints": [{"matchings_index": "bad"}]},
        {"code": "Ok", "matchings": [{"confidence": 2}], "tracepoints": []},
        {"code": "Ok", "matchings": [{"legs": [{"steps": [{"name": 7}]}]}], "tracepoints": []},
        {"code": "Ok", "matchings": [{"legs": [{"annotation": "raw"}]}], "tracepoints": []},
    ],
)
def test_malformed_match_fails_closed_without_payload_leak(payload):
    result = classify_match_response(payload)
    assert result["category"] == "invalid_input"
    assert set(result) == OUTPUT_KEYS
    assert json.dumps(result).find("bad") == -1


def test_json_decoder_and_depth_size_limits_fail_closed():
    assert classify_match_json(b"not-json")["category"] == "invalid_input"
    assert classify_match_json(b"x" * (2 * 1024 * 1024 + 1))["category"] == "resource_limit"
    deeply_nested_json = b"[" * 5000 + b"0" + b"]" * 5000
    assert classify_match_json(deeply_nested_json)["category"] == "resource_limit"
    nested = None
    for _ in range(20):
        nested = [nested]
    assert classify_match_response({"code": "Ok", "matchings": nested, "tracepoints": []})["category"] == "resource_limit"


@pytest.mark.parametrize(
    "payload",
    [
        {"code": "NoMatch", "matchings": [{}] * 513, "tracepoints": []},
        {"code": "NoMatch", "matchings": [], "tracepoints": [None] * 10001},
        {"code": "NoMatch", "matchings": [{}], "tracepoints": [{"matchings_index": "bad"}]},
    ],
)
def test_no_match_metadata_is_bounded_and_structurally_validated(payload):
    result = classify_match_response(payload)
    expected = "resource_limit" if len(payload.get("matchings", [])) > 512 or len(payload.get("tracepoints", [])) > 10000 else "invalid_input"
    assert result["category"] == expected
