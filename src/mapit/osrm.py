"""Offline-safe classification helpers for a local OSRM Match response.

This module never returns response values.  It is deliberately independent of
MAPIT and of any HTTP implementation so synthetic fixtures can exercise the
redaction and fail-closed rules without network access.
"""

from __future__ import annotations

import json
import math
from typing import Any

ENGINE = "osrm-local"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DEPTH = 16
MAX_CONTAINER_ITEMS = 10_000
MAX_MATCHINGS = 512
MAX_TRACEPOINTS = 10_000

CATEGORIES = frozenset({
    "matched",
    "partial",
    "no_match",
    "invalid_input",
    "resource_limit",
    "engine_unavailable",
})
MATCHING_COUNT_BANDS = frozenset({"none", "few", "many", "unknown"})
TRACEPOINT_COVERAGE_BANDS = frozenset({"none", "partial", "all", "unknown"})
CONFIDENCE_BANDS = frozenset({"none", "low", "medium", "high", "unknown"})

OUTPUT_KEYS = frozenset({
    "engine",
    "category",
    "code_ok",
    "matching_count_band",
    "tracepoint_coverage_band",
    "confidence_band",
    "steps_present",
    "annotations_present",
    "names_present",
    "raw_discarded",
})


class OSRMAnalysisError(ValueError):
    """Internal fail-closed classification error."""

    def __init__(self, category: str = "invalid_input") -> None:
        self.category = category if category in CATEGORIES else "invalid_input"
        super().__init__(self.category)


def _empty(category: str, *, code_ok: bool = False) -> dict[str, Any]:
    return {
        "engine": ENGINE,
        "category": category if category in CATEGORIES else "invalid_input",
        "code_ok": bool(code_ok),
        "matching_count_band": "unknown",
        "tracepoint_coverage_band": "unknown",
        "confidence_band": "unknown",
        "steps_present": False,
        "annotations_present": False,
        "names_present": False,
        "raw_discarded": True,
    }


def safe_osrm_result(category: str) -> dict[str, Any]:
    """Return a fixed safe result for a transport or route-stage failure."""
    return _empty(category)


def _band(count: int) -> str:
    if count == 0:
        return "none"
    return "few" if count <= 3 else "many"


def _finite(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _budget(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise OSRMAnalysisError("resource_limit")
    if isinstance(value, dict):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise OSRMAnalysisError("resource_limit")
        for key, child in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise OSRMAnalysisError("invalid_input")
            _budget(child, depth + 1)
    elif isinstance(value, list):
        if len(value) > MAX_CONTAINER_ITEMS:
            raise OSRMAnalysisError("resource_limit")
        for child in value:
            _budget(child, depth + 1)
    elif isinstance(value, str) and len(value) > 4096:
        raise OSRMAnalysisError("resource_limit")


def validate_payload_budget(value: Any) -> None:
    """Validate decoded response depth/container/string limits before inspection."""
    _budget(value)


def _validate_no_match_shape(payload: dict[str, Any]) -> None:
    """Validate bounded structural metadata for NoMatch without inspecting values."""
    matchings = payload.get("matchings")
    tracepoints = payload.get("tracepoints")
    if matchings is not None:
        if not isinstance(matchings, list):
            raise OSRMAnalysisError("invalid_input")
        if len(matchings) > MAX_MATCHINGS:
            raise OSRMAnalysisError("resource_limit")
        for matching in matchings:
            if not isinstance(matching, dict):
                raise OSRMAnalysisError("invalid_input")
            if not isinstance(matching.get("legs", []), list):
                raise OSRMAnalysisError("invalid_input")
    if tracepoints is not None:
        if not isinstance(tracepoints, list):
            raise OSRMAnalysisError("invalid_input")
        if len(tracepoints) > MAX_TRACEPOINTS:
            raise OSRMAnalysisError("resource_limit")
        for tracepoint in tracepoints:
            if tracepoint is None:
                continue
            if not isinstance(tracepoint, dict) or "matchings_index" not in tracepoint:
                raise OSRMAnalysisError("invalid_input")
            index = tracepoint["matchings_index"]
            if index is not None and (type(index) is not int or not 0 <= index < len(matchings or [])):
                raise OSRMAnalysisError("invalid_input")


def _confidence(matchings: list[dict[str, Any]]) -> str:
    values: list[float] = []
    for matching in matchings:
        value = matching.get("confidence")
        if value is None:
            continue
        if not _finite(value) or not 0 <= float(value) <= 1:
            raise OSRMAnalysisError("invalid_input")
        values.append(float(value))
    if not values:
        return "unknown"
    lowest = min(values)
    if lowest >= 0.85:
        return "high"
    if lowest >= 0.60:
        return "medium"
    return "low"


def classify_match_response(payload: Any, *, raw_size: int | None = None) -> dict[str, Any]:
    """Classify one decoded OSRM Match response into a fixed safe schema."""
    try:
        if raw_size is not None and (not isinstance(raw_size, int) or raw_size < 0):
            raise OSRMAnalysisError("invalid_input")
        if raw_size is None:
            try:
                estimated_size = len(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            except RecursionError:
                raise OSRMAnalysisError("resource_limit") from None
            except (TypeError, ValueError, OverflowError):
                raise OSRMAnalysisError("invalid_input") from None
            if estimated_size > MAX_JSON_BYTES:
                raise OSRMAnalysisError("resource_limit")
        if raw_size is not None and raw_size > MAX_JSON_BYTES:
            raise OSRMAnalysisError("resource_limit")
        _budget(payload)
        if not isinstance(payload, dict):
            raise OSRMAnalysisError("invalid_input")
        code = payload.get("code")
        if not isinstance(code, str):
            raise OSRMAnalysisError("invalid_input")
        if code in {"TooBig", "TooManyCoordinates", "ResourceLimit"}:
            return _empty("resource_limit")
        if code in {"NoMatch", "NoSegment"}:
            _validate_no_match_shape(payload)
            return {
                **_empty("no_match"),
                "tracepoint_coverage_band": "none",
            }
        if code != "Ok":
            return _empty("invalid_input")

        matchings = payload.get("matchings")
        tracepoints = payload.get("tracepoints")
        if not isinstance(matchings, list) or not isinstance(tracepoints, list):
            raise OSRMAnalysisError("invalid_input")
        if len(matchings) > MAX_MATCHINGS or len(tracepoints) > MAX_TRACEPOINTS:
            raise OSRMAnalysisError("resource_limit")
        normalized_matchings: list[dict[str, Any]] = []
        for matching in matchings:
            if not isinstance(matching, dict):
                raise OSRMAnalysisError("invalid_input")
            legs = matching.get("legs", [])
            if not isinstance(legs, list):
                raise OSRMAnalysisError("invalid_input")
            normalized_matchings.append(matching)

        matched_tracepoints = 0
        for tracepoint in tracepoints:
            if tracepoint is None:
                continue
            if not isinstance(tracepoint, dict):
                raise OSRMAnalysisError("invalid_input")
            if "matchings_index" not in tracepoint:
                raise OSRMAnalysisError("invalid_input")
            index = tracepoint["matchings_index"]
            if index is not None and (type(index) is not int or not 0 <= index < len(matchings)):
                raise OSRMAnalysisError("invalid_input")
            if index is not None:
                matched_tracepoints += 1

        steps_present = False
        annotations_present = False
        names_present = False
        for matching in normalized_matchings:
            for leg in matching.get("legs", []):
                if not isinstance(leg, dict):
                    raise OSRMAnalysisError("invalid_input")
                if "annotation" in leg:
                    annotation = leg["annotation"]
                    if annotation is not None and not isinstance(annotation, dict):
                        raise OSRMAnalysisError("invalid_input")
                    if isinstance(annotation, dict):
                        annotations_present = True
                steps = leg.get("steps", [])
                if not isinstance(steps, list):
                    raise OSRMAnalysisError("invalid_input")
                if steps:
                    steps_present = True
                for step in steps:
                    if not isinstance(step, dict):
                        raise OSRMAnalysisError("invalid_input")
                    name = step.get("name")
                    if name is not None and not isinstance(name, str):
                        raise OSRMAnalysisError("invalid_input")
                    if isinstance(name, str) and name.strip():
                        names_present = True

        coverage = "none" if not tracepoints else "all" if matched_tracepoints == len(tracepoints) else "partial"
        if not matchings:
            category = "no_match"
        elif coverage == "all":
            category = "matched"
        else:
            category = "partial"
        return {
            "engine": ENGINE,
            "category": category,
            "code_ok": True,
            "matching_count_band": _band(len(matchings)),
            "tracepoint_coverage_band": coverage,
            "confidence_band": _confidence(normalized_matchings),
            "steps_present": steps_present,
            "annotations_present": annotations_present,
            "names_present": names_present,
            "raw_discarded": True,
        }
    except OSRMAnalysisError as exc:
        return _empty(exc.category)
    except (TypeError, ValueError, OverflowError, KeyError, IndexError):
        return _empty("invalid_input")


def classify_match_json(raw: bytes | str) -> dict[str, Any]:
    """Decode and classify bounded JSON without exposing decode errors."""
    try:
        if isinstance(raw, bytes):
            size = len(raw)
            if size > MAX_JSON_BYTES:
                return _empty("resource_limit")
            value = json.loads(raw.decode("utf-8"))
        elif isinstance(raw, str):
            size = len(raw.encode("utf-8"))
            if size > MAX_JSON_BYTES:
                return _empty("resource_limit")
            value = json.loads(raw)
        else:
            return _empty("invalid_input")
    except RecursionError:
        return _empty("resource_limit")
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        return _empty("invalid_input")
    return classify_match_response(value, raw_size=size)


__all__ = [
    "CATEGORIES",
    "CONFIDENCE_BANDS",
    "ENGINE",
    "MATCHING_COUNT_BANDS",
    "OUTPUT_KEYS",
    "OSRMAnalysisError",
    "TRACEPOINT_COVERAGE_BANDS",
    "classify_match_json",
    "classify_match_response",
    "safe_osrm_result",
    "validate_payload_budget",
]
