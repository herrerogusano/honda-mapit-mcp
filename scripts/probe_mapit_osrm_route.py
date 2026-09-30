"""Bounded all-LineString assessment; never claims an exact or complete route."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
for path in (ROOT, ROOT / "src"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

from mapit.route_input_analyzer import analyze_route_input  # noqa: E402
from scripts.probe_local_osrm_fixture import _decode_payload, _ProbeError  # noqa: E402
from scripts.probe_mapit_osrm import (  # noqa: E402
    DEFAULT_OSRM_URL, _OutsideBBoxError, _line_string_coordinates,
    _local_osrm_transport, _loopback_base_url, _match_local_osrm,
    perform_mapit_osrm_probe,
)

MAX_LINES = 8
MAX_TOTAL_POINTS = 2_000
OUTPUT_KEYS = frozenset({
    "category", "stage_category", "engine", "line_count_band",
    "checked_line_coverage", "tracepoint_coverage", "lowest_confidence_band",
    "source_inferred_class", "inferred_flag_availability",
    "excluded_point_features", "multiple_subtraces_present",
    "max_internal_gap_band", "max_feature_boundary_gap_band",
    "whole_route_claim", "raw_discarded",
})
CATEGORIES = frozenset({
    "matched_lines", "partial_lines", "no_match", "invalid_input",
    "resource_limit", "engine_unavailable",
})


def _empty(category: str = "invalid_input", stage: str = "route_detail_invalid") -> dict[str, Any]:
    return {
        "category": category if category in CATEGORIES else "invalid_input",
        "stage_category": stage, "engine": "osrm-local",
        "line_count_band": "unknown", "checked_line_coverage": "none",
        "tracepoint_coverage": "unknown", "lowest_confidence_band": "unknown",
        "source_inferred_class": "unknown", "inferred_flag_availability": "none",
        "excluded_point_features": False, "multiple_subtraces_present": False,
        "max_internal_gap_band": "unknown", "max_feature_boundary_gap_band": "unknown",
        "whole_route_claim": False, "raw_discarded": True,
    }


def assess_route(detail: Any, *, base_url: str = DEFAULT_OSRM_URL, transport=None) -> dict[str, Any]:
    """Validate all features before dispatch; return only value-free diagnostics."""
    result = _empty()
    lines = []
    checked = []
    try:
        _loopback_base_url(base_url)
        analysis = analyze_route_input(detail)
        geo = detail.get("geoJSON")
        if not isinstance(geo, dict) or geo.get("type") != "FeatureCollection":
            return result
        features = geo["features"]
        total = 0
        flags = []
        for feature in features:
            geometry = feature["geometry"]
            if geometry["type"] == "Point":
                result["excluded_point_features"] = True
                continue
            if geometry["type"] != "LineString":
                return result
            if len(lines) >= MAX_LINES:
                raise _ProbeError("resource_limit")
            points = _line_string_coordinates({"geoJSON": feature})
            total += len(points)
            if total > MAX_TOTAL_POINTS:
                raise _ProbeError("resource_limit")
            properties = feature.get("properties", {})
            flag = properties.get("inferred") if isinstance(properties, dict) else None
            if flag is not None and type(flag) is not bool:
                return result
            flags.append(flag)
            lines.append(points)
        if not lines:
            return result
        result["line_count_band"] = "few" if len(lines) <= 3 else "many"
        known = [flag for flag in flags if flag is not None]
        result["inferred_flag_availability"] = "all" if len(known) == len(flags) else "partial" if known else "none"
        if len(known) == len(flags):
            result["source_inferred_class"] = "all_true" if all(known) else "all_false" if not any(known) else "mixed"
        result["max_internal_gap_band"] = analysis["max_gap_within_linestring_band"]
        result["max_feature_boundary_gap_band"] = analysis["max_gap_between_features_band"]
        sender = transport or _local_osrm_transport
        result["stage_category"] = "matcher"
        for points in lines:
            def checked_transport(method, url, timeout):
                payload = _decode_payload(sender(method, url, timeout))
                if payload.get("code") == "Ok":
                    tracepoints = payload.get("tracepoints")
                    if not isinstance(tracepoints, list) or len(tracepoints) != len(points):
                        raise _ProbeError("invalid_input")
                    matchings = payload.get("matchings")
                    if isinstance(matchings, list) and len(matchings) > 1:
                        result["multiple_subtraces_present"] = True
                return payload

            match = _match_local_osrm(points, base_url=base_url, transport=checked_transport)
            if match["category"] in {"invalid_input", "resource_limit", "engine_unavailable"}:
                result["category"] = match["category"]
                result["stage_category"] = "matcher_failed"
                return result
            checked.append(match)
            result["checked_line_coverage"] = "all" if len(checked) == len(lines) else "partial"
        coverage = [match["tracepoint_coverage_band"] for match in checked]
        result["tracepoint_coverage"] = "all" if all(value == "all" for value in coverage) else "partial" if any(value in {"all", "partial"} for value in coverage) else "none" if all(value == "none" for value in coverage) else "unknown"
        confidence = [match["confidence_band"] for match in checked]
        result["lowest_confidence_band"] = "unknown" if any(value not in {"low", "medium", "high"} for value in confidence) else min(confidence, key={"low": 0, "medium": 1, "high": 2}.get)
        result["category"] = "matched_lines" if result["tracepoint_coverage"] == "all" else "partial_lines" if result["tracepoint_coverage"] == "partial" else "no_match"
        result["stage_category"] = "success"
        return result
    except _OutsideBBoxError:
        result.update(category="invalid_input", stage_category="outside_bbox")
    except _ProbeError as exc:
        result.update(category=exc.category, stage_category="matcher_failed" if result["stage_category"] == "matcher" else "route_detail_limit")
    except (OSError, TimeoutError):
        result.update(category="engine_unavailable", stage_category="matcher_unavailable")
    except Exception:
        result.update(category="invalid_input", stage_category="route_detail_invalid")
    finally:
        lines.clear()
        detail = None
    return result


def perform_route_probe(**kwargs) -> dict[str, Any]:
    base_url = kwargs.get("osrm_base_url", DEFAULT_OSRM_URL)
    transport = kwargs.pop("osrm_transport", None)
    result = perform_mapit_osrm_probe(
        **kwargs, detail_processor=lambda detail: assess_route(detail, base_url=base_url, transport=transport),
    )
    if set(result) == OUTPUT_KEYS:
        return result
    return _empty(result.get("category", "invalid_input"), result.get("stage_category", "route_detail_invalid"))


def main() -> int:
    result = perform_route_probe()
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["category"] == "matched_lines" else 1


if __name__ == "__main__":
    raise SystemExit(main())
