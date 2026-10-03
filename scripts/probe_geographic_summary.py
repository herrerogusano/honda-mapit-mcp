"""Injected one-attempt summer geography probe; no SDK or credential construction.

The trusted operator must persist its one-shot intent before calling this helper.
It supplies a lazy services factory and the existing bounded transport. This
helper never saves geometry, sessions or a history database.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from mapit.geography import summer_window_utc
from mapit.geographic_tools import AREA_SOURCE, _load_menorca_area
from mapit.services import MapitServices, ServiceError, _iso, split_month_windows


class ProbeError(ValueError):
    """Fixed-category probe contract failure."""


_SUMMARY_FIELDS = (
    "from_time", "to_time", "area_source", "area_type", "matched_routes",
    "fully_inside_routes", "outside_routes", "crossing_routes", "unknown_routes",
    "fully_inside_distance", "fully_inside_distance_km", "inferred_marked_inside_routes",
    "not_marked_inferred_inside_routes", "inference_unknown_inside_routes",
    "metric_unit", "conversion_basis", "completeness", "interpretation_warning",
)


class _ReadBudget:
    def __init__(self, client: Any, start: str, end: str):
        self.client = client
        begin = datetime.fromisoformat(start.replace("Z", "+00:00"))
        finish = datetime.fromisoformat(end.replace("Z", "+00:00"))
        self.windows = [(_iso(a), _iso(b)) for a, b in split_month_windows(begin, finish)]
        if len(self.windows) != 4:
            raise ProbeError("probe_window_invalid")
        self.core_reads = 0
        self.geo_reads = 0

    def get_core(self, path: str, *, params=None, max_response_bytes=None):
        if (path != "/v1/account-summary" or params is not None or self.core_reads != 0
                or type(max_response_bytes) is not int or max_response_bytes != 2 * 1024 * 1024):
            raise ProbeError("probe_read_budget_exceeded")
        self.core_reads += 1
        return self.client.get_core(path, params=params, max_response_bytes=max_response_bytes)

    def get_geo(self, path: str, *, params=None, max_response_bytes=None):
        if (
            path != "/v1/routes" or type(params) is not dict
            or set(params) != {"vehicleId", "from", "to"}
            or self.core_reads != 1 or self.geo_reads >= len(self.windows)
            or (params["from"], params["to"]) != self.windows[self.geo_reads]
            or max_response_bytes != 2 * 1024 * 1024
        ):
            raise ProbeError("probe_read_budget_exceeded")
        self.geo_reads += 1
        return self.client.get_geo(path, params=params, max_response_bytes=max_response_bytes)


def run_probe(factory: Callable[[], MapitServices], *, year: int = 2026) -> dict[str, Any]:
    """Run only the fixed approved example, exposing aggregates without IDs."""
    if not callable(factory) or type(year) is not int or year != 2026:
        raise ProbeError("probe_configuration_invalid")
    start, end = summer_window_utc(year)
    area = _load_menorca_area()
    services = factory()
    if type(services) is not MapitServices:
        raise ProbeError("probe_configuration_invalid")
    original = services.client
    budget = _ReadBudget(original, start, end)
    services.client = budget
    try:
        result = services.get_geographic_summary(start, end, area, AREA_SOURCE)
        if budget.core_reads != 1 or budget.geo_reads != 4:
            raise ProbeError("probe_read_budget_unverified")
        values = result.model_dump(mode="json")
        summary = {key: values[key] for key in _SUMMARY_FIELDS}
        return {
            "success": True, "category": "geographic_probe_passed",
            "core_logical_reads": budget.core_reads, "geo_logical_reads": budget.geo_reads,
            "summary": summary,
        }
    except (ServiceError, ProbeError):
        raise
    finally:
        services.client = original
