"""Bounded, redacted diagnostic for MAPIT route-completion query variants.

The probe is live-capable but tests use only injected sessions and fake clients.
Its results can compare returned route summaries; they cannot establish the
meaning of ``complete`` or prove route-history completeness.
"""

from __future__ import annotations

import inspect
import math
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.auth import CognitoHTTPError, SessionRefreshError, UnsupportedCognitoChallenge  # noqa: E402
from mapit.client import (  # noqa: E402
    MapitClient,
    MapitHTTPError,
    MapitResponseError,
    MapitResponseTooLarge,
    MapitTransportError,
)
from mapit.config import MapitConfig  # noqa: E402
from mapit.session import ManagedSession, SessionManager, SessionManagerError  # noqa: E402
from scripts.probe_monthly_measurement import (  # noqa: E402
    BoundedMapitTransport,
    MeasurementBudgetExceeded,
    MeasurementCounters,
    MeasurementTimeExceeded,
    MAX_RESPONSE_BYTES,
    TIMEOUT_SECONDS,
    _error_category,
)
from scripts.probe_route_input_sufficiency import _local_store, _select_vehicle_id  # noqa: E402

MAX_CORE_WIRE_GETS = 2
MAX_GEO_WIRE_GETS = 6
MAX_GEO_LOGICAL_READS = 3
MAX_ROUTE_COUNT = 10_000
MAX_ROUTE_ID_BYTES = 256
MEASUREMENT_SECONDS = 180.0

VARIANTS = ("omitted", "false", "true")
ID_SET_CLASSES = frozenset({"same", "different", "unknown"})
CATEGORIES = frozenset({
    "success",
    "session_missing",
    "session_failed",
    "credential_store_failed",
    "account_summary_invalid",
    "account_summary_transport_failed",
    "account_summary_http_error",
    "account_summary_http_401",
    "account_summary_http_403",
    "account_summary_http_429",
    "account_summary_response_too_large",
    "routes_list_invalid",
    "routes_list_transport_failed",
    "routes_list_http_error",
    "routes_list_http_401",
    "routes_list_http_403",
    "routes_list_http_429",
    "routes_list_response_too_large",
    "pagination_unsupported",
    "budget_exceeded",
    "time_limit_exceeded",
    "measurement_failed",
})
COMPLETE_CLASSES = frozenset({"empty", "all_true", "all_false", "mixed", "unknown"})
OUTPUT_KEYS = frozenset({
    "success", "category", "core_logical_reads", "core_wire_gets", "geo_logical_reads",
    "geo_wire_gets", "window", "coverage", "complete_class", "false_has_valid_past_end_older_24h",
    "false_has_past_start_older_7d", "false_has_positive_native_distance", "false_has_inferred_feature",
    "false_has_starts_at_last_known", "omitted_vs_false_id_set", "omitted_vs_false_same_fact_signature",
    "omitted_vs_true_id_set", "omitted_vs_true_same_fact_signature",
})


class CompletionCounters(MeasurementCounters):
    """Monthly probe counters with the narrower three-variant wire budget."""

    def reserve_wire(self, kind: str) -> None:
        self.check_time()
        if kind == "core":
            if self.core_wire >= MAX_CORE_WIRE_GETS:
                raise MeasurementBudgetExceeded
            self.core_wire += 1
        elif kind == "geo":
            if self.geo_wire >= MAX_GEO_WIRE_GETS:
                raise MeasurementBudgetExceeded
            self.geo_wire += 1
        else:
            raise MeasurementBudgetExceeded

    def start_window(self) -> None:
        self.deadline = self.clock() + MEASUREMENT_SECONDS

    def remaining_seconds(self) -> float:
        self.check_time()
        return MEASUREMENT_SECONDS if self.deadline is None else max(0.001, self.deadline - self.clock())


class _PaginationFound(Exception):
    pass


class CompletionTransport(BoundedMapitTransport):
    """Same proxy-free, no-redirect, chunk-bounded transport with this probe's caps."""

    def __call__(self, method: str, url: str, headers: Mapping[str, str]) -> bytes:
        # The parent transport delegates reservation and deadline checks to
        # CompletionCounters, so its limits and chunk behavior remain shared.
        return super().__call__(method, url, headers)


@dataclass(frozen=True)
class _VariantEvidence:
    route_ids: frozenset[str]
    facts: Mapping[str, tuple[Any, ...]]
    complete_class: str
    false_end_older_24h: bool
    false_start_older_7d: bool
    false_positive_distance: bool
    false_inferred_feature: bool
    false_starts_at_last_known: bool


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    except (OverflowError, ValueError):
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _before_days(value: datetime, current: datetime, days: int) -> bool:
    try:
        return value < current - timedelta(days=days)
    except OverflowError:
        return False


def analyze_route_payload(payload: Any, now: datetime) -> _VariantEvidence:
    """Validate one route-list envelope and reduce its private values in memory."""
    if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), list):
        raise ValueError("routes envelope invalid")
    if "lastEvaluatedKey" in payload:
        raise _PaginationFound
    rows = payload["data"]
    if len(rows) > MAX_ROUTE_COUNT:
        raise OverflowError("route count")
    route_ids: set[str] = set()
    facts: dict[str, tuple[Any, ...]] = {}
    complete_values: list[bool] = []
    false_end_old = False
    false_start_old = False
    false_positive_distance = False
    false_inferred = False
    false_starts_last_known = False
    current = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("route entry invalid")
        route_id = row.get("id")
        if not isinstance(route_id, str) or not route_id.strip() or len(route_id.encode("utf-8")) > MAX_ROUTE_ID_BYTES:
            raise ValueError("route id invalid")
        if route_id in route_ids:
            raise ValueError("duplicate route id")
        route_ids.add(route_id)
        complete = row.get("complete")
        if isinstance(complete, bool):
            complete_values.append(complete)
        facts[route_id] = (route_id, row.get("startedAt"), row.get("endedAt"), row.get("distance"), complete)
        if complete is not False:
            continue
        ended = _parse_timestamp(row.get("endedAt"))
        started = _parse_timestamp(row.get("startedAt"))
        if started is not None and ended is not None and started <= ended and _before_days(ended, current, 1):
            false_end_old = True
        if started is not None and _before_days(started, current, 7):
            false_start_old = True
        distance = row.get("distance")
        if isinstance(distance, (int, float)) and not isinstance(distance, bool) and math.isfinite(float(distance)) and distance > 0:
            false_positive_distance = True
        geojson = row.get("geoJSON")
        features = geojson.get("features") if isinstance(geojson, Mapping) else None
        inferred = isinstance(features, list) and any(
            isinstance(feature, Mapping)
            and isinstance(feature.get("properties"), Mapping)
            and feature["properties"].get("inferred") is True
            for feature in features
        )
        false_inferred = false_inferred or inferred
        false_starts_last_known = false_starts_last_known or row.get("startsAtLastKnown") is True
    if not rows:
        complete_class = "empty"
    elif len(complete_values) != len(rows):
        complete_class = "unknown"
    elif all(complete_values):
        complete_class = "all_true"
    elif not any(complete_values):
        complete_class = "all_false"
    else:
        complete_class = "mixed"
    return _VariantEvidence(
        frozenset(route_ids), facts, complete_class, false_end_old, false_start_old,
        false_positive_distance, false_inferred, false_starts_last_known,
    )


def _id_comparison(left: _VariantEvidence | None, right: _VariantEvidence | None) -> str:
    if left is None or right is None:
        return "unknown"
    return "same" if left.route_ids == right.route_ids else "different"


def _signature_comparison(left: _VariantEvidence | None, right: _VariantEvidence | None) -> bool | None:
    if left is None or right is None:
        return None
    return left.facts == right.facts


def _blank_result() -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": False,
        "category": "measurement_failed",
        "core_logical_reads": 0,
        "core_wire_gets": 0,
        "geo_logical_reads": 0,
        "geo_wire_gets": 0,
        "window": "current_utc_month",
        "coverage": "UNKNOWN",
        "complete_class": {name: "unknown" for name in VARIANTS},
        "false_has_valid_past_end_older_24h": None,
        "false_has_past_start_older_7d": None,
        "false_has_positive_native_distance": None,
        "false_has_inferred_feature": None,
        "false_has_starts_at_last_known": None,
        "omitted_vs_false_id_set": "unknown",
        "omitted_vs_false_same_fact_signature": None,
        "omitted_vs_true_id_set": "unknown",
        "omitted_vs_true_same_fact_signature": None,
    }
    assert frozenset(result) == OUTPUT_KEYS
    return result


def perform_route_completion_probe(
    *,
    store: Any | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[..., Any] | None = None,
    now: datetime | None = None,
    perf_counter: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Fetch one account summary and three identical-window route variants."""
    result = _blank_result()
    counters = CompletionCounters(clock=perf_counter)
    evidence: dict[str, _VariantEvidence] = {}
    context: ManagedSession | None = None
    client: Any = None
    try:
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            result["category"] = "credential_store_failed"
            return result
        try:
            manager = manager_factory(store=selected_store)
            context = manager.login_saved()
        except SessionManagerError as exc:
            result["category"] = _safe_error("session", exc)
            return result
        except Exception:
            result["category"] = "session_failed"
            return result
        if context is None:
            category = getattr(manager, "last_error_category", None)
            result["category"] = "credential_store_failed" if category == "credential_store_failed" else "session_missing" if category is None else "session_failed"
            return result
        if not isinstance(context, ManagedSession):
            result["category"] = "session_failed"
            return result
        counters.start_window()
        if client_factory is None:
            transport = CompletionTransport(context.config, counters)
            client = MapitClient(context.config, context.session, transport=transport)
        else:
            try:
                parameters = inspect.signature(client_factory).parameters.values()
                accepts_counters = any(parameter.kind is inspect.Parameter.VAR_POSITIONAL for parameter in parameters) or sum(
                    parameter.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
                    for parameter in parameters
                ) >= 3
            except (TypeError, ValueError):
                accepts_counters = False
            client = client_factory(context.config, context.session, counters) if accepts_counters else client_factory(context.config, context.session)
        instrumented_transport = isinstance(getattr(client, "transport", None), BoundedMapitTransport)

        if not instrumented_transport:
            counters.reserve_wire("core")
        counters.core_logical += 1
        try:
            summary = client.get_core("/v1/account-summary", max_response_bytes=MAX_RESPONSE_BYTES)
        except Exception as exc:
            result["category"] = _safe_error("account_summary", exc)
            return result
        counters.check_time()
        vehicle_id = _select_vehicle_id(summary)
        if vehicle_id is None:
            result["category"] = "account_summary_invalid"
            return result

        current = now.replace(tzinfo=timezone.utc) if now is not None and now.tzinfo is None else (now.astimezone(timezone.utc) if now is not None else datetime.now(timezone.utc))
        window_start = datetime(current.year, current.month, 1, tzinfo=timezone.utc)
        if current.month == 12:
            window_end = datetime(current.year + 1, 1, 1, tzinfo=timezone.utc)
        else:
            window_end = datetime(current.year, current.month + 1, 1, tzinfo=timezone.utc)
        params: dict[str, Any] = {
            "vehicleId": vehicle_id,
            "from": window_start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "to": window_end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
        for name in VARIANTS:
            counters.check_time()
            if counters.geo_logical >= MAX_GEO_LOGICAL_READS:
                raise MeasurementBudgetExceeded
            variant_params = dict(params)
            if name == "false":
                variant_params["includeInProgress"] = "false"
            elif name == "true":
                variant_params["includeInProgress"] = "true"
            if not instrumented_transport:
                counters.reserve_wire("geo")
            counters.geo_logical += 1
            try:
                payload = client.get_geo("/v1/routes", params=variant_params, max_response_bytes=MAX_RESPONSE_BYTES)
                variant_evidence = analyze_route_payload(payload, current)
            except _PaginationFound:
                result["category"] = "pagination_unsupported"
                return result
            except OverflowError:
                result["category"] = "routes_list_invalid"
                return result
            except Exception as exc:
                result["category"] = _safe_error("routes_list", exc)
                return result
            evidence[name] = variant_evidence
            counters.check_time()

        result["success"] = True
        result["category"] = "success"
        result["coverage"] = "PARTIAL"
        result["complete_class"] = {name: evidence[name].complete_class for name in VARIANTS}
        false_evidence = evidence["false"]
        result["false_has_valid_past_end_older_24h"] = false_evidence.false_end_older_24h
        result["false_has_past_start_older_7d"] = false_evidence.false_start_older_7d
        result["false_has_positive_native_distance"] = false_evidence.false_positive_distance
        result["false_has_inferred_feature"] = false_evidence.false_inferred_feature
        result["false_has_starts_at_last_known"] = false_evidence.false_starts_at_last_known
        omitted, false = evidence["omitted"], evidence["false"]
        omitted_true, true = evidence["omitted"], evidence["true"]
        result["omitted_vs_false_id_set"] = _id_comparison(omitted, false)
        result["omitted_vs_false_same_fact_signature"] = _signature_comparison(omitted, false)
        result["omitted_vs_true_id_set"] = _id_comparison(omitted_true, true)
        result["omitted_vs_true_same_fact_signature"] = _signature_comparison(omitted_true, true)
    except MeasurementBudgetExceeded:
        result["category"] = "budget_exceeded"
    except MeasurementTimeExceeded:
        result["category"] = "time_limit_exceeded"
    except SessionManagerError as exc:
        result["category"] = _safe_error("session", exc)
    except Exception:
        result["category"] = "measurement_failed"
    finally:
        result["core_logical_reads"] = min(counters.core_logical, 1)
        result["core_wire_gets"] = min(counters.core_wire, MAX_CORE_WIRE_GETS)
        result["geo_logical_reads"] = min(counters.geo_logical, MAX_GEO_LOGICAL_READS)
        result["geo_wire_gets"] = min(counters.geo_wire, MAX_GEO_WIRE_GETS)
        context = None
        client = None
        evidence.clear()
    return result


def _safe_error(stage: str, exc: Exception) -> str:
    if isinstance(exc, MeasurementTimeExceeded):
        return "time_limit_exceeded"
    if isinstance(exc, MeasurementBudgetExceeded):
        return "budget_exceeded"
    if isinstance(exc, SessionManagerError):
        return "credential_store_failed" if exc.category == "credential_store_failed" else "session_failed"
    if isinstance(exc, (SessionRefreshError, CognitoHTTPError, UnsupportedCognitoChallenge)):
        return "session_failed"
    if isinstance(exc, MapitHTTPError) and exc.status in (401, 403, 429):
        return f"{stage}_http_{exc.status}"
    if isinstance(exc, (MapitHTTPError,)):
        return f"{stage}_http_error"
    if isinstance(exc, MapitResponseTooLarge):
        return f"{stage}_response_too_large"
    if isinstance(exc, (MapitTransportError, OSError, TimeoutError)):
        return f"{stage}_transport_failed"
    if isinstance(exc, (MapitResponseError, ValueError)):
        return f"{stage}_invalid"
    # Reuse known safe mappings for shared HTTP/client exception classes.
    try:
        shared = _error_category(stage, exc)
    except Exception:
        shared = "measurement_failed"
    return shared if shared in CATEGORIES else "measurement_failed"


def main() -> int:
    import json

    result = perform_route_completion_probe()
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0 if result["success"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
