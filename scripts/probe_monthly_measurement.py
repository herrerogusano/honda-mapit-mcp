"""Bounded monthly-read measurement harness.

The default path is live-capable but intentionally not executed by this
project's tests.  Tests inject session/client/transport doubles and retain
only coarse operational metadata; route values and identifiers are ephemeral.
"""

from __future__ import annotations

import inspect
import json
import math
import sys
import time
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.client import (  # noqa: E402
    MapitClient,
    MapitHTTPError,
    MapitResponseError,
    MapitResponseTooLarge,
    MapitTransportError,
)
from mapit.auth import CognitoHTTPError, SessionRefreshError, UnsupportedCognitoChallenge  # noqa: E402
from mapit.config import MapitConfig  # noqa: E402
from mapit.session import ManagedSession, SessionManager, SessionManagerError  # noqa: E402
from scripts.probe_route_input_sufficiency import _local_store, _select_vehicle_id  # noqa: E402

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_CORE_WIRE_GETS = 2
MAX_GEO_WIRE_GETS = 12
MAX_GEO_LOGICAL_READS = 6
MONTHLY_REPETITIONS = 5
MAX_ROUTE_ID_CHARS = 256
REFERENCE_REPEATED_QUERIES = 10
REFERENCE_BASELINE_WIRE_GETS = 20
TIMEOUT_SECONDS = 20.0
MEASUREMENT_SECONDS = 180.0

LATENCY_BUCKETS = frozenset({"<1", "1-5", "5-15", ">=15", "unknown"})
SIZE_BUCKETS = frozenset({"<64KiB", "64-256KiB", "256KiB-1MiB", "1-2MiB", ">2MiB", "unknown"})
CONTROL_CLASSES = frozenset({"overlap", "disjoint", "empty", "unknown"})
COVERAGE_CLASSES = frozenset({"PARTIAL", "UNKNOWN"})
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
    "budget_exceeded",
    "measurement_failed",
    "time_limit_exceeded",
})
OUTPUT_KEYS = frozenset({
    "success",
    "category",
    "operation_class",
    "repetitions",
    "successful_repetitions",
    "core_logical_reads",
    "core_wire_gets",
    "geo_logical_reads",
    "geo_wire_gets",
    "latency_p50_bucket",
    "latency_p95_bucket",
    "response_size_bucket",
    "error_categories",
    "monthly_control_class",
    "pagination_metadata_observed",
    "coverage_class",
})


class MeasurementBudgetExceeded(RuntimeError):
    """A wire-read cap was reached before an additional request was sent."""


class MeasurementTimeExceeded(RuntimeError):
    """The bounded measurement window expired before another request."""


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, newurl, code=None, msg=None, headers=None):  # type: ignore[override]
        return None


_NO_PROXY_HANDLER = ProxyHandler({})
_NO_REDIRECT_OPENER = build_opener(_NO_PROXY_HANDLER, _NoRedirectHandler)


class MeasurementCounters:
    """In-memory counters shared by the logical runner and wire transport."""

    def __init__(self, *, clock: Callable[[], float] = time.perf_counter) -> None:
        self.core_logical = 0
        self.geo_logical = 0
        self.core_wire = 0
        self.geo_wire = 0
        self.response_sizes: list[int] = []
        self.clock = clock
        self.deadline: float | None = None

    def start_window(self) -> None:
        self.deadline = self.clock() + MEASUREMENT_SECONDS

    def check_time(self) -> None:
        if self.deadline is not None and self.clock() >= self.deadline:
            raise MeasurementTimeExceeded

    def remaining_seconds(self) -> float:
        self.check_time()
        return MEASUREMENT_SECONDS if self.deadline is None else max(0.001, self.deadline - self.clock())

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


class BoundedMapitTransport:
    """Proxy-free/no-redirect bounded transport for an instrumented MapitClient."""

    def __init__(self, config: MapitConfig, counters: MeasurementCounters) -> None:
        self.config = config
        self.counters = counters
        self._core_host = config.core_api_url.split("//", 1)[-1].split("/", 1)[0].lower()
        self._geo_host = config.geo_api_url.split("//", 1)[-1].split("/", 1)[0].lower()

    def __call__(self, method: str, url: str, headers: Mapping[str, str]) -> bytes:
        if method != "GET":
            raise MapitTransportError()
        host = url.split("//", 1)[-1].split("/", 1)[0].lower()
        kind = "core" if host == self._core_host else "geo" if host == self._geo_host else "unknown"
        self.counters.reserve_wire(kind)
        request = Request(url, method=method, headers=dict(headers))
        try:
            timeout = min(TIMEOUT_SECONDS, self.config.http_timeout, self.counters.remaining_seconds())
            with _NO_REDIRECT_OPENER.open(request, timeout=timeout) as response:  # noqa: S310 - host is MapitClient-allowlisted.
                read_chunk = getattr(response, "read1", None)
                if not callable(read_chunk):
                    read_chunk = response.read
                chunks: list[bytes] = []
                total = 0
                while total <= MAX_RESPONSE_BYTES:
                    self.counters.check_time()
                    chunk = read_chunk(min(64 * 1024, MAX_RESPONSE_BYTES + 1 - total))
                    self.counters.check_time()
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                raw = b"".join(chunks)
        except urllib.error.HTTPError:
            raise
        if kind == "geo":
            self.counters.response_sizes.append(len(raw))
        if len(raw) > MAX_RESPONSE_BYTES:
            raise MapitResponseTooLarge()
        return raw


def _empty(category: str = "measurement_failed", *, success: bool = False) -> dict[str, Any]:
    return {
        "success": success,
        "category": category if category in CATEGORIES else "measurement_failed",
        "operation_class": "monthly_measurement",
        "repetitions": MONTHLY_REPETITIONS,
        "successful_repetitions": 0,
        "core_logical_reads": 0,
        "core_wire_gets": 0,
        "geo_logical_reads": 0,
        "geo_wire_gets": 0,
        "latency_p50_bucket": "unknown",
        "latency_p95_bucket": "unknown",
        "response_size_bucket": "unknown",
        "error_categories": [],
        "monthly_control_class": "unknown",
        "pagination_metadata_observed": False,
        "coverage_class": "UNKNOWN",
    }


def _latency_bucket(seconds: float) -> str:
    if seconds < 1:
        return "<1"
    if seconds < 5:
        return "1-5"
    if seconds < 15:
        return "5-15"
    return ">=15"


def _size_bucket(size: int) -> str:
    if size > MAX_RESPONSE_BYTES:
        return ">2MiB"
    if size < 64 * 1024:
        return "<64KiB"
    if size < 256 * 1024:
        return "64-256KiB"
    if size < 1024 * 1024:
        return "256KiB-1MiB"
    return "1-2MiB"


def _month_bounds(now: datetime) -> tuple[datetime, datetime, datetime, datetime]:
    current = now.replace(tzinfo=timezone.utc) if now.tzinfo is None else now.astimezone(timezone.utc)
    start = datetime(current.year, current.month, 1, tzinfo=timezone.utc)
    if current.month == 12:
        next_start = datetime(current.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        next_start = datetime(current.year, current.month + 1, 1, tzinfo=timezone.utc)
    if current.month == 1:
        previous_start = datetime(current.year - 1, 12, 1, tzinfo=timezone.utc)
    else:
        previous_start = datetime(current.year, current.month - 1, 1, tzinfo=timezone.utc)
    return start, next_start, previous_start, start


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _route_ids_and_pagination(payload: Any) -> tuple[set[str], bool]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("invalid route-list envelope")
    ids: set[str] = set()
    for route in payload["data"]:
        if not isinstance(route, dict):
            raise ValueError("invalid route entry")
        route_id = route.get("id")
        if not isinstance(route_id, str) or len(route_id) > MAX_ROUTE_ID_CHARS or not route_id.strip():
            raise ValueError("invalid route identifier")
        ids.add(route_id.strip())
    return ids, "lastEvaluatedKey" in payload


def _control_class(repetitions: list[set[str]], adjacent: set[str]) -> str:
    if not repetitions or any(not values for values in repetitions) or not adjacent:
        return "empty"
    current = set().union(*repetitions)
    if current & adjacent:
        return "overlap"
    return "disjoint"


def perform_monthly_measurement(
    *,
    store: Any | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[..., Any] | None = None,
    now: datetime | None = None,
    perf_counter: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Run the fixed five-plus-one monthly read sample without persistence."""
    result = _empty()
    counters = MeasurementCounters(clock=perf_counter)
    monthly_latencies: list[float] = []
    monthly_sizes: list[int] = []
    errors: list[str] = []
    current_sets: list[set[str]] = []
    adjacent_ids: set[str] = set()
    context: ManagedSession | None = None
    client: Any = None
    vehicle_id: str | None = None
    try:
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            result["category"] = "credential_store_failed"
            return result
        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if context is None:
            last_error_category = getattr(manager, "last_error_category", None)
            if last_error_category is None:
                result["category"] = "session_missing"
            elif last_error_category == "credential_store_failed":
                result["category"] = "credential_store_failed"
            elif last_error_category in {"discovery_failed", "authentication_failed", "authentication_rejected"}:
                result["category"] = "session_failed"
            else:
                result["category"] = "session_failed"
            return result
        if not isinstance(context, ManagedSession):
            result["category"] = "session_failed"
            return result
        # Secure saved-session preparation is outside the measurement window.
        counters.start_window()
        if client_factory is None:
            transport = BoundedMapitTransport(context.config, counters)
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
        except (MeasurementBudgetExceeded, MeasurementTimeExceeded):
            raise
        except Exception as exc:
            errors.append(_error_category("account_summary", exc))
            result["category"] = errors[-1]
            return result
        counters.check_time()
        vehicle_id = _select_vehicle_id(summary)
        if vehicle_id is None:
            result["category"] = "account_summary_invalid"
            return result

        current_start, current_end, previous_start, previous_end = _month_bounds(now or datetime.now(timezone.utc))
        current_params = {"vehicleId": vehicle_id, "from": _iso(current_start), "to": _iso(current_end)}
        adjacent_params = {"vehicleId": vehicle_id, "from": _iso(previous_start), "to": _iso(previous_end)}
        for repetition in range(MONTHLY_REPETITIONS + 1):
            counters.check_time()
            if counters.geo_logical >= MAX_GEO_LOGICAL_READS:
                raise MeasurementBudgetExceeded
            if not instrumented_transport:
                counters.reserve_wire("geo")
            counters.geo_logical += 1
            params = current_params if repetition < MONTHLY_REPETITIONS else adjacent_params
            size_start = len(counters.response_sizes)
            started = perf_counter()
            try:
                payload = client.get_geo("/v1/routes", params=params, max_response_bytes=MAX_RESPONSE_BYTES)
                ids, observed_pagination = _route_ids_and_pagination(payload)
            except (MeasurementBudgetExceeded, MeasurementTimeExceeded):
                raise
            except Exception as exc:
                errors.append(_error_category("routes_list", exc))
                result["category"] = errors[-1]
                if repetition < MONTHLY_REPETITIONS:
                    monthly_latencies.append(max(0.0, perf_counter() - started))
                    monthly_sizes.extend(counters.response_sizes[size_start:])
                return result
            result["pagination_metadata_observed"] = bool(result["pagination_metadata_observed"] or observed_pagination)
            if repetition < MONTHLY_REPETITIONS:
                monthly_latencies.append(max(0.0, perf_counter() - started))
                monthly_sizes.extend(counters.response_sizes[size_start:])
                current_sets.append(ids)
                result["successful_repetitions"] += 1
            else:
                adjacent_ids = ids
            counters.check_time()

        result["success"] = True
        result["category"] = "success"
        result["monthly_control_class"] = _control_class(current_sets, adjacent_ids)
        result["coverage_class"] = "PARTIAL"
    except MeasurementBudgetExceeded:
        result["category"] = "budget_exceeded"
        errors.append("budget_exceeded")
    except MeasurementTimeExceeded:
        result["category"] = "time_limit_exceeded"
        errors.append("time_limit_exceeded")
    except SessionManagerError:
        result["category"] = "session_failed"
    except Exception:
        result["category"] = "measurement_failed"
    finally:
        result["core_logical_reads"] = min(counters.core_logical, 1)
        result["core_wire_gets"] = min(counters.core_wire, MAX_CORE_WIRE_GETS)
        result["geo_logical_reads"] = min(counters.geo_logical, MAX_GEO_LOGICAL_READS)
        result["geo_wire_gets"] = min(counters.geo_wire, MAX_GEO_WIRE_GETS)
        if monthly_latencies:
            ordered = sorted(monthly_latencies)
            result["latency_p50_bucket"] = _latency_bucket(ordered[(len(ordered) - 1) // 2])
            result["latency_p95_bucket"] = _latency_bucket(ordered[min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)])
        if monthly_sizes:
            result["response_size_bucket"] = _size_bucket(max(monthly_sizes))
        result["error_categories"] = sorted({error for error in errors if error in CATEGORIES})
        context = None
        client = None
        vehicle_id = None
        current_sets.clear()
        adjacent_ids.clear()
        monthly_sizes.clear()
        monthly_latencies.clear()
    return result


def _error_category(stage: str, exc: Exception) -> str:
    if isinstance(exc, MeasurementTimeExceeded):
        return "time_limit_exceeded"
    if isinstance(exc, MeasurementBudgetExceeded):
        return "budget_exceeded"
    if isinstance(exc, SessionManagerError):
        return "credential_store_failed" if exc.category == "credential_store_failed" else "session_failed"
    if isinstance(exc, (SessionRefreshError, CognitoHTTPError, UnsupportedCognitoChallenge)):
        return "session_failed"
    if isinstance(exc, MapitResponseTooLarge):
        return f"{stage}_response_too_large"
    if isinstance(exc, MapitHTTPError):
        if exc.status in (401, 403, 429):
            return f"{stage}_http_{exc.status}"
        return f"{stage}_http_error"
    if isinstance(exc, (MapitTransportError, OSError, TimeoutError)):
        return f"{stage}_transport_failed"
    if isinstance(exc, MapitResponseError):
        return f"{stage}_invalid"
    return f"{stage}_invalid"


def main() -> int:
    result = perform_monthly_measurement()
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0 if result["success"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
