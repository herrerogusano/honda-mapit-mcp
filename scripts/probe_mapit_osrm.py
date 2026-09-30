"""Bounded MAPIT route-to-local-OSRM probe.

This is a live-capable, non-interactive probe, but it is intentionally tested
only with injected session/client/transport doubles.  It performs the same
three read-only MAPIT reads as the route-input sufficiency probe, keeps one
LineString in memory without sampling, and emits only the fixed OSRM result.
"""

from __future__ import annotations

import json
import math
import sys
import urllib.error
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode
from urllib.request import Request

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
from mapit.config import MapitConfig  # noqa: E402
from mapit.osrm import (  # noqa: E402
    MAX_JSON_BYTES,
    OSRMAnalysisError,
    classify_match_json,
    classify_match_response,
    safe_osrm_result,
    validate_payload_budget,
)
from mapit.session import (  # noqa: E402
    ManagedSession,
    SessionManager,
    SessionManagerError,
)
from scripts.probe_local_osrm_fixture import (  # noqa: E402
    _NO_REDIRECT_OPENER,
    _ProbeError,
    _loopback_base_url,
)
from scripts.probe_route_input_sufficiency import (  # noqa: E402
    _local_store,
    _select_route_id,
    _select_vehicle_id,
)

DEFAULT_OSRM_URL = "http://127.0.0.1:5000"
MAX_SUMMARY_LIST_BYTES = 2 * 1024 * 1024
MAX_DETAIL_BYTES = 1 * 1024 * 1024
MAX_COORDINATES = 500
MAX_OSRM_URL_BYTES = 16 * 1024
OSRM_TIMEOUT_SECONDS = 5.0
# Fixed public geography guard; it is deliberately not derived from a route.
BARCELONA_BBOX = (1.8, 41.2, 2.45, 41.65)  # min_lon, min_lat, max_lon, max_lat

Transport = Callable[[str, str, float], Any]
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
    "stage_category",
})

STAGE_CATEGORIES = frozenset(
    {
        "success",
        "session_missing",
        "session_failed",
        "credential_store_failed",
        "authentication_failed",
        "discovery_failed",
        "account_summary_invalid",
        "account_summary_too_large",
        "routes_list_invalid",
        "routes_list_too_large",
        "route_detail_invalid",
        "route_detail_too_large",
        "outside_bbox",
        "matcher_invalid",
        "matcher_no_match",
        "matcher_resource_limit",
        "matcher_unavailable",
    }
)


def _result(category: str, stage_category: str) -> dict[str, Any]:
    result = safe_osrm_result(category)
    result["stage_category"] = stage_category if stage_category in STAGE_CATEGORIES else "matcher_unavailable"
    return result


def _matcher_result(result: dict[str, Any]) -> dict[str, Any]:
    category = result.get("category")
    stage = {
        "matched": "success",
        "no_match": "matcher_no_match",
        "resource_limit": "matcher_resource_limit",
        "partial": "success",
        "invalid_input": "matcher_invalid",
    }.get(category, "matcher_unavailable")
    result = dict(result)
    result["stage_category"] = stage
    return result


def _local_osrm_transport(method: str, url: str, timeout: float) -> bytes:
    """Read one bounded response through the proxy-free, no-redirect opener."""
    request = Request(url, method=method, headers={"Accept": "application/json"})
    try:
        with _NO_REDIRECT_OPENER.open(request, timeout=timeout) as response:  # noqa: S310 - URL is loopback-validated.
            status = response.getcode()
            if status is not None and 300 <= status < 400:
                raise _ProbeError("engine_unavailable")
            raw = response.read(MAX_JSON_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            if exc.code != 400:
                raise _ProbeError("engine_unavailable") from None
            raw = exc.read(MAX_JSON_BYTES + 1)
        finally:
            exc.close()
    if len(raw) > MAX_JSON_BYTES:
        raise _ProbeError("resource_limit")
    return raw


def _finite_coordinate(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


class _OutsideBBoxError(ValueError):
    """A coordinate is structurally valid but outside the fixed public guard."""


def _line_string_coordinates(detail: Any) -> list[tuple[float, float]]:
    """Select the first structural GeoJSON LineString without sampling it."""
    if not isinstance(detail, dict):
        raise ValueError("invalid detail")
    geo = detail.get("geoJSON")
    if not isinstance(geo, dict):
        raise ValueError("invalid detail")
    geo_type = geo.get("type")
    if not isinstance(geo_type, str):
        raise ValueError("invalid detail")

    candidates: list[dict[str, Any]] = []
    if geo_type == "FeatureCollection":
        features = geo.get("features")
        if not isinstance(features, list):
            raise ValueError("invalid detail")
        for feature in features:
            if not isinstance(feature, dict) or feature.get("type") != "Feature":
                raise ValueError("invalid detail")
            geometry = feature.get("geometry")
            if isinstance(geometry, dict) and geometry.get("type") == "LineString":
                candidates.append(geometry)
    elif geo_type == "Feature":
        geometry = geo.get("geometry")
        if isinstance(geometry, dict) and geometry.get("type") == "LineString":
            candidates.append(geometry)
    elif geo_type == "LineString":
        candidates.append(geo)
    else:
        raise ValueError("unsupported detail geometry")
    if not candidates:
        raise ValueError("missing linestring")

    coordinates = candidates[0].get("coordinates")
    if not isinstance(coordinates, list) or len(coordinates) < 2:
        raise ValueError("invalid linestring")
    if len(coordinates) > MAX_COORDINATES:
        raise _ProbeError("resource_limit")
    normalized: list[tuple[float, float]] = []
    min_lon, min_lat, max_lon, max_lat = BARCELONA_BBOX
    for coordinate in coordinates:
        if not isinstance(coordinate, list) or len(coordinate) not in (2, 3):
            raise ValueError("invalid coordinate shape")
        # The third ordinate is intentionally discarded and never interpreted.
        lon, lat = coordinate[0], coordinate[1]
        if not _finite_coordinate(lon) or not _finite_coordinate(lat):
            raise ValueError("invalid coordinate")
        lon_float, lat_float = float(lon), float(lat)
        if not (
            min_lon <= lon_float <= max_lon
            and min_lat <= lat_float <= max_lat
        ):
            raise _OutsideBBoxError("coordinate outside fixed bbox")
        normalized.append((lon_float, lat_float))
    return normalized


def _coordinate_path(points: list[tuple[float, float]]) -> str:
    return ";".join(f"{lon:.7f},{lat:.7f}" for lon, lat in points)


def _match_local_osrm(
    points: list[tuple[float, float]],
    *,
    base_url: str,
    transport: Transport,
) -> dict[str, Any]:
    base = _loopback_base_url(base_url)
    path = quote(_coordinate_path(points), safe=",;.-")
    query = urlencode({"overview": "false", "steps": "true", "annotations": "true", "tidy": "false"})
    url = f"{base}/match/v1/driving/{path}?{query}"
    if len(url.encode("utf-8")) > MAX_OSRM_URL_BYTES:
        raise _ProbeError("resource_limit")
    payload = transport("GET", url, OSRM_TIMEOUT_SECONDS)
    if isinstance(payload, (bytes, str)):
        return classify_match_json(payload)
    return classify_match_response(payload)


def perform_mapit_osrm_probe(
    *,
    store: Any | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[[MapitConfig, Any], Any] = MapitClient,
    osrm_transport: Transport | None = None,
    osrm_base_url: str = DEFAULT_OSRM_URL,
) -> dict[str, Any]:
    """Perform exactly three bounded MAPIT reads, then one local OSRM Match."""
    summary_payload: Any = None
    routes_payload: Any = None
    detail_payload: Any = None
    vehicle_id: str | None = None
    route_id: str | None = None
    context: ManagedSession | None = None
    client: Any = None
    stage = "session"
    try:
        # Validate before login so a bad local matcher endpoint cannot trigger MAPIT reads.
        try:
            _loopback_base_url(osrm_base_url)
        except (TypeError, ValueError):
            return _result("invalid_input", "matcher_invalid")
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            return _result("engine_unavailable", "credential_store_failed")
        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if not isinstance(context, ManagedSession):
            return _result("engine_unavailable", "session_missing")
        client = client_factory(context.config, context.session)

        stage = "account"
        summary_payload = client.get_core("/v1/account-summary", max_response_bytes=MAX_SUMMARY_LIST_BYTES)
        vehicle_id = _select_vehicle_id(summary_payload)
        summary_payload = None
        if vehicle_id is None:
            return _result("invalid_input", "account_summary_invalid")

        stage = "list"
        routes_payload = client.get_geo(
            "/v1/routes",
            params={"vehicleId": vehicle_id, "limit": 1},
            max_response_bytes=MAX_SUMMARY_LIST_BYTES,
        )
        route_id = _select_route_id(routes_payload)
        routes_payload = None
        if route_id is None:
            return _result("invalid_input", "routes_list_invalid")

        stage = "detail"
        detail_payload = client.get_geo(
            f"/v1/vehicles/{quote(vehicle_id, safe='')}/routes/{quote(route_id, safe='')}",
            params={"includeStats": "true"},
            max_response_bytes=MAX_DETAIL_BYTES,
        )
        try:
            validate_payload_budget(detail_payload)
        except OSRMAnalysisError as exc:
            raise _ProbeError(exc.category) from None
        points = _line_string_coordinates(detail_payload)
        detail_payload = None
        stage = "matcher"
        result = _match_local_osrm(points, base_url=osrm_base_url, transport=osrm_transport or _local_osrm_transport)
        return _matcher_result(result)
    except _ProbeError as exc:
        if stage == "detail":
            return _result(exc.category, "route_detail_too_large" if exc.category == "resource_limit" else "route_detail_invalid")
        return _result(exc.category, "matcher_resource_limit" if exc.category == "resource_limit" else "matcher_unavailable")
    except MapitResponseTooLarge:
        stage_category = {
            "account": "account_summary_too_large",
            "list": "routes_list_too_large",
            "detail": "route_detail_too_large",
            "matcher": "matcher_resource_limit",
        }.get(stage, "matcher_resource_limit")
        return _result("resource_limit", stage_category)
    except MapitResponseError:
        stage_category = {"account": "account_summary_invalid", "list": "routes_list_invalid", "detail": "route_detail_invalid"}.get(stage, "matcher_invalid")
        return _result("invalid_input", stage_category)
    except (MapitHTTPError, MapitTransportError, OSError, TimeoutError):
        return _result("engine_unavailable", "matcher_unavailable" if stage == "matcher" else "session_failed")
    except SessionManagerError:
        return _result("engine_unavailable", "session_failed")
    except _OutsideBBoxError:
        return _result("invalid_input", "outside_bbox")
    except (TypeError, ValueError, KeyError, IndexError):
        stage_category = {"account": "account_summary_invalid", "list": "routes_list_invalid", "detail": "route_detail_invalid"}.get(stage, "matcher_invalid")
        return _result("invalid_input", stage_category)
    except Exception:
        return _result("engine_unavailable", "matcher_unavailable" if stage == "matcher" else "session_failed")
    finally:
        summary_payload = None
        routes_payload = None
        detail_payload = None
        vehicle_id = None
        route_id = None
        context = None
        client = None


def main() -> int:
    result = perform_mapit_osrm_probe()
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0 if result["category"] == "matched" else 1


if __name__ == "__main__":
    raise SystemExit(main())
