"""Bounded, non-interactive route-input sufficiency probe.

The script performs one saved-session account lookup, one limited route-list
lookup, and one current vehicle-scoped detail lookup.  Detail is analyzed only
in memory and the fixed redacted analyzer result is the only output.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
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
from mapit.route_input_analyzer import RouteInputAnalysisError, analyze_route_input, safe_analyze_route_input  # noqa: E402
from mapit.session import (  # noqa: E402
    ManagedSession,
    SessionManager,
    SessionManagerError,
    WindowsKeyringRefreshTokenStore,
)

SAFE_CATEGORIES = frozenset(
    {
        "success",
        "session_missing",
        "session_failed",
        "credential_store_failed",
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "account_summary_missing_vehicle",
        "routes_list_missing_route",
        "account_summary_transport_failed",
        "routes_list_transport_failed",
        "route_detail_transport_failed",
        "account_summary_invalid_response",
        "routes_list_invalid_response",
        "route_detail_invalid_response",
        "account_summary_response_too_large",
        "routes_list_response_too_large",
        "route_detail_response_too_large",
        "account_summary_http_error",
        "account_summary_http_400",
        "account_summary_http_401",
        "account_summary_http_403",
        "account_summary_http_404",
        "account_summary_http_429",
        "routes_list_http_error",
        "routes_list_http_400",
        "routes_list_http_401",
        "routes_list_http_403",
        "routes_list_http_404",
        "routes_list_http_429",
        "route_detail_http_error",
        "route_detail_http_400",
        "route_detail_http_401",
        "route_detail_http_403",
        "route_detail_http_404",
        "route_detail_http_429",
        "route_input_invalid_structure",
        "route_input_oversized",
        "route_input_unsupported_geometry",
    }
)
MAX_ACCOUNT_AND_LIST_BYTES = 2 * 1024 * 1024
MAX_DETAIL_BYTES = 1024 * 1024
MAX_ID_CHARS = 256


def _failure(category: str) -> dict[str, Any]:
    result = safe_analyze_route_input(None)
    result["success"] = False
    result["category"] = category if category in SAFE_CATEGORIES else "session_failed"
    return result


def _select_vehicle_id(summary: Any) -> str | None:
    if not isinstance(summary, dict) or not isinstance(summary.get("vehicles"), list):
        return None
    fallback: str | None = None
    for vehicle in summary["vehicles"]:
        if not isinstance(vehicle, dict):
            continue
        vehicle_id = vehicle.get("id")
        if not isinstance(vehicle_id, str):
            continue
        vehicle_id = vehicle_id.strip()
        if not vehicle_id or len(vehicle_id) > MAX_ID_CHARS:
            continue
        if fallback is None:
            fallback = vehicle_id
        if vehicle.get("device") is not None:
            return vehicle_id
    return fallback


def _select_route_id(routes: Any) -> str | None:
    if not isinstance(routes, dict) or not isinstance(routes.get("data"), list):
        return None
    for route in routes["data"]:
        if isinstance(route, dict) and isinstance(route.get("id"), str):
            route_id = route["id"].strip()
            if route_id and len(route_id) <= MAX_ID_CHARS:
                return route_id
    return None


def _local_store() -> Any | None:
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def _stage_prefix(stage: str) -> str:
    return {"account": "account_summary", "list": "routes_list", "detail": "route_detail"}.get(stage, "route_detail")


def _http_category(stage: str, status: Any) -> str:
    prefix = _stage_prefix(stage)
    if isinstance(status, int) and not isinstance(status, bool):
        if status in {400, 401, 403, 404, 429}:
            return f"{prefix}_http_{status}"
        if 500 <= status <= 599:
            return f"{prefix}_http_error"
    return f"{prefix}_http_error"


def _request_category(stage: str, kind: str) -> str:
    return f"{_stage_prefix(stage)}_{kind}"


def perform_route_input_sufficiency_probe(
    *,
    store: Any | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[[MapitConfig, Any], Any] = MapitClient,
) -> dict[str, Any]:
    """Run the three logical reads and return fixed, value-free metadata."""
    stage = "session"
    summary_payload: Any = None
    routes_payload: Any = None
    detail_payload: Any = None
    vehicle_id: str | None = None
    route_id: str | None = None
    context: ManagedSession | None = None
    client: Any = None
    try:
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            return _failure("credential_store_failed")
        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if context is None:
            category = getattr(manager, "last_error_category", None)
            return _failure(category if isinstance(category, str) and category in SAFE_CATEGORIES else "session_missing")
        if not isinstance(context, ManagedSession):
            return _failure("session_failed")
        client = client_factory(context.config, context.session)

        stage = "account"
        summary_payload = client.get_core(
            "/v1/account-summary",
            max_response_bytes=MAX_ACCOUNT_AND_LIST_BYTES,
        )
        vehicle_id = _select_vehicle_id(summary_payload)
        summary_payload = None
        if vehicle_id is None:
            return _failure("account_summary_missing_vehicle")

        stage = "list"
        routes_payload = client.get_geo(
            "/v1/routes",
            params={"vehicleId": vehicle_id, "limit": 1},
            max_response_bytes=MAX_ACCOUNT_AND_LIST_BYTES,
        )
        route_id = _select_route_id(routes_payload)
        routes_payload = None
        if route_id is None:
            return _failure("routes_list_missing_route")

        stage = "detail"
        detail_payload = client.get_geo(
            f"/v1/vehicles/{quote(vehicle_id, safe='')}/routes/{quote(route_id, safe='')}",
            params={"includeStats": "true"},
            max_response_bytes=MAX_DETAIL_BYTES,
        )
        stage = "analysis"
        result = analyze_route_input(detail_payload)
        detail_payload = None
        return result
    except SessionManagerError as exc:
        return _failure(exc.category if exc.category in SAFE_CATEGORIES else "session_failed")
    except MapitHTTPError as exc:
        return _failure(_http_category(stage, exc.status))
    except MapitResponseTooLarge:
        return _failure(_request_category(stage, "response_too_large"))
    except MapitTransportError:
        return _failure(_request_category(stage, "transport_failed"))
    except MapitResponseError:
        return _failure(_request_category(stage, "invalid_response"))
    except RouteInputAnalysisError as exc:
        return _failure(f"route_input_{exc.category}")
    except Exception:
        if stage == "analysis":
            return _failure("route_input_invalid_structure")
        return _failure(_request_category(stage, "invalid_response"))
    finally:
        summary_payload = None
        routes_payload = None
        detail_payload = None
        vehicle_id = None
        route_id = None
        context = None
        client = None


def main() -> int:
    result = perform_route_input_sufficiency_probe()
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0 if result.get("success") is True else 1


perform_route_input_probe = perform_route_input_sufficiency_probe


if __name__ == "__main__":
    raise SystemExit(main())
