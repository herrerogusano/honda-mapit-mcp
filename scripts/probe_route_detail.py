"""Safe, non-interactive route-detail schema probe using a saved session.

The probe is deliberately bounded: it reads the account summary once, lists
at most one route, then reads exactly one current route-detail resource.  Only
the anonymized schema is persisted and the process emits value-free JSON.
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

from mapit.anonymizer import schema_only  # noqa: E402
from mapit.client import (  # noqa: E402
    MapitClient,
    MapitHTTPError,
    MapitResponseError,
    MapitTransportError,
)
from mapit.config import MapitConfig  # noqa: E402
from mapit.session import (  # noqa: E402
    ManagedSession,
    RefreshTokenStore,
    SessionManager,
    SessionManagerError,
    WindowsKeyringRefreshTokenStore,
)

try:  # Support both ``python -m`` and direct script execution.
    from scripts.account_summary_prompt_gui import atomic_write_schema  # noqa: E402
    from scripts.probe_auth import safe_error_summary  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - direct script path fallback.
    from account_summary_prompt_gui import atomic_write_schema  # type: ignore[no-redef]  # noqa: E402
    from probe_auth import safe_error_summary  # type: ignore[no-redef]  # noqa: E402


DEFAULT_SCHEMA_PATH = ROOT / "samples" / "anonymized" / "route-detail.schema.json"

_SAFE_SESSION_CATEGORIES = frozenset(
    {
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
    }
)


def _safe_session_category(value: Any) -> str:
    if isinstance(value, str) and value in _SAFE_SESSION_CATEGORIES:
        return value
    return "session_failed"


def _stage_prefix(stage: str) -> str:
    return {
        "account": "account_summary",
        "list": "routes_list",
        "detail": "route_detail",
    }.get(stage, "route_detail")


def _http_category(stage: str, status: Any) -> str:
    prefix = _stage_prefix(stage)
    if not isinstance(status, int) or isinstance(status, bool):
        return f"{prefix}_http_error"
    if status in {400, 401, 403, 404, 429}:
        return f"{prefix}_http_{status}"
    if 500 <= status <= 599:
        return f"{prefix}_http_5xx"
    return f"{prefix}_http_error"


def _request_category(stage: str, kind: str) -> str:
    return f"{_stage_prefix(stage)}_{kind}"


def _stage_category(stage: str) -> str:
    if stage == "schema":
        return "route_detail_schema_failed"
    if stage == "persist":
        return "route_detail_persist_failed"
    if stage in {"account", "list", "detail"}:
        return f"{_stage_prefix(stage)}_request_failed"
    return "session_failed"


def _select_vehicle_id(summary: Any) -> str | None:
    """Select a non-empty vehicle ID, preferring one with a device."""
    if not isinstance(summary, dict) or not isinstance(summary.get("vehicles"), list):
        return None
    fallback: str | None = None
    for vehicle in summary["vehicles"]:
        if not isinstance(vehicle, dict):
            continue
        vehicle_id = vehicle.get("id")
        if not isinstance(vehicle_id, str) or not vehicle_id.strip():
            continue
        if fallback is None:
            fallback = vehicle_id
        if vehicle.get("device") is not None:
            return vehicle_id
    return fallback


def _select_route_id(routes: Any) -> str | None:
    """Select the first non-empty route ID from the current list response."""
    if not isinstance(routes, dict) or not isinstance(routes.get("data"), list):
        return None
    for route in routes["data"]:
        if not isinstance(route, dict):
            continue
        route_id = route.get("id")
        if isinstance(route_id, str) and route_id.strip():
            return route_id
    return None


def _local_store() -> RefreshTokenStore | None:
    """Create only the approved Windows Credential Manager backend."""
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def perform_route_detail_probe(
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[[MapitConfig, Any], Any] = MapitClient,
    save_path: Path = DEFAULT_SCHEMA_PATH,
) -> dict[str, Any]:
    """Run the saved-session route-detail probe without exposing live data."""
    region = "eu-west-1"
    stage = "session"
    manager: Any = None
    context: ManagedSession | None = None
    client: Any = None
    summary_payload: Any = None
    routes_payload: Any = None
    detail_payload: Any = None
    vehicle_id: str | None = None
    route_id: str | None = None
    try:
        # A caller-supplied store is used only for offline tests or an approved
        # Windows store.  The default never falls back to files or plaintext.
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            return safe_error_summary(region=region, category="credential_store_failed")

        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if context is None:
            category = getattr(manager, "last_error_category", None)
            if category is None:
                category = "session_missing"
            return safe_error_summary(region=region, category=_safe_session_category(category) if category != "session_missing" else category)
        if not isinstance(context, ManagedSession):
            return safe_error_summary(region=region, category="session_failed")
        region = context.config.region

        client = client_factory(context.config, context.session)

        stage = "account"
        summary_payload = client.get_core("/v1/account-summary")
        vehicle_id = _select_vehicle_id(summary_payload)
        summary_payload = None
        if vehicle_id is None:
            return safe_error_summary(region=region, category="route_detail_missing_vehicle")

        stage = "list"
        routes_payload = client.get_geo(
            "/v1/routes",
            params={"vehicleId": vehicle_id, "limit": 1},
        )
        route_id = _select_route_id(routes_payload)
        routes_payload = None
        if route_id is None:
            return safe_error_summary(region=region, category="route_detail_missing_route")

        stage = "detail"
        encoded_vehicle_id = quote(vehicle_id, safe="")
        encoded_route_id = quote(route_id, safe="")
        detail_payload = client.get_geo(
            f"/v1/vehicles/{encoded_vehicle_id}/routes/{encoded_route_id}",
            params={"includeStats": "true"},
        )

        stage = "schema"
        schema = schema_only(detail_payload)
        detail_payload = None
        stage = "persist"
        atomic_write_schema(schema, Path(save_path))
        fields = schema.get("fields", {}) if schema.get("type") == "object" else {}
        return {
            "success": True,
            "region": region,
            "path": str(Path(save_path)),
            "top_level_keys": list(fields.keys()),
        }
    except SessionManagerError as exc:
        return safe_error_summary(region=region, category=_safe_session_category(exc.category))
    except MapitHTTPError as exc:
        return safe_error_summary(region=region, category=_http_category(stage, exc.status))
    except MapitTransportError:
        return safe_error_summary(region=region, category=_request_category(stage, "transport_failed"))
    except MapitResponseError:
        return safe_error_summary(region=region, category=_request_category(stage, "invalid_response"))
    except Exception:
        return safe_error_summary(region=region, category=_stage_category(stage))
    finally:
        # Drop live response objects and identifiers before returning.  They
        # are never interpolated into errors or output.
        summary_payload = None
        routes_payload = None
        detail_payload = None
        vehicle_id = None
        route_id = None
        context = None
        client = None
        manager = None


def main() -> int:
    result = perform_route_detail_probe()
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
