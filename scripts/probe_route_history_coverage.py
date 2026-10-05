"""Ephemeral, bounded gate for one vehicle's returned route-history coverage."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

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
from mapit.session import (  # noqa: E402
    ManagedSession,
    RefreshTokenStore,
    SessionManager,
    SessionManagerError,
    WindowsKeyringRefreshTokenStore,
)

try:  # Support both package imports and direct script execution.
    from scripts.probe_auth import safe_error_summary  # noqa: E402
    from scripts.probe_route_detail import _select_vehicle_id  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - direct script fallback.
    from probe_auth import safe_error_summary  # type: ignore[no-redef]  # noqa: E402
    from probe_route_detail import _select_vehicle_id  # type: ignore[no-redef]  # noqa: E402


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_PAGINATION_KEYS = frozenset({"lastEvaluatedKey", "nextToken", "cursor", "offset", "page", "total", "count"})
_SAFE_SESSION_CATEGORIES = frozenset(
    {"discovery_failed", "authentication_rejected", "authentication_failed", "credential_store_failed"}
)


def _safe_session_category(value: Any) -> str:
    return value if isinstance(value, str) and value in _SAFE_SESSION_CATEGORIES else "session_failed"


def _http_category(status: Any) -> str:
    if status == 429:
        return "rate_limited"
    if isinstance(status, int) and not isinstance(status, bool):
        if status in {400, 401, 403, 404}:
            return f"route_history_http_{status}"
        if 500 <= status <= 599:
            return "route_history_http_5xx"
    return "route_history_http_error"


def _parse_started_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _month(value: datetime) -> str:
    return value.strftime("%Y-%m")


def _month_window(month: str) -> tuple[str, str]:
    year, month_number = (int(part) for part in month.split("-"))
    start = datetime(year, month_number, 1, tzinfo=timezone.utc)
    if month_number == 12:
        end = datetime(year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(year, month_number + 1, 1, tzinfo=timezone.utc)
    return (
        start.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        end.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
    )


def _inspect_response(payload: Any) -> dict[str, Any]:
    """Inspect only bounded metadata needed for the coverage classification."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        return {
            "shape": False,
            "empty": False,
            "ids": set(),
            "ids_by_month": {},
            "months": [],
            "timestamp_valid": False,
            "ids_valid": False,
            "duplicate_ids": False,
        }
    data = payload["data"]
    metadata = any(key in payload for key in _PAGINATION_KEYS)
    if not data:
        return {
            "shape": True,
            "empty": True,
            "ids": set(),
            "ids_by_month": {},
            "months": [],
            "timestamp_valid": True,
            "ids_valid": True,
            "duplicate_ids": False,
            "metadata": metadata,
        }
    ids: set[str] = set()
    ids_by_month: dict[str, set[str]] = {}
    months: list[str] = []
    ids_valid = True
    timestamps_valid = True
    duplicate_ids = False
    for item in data:
        if not isinstance(item, dict):
            ids_valid = False
            timestamps_valid = False
            continue
        route_id = item.get("id")
        if isinstance(route_id, str) and route_id.strip():
            if route_id in ids:
                duplicate_ids = True
            ids.add(route_id)
        else:
            ids_valid = False
        parsed = _parse_started_at(item.get("startedAt"))
        if parsed is None:
            timestamps_valid = False
        else:
            month = _month(parsed)
            months.append(month)
            if isinstance(route_id, str) and route_id.strip():
                ids_by_month.setdefault(month, set()).add(route_id)
    return {
        "shape": True,
        "empty": False,
        "ids": ids,
        "ids_by_month": ids_by_month,
        "months": months,
        "timestamp_valid": timestamps_valid,
        "ids_valid": ids_valid,
        "duplicate_ids": duplicate_ids,
        "metadata": metadata,
        "route_count": len(data),
    }


def _result(
    *,
    region: str,
    route_count: int,
    oldest: str | None,
    newest: str | None,
    metadata: bool,
    coverage: str,
) -> dict[str, Any]:
    return {
        "success": True,
        "region": region,
        "route_count_observed": route_count,
        "oldest_month_observed": oldest,
        "newest_month_observed": newest,
        "pagination_metadata_observed": metadata,
        "coverage_class": coverage,
    }


def _local_store() -> RefreshTokenStore | None:
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def perform_route_history_coverage_probe(
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[[MapitConfig, Any], Any] = MapitClient,
) -> dict[str, Any]:
    """Run the historical gate without persisting bodies, schemas, or logs."""
    region = "eu-west-1"
    stage = "session"
    manager: Any = None
    context: ManagedSession | None = None
    client: Any = None
    summary_payload: Any = None
    payload: Any = None
    vehicle_id: str | None = None
    base_info: dict[str, Any] | None = None
    try:
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            return safe_error_summary(region=region, category="credential_store_failed")
        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if context is None:
            category = getattr(manager, "last_error_category", None)
            category = "session_missing" if category is None else _safe_session_category(category)
            return safe_error_summary(region=region, category=category)
        if not isinstance(context, ManagedSession):
            return safe_error_summary(region=region, category="session_failed")
        region = context.config.region
        client = client_factory(context.config, context.session)

        stage = "account"
        summary_payload = client.get_core("/v1/account-summary")
        vehicle_id = _select_vehicle_id(summary_payload)
        summary_payload = None
        if vehicle_id is None:
            return safe_error_summary(region=region, category="route_history_missing_vehicle")

        stage = "base"
        payload = client.get_geo(
            "/v1/routes",
            params={"vehicleId": vehicle_id},
            max_response_bytes=MAX_RESPONSE_BYTES,
        )
        base_info = _inspect_response(payload)
        payload = None
        if not base_info["shape"] or base_info["empty"]:
            return _result(
                region=region,
                route_count=0 if base_info["empty"] else 0,
                oldest=None,
                newest=None,
                metadata=bool(base_info.get("metadata", False)),
                coverage="UNKNOWN",
            )
        route_count = int(base_info["route_count"])
        if not base_info["timestamp_valid"]:
            return _result(region=region, route_count=route_count, oldest=None, newest=None, metadata=bool(base_info.get("metadata")), coverage="UNKNOWN")
        if not base_info["ids_valid"] or base_info.get("duplicate_ids"):
            return _result(region=region, route_count=route_count, oldest=min(base_info["months"]), newest=max(base_info["months"]), metadata=bool(base_info.get("metadata")), coverage="PARTIAL")

        oldest = min(base_info["months"])
        newest = max(base_info["months"])
        control_months = [oldest] if oldest == newest else [oldest, newest]
        coverage = "COMPLETE_FOR_RETURNED_RESPONSE"
        pagination_metadata_observed = bool(base_info.get("metadata"))
        if pagination_metadata_observed:
            coverage = "PARTIAL"
        for control_month in control_months:
            from_value, to_value = _month_window(control_month)
            stage = "control"
            payload = client.get_geo(
                "/v1/routes",
                params={"vehicleId": vehicle_id, "from": from_value, "to": to_value},
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
            control_info = _inspect_response(payload)
            payload = None
            if control_info.get("metadata"):
                pagination_metadata_observed = True
            if (
                not control_info["shape"]
                or control_info["empty"]
                or not control_info["timestamp_valid"]
                or not control_info["ids_valid"]
                or control_info.get("duplicate_ids")
                or set(control_info["ids"]) != set(base_info["ids_by_month"].get(control_month, set()))
                or any(month != control_month for month in control_info["months"])
                or control_info.get("metadata")
            ):
                coverage = "PARTIAL"

        return _result(
            region=region,
            route_count=route_count,
            oldest=oldest,
            newest=newest,
            metadata=pagination_metadata_observed,
            coverage=coverage,
        )
    except SessionManagerError as exc:
        return safe_error_summary(region=region, category=_safe_session_category(exc.category))
    except MapitResponseTooLarge:
        return safe_error_summary(region=region, category="response_too_large")
    except MapitHTTPError as exc:
        return safe_error_summary(region=region, category=_http_category(exc.status))
    except MapitTransportError:
        return safe_error_summary(region=region, category="transport_failed")
    except MapitResponseError:
        return safe_error_summary(region=region, category="invalid_response")
    except Exception:
        return safe_error_summary(region=region, category="request_failed" if stage in {"account", "base", "control"} else "coverage_failed")
    finally:
        summary_payload = None
        payload = None
        vehicle_id = None
        base_info = None
        context = None
        client = None
        manager = None


def main() -> int:
    result = perform_route_history_coverage_probe()
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
