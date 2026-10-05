"""Bounded saved-session probe for the frontend's monthly route filters.

The probe performs two read-only, ``limit=1`` requests and retains no route
data.  It records only whether the allowlisted ``lastEvaluatedKey`` field was
present in either response.
"""

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

from mapit.client import MapitClient, MapitHTTPError, MapitResponseError, MapitTransportError  # noqa: E402
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


_SAFE_SESSION_CATEGORIES = frozenset(
    {
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
    }
)
_LAST_EVALUATED_KEY = "lastEvaluatedKey"


def _safe_session_category(value: Any) -> str:
    return value if isinstance(value, str) and value in _SAFE_SESSION_CATEGORIES else "session_failed"


def _http_category(stage: str, status: Any) -> str:
    prefix = "account_summary" if stage == "account" else "route_history"
    if not isinstance(status, int) or isinstance(status, bool):
        return f"{prefix}_http_error"
    if status in {400, 401, 403, 404, 429}:
        return f"{prefix}_http_{status}"
    if 500 <= status <= 599:
        return f"{prefix}_http_5xx"
    return f"{prefix}_http_error"


def _request_category(stage: str, kind: str) -> str:
    prefix = "account_summary" if stage == "account" else "route_history"
    return f"{prefix}_{kind}"


def _stage_category(stage: str) -> str:
    if stage == "account":
        return "account_summary_request_failed"
    if stage == "window":
        return "route_history_request_failed"
    return "session_failed"


def _localize(value: datetime) -> datetime:
    """Treat naive values as host-local and aware values in their own zone."""
    if value.tzinfo is None:
        local_zone = datetime.now().astimezone().tzinfo
        return value.replace(tzinfo=local_zone)
    # An injected aware clock already carries the local browser zone.  Do not
    # convert it to the process zone, which would make deterministic DST tests
    # (and callers modelling the frontend zone) observe the wrong calendar.
    return value


def _month_start(year: int, month: int, tzinfo: Any, *, system_local: bool) -> datetime:
    naive = datetime(year, month, 1)
    if system_local:
        # For a real local clock, astimezone() asks the operating system for
        # the offset at this boundary (including a different DST offset than
        # the current instant).  Attaching ``now().astimezone().tzinfo`` would
        # freeze today's offset and disagree with the browser around DST.
        return naive.astimezone()
    return naive.replace(tzinfo=tzinfo)


def _previous_month(year: int, month: int) -> tuple[int, int]:
    return (year - 1, 12) if month == 1 else (year, month - 1)


def _next_month(year: int, month: int) -> tuple[int, int]:
    return (year + 1, 1) if month == 12 else (year, month + 1)


def _utc_iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_month_windows(now: datetime | None = None) -> list[tuple[str, str]]:
    """Return current then previous local-calendar month as UTC ISO ranges.

    This mirrors the browser's local ``new Date(year, month, 1)`` boundaries
    followed by ``toISOString()``.  The optional clock makes DST and year
    boundaries testable without relying on the host clock.
    """
    supplied_clock = now is not None
    local_now = _localize(now or datetime.now().astimezone())
    system_local = not supplied_clock or now.tzinfo is None
    current_year, current_month = local_now.year, local_now.month
    previous_year, previous_month = _previous_month(current_year, current_month)
    windows: list[tuple[str, str]] = []
    for year, month in ((current_year, current_month), (previous_year, previous_month)):
        next_year, next_month = _next_month(year, month)
        start = _month_start(year, month, local_now.tzinfo, system_local=system_local)
        end = _month_start(next_year, next_month, local_now.tzinfo, system_local=system_local)
        windows.append((_utc_iso(start), _utc_iso(end)))
    return windows


def _valid_route_list_response(payload: Any) -> bool:
    return isinstance(payload, dict) and isinstance(payload.get("data"), list)


def _local_store() -> RefreshTokenStore | None:
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def perform_route_history_filters_probe(
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[[MapitConfig, Any], Any] = MapitClient,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, Any]:
    """Check two monthly ``from``/``to`` windows without retaining payloads."""
    region = "eu-west-1"
    stage = "session"
    manager: Any = None
    context: ManagedSession | None = None
    client: Any = None
    summary_payload: Any = None
    route_payload: Any = None
    vehicle_id: str | None = None
    last_evaluated_key_observed = False
    try:
        selected_store = store if store is not None else _local_store()
        if selected_store is None:
            return safe_error_summary(region=region, category="credential_store_failed")
        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if context is None:
            category = getattr(manager, "last_error_category", None)
            if category is None:
                category = "session_missing"
            return safe_error_summary(
                region=region,
                category=category if category == "session_missing" else _safe_session_category(category),
            )
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

        for from_value, to_value in build_month_windows(clock() if clock is not None else None):
            stage = "window"
            route_payload = client.get_geo(
                "/v1/routes",
                params={
                    "vehicleId": vehicle_id,
                    "limit": 1,
                    "from": from_value,
                    "to": to_value,
                },
            )
            if not _valid_route_list_response(route_payload):
                return safe_error_summary(region=region, category="route_history_invalid_response")
            if _LAST_EVALUATED_KEY in route_payload:
                last_evaluated_key_observed = True
            route_payload = None

        return {
            "success": True,
            "region": region,
            "windows_checked": 2,
            "last_evaluated_key_observed": last_evaluated_key_observed,
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
        summary_payload = None
        route_payload = None
        vehicle_id = None
        context = None
        client = None
        manager = None


def main() -> int:
    result = perform_route_history_filters_probe()
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
