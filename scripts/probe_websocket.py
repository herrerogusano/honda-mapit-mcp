"""Bounded, non-interactive account-level WebSocket schema probe."""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.anonymizer import _merge, schema_only  # noqa: E402
from mapit.client import MapitClient, MapitHTTPError, MapitResponseError, MapitTransportError  # noqa: E402
from mapit.config import MapitConfig  # noqa: E402
from mapit.session import (  # noqa: E402
    ManagedSession,
    RefreshTokenStore,
    SessionManager,
    SessionManagerError,
    WindowsKeyringRefreshTokenStore,
)
from mapit.websocket import WebSocketDependencyError, connect_account_socket  # noqa: E402

try:  # Support both package imports and direct script execution.
    from scripts.account_summary_prompt_gui import atomic_write_schema  # noqa: E402
    from scripts.probe_auth import safe_error_summary  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - direct script fallback.
    from account_summary_prompt_gui import atomic_write_schema  # type: ignore[no-redef]  # noqa: E402
    from probe_auth import safe_error_summary  # type: ignore[no-redef]  # noqa: E402


DEFAULT_SCHEMA_PATH = ROOT / "samples" / "anonymized" / "websocket-message.schema.json"
WEBSOCKET_BASE = "wss://dsw.prod.mapit.me/accounts/"
MAX_SECONDS = 10.0
MAX_FRAMES = 3
MAX_FRAME_BYTES = 64 * 1024
MAX_QUEUE = 4

_SAFE_SESSION_CATEGORIES = frozenset(
    {
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
    }
)


def _safe_session_category(value: Any) -> str:
    return value if isinstance(value, str) and value in _SAFE_SESSION_CATEGORIES else "session_failed"


def _select_account_id(summary: Any) -> str | None:
    if not isinstance(summary, dict):
        return None
    account = summary.get("account")
    if not isinstance(account, dict):
        return None
    account_id = account.get("id")
    if not isinstance(account_id, str) or not account_id.strip():
        return None
    return account_id.strip()


def _safe_exception_category(exc: BaseException, *, connected: bool) -> str:
    name = type(exc).__name__.lower()
    if "timeout" in name:
        return "websocket_timeout"
    if "close" in name or "connectionclosed" in name:
        return "websocket_closed"
    if not connected and ("status" in name or "handshake" in name or "response" in name):
        return "websocket_handshake_failed"
    return "websocket_transport_failed"


def _base_result(*, region: str, connected: bool, valid: bool, written: bool) -> dict[str, Any]:
    return {
        "success": True,
        "region": region,
        "connected": connected,
        "valid_shape_observed": valid,
        "schema_written": written,
    }


def _error_result(*, region: str, category: str, connected: bool = False) -> dict[str, Any]:
    return {
        "success": False,
        "region": region,
        "connected": connected,
        "error": category,
    }


def _default_store() -> RefreshTokenStore | None:
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def perform_websocket_probe(
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    client_factory: Callable[[MapitConfig, Any], Any] = MapitClient,
    connector_factory: Callable[..., Any] = connect_account_socket,
    save_path: Path = DEFAULT_SCHEMA_PATH,
    clock: Callable[[], float] = time.monotonic,
) -> dict[str, Any]:
    """Read account ID once, receive at most three frames, and persist a schema."""
    region = "eu-west-1"
    stage = "session"
    manager: Any = None
    context: ManagedSession | None = None
    client: Any = None
    socket: Any = None
    summary_payload: Any = None
    frame: Any = None
    frame_payload: Any = None
    account_id: str | None = None
    merged_schema: dict[str, Any] | None = None
    connected = False
    valid_shape_observed = False
    schema_written = False
    termination_category: str | None = None
    try:
        selected_store = store if store is not None else _default_store()
        if selected_store is None:
            return _error_result(region=region, category="credential_store_failed")
        manager = manager_factory(store=selected_store)
        context = manager.login_saved()
        if context is None:
            category = getattr(manager, "last_error_category", None)
            if category is None:
                category = "session_missing"
            return _error_result(
                region=region,
                category=category if category == "session_missing" else _safe_session_category(category),
            )
        if not isinstance(context, ManagedSession):
            return _error_result(region=region, category="session_failed")
        region = context.config.region
        stage = "account"
        client = client_factory(context.config, context.session)
        summary_payload = client.get_core("/v1/account-summary")
        account_id = _select_account_id(summary_payload)
        summary_payload = None
        if account_id is None:
            return _error_result(region=region, category="websocket_missing_account")

        ws_url = WEBSOCKET_BASE + quote(account_id, safe="")
        account_id = None
        stage = "websocket"
        deadline = clock() + MAX_SECONDS
        remaining = max(0.0, deadline - clock())
        try:
            socket = connector_factory(
                ws_url,
                context.session.id_token,
                timeout=remaining,
                max_size=MAX_FRAME_BYTES,
                max_queue=MAX_QUEUE,
            )
            connected = True
            ws_url = ""
        except WebSocketDependencyError:
            return _error_result(region=region, category="websocket_dependency_missing")
        except Exception as exc:
            return _error_result(region=region, category=_safe_exception_category(exc, connected=False))

        for _ in range(MAX_FRAMES):
            remaining = deadline - clock()
            if remaining <= 0:
                termination_category = "websocket_timeout"
                break
            try:
                frame = socket.recv(timeout=remaining)
            except Exception as exc:
                termination_category = _safe_exception_category(exc, connected=True)
                break
            if isinstance(frame, bytes):
                frame = None
                continue
            if not isinstance(frame, str):
                frame = None
                continue
            if len(frame.encode("utf-8", errors="ignore")) > MAX_FRAME_BYTES:
                frame = None
                continue
            try:
                frame_payload = json.loads(frame)
            except (UnicodeDecodeError, json.JSONDecodeError):
                frame = None
                frame_payload = None
                continue
            frame = None
            if not isinstance(frame_payload, dict):
                frame_payload = None
                continue
            candidate = frame_payload.get("id")
            if not (isinstance(candidate, str) and candidate.strip()):
                candidate = frame_payload.get("deviceId")
            if not (isinstance(candidate, str) and candidate.strip()):
                frame_payload = None
                continue
            stage = "schema"
            current_schema = schema_only(frame_payload)
            frame_payload = None
            merged_schema = current_schema if merged_schema is None else _merge(merged_schema, current_schema)
            valid_shape_observed = True
            stage = "websocket"

        if valid_shape_observed and merged_schema is not None:
            stage = "persist"
            atomic_write_schema(merged_schema, Path(save_path))
            schema_written = True
        result = _base_result(
            region=region,
            connected=connected,
            valid=valid_shape_observed,
            written=schema_written,
        )
        if termination_category is not None:
            result["status"] = termination_category
        if schema_written:
            result["path"] = str(Path(save_path))
        return result
    except SessionManagerError as exc:
        return _error_result(region=region, category=_safe_session_category(exc.category), connected=connected)
    except MapitHTTPError as exc:
        category = "account_summary_http_error"
        if isinstance(exc.status, int) and not isinstance(exc.status, bool):
            if exc.status in {400, 401, 403, 404, 429}:
                category = f"account_summary_http_{exc.status}"
            elif 500 <= exc.status <= 599:
                category = "account_summary_http_5xx"
        return _error_result(region=region, category=category, connected=connected)
    except MapitTransportError:
        return _error_result(region=region, category="account_summary_transport_failed", connected=connected)
    except MapitResponseError:
        return _error_result(region=region, category="account_summary_invalid_response", connected=connected)
    except Exception as exc:
        if stage == "persist":
            category = "websocket_schema_persist_failed"
        elif stage == "schema":
            category = "websocket_schema_failed"
        elif stage == "account":
            category = "account_summary_request_failed"
        elif stage == "websocket":
            category = _safe_exception_category(exc, connected=connected)
        else:
            category = "websocket_probe_failed"
        return _error_result(region=region, category=category, connected=connected)
    finally:
        summary_payload = None
        frame = None
        frame_payload = None
        account_id = None
        merged_schema = None
        context = None
        client = None
        manager = None
        if socket is not None:
            try:
                socket.close()
            except Exception:
                pass
            socket = None


def main() -> int:
    result = perform_websocket_probe()
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
