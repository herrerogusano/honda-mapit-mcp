"""Local GUI for one bounded, read-only routes-list schema probe."""

from __future__ import annotations

import json
import queue
import sys
import threading
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:  # Tk is optional at import time so CI never needs a display.
    import tkinter as tk
except ImportError:  # pragma: no cover - host dependent.
    tk = None  # type: ignore[assignment]

from mapit.anonymizer import schema_only  # noqa: E402
from mapit.auth import CognitoAuthenticator, MapitSession  # noqa: E402
from mapit.client import MapitClient, MapitHTTPError, MapitResponseError, MapitTransportError  # noqa: E402
from mapit.config import MapitConfig, RuntimeConfig, fetch_public_runtime_config  # noqa: E402
from mapit.session import ManagedSession, SessionManager, SessionManagerError, WindowsKeyringRefreshTokenStore  # noqa: E402

try:  # Support package imports in tests and direct script execution.
    from scripts.account_summary_prompt_gui import atomic_write_schema  # noqa: E402
    from scripts.probe_auth import error_category, safe_error_summary  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - direct script path.
    from account_summary_prompt_gui import atomic_write_schema  # type: ignore[no-redef]  # noqa: E402
    from probe_auth import error_category, safe_error_summary  # type: ignore[no-redef]  # noqa: E402


DEFAULT_SCHEMA_PATH = ROOT / "samples" / "anonymized" / "routes-list.schema.json"
SAFE_SESSION_CATEGORIES = frozenset(
    {
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
    }
)


def _safe_session_category(value: Any) -> str:
    return value if isinstance(value, str) and value in SAFE_SESSION_CATEGORIES else "authentication_failed"


def _routes_http_category(status: Any) -> str:
    """Map only an HTTP status to a stable, value-free routes category."""
    if not isinstance(status, int) or isinstance(status, bool):
        return "routes_list_http_error"
    if status in {400, 401, 403, 404, 429}:
        return f"routes_list_http_{status}"
    if 500 <= status <= 599:
        return "routes_list_http_5xx"
    return "routes_list_http_error"


def _http_category(prefix: str, status: Any) -> str:
    return f"{prefix}_http_{_routes_http_category(status).removeprefix('routes_list_http_')}"


def _request_failure_category(*, vehicle_id: str | None, kind: str) -> str:
    prefix = "routes_list" if vehicle_id is not None else "account_summary"
    return f"{prefix}_{kind}"


def _select_vehicle_id(summary: Any) -> str | None:
    """Prefer a non-null device, then fall back to the first valid ID."""
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


def perform_routes_list_with_session(
    config: MapitConfig,
    session: MapitSession,
    *,
    client_factory: Callable[[MapitConfig, MapitSession], Any] = MapitClient,
    save_path: Path = DEFAULT_SCHEMA_PATH,
) -> dict[str, Any]:
    """Run only the bounded routes request using an already valid session."""
    region = config.region
    if not isinstance(session, MapitSession):
        return safe_error_summary(region=region, category="authentication_failed")
    summary_payload: Any = None
    routes_payload: Any = None
    vehicle_id: str | None = None
    try:
        client = client_factory(config, session)
        summary_payload = client.get_core("/v1/account-summary")
        vehicle_id = _select_vehicle_id(summary_payload)
        summary_payload = None
        if vehicle_id is None:
            return safe_error_summary(region=region, category="routes_list_missing_vehicle")
        routes_payload = client.get_geo("/v1/routes", params={"vehicleId": vehicle_id, "limit": 1})
        schema = schema_only(routes_payload)
        routes_payload = None
        atomic_write_schema(schema, Path(save_path))
        fields = schema.get("fields", {}) if schema.get("type") == "object" else {}
        return {"success": True, "region": region, "path": str(Path(save_path)), "top_level_keys": list(fields.keys())}
    except SessionManagerError as exc:
        return safe_error_summary(region=region, category=_safe_session_category(exc.category))
    except MapitHTTPError as exc:
        return safe_error_summary(
            region=region,
            category=_routes_http_category(exc.status) if vehicle_id is not None else _http_category("account_summary", exc.status),
        )
    except MapitTransportError:
        return safe_error_summary(region=region, category=_request_failure_category(vehicle_id=vehicle_id, kind="transport_failed"))
    except MapitResponseError:
        return safe_error_summary(region=region, category=_request_failure_category(vehicle_id=vehicle_id, kind="invalid_response"))
    except Exception:
        category = "routes_list_request_failed" if vehicle_id is not None else "account_summary_request_failed"
        return safe_error_summary(region=region, category=category)
    finally:
        summary_payload = None
        routes_payload = None
        vehicle_id = None


def perform_routes_list_probe(
    email: str,
    password: str,
    *,
    discover: Callable[..., RuntimeConfig] = fetch_public_runtime_config,
    authenticator_factory: Callable[[MapitConfig], Any] = CognitoAuthenticator,
    client_factory: Callable[[MapitConfig, MapitSession], Any] = MapitClient,
    save_path: Path = DEFAULT_SCHEMA_PATH,
) -> dict[str, Any]:
    """Read account summary, then make one bounded Geo routes-list GET."""
    stage = "configuration"
    config = MapitConfig(email=email, password=password)
    region = config.region
    summary_payload: Any = None
    routes_payload: Any = None
    session: MapitSession | None = None
    client: Any = None
    vehicle_id: str | None = None
    try:
        stage = "discovery"
        runtime = discover(config.frontend_url, timeout=config.http_timeout)
        config = config.with_runtime(runtime)
        region = config.region
        stage = "authentication"
        session = authenticator_factory(config).authenticate()
        return perform_routes_list_with_session(config, session, client_factory=client_factory, save_path=save_path)
    except Exception as exc:
        if stage == "account_summary_request":
            category = "account_summary_request_failed"
        elif stage == "routes_list_request":
            category = "routes_list_request_failed"
        else:
            category = error_category(exc, stage=stage)
        return safe_error_summary(region=region, category=category)
    finally:
        summary_payload = None
        routes_payload = None
        session = None
        client = None
        vehicle_id = None
        email = ""
        password = ""


if tk is not None:

    def _local_store():
        try:
            return WindowsKeyringRefreshTokenStore()
        except Exception:
            return None

    class RoutesListPromptApp:
        def __init__(self, root: Any | None = None) -> None:
            self.root = root or tk.Tk()
            self.root.title("MAPIT routes-list schema probe")
            self.root.resizable(False, False)
            self._closing = False
            self._results: queue.Queue[dict[str, Any]] = queue.Queue()
            self._worker_thread: threading.Thread | None = None
            self.manager = SessionManager(store=_local_store())

            frame = tk.Frame(self.root, padx=16, pady=16)
            frame.grid(row=0, column=0, sticky="nsew")
            tk.Label(frame, text="Rutas MAPIT", font=("Segoe UI", 13, "bold")).grid(
                row=0, column=0, columnspan=2, sticky="w", pady=(0, 10)
            )
            tk.Button(frame, text="Reintentar sesión guardada", command=self._start_saved_session).grid(
                row=1, column=0, pady=(4, 0), sticky="w"
            )
            tk.Button(frame, text="Borrar sesión guardada", command=self._forget_saved).grid(
                row=1, column=1, pady=(4, 0), sticky="e"
            )
            tk.Button(frame, text="Cerrar", command=self.close).grid(
                row=2, column=0, columnspan=2, pady=(8, 0), sticky="ew"
            )
            self.status_var = tk.StringVar(value="Comprobando sesión guardada…")
            tk.Label(frame, textvariable=self.status_var, font=("Segoe UI", 12, "bold"), anchor="w", justify="left").grid(
                row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0)
            )
            self.result_var = tk.StringVar()
            tk.Label(frame, textvariable=self.result_var, justify="left", anchor="w").grid(row=4, column=0, columnspan=2, sticky="ew", pady=(4, 0))
            self.root.protocol("WM_DELETE_WINDOW", self.close)
            self.root.after(0, self._start_saved_session)
            self.root.after(100, self._poll_results)

        def _start_saved_session(self) -> None:
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return
            self.status_var.set("Checking saved session…")
            self._worker_thread = threading.Thread(target=self._saved_worker, daemon=True)
            self._worker_thread.start()

        def _saved_worker(self) -> None:
            try:
                context = self.manager.login_saved()
                if context is None:
                    self._results.put(
                        {
                            "_saved_missing": True,
                            "_category": (
                                _safe_session_category(self.manager.last_error_category)
                                if self.manager.last_error_category
                                else None
                            ),
                        }
                    )
                    return
                result = perform_routes_list_with_session(context.config, context.session)
            except Exception:
                result = safe_error_summary(
                    region="eu-west-1",
                    category=_safe_session_category(self.manager.last_error_category),
                )
            self._results.put(result)

        def _poll_results(self) -> None:
            if self._closing:
                return
            try:
                result = self._results.get_nowait()
            except queue.Empty:
                self.root.after(100, self._poll_results)
                return
            if result.pop("_saved_missing", False):
                category = result.pop("_category", None)
                if category is not None:
                    category = _safe_session_category(category)
                if category:
                    self.status_var.set(f"Sesión no disponible [{category}]. Ejecuta session_setup_gui.py primero.")
                    self.result_var.set(
                        json.dumps(
                            safe_error_summary(region="eu-west-1", category=category),
                            indent=2,
                            sort_keys=True,
                        )
                    )
                else:
                    self.status_var.set("Primero ejecuta session_setup_gui.py para guardar la sesión.")
                    self.result_var.set(json.dumps({"success": False, "error": "session_setup_required"}, sort_keys=True))
            else:
                self.status_var.set("Complete" if result.get("success") else "Failed")
                self.result_var.set(json.dumps(result, indent=2, sort_keys=True))
            self._worker_thread = None
            self.root.after(100, self._poll_results)

        def _forget_saved(self) -> None:
            if self.manager.forget_saved_session():
                self.status_var.set("Saved session forgotten")
            else:
                self.status_var.set("Failed: credential_store_failed")
            self.result_var.set("")

        def close(self) -> None:
            if self._closing:
                return
            self._closing = True
            self.root.destroy()


def main() -> int:
    if tk is None:
        print(json.dumps(safe_error_summary(region="eu-west-1", category="gui_unavailable")))
        return 1
    try:
        app = RoutesListPromptApp()
        app.root.mainloop()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps(safe_error_summary(region="eu-west-1", category="gui_unavailable")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
