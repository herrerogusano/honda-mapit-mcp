"""Local GUI for discovery, Cognito login, and refresh-token persistence only.

This module deliberately has no Core/Geo client import and makes no data call.
The pure ``perform_session_setup`` function is injectable for offline tests.
"""

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

try:  # Tk is optional so CI never requires a display.
    import tkinter as tk
except ImportError:  # pragma: no cover - depends on the host Python build.
    tk = None  # type: ignore[assignment]

from mapit.auth import CognitoAuthenticator  # noqa: E402
from mapit.config import RuntimeConfig, fetch_public_runtime_config  # noqa: E402
from mapit.session import (  # noqa: E402
    RefreshTokenStore,
    SessionManager,
    SessionManagerError,
    WindowsKeyringRefreshTokenStore,
)


SAFE_CATEGORIES = frozenset(
    {
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
    }
)


def _safe_failure(manager: Any, fallback: str = "authentication_failed") -> dict[str, Any]:
    category = getattr(manager, "last_error_category", None) or fallback
    if not isinstance(category, str) or category not in SAFE_CATEGORIES:
        category = fallback
    if not isinstance(category, str) or category not in SAFE_CATEGORIES:
        category = "authentication_failed"
    return {"success": False, "error": category}


def _default_store() -> RefreshTokenStore | None:
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def perform_session_setup(
    email: str,
    password: str,
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    discover: Callable[..., RuntimeConfig] = fetch_public_runtime_config,
    authenticator_factory: Callable[..., Any] = CognitoAuthenticator,
) -> dict[str, Any]:
    """Discover, authenticate, and save only the refresh token.

    The returned dictionary is intentionally limited to success, saved state,
    and a stable public category.  No session or error payload is returned.
    """
    if store is None:
        store = _default_store()
    if store is None:
        return {"success": False, "error": "credential_store_failed"}
    try:
        manager = manager_factory(
            store=store,
            discover=discover,
            authenticator_factory=authenticator_factory,
        )
        manager.login_manual(email, password)
        return {"success": True, "saved": True}
    except SessionManagerError as exc:
        category = exc.category if isinstance(exc.category, str) and exc.category in SAFE_CATEGORIES else "authentication_failed"
        return {"success": False, "error": category}
    except Exception:
        return _safe_failure(locals().get("manager")) if "manager" in locals() else {
            "success": False,
            "error": "authentication_failed",
        }
    finally:
        email = ""
        password = ""


def _status_text(result: dict[str, Any]) -> str:
    if result.get("success"):
        return "Sesión guardada correctamente."
    category = result.get("error")
    if not isinstance(category, str) or category not in SAFE_CATEGORIES:
        category = "authentication_failed"
    messages = {
        "discovery_failed": "No se pudo descubrir la configuración pública.",
        "authentication_rejected": "Cognito rechazó las credenciales o requiere un challenge no compatible.",
        "authentication_failed": "La autenticación no pudo completarse.",
        "credential_store_failed": "No se pudo guardar en Credential Manager de Windows.",
    }
    return f"{messages.get(category, 'No se pudo completar la operación')} [{category}]"


if tk is not None:

    class SessionSetupApp:
        def __init__(self, root: Any | None = None) -> None:
            self.root = root or tk.Tk()
            self.root.title("MAPIT — Guardar sesión")
            self.root.resizable(False, False)
            self._closing = False
            self._results: queue.Queue[dict[str, Any]] = queue.Queue()
            self._worker_thread: threading.Thread | None = None
            self.store = _default_store()

            frame = tk.Frame(self.root, padx=18, pady=18)
            frame.grid(row=0, column=0, sticky="nsew")
            tk.Label(frame, text="Configurar sesión MAPIT", font=("Segoe UI", 14, "bold")).grid(
                row=0, column=0, columnspan=2, sticky="w", pady=(0, 14)
            )
            self.email_var = tk.StringVar()
            self.password_var = tk.StringVar()
            tk.Label(frame, text="Email").grid(row=1, column=0, sticky="w", pady=(0, 7))
            tk.Entry(frame, textvariable=self.email_var, width=44).grid(row=1, column=1, sticky="ew", pady=(0, 7))
            tk.Label(frame, text="Password").grid(row=2, column=0, sticky="w", pady=(0, 7))
            tk.Entry(frame, textvariable=self.password_var, show="*", width=44).grid(row=2, column=1, sticky="ew", pady=(0, 7))
            self.save_button = tk.Button(frame, text="Guardar sesión", command=self._on_save, width=20)
            self.save_button.grid(row=3, column=0, pady=(9, 0), sticky="w")
            self.forget_button = tk.Button(frame, text="Borrar sesión guardada", command=self._on_forget, width=20)
            self.forget_button.grid(row=3, column=1, pady=(9, 0), sticky="e")
            tk.Button(frame, text="Cerrar", command=self.close, width=20).grid(
                row=4, column=0, columnspan=2, pady=(8, 0), sticky="ew"
            )
            self.status_var = tk.StringVar(value="Introduce tus credenciales para guardar la sesión.")
            tk.Label(frame, textvariable=self.status_var, font=("Segoe UI", 12, "bold"), anchor="w", justify="left").grid(
                row=5, column=0, columnspan=2, sticky="ew", pady=(16, 0)
            )
            self.root.protocol("WM_DELETE_WINDOW", self.close)
            self.root.after(100, self._poll_results)

        def _set_busy(self, busy: bool) -> None:
            state = "disabled" if busy else "normal"
            self.save_button.configure(state=state)
            self.forget_button.configure(state=state)

        def _on_save(self) -> None:
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return
            email = self.email_var.get()
            password = self.password_var.get()
            self.email_var.set("")
            self.password_var.set("")
            if not email or not password:
                self.status_var.set("Introduce email y password.")
                return
            self._set_busy(True)
            self.status_var.set("Descubriendo y autenticando…")
            self._worker_thread = threading.Thread(target=self._save_worker, args=(email, password), daemon=True)
            self._worker_thread.start()

        def _save_worker(self, email: str, password: str) -> None:
            try:
                result = perform_session_setup(email, password, store=self.store)
            except Exception:
                result = {"success": False, "error": "authentication_failed"}
            finally:
                email = ""
                password = ""
            self._results.put({"kind": "setup", "result": result})

        def _on_forget(self) -> None:
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return
            self._set_busy(True)
            self.status_var.set("Borrando sesión guardada…")
            self._worker_thread = threading.Thread(target=self._forget_worker, daemon=True)
            self._worker_thread.start()

        def _forget_worker(self) -> None:
            try:
                if self.store is None:
                    result = {"success": False, "error": "credential_store_failed"}
                else:
                    deleted = self.store.delete()
                    result = (
                        {"success": False, "error": "credential_store_failed"}
                        if deleted is False
                        else {"success": True, "forgotten": True}
                    )
            except Exception:
                result = {"success": False, "error": "credential_store_failed"}
            self._results.put({"kind": "forget", "result": result})

        def _poll_results(self) -> None:
            if self._closing:
                return
            try:
                payload = self._results.get_nowait()
            except queue.Empty:
                self.root.after(100, self._poll_results)
                return
            result = payload["result"]
            self.status_var.set(_status_text(result) if payload["kind"] == "setup" else (
                "Sesión guardada borrada." if result.get("success") else "No se pudo borrar la sesión guardada [credential_store_failed]"
            ))
            self._worker_thread = None
            self._set_busy(False)
            if payload["kind"] == "setup":
                print(json.dumps(result, separators=(",", ":")), flush=True)
                if result.get("success"):
                    self.root.after(120, self.close)
            self.root.after(100, self._poll_results)

        def close(self) -> None:
            if self._closing:
                return
            self._closing = True
            self.email_var.set("")
            self.password_var.set("")
            self.root.destroy()


def main() -> int:
    if tk is None:
        print(json.dumps({"success": False, "error": "gui_unavailable"}, separators=(",", ":")))
        return 1
    try:
        app = SessionSetupApp()
        app.root.mainloop()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps({"success": False, "error": "gui_unavailable"}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
