"""Local GUI for one authorized, read-only account-summary schema probe."""

from __future__ import annotations

import json
import os
import queue
import sys
import tempfile
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

from mapit.auth import CognitoAuthenticator, MapitSession  # noqa: E402
from mapit.client import MapitClient  # noqa: E402
from mapit.config import MapitConfig, RuntimeConfig, fetch_public_runtime_config  # noqa: E402
from mapit.anonymizer import schema_only  # noqa: E402

try:  # Direct script and package import both remain supported.
    from scripts.probe_auth import error_category, safe_error_summary  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - direct script path.
    from probe_auth import error_category, safe_error_summary  # type: ignore[no-redef]  # noqa: E402


DEFAULT_SCHEMA_PATH = ROOT / "samples" / "anonymized" / "account-summary.schema.json"


def atomic_write_schema(schema: dict[str, Any], path: Path) -> None:
    """Atomically write only an already-anonymized schema."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", suffix=".tmp", delete=False) as handle:
            temp_name = handle.name
            json.dump(schema, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.replace(temp_name, path)
        temp_name = None
    finally:
        if temp_name:
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass


def perform_account_summary_probe(
    email: str,
    password: str,
    *,
    discover: Callable[..., RuntimeConfig] = fetch_public_runtime_config,
    authenticator_factory: Callable[[MapitConfig], Any] = CognitoAuthenticator,
    client_factory: Callable[[MapitConfig, MapitSession], Any] = MapitClient,
    save_path: Path = DEFAULT_SCHEMA_PATH,
) -> dict[str, Any]:
    """Authenticate and make exactly one account-summary GET before anonymizing."""
    stage = "configuration"
    config = MapitConfig(email=email, password=password)
    region = config.region
    payload: Any = None
    session: MapitSession | None = None
    client: Any = None
    try:
        stage = "discovery"
        runtime = discover(config.frontend_url, timeout=config.http_timeout)
        config = config.with_runtime(runtime)
        region = config.region
        stage = "authentication"
        session = authenticator_factory(config).authenticate()
        stage = "account_summary_request"
        client = client_factory(config, session)
        payload = client.get_core("/v1/account-summary")
        schema = schema_only(payload)
        payload = None  # Drop the live response immediately after conversion.
        atomic_write_schema(schema, Path(save_path))
        fields = schema.get("fields", {}) if schema.get("type") == "object" else {}
        return {
            "success": True,
            "region": region,
            "path": str(Path(save_path)),
            "top_level_keys": list(fields.keys()),
        }
    except Exception as exc:
        category = "account_summary_request_failed" if stage == "account_summary_request" else error_category(exc, stage=stage)
        return safe_error_summary(region=region, category=category)
    finally:
        payload = None
        session = None
        client = None
        email = ""
        password = ""


if tk is not None:

    class AccountSummaryPromptApp:
        def __init__(self, root: Any | None = None) -> None:
            self.root = root or tk.Tk()
            self.root.title("MAPIT account-summary schema probe")
            self.root.resizable(False, False)
            self._closing = False
            self._results: queue.Queue[dict[str, Any]] = queue.Queue()
            self._worker_thread: threading.Thread | None = None

            frame = tk.Frame(self.root, padx=16, pady=16)
            frame.grid(row=0, column=0, sticky="nsew")
            self.email_var = tk.StringVar()
            self.password_var = tk.StringVar()
            tk.Label(frame, text="Email").grid(row=0, column=0, sticky="w", pady=(0, 6))
            tk.Entry(frame, textvariable=self.email_var, show="*", width=42).grid(row=0, column=1, sticky="ew", pady=(0, 6))
            tk.Label(frame, text="Password").grid(row=1, column=0, sticky="w", pady=(0, 6))
            tk.Entry(frame, textvariable=self.password_var, show="*", width=42).grid(row=1, column=1, sticky="ew", pady=(0, 6))
            self.authenticate_button = tk.Button(frame, text="Authenticate + read summary", command=self._on_authenticate)
            self.authenticate_button.grid(row=2, column=0, pady=(8, 0), sticky="w")
            tk.Button(frame, text="Close", command=self.close).grid(row=2, column=1, pady=(8, 0), sticky="e")
            self.status_var = tk.StringVar(value="Ready")
            tk.Label(frame, textvariable=self.status_var, anchor="w").grid(row=3, column=0, columnspan=2, sticky="ew", pady=(12, 0))
            self.result_var = tk.StringVar()
            tk.Label(frame, textvariable=self.result_var, justify="left", anchor="w").grid(row=4, column=0, columnspan=2, sticky="ew", pady=(4, 0))
            self.root.protocol("WM_DELETE_WINDOW", self.close)
            self.root.after(100, self._poll_results)

        def _on_authenticate(self) -> None:
            if self._worker_thread is not None and self._worker_thread.is_alive():
                return
            email = self.email_var.get()
            password = self.password_var.get()
            self.email_var.set("")
            self.password_var.set("")
            if not email or not password:
                self.status_var.set("Enter both values")
                return
            self.authenticate_button.configure(state="disabled")
            self.status_var.set("Authenticating and reading one summary…")
            self.result_var.set("")
            self._worker_thread = threading.Thread(target=self._worker, args=(email, password), daemon=True)
            self._worker_thread.start()

        def _worker(self, email: str, password: str) -> None:
            try:
                result = perform_account_summary_probe(email, password)
            except Exception:
                result = safe_error_summary(region="eu-west-1", category="account_summary_request_failed")
            finally:
                email = ""
                password = ""
            self._results.put(result)

        def _poll_results(self) -> None:
            if self._closing:
                return
            try:
                result = self._results.get_nowait()
            except queue.Empty:
                self.root.after(100, self._poll_results)
                return
            self.status_var.set("Complete" if result.get("success") else "Failed")
            self.result_var.set(json.dumps(result, indent=2, sort_keys=True))
            self.authenticate_button.configure(state="normal")
            self._worker_thread = None
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
        print(json.dumps(safe_error_summary(region="eu-west-1", category="gui_unavailable")))
        return 1
    try:
        app = AccountSummaryPromptApp()
        app.root.mainloop()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(json.dumps(safe_error_summary(region="eu-west-1", category="gui_unavailable")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

