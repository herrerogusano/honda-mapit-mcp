"""Local Telegram Credential Manager setup; never contacts Telegram."""

from __future__ import annotations

import json
import secrets
from typing import Any

from mapit.telegram_credentials import (
    TelegramCredentialStoreError,
    WindowsKeyringTelegramCredentialStore,
)


def save_telegram_token(store: Any, token: str) -> dict[str, object]:
    """Validate and save only the bot token without exposing it."""
    if not isinstance(token, str) or not token:
        return {"success": False, "category": "invalid_input"}
    challenge = secrets.token_urlsafe(32)
    try:
        store.save_token(token, challenge=challenge)
    except TelegramCredentialStoreError:
        return {"success": False, "category": "credential_store_failed"}
    except Exception:
        return {"success": False, "category": "credential_store_failed"}
    return {"success": True, "category": "saved", "challenge": challenge}


def load_telegram_challenge(store: Any) -> dict[str, object]:
    """Read only the pending challenge for the local display, never print it."""
    try:
        challenge = store.load_challenge()
    except TelegramCredentialStoreError:
        return {"success": False, "category": "credential_store_failed"}
    except Exception:
        return {"success": False, "category": "credential_store_failed"}
    if challenge is None:
        return {"success": True, "category": "no_challenge"}
    if not isinstance(challenge, str) or not challenge:
        return {"success": False, "category": "credential_store_failed"}
    return {"success": True, "category": "challenge_available", "challenge": challenge}


def _emit(result: dict[str, object]) -> None:
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))


def main(store: Any | None = None) -> int:
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception:
        _emit({"success": False, "category": "gui_unavailable"})
        return 1
    try:
        credential_store = store or WindowsKeyringTelegramCredentialStore()
    except Exception:
        _emit({"success": False, "category": "credential_store_failed"})
        return 1

    root = tk.Tk()
    root.title("MAPIT Telegram setup")
    root.resizable(False, False)
    token_var = tk.StringVar()
    command_var = tk.StringVar()
    status_var = tk.StringVar(value="Introduce el token del bot. No se realiza ninguna llamada de red.")

    frame = ttk.Frame(root, padding=16)
    frame.grid()
    ttk.Label(frame, text="Bot token").grid(row=0, column=0, sticky="w")
    token_entry = ttk.Entry(frame, textvariable=token_var, show="*", width=48)
    token_entry.grid(row=1, column=0, columnspan=2, pady=(2, 8))
    ttk.Label(frame, text="Comando de emparejamiento (seleccionable)").grid(row=2, column=0, columnspan=2, sticky="w")
    command_entry = ttk.Entry(frame, textvariable=command_var, state="disabled", width=48)
    command_entry.grid(row=3, column=0, pady=(2, 2))
    copy_button = ttk.Button(frame, text="Copiar comando", state="disabled")
    copy_button.grid(row=3, column=1, pady=(2, 2), padx=(6, 0))
    ttk.Label(frame, textvariable=status_var, wraplength=380).grid(row=4, column=0, columnspan=2, pady=10)
    save_button = ttk.Button(frame, text="Guardar en Credential Manager")
    save_button.grid(row=5, column=0, pady=(0, 4))
    ttk.Button(frame, text="Close", command=root.destroy).grid(row=5, column=1, pady=(0, 4))

    def set_challenge(challenge: object) -> None:
        if isinstance(challenge, str) and challenge:
            command_var.set(f"/start {challenge}")
            command_entry.state(["!disabled", "readonly"])
            copy_button.state(["!disabled"])
        else:
            command_var.set("")
            command_entry.state(["disabled"])
            copy_button.state(["disabled"])

    def copy_command() -> None:
        command = command_var.get()
        if not command:
            return
        try:
            root.clipboard_clear()
            root.clipboard_append(command)
        except Exception:
            status_var.set("No se pudo copiar el comando.")
            return
        status_var.set("Comando copiado.")

    copy_button.configure(command=copy_command)
    initial = load_telegram_challenge(credential_store)
    set_challenge(initial.get("challenge"))
    if initial["category"] == "challenge_available":
        status_var.set("Hay un challenge pendiente. Usa el comando mostrado.")
    elif initial["category"] == "credential_store_failed":
        status_var.set("No se pudo leer la credencial guardada.")

    def save() -> None:
        token = token_var.get()
        token_var.set("")
        save_button.state(["disabled"])
        result = save_telegram_token(credential_store, token)
        if result["success"]:
            set_challenge(result["challenge"])
            status_var.set("Guardado. Usa el comando de emparejamiento mostrado.")
        else:
            set_challenge(None)
            status_var.set("No se pudo guardar (credencial/configuración).")
        _emit({"success": result["success"], "category": result["category"]})
        save_button.state(["!disabled"])

    save_button.configure(command=save)
    token_entry.focus_set()
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
