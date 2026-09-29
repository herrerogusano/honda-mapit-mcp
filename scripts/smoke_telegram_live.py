"""Explicit-confirmation Telegram smoke seam; never run implicitly."""

from __future__ import annotations

import argparse
import json
from typing import Any, Callable

from mapit.telegram_bot import BotApiTransport, TelegramBotError, TelegramBotTransportProtocol
from mapit.telegram_credentials import WindowsKeyringTelegramCredentialStore


def run_live_smoke(
    store: Any,
    *,
    transport_factory: Callable[[str], TelegramBotTransportProtocol] = BotApiTransport,
    allow_get_updates: bool = False,
    allow_send_message: bool = False,
) -> dict[str, object]:
    """Run only when both explicit confirmation flags are true."""
    if not allow_get_updates or not allow_send_message:
        return {"success": False, "category": "confirmation_required"}
    try:
        token = store.load_token()
        if token is None:
            return {"success": False, "category": "no_saved_credentials"}
        challenge = store.load_challenge()
        if challenge is None:
            return {"success": False, "category": "onboarding_challenge_missing"}
        transport = transport_factory(token)
        if transport.get_me() is not True:
            return {"success": False, "category": "bot_identity_failed"}
        if transport.get_webhook_info() is not True:
            return {"success": False, "category": "webhook_active"}
        updates = transport.get_updates(timeout_seconds=25)
        if len(updates) == 0:
            return {"success": False, "category": "onboarding_update_missing"}
        if len(updates) != 1:
            return {"success": False, "category": "invalid_onboarding_update"}
        envelope = updates[0]
        update = envelope.update
        if (
            envelope.sender_is_bot
            or update.chat_type != "private"
            or update.text != f"/start {challenge}"
            or update.user_id <= 0
            or update.chat_id <= 0
        ):
            return {"success": False, "category": "onboarding_update_invalid"}
        store.save_allowlist((update.user_id, update.chat_id))
        store.delete_challenge(challenge)
        transport.send_message(update.chat_id, "MAPIT smoke check")
        return {"success": True, "category": "success", "get_updates": True, "send_message": True}
    except TelegramBotError as exc:
        return {"success": False, "category": exc.category}
    except Exception:
        return {"success": False, "category": "smoke_failed"}


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--allow-get-updates", action="store_true")
    parser.add_argument("--allow-send-message", action="store_true")
    args = parser.parse_args()
    try:
        store = WindowsKeyringTelegramCredentialStore()
    except Exception:
        result = {"success": False, "category": "credential_store_failed"}
    else:
        result = run_live_smoke(
            store,
            allow_get_updates=args.allow_get_updates,
            allow_send_message=args.allow_send_message,
        )
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
