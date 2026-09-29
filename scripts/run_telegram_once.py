"""Run at most two explicitly-authorized Telegram polling cycles.

This is an operational seam, not a background daemon.  It reads the native
Windows store, keeps one poller (and therefore one in-memory offset), and
prints only allowlisted booleans/categories.  No live call is made on import.
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Callable

from mapit.codex_cli_backend import CodexCliBackend
from mapit.telegram_bot import TelegramBotPoller, TelegramPollResult
from mapit.telegram_credentials import WindowsKeyringTelegramCredentialStore

MAX_CYCLES = 2
SAFE_CATEGORIES = frozenset(
    {
        "success",
        "confirmation_required",
        "credential_store_failed",
        "no_saved_credentials",
        "bot_identity_failed",
        "transport_failed",
        "api_rejected",
        "invalid_response",
        "response_too_large",
        "adapter_failed",
        "send_failed",
        "no_update",
        "message_not_sent",
        "poll_failed",
    }
)


def _safe_category(category: object) -> str:
    return category if isinstance(category, str) and category in SAFE_CATEGORIES else "poll_failed"


def run_bounded_cycles(poller: Any, *, max_cycles: int = MAX_CYCLES) -> dict[str, object]:
    """Run sequential cycles, stopping at the first send or safe failure."""
    if max_cycles != MAX_CYCLES:
        return {
            "success": False,
            "category": "poll_failed",
            "cycles": 0,
            "update_processed": False,
            "message_sent": False,
        }
    processed = False
    sent = False
    for cycle in range(1, MAX_CYCLES + 1):
        try:
            result = poller.poll_once()
        except Exception:
            return {
                "success": False,
                "category": "poll_failed",
                "cycles": cycle,
                "update_processed": processed,
                "message_sent": sent,
            }
        if not isinstance(result, TelegramPollResult):
            return {
                "success": False,
                "category": "poll_failed",
                "cycles": cycle,
                "update_processed": processed,
                "message_sent": sent,
            }
        processed = processed or result.update_processed
        sent = sent or result.message_sent
        if not result.success:
            return {
                "success": False,
                "category": _safe_category(result.category),
                "cycles": cycle,
                "update_processed": processed,
                "message_sent": sent,
            }
        if sent:
            return {
                "success": True,
                "category": "success",
                "cycles": cycle,
                "update_processed": processed,
                "message_sent": True,
            }
    return {
        "success": False,
        "category": "message_not_sent" if processed else "no_update",
        "cycles": MAX_CYCLES,
        "update_processed": processed,
        "message_sent": False,
    }


def _emit(result: dict[str, object]) -> None:
    safe = {
        "success": type(result.get("success")) is bool and result["success"],
        "category": _safe_category(result.get("category")),
        "cycles": result.get("cycles") if type(result.get("cycles")) is int else 0,
        "update_processed": type(result.get("update_processed")) is bool and result["update_processed"],
        "message_sent": type(result.get("message_sent")) is bool and result["message_sent"],
    }
    print(json.dumps(safe, ensure_ascii=True, separators=(",", ":")))


def main(
    argv: list[str] | None = None,
    *,
    store_factory: Callable[[], Any] = WindowsKeyringTelegramCredentialStore,
    backend_factory: Callable[[], Any] = CodexCliBackend,
    poller_factory: Callable[[Any, Any], Any] = TelegramBotPoller,
) -> int:
    parser = argparse.ArgumentParser(description="Run two bounded Telegram cycles.")
    parser.add_argument("--allow-poll", action="store_true")
    parser.add_argument("--allow-agent", action="store_true")
    parser.add_argument("--allow-send", action="store_true")
    args = parser.parse_args(argv)
    if not (args.allow_poll and args.allow_agent and args.allow_send):
        result = {
            "success": False,
            "category": "confirmation_required",
            "cycles": 0,
            "update_processed": False,
            "message_sent": False,
        }
        _emit(result)
        return 1
    try:
        store = store_factory()
        backend = backend_factory()
        poller = poller_factory(store, backend)
        result = run_bounded_cycles(poller)
    except Exception:
        result = {
            "success": False,
            "category": "poll_failed",
            "cycles": 0,
            "update_processed": False,
            "message_sent": False,
        }
    _emit(result)
    return 0 if result.get("success") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
