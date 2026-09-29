"""Bounded, injectable Telegram Bot API transport.

This module has no polling side effect at import time.  The production seam
loads credentials only from the Windows Credential Manager store; tests inject
an in-memory transport and never open a socket.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .telegram_adapter import TelegramAccessPolicy, TelegramAdapter, TelegramDispatchResult, TelegramSender, TelegramUpdate
from .telegram_credentials import TelegramCredentialStoreError, TelegramCredentials

MAX_UPDATES = 1
MAX_TIMEOUT_SECONDS = 25.0
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TEXT_CHARS = 4096
_BOT_TOKEN_RE = re.compile(r"\A[0-9]{1,20}:[A-Za-z0-9_-]{16,128}\Z")


class TelegramBotError(RuntimeError):
    """Safe public category; token, URL and response body never escape."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class TelegramBotTransportProtocol(Protocol):
    def get_me(self) -> bool: ...
    def get_webhook_info(self) -> bool: ...
    def get_updates(self, *, timeout_seconds: float = MAX_TIMEOUT_SECONDS, offset: int | None = None) -> tuple["TelegramIncomingUpdate", ...]: ...
    def send_message(self, chat_id: int, text: str) -> None: ...


@dataclass(frozen=True)
class TelegramIncomingUpdate:
    update: TelegramUpdate
    sender_is_bot: bool


class BotApiTransport:
    """Synchronous stdlib transport with bounded response and timeout."""

    def __init__(
        self,
        token: str,
        *,
        opener: Callable[..., Any] | None = None,
        api_base: str = "https://api.telegram.org",
        timeout_seconds: float = MAX_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(token, str) or not _BOT_TOKEN_RE.fullmatch(token) or "\x00" in token:
            raise TelegramBotError("invalid_configuration")
        if api_base != "https://api.telegram.org":
            raise TelegramBotError("invalid_configuration")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise TelegramBotError("invalid_configuration")
        self._token = token
        self._opener = opener or urllib.request.urlopen
        self._api_base = api_base.rstrip("/")
        self._timeout = float(timeout_seconds)

    def __repr__(self) -> str:
        return "BotApiTransport(<redacted>)"

    def _call(self, method: str, payload: Mapping[str, Any]) -> Any:
        body = json.dumps(dict(payload), ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            f"{self._api_base}/bot{self._token}/{method}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            response = self._opener(request, timeout=self._timeout)
            try:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
            raise TelegramBotError("transport_failed") from None
        if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
            raise TelegramBotError("response_too_large")
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise TelegramBotError("invalid_response") from None
        if not isinstance(parsed, dict) or parsed.get("ok") is not True or "result" not in parsed:
            raise TelegramBotError("api_rejected")
        return parsed["result"]

    def get_me(self) -> bool:
        result = self._call("getMe", {})
        return isinstance(result, dict) and type(result.get("is_bot")) is bool and result["is_bot"] is True

    def get_webhook_info(self) -> bool:
        result = self._call("getWebhookInfo", {})
        return isinstance(result, dict) and result.get("url") == ""

    def get_updates(self, *, timeout_seconds: float = MAX_TIMEOUT_SECONDS, offset: int | None = None) -> tuple[TelegramIncomingUpdate, ...]:
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or not 0 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
            raise TelegramBotError("invalid_configuration")
        payload: dict[str, Any] = {"limit": MAX_UPDATES, "timeout": int(timeout_seconds), "allowed_updates": ["message"]}
        if offset is not None:
            if type(offset) is not int or offset < 0:
                raise TelegramBotError("invalid_configuration")
            payload["offset"] = offset
        result = self._call("getUpdates", payload)
        if not isinstance(result, list) or len(result) > MAX_UPDATES:
            raise TelegramBotError("invalid_response")
        updates: list[TelegramIncomingUpdate] = []
        for raw in result:
            if not isinstance(raw, dict):
                raise TelegramBotError("invalid_response")
            message = raw.get("message")
            sender = message.get("from") if isinstance(message, dict) else None
            if not isinstance(sender, dict) or type(sender.get("is_bot")) is not bool:
                raise TelegramBotError("invalid_response")
            try:
                update = TelegramUpdate.from_mapping(raw)
            except Exception:
                # Onboarding intentionally accepts only private text updates;
                # all malformed/group updates fail closed without exposing raw data.
                raise TelegramBotError("invalid_response") from None
            updates.append(TelegramIncomingUpdate(update, sender["is_bot"]))
        return tuple(updates)

    def send_message(self, chat_id: int, text: str) -> None:
        if type(chat_id) is not int or chat_id <= 0 or not isinstance(text, str) or not text or len(text) > MAX_TEXT_CHARS:
            raise TelegramBotError("invalid_configuration")
        self._call("sendMessage", {"chat_id": chat_id, "text": text})


class TelegramBotSender(TelegramSender):
    def __init__(self, transport: TelegramBotTransportProtocol) -> None:
        self._transport = transport

    async def send_message(self, chat_id: int, text: str) -> None:
        import asyncio

        await asyncio.to_thread(self._transport.send_message, chat_id, text)


@dataclass(frozen=True)
class TelegramPollResult:
    success: bool
    category: str
    update_processed: bool = False
    message_sent: bool = False


class TelegramBotPoller:
    """One sequential bounded cycle using only stored credentials."""

    def __init__(
        self,
        store: Any,
        backend: Any,
        *,
        transport_factory: Callable[[str], TelegramBotTransportProtocol] = BotApiTransport,
        timeout_seconds: float = MAX_TIMEOUT_SECONDS,
    ) -> None:
        self._store = store
        self._backend = backend
        self._transport_factory = transport_factory
        self._timeout = timeout_seconds
        self._next_offset: int | None = None

    def poll_once(self) -> TelegramPollResult:
        try:
            credentials = self._store.load()
        except Exception:
            return TelegramPollResult(False, "credential_store_failed")
        if not isinstance(credentials, TelegramCredentials):
            return TelegramPollResult(False, "no_saved_credentials")
        try:
            transport = self._transport_factory(credentials.token)
            if transport.get_me() is not True or transport.get_webhook_info() is not True:
                return TelegramPollResult(False, "bot_identity_failed")
            updates = transport.get_updates(timeout_seconds=self._timeout, offset=self._next_offset)
            if updates:
                self._next_offset = max(item.update.update_id for item in updates) + 1
            adapter = TelegramAdapter(TelegramAccessPolicy(credentials.allowed_pairs), self._backend, TelegramBotSender(transport))
            processed = False
            sent = False
            for envelope in updates:
                update = envelope.update
                processed = True
                if envelope.sender_is_bot or update.text.strip().startswith("/start"):
                    # Onboarding is deliberately side-effect free here; the
                    # allowlist is configured in Credential Manager instead.
                    continue
                result: TelegramDispatchResult = _run_async(adapter.process_update(update))
                if result.sent:
                    sent = True
                if not result.success:
                    return TelegramPollResult(False, "adapter_failed", True, sent)
            return TelegramPollResult(True, "success", processed, sent)
        except TelegramBotError as exc:
            return TelegramPollResult(False, exc.category)
        except TelegramCredentialStoreError:
            return TelegramPollResult(False, "credential_store_failed")
        except Exception:
            return TelegramPollResult(False, "transport_failed")


def _run_async(awaitable: Any) -> Any:
    """Run the adapter's one async critical section without a worker thread."""
    import asyncio

    return asyncio.run(awaitable)


__all__ = [
    "BotApiTransport",
    "MAX_RESPONSE_BYTES",
    "MAX_TIMEOUT_SECONDS",
    "MAX_UPDATES",
    "TelegramBotError",
    "TelegramIncomingUpdate",
    "TelegramBotPoller",
    "TelegramBotSender",
    "TelegramBotTransportProtocol",
    "TelegramPollResult",
]
