"""Private, offline-testable Telegram adapter seams for Phase 5.

This module deliberately contains no Telegram SDK import and no network
transport.  A caller supplies synthetic updates, a Codex backend, and a sender
protocol.  The sender is the only future write boundary and is expected to be a
fake until the separately authorized external gate.
"""

from __future__ import annotations

import asyncio
import inspect
import re
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Awaitable, Mapping, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .agent import AgentAnswer, READ_ONLY_TOOL_NAMES
from .codex_cli_backend import CodexCliResult

MAX_MESSAGE_CHARS = 4096
MAX_DEDUPE_ENTRIES = 64
SAFE_CATEGORIES = frozenset(
    {
        "success",
        "malformed_update",
        "unauthorized",
        "empty_message",
        "command_ignored",
        "oversize_message",
        "duplicate_update",
        "backend_failed",
        "backend_invalid",
        "output_too_long",
        "unsafe_output",
        "sender_failed",
    }
)


class TelegramUpdate(BaseModel):
    """Strict synthetic update projection; no raw Telegram object is retained."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)

    update_id: int = Field(ge=0)
    user_id: int = Field(gt=0)
    chat_id: int = Field(gt=0)
    chat_type: str
    text: str

    @field_validator("chat_type")
    @classmethod
    def _private_only(cls, value: str) -> str:
        if value != "private":
            raise ValueError("private chats only")
        return value

    @field_validator("text")
    @classmethod
    def _valid_text(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("NUL is not accepted")
        return value

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "TelegramUpdate":
        """Project a synthetic/simple or Telegram-shaped mapping without retaining raw data."""
        if not isinstance(raw, Mapping):
            raise ValueError("update must be a mapping")
        if "message" in raw:
            message = raw.get("message")
            if not isinstance(message, Mapping):
                raise ValueError("message is invalid")
            sender = message.get("from")
            chat = message.get("chat")
            if not isinstance(sender, Mapping) or not isinstance(chat, Mapping):
                raise ValueError("sender or chat is invalid")
            projected = {
                "update_id": raw.get("update_id"),
                "user_id": sender.get("id"),
                "chat_id": chat.get("id"),
                "chat_type": chat.get("type"),
                "text": message.get("text"),
            }
        else:
            projected = dict(raw)
        return cls.model_validate(projected)


class TelegramAccessPolicy:
    """Fail-closed allowlist of numeric private `(user_id, chat_id)` pairs."""

    def __init__(self, allowed_pairs: Any) -> None:
        normalized: set[tuple[int, int]] = set()
        if allowed_pairs is None:
            raise ValueError("invalid access policy")
        try:
            pairs = iter(allowed_pairs)
        except TypeError:
            raise ValueError("invalid access policy") from None
        for pair in pairs:
            if (
                not isinstance(pair, tuple)
                or len(pair) != 2
                or type(pair[0]) is not int
                or type(pair[1]) is not int
                or pair[0] <= 0
                or pair[1] <= 0
            ):
                raise ValueError("invalid access pair")
            normalized.add(pair)
        self._allowed_pairs = frozenset(normalized)

    def allows(self, update: TelegramUpdate) -> bool:
        return update.chat_type == "private" and (update.user_id, update.chat_id) in self._allowed_pairs


PrivateTelegramPolicy = TelegramAccessPolicy


class TelegramBackend(Protocol):
    async def ask(self, question: str) -> CodexCliResult: ...


class TelegramSender(Protocol):
    async def send_message(self, chat_id: int, text: str) -> None: ...


@dataclass(frozen=True)
class TelegramDispatchResult:
    success: bool
    sent: bool
    category: str


def _dispatch(category: str, *, sent: bool = False) -> TelegramDispatchResult:
    safe_category = category if category in SAFE_CATEGORIES else "backend_failed"
    return TelegramDispatchResult(safe_category == "success", sent, safe_category)


def format_agent_answer(answer: AgentAnswer) -> str:
    """Render only the strict answer model as bounded plain text."""
    if not isinstance(answer, AgentAnswer):
        raise ValueError("invalid answer")
    parts = [answer.answer.strip()]
    caveats = [caveat.strip() for caveat in answer.caveats if isinstance(caveat, str) and caveat.strip()]
    if caveats:
        parts.append("Caveats: " + "; ".join(caveats))
    if answer.needs_clarification:
        parts.append("Clarification required.")
    rendered = "\n".join(parts)
    if not rendered or len(rendered) > MAX_MESSAGE_CHARS or "\x00" in rendered:
        raise ValueError("output is too long or invalid")
    return rendered


_UUID_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])")
_VIN_RE = re.compile(r"(?i)(?<![A-Z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Z0-9])")
_COORD_PAIR_RE = re.compile(r"(?<![0-9])[-+]?(?:[0-9]{1,3})\.[0-9]+\s*(?:[,;/]|\s)\s*[-+]?(?:[0-9]{1,3})\.[0-9]+(?![0-9])")
_COORD_COMMA_PAIR_RE = re.compile(r"(?<![0-9])[-+]?(?:[0-9]{1,3}),[0-9]+\s*(?:[,;/]|\s+)\s*[-+]?(?:[0-9]{1,3}),[0-9]+(?![0-9])")
_COORD_LABEL_RE = re.compile(
    r"(?ix)(?:"
    r"\b(?:lat(?:itude)?|latitude)\b\s*[\"']?\s*(?::|=)\s*[-+]?[0-9]{1,3}[.,][0-9]+"
    r".{0,80}?\b(?:lon(?:gitude)?|lng)\b\s*[\"']?\s*(?::|=)\s*[-+]?[0-9]{1,3}[.,][0-9]+"
    r"|\b(?:lon(?:gitude)?|lng)\b\s*[\"']?\s*(?::|=)\s*[-+]?[0-9]{1,3}[.,][0-9]+"
    r".{0,80}?\b(?:lat(?:itude)?|latitude)\b\s*[\"']?\s*(?::|=)\s*[-+]?[0-9]{1,3}[.,][0-9]+"
    r")"
)
_COORD_LABEL_WORD_RE = re.compile(r"(?i)\b(?:lat|latitude|lon|lng|longitude)\b")
_NUMERIC_ID_RE = re.compile(r"(?<![0-9])[0-9]{10,}(?![0-9])")
_URL_RE = re.compile(r"(?i)(?:https?://|www\.)[^\s<>()]+")
_SENSITIVE_ASSIGNMENT_RE = re.compile(r"(?i)\b(?:token|api[_-]?key|key|secret|password|authorization)\s*[:=]")
_SENSITIVE_COMPOUND_RE = re.compile(r"(?i)\b(?:access[_-]?key|client[_-]?secret|refresh[_-]?token|id[_-]?token|api[_-]?token)\b")
_TOKEN_RE = re.compile(
    r"(?i)(?:\b(?:bearer\s+|eyJ[a-z0-9_-]{10,}|(?:sk|pk|ghp|glpat|xox[baprs])[-_][a-z0-9_-]{10,})|(?<![A-Za-z0-9])[A-Za-z0-9_-]{32,}(?![A-Za-z0-9]))"
)


def is_channel_safe_text(text: str) -> bool:
    """Conservative lexical gate before the future Telegram sender.

    This intentionally rejects likely identifiers and payload credentials; it
    is not a semantic privacy proof and may require a human-safe rewrite.
    Ordinary dates and single distances remain allowed.
    """
    if not isinstance(text, str) or not text or "\x00" in text:
        return False
    return not any(
        pattern.search(text)
        for pattern in (
            _UUID_RE,
            _VIN_RE,
            _COORD_PAIR_RE,
            _COORD_COMMA_PAIR_RE,
            _COORD_LABEL_RE,
            _COORD_LABEL_WORD_RE,
            _NUMERIC_ID_RE,
            _URL_RE,
            _SENSITIVE_ASSIGNMENT_RE,
            _SENSITIVE_COMPOUND_RE,
            _TOKEN_RE,
        )
    )


class TelegramAdapter:
    """Sequential in-memory dispatcher with bounded duplicate suppression."""

    def __init__(self, policy: TelegramAccessPolicy, backend: TelegramBackend, sender: TelegramSender) -> None:
        self._policy = policy
        self._backend = backend
        self._sender = sender
        self._lock = asyncio.Lock()
        # Values are reservations.  A failed backend/validation can release its
        # reservation; once send starts, the update remains consumed because a
        # sender failure is ambiguous and retrying could duplicate a message.
        self._seen: OrderedDict[int, str] = OrderedDict()

    @staticmethod
    def _parse_update(raw: TelegramUpdate | Mapping[str, Any]) -> TelegramUpdate:
        if isinstance(raw, TelegramUpdate):
            return raw
        return TelegramUpdate.from_mapping(raw)

    async def process_update(self, raw: TelegramUpdate | Mapping[str, Any]) -> TelegramDispatchResult:
        try:
            update = self._parse_update(raw)
        except (TypeError, ValueError, ValidationError):
            return _dispatch("malformed_update")
        if not self._policy.allows(update):
            return _dispatch("unauthorized")
        if not update.text.strip():
            return _dispatch("empty_message")
        if update.text.lstrip().startswith("/"):
            return _dispatch("command_ignored")
        if len(update.text) > MAX_MESSAGE_CHARS:
            return _dispatch("oversize_message")

        async with self._lock:
            if update.update_id in self._seen:
                return _dispatch("duplicate_update")
            self._seen[update.update_id] = "backend"
            self._seen.move_to_end(update.update_id)
            while len(self._seen) > MAX_DEDUPE_ENTRIES:
                self._seen.popitem(last=False)
            try:
                result = self._backend.ask(update.text)
                if inspect.isawaitable(result):
                    result = await result
            except asyncio.CancelledError:
                self._seen.pop(update.update_id, None)
                raise
            except Exception:
                self._seen.pop(update.update_id, None)
                return _dispatch("backend_failed")
            if not isinstance(result, CodexCliResult):
                self._seen.pop(update.update_id, None)
                return _dispatch("backend_invalid")
            if result.category != "success" or not result.success or not isinstance(result.answer, AgentAnswer):
                self._seen.pop(update.update_id, None)
                return _dispatch("backend_failed")
            try:
                text = format_agent_answer(result.answer)
            except (TypeError, ValueError, ValidationError):
                self._seen.pop(update.update_id, None)
                return _dispatch("output_too_long")
            valid_tools = (
                type(result.used_tool_names) is tuple
                and all(type(tool) is str and tool in READ_ONLY_TOOL_NAMES for tool in result.used_tool_names)
                and (result.answer.needs_clarification or bool(result.used_tool_names))
            )
            if not valid_tools:
                self._seen.pop(update.update_id, None)
                return _dispatch("backend_invalid")
            if not is_channel_safe_text(text):
                self._seen.pop(update.update_id, None)
                return _dispatch("unsafe_output")
            self._seen[update.update_id] = "send_started"
            try:
                send_result = self._sender.send_message(update.chat_id, text)
                if inspect.isawaitable(send_result):
                    await send_result
            except asyncio.CancelledError:
                raise
            except Exception:
                return _dispatch("sender_failed")
            self._seen[update.update_id] = "sent"
            return _dispatch("success", sent=True)

    async def handle_update(self, raw: TelegramUpdate | Mapping[str, Any]) -> TelegramDispatchResult:
        """Alias for transport adapters that expose a handler-shaped API."""
        return await self.process_update(raw)


__all__ = [
    "MAX_DEDUPE_ENTRIES",
    "MAX_MESSAGE_CHARS",
    "PrivateTelegramPolicy",
    "TelegramAccessPolicy",
    "TelegramAdapter",
    "TelegramBackend",
    "TelegramDispatchResult",
    "TelegramSender",
    "TelegramUpdate",
    "format_agent_answer",
    "is_channel_safe_text",
]
