"""Bounded, injected, local Telegram delivery; no polling/network construction.

An authenticated Bot API transport must supply updates. The injected resolver
supplies a fresh OAuth grant; the registry independently checks its exact pair
binding. In-memory receipts cover one bounded process, not durable delivery or
an always-on/multi-instance service. Ambiguous sends are never retried here.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Mapping

from .telegram_adapter import TelegramUpdate
from .telegram_geographic_commands import dispatch_geographic_command
from .tenant_linking import TenantLinkChallengeRegistry, TrustedPrivateTelegramPair
from .tenant_router import AuthenticatedTenant, TenantServicesRouter


@dataclass(frozen=True)
class TenantTelegramResult:
    category: str
    sent: bool = False


class BoundedTenantTelegramAdapter:
    """Serialize at most 64 updates with one attempt per numeric update ID.

    Nothing reads credentials by default. The trusted grant resolver must not
    fall back to the owner, and cannot establish a Telegram binding by itself.
    """

    def __init__(self, registry: TenantLinkChallengeRegistry,
                 router: TenantServicesRouter,
                 grant_resolver: Callable[[TelegramUpdate], Awaitable[AuthenticatedTenant]],
                 sender: Any):
        if (type(registry) is not TenantLinkChallengeRegistry
            or type(router) is not TenantServicesRouter or not callable(grant_resolver)
            or not callable(getattr(sender, "send_message", None))):
            raise ValueError("telegram_tenant_configuration_invalid")
        self._registry, self._router = registry, router
        self._resolver, self._sender = grant_resolver, sender
        self._lock = asyncio.Lock()
        self._seen: set[int] = set()

    def __repr__(self) -> str:
        return "BoundedTenantTelegramAdapter(<redacted>)"

    async def handle(self, raw: Mapping[str, Any]) -> TenantTelegramResult:
        try:
            if isinstance(raw, Mapping) and "message" in raw:
                message = raw.get("message")
                sender = message.get("from") if isinstance(message, Mapping) else None
                if not isinstance(sender, Mapping) or sender.get("is_bot") is not False:
                    return TenantTelegramResult("invalid_update")
            update = TelegramUpdate.from_mapping(raw)
            if not 1 <= len(update.text) <= 2048:
                return TenantTelegramResult("invalid_update")
            pair = TrustedPrivateTelegramPair(chat_id=update.chat_id, user_id=update.user_id)
        except Exception:
            return TenantTelegramResult("invalid_update")
        async with self._lock:
            if update.update_id in self._seen:
                return TenantTelegramResult("duplicate_update")
            if len(self._seen) >= 64:
                return TenantTelegramResult("batch_capacity_exhausted")
            # Local intent precedes resolver/business/send; cancellation or an
            # ambiguous sender exception leaves this update consumed.
            self._seen.add(update.update_id)
            try:
                grant = await self._resolver(update)
                await self._registry.resolve(pair, grant)
            except Exception:
                return TenantTelegramResult("unauthorized")
            try:
                answer = dispatch_geographic_command(update.text, grant, self._router)
                if type(answer) is not str or not 1 <= len(answer) <= 4096:
                    return TenantTelegramResult("command_failed")
                # Recheck revocation, grant expiry and unlink after the service
                # call, immediately before the sole permitted write boundary.
                await self._registry.resolve(pair, grant)
            except Exception:
                return TenantTelegramResult("command_failed")
            try:
                await self._sender.send_message(update.chat_id, answer)
            except Exception:
                return TenantTelegramResult("sender_failed_no_retry")
            return TenantTelegramResult("success", sent=True)
