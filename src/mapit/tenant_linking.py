"""In-memory, invitation-bound Telegram pair linking primitives.

This module does not authenticate Telegram updates or Cognito tokens itself.
The caller must supply an exact private chat/user pair from a trusted update
and a fresh AuthenticatedTenant issued by InvitedTenantAuthority. No message
text, names, external identifiers, grants, or raw challenges are persisted.
"""
from __future__ import annotations

import asyncio
import hashlib
import math
import re
import secrets
from dataclasses import dataclass, field
from typing import Callable

from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority, TenantIsolationError

_MAX_PENDING = 16
_MAX_BINDINGS = 16
_MAX_CONSUMED_HISTORY = 64
_CHALLENGE_TTL_SECONDS = 300.0
_CHALLENGE_FORMAT = re.compile(r"^[A-Za-z0-9_-]{43}$")


class TenantLinkError(ValueError):
    """Fixed-category linking failure without identifiers or token material."""

    def __init__(self, category: str):
        allowed = {
            "tenant_link_configuration_invalid",
            "tenant_link_pair_invalid",
            "tenant_link_challenge_invalid",
            "tenant_link_challenge_expired",
            "tenant_link_registry_full",
            "tenant_link_already_bound",
            "tenant_link_not_found",
            "tenant_link_grant_invalid",
            "tenant_link_clock_invalid",
            "tenant_link_clock_rollback",
        }
        self.category = category if category in allowed else "tenant_link_challenge_invalid"
        super().__init__(self.category)


@dataclass(frozen=True, repr=False)
class TrustedPrivateTelegramPair:
    """Exact private-chat identity pair supplied by a trusted update adapter.

    Telegram private chats use the user's positive numeric ID as the chat ID.
    Construction validates that invariant but is not a Telegram signature
    check; callers remain responsible for authenticating the update.
    """

    chat_id: int = field(repr=False)
    user_id: int = field(repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.chat_id) is not int
            or type(self.user_id) is not int
            or self.chat_id <= 0
            or self.user_id <= 0
            or self.chat_id != self.user_id
        ):
            raise TenantLinkError("tenant_link_pair_invalid")

    def __repr__(self) -> str:
        return "TrustedPrivateTelegramPair(<redacted>)"


@dataclass(frozen=True, repr=False)
class _Pending:
    digest: bytes = field(repr=False)
    pair: TrustedPrivateTelegramPair = field(repr=False)
    expires_at: float

    def __repr__(self) -> str:
        return "_Pending(<redacted>)"


@dataclass(frozen=True, repr=False)
class _Consumed:
    digest: bytes = field(repr=False)
    expires_at: float

    def __repr__(self) -> str:
        return "_Consumed(<redacted>)"


class TenantLinkChallengeRegistry:
    """Short-lived atomic challenge-to-tenant bindings, held only in RAM."""

    def __init__(
        self,
        authority: InvitedTenantAuthority,
        *,
        clock: Callable[[], float] = __import__("time").monotonic,
        _challenge_factory: Callable[[], str] | None = None,
    ) -> None:
        if type(authority) is not InvitedTenantAuthority or not callable(clock):
            raise TenantLinkError("tenant_link_configuration_invalid")
        if _challenge_factory is not None and not callable(_challenge_factory):
            raise TenantLinkError("tenant_link_configuration_invalid")
        self._authority = authority
        self._clock = clock
        self._challenge_factory = (
            _challenge_factory if _challenge_factory is not None else lambda: secrets.token_urlsafe(32)
        )
        self._last_clock: float | None = None
        self._pending: list[_Pending] = []
        self._consumed: list[_Consumed] = []
        self._by_tenant: dict[str, TrustedPrivateTelegramPair] = {}
        self._by_pair: dict[TrustedPrivateTelegramPair, str] = {}
        self._lock = asyncio.Lock()

    def __repr__(self) -> str:
        return "TenantLinkChallengeRegistry(<redacted>)"

    def _now(self) -> float:
        try:
            value = self._clock()
            if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
                raise TenantLinkError("tenant_link_clock_invalid")
            sampled = float(value)
        except TenantLinkError:
            raise
        except Exception:
            raise TenantLinkError("tenant_link_clock_invalid") from None
        if self._last_clock is not None and sampled < self._last_clock:
            raise TenantLinkError("tenant_link_clock_rollback")
        self._last_clock = sampled
        return sampled

    @staticmethod
    def _pair(pair: TrustedPrivateTelegramPair) -> TrustedPrivateTelegramPair:
        if type(pair) is not TrustedPrivateTelegramPair:
            raise TenantLinkError("tenant_link_pair_invalid")
        return pair

    def _grant_key(self, grant: AuthenticatedTenant) -> str:
        try:
            self._authority.validate(grant)
        except TenantIsolationError:
            raise TenantLinkError("tenant_link_grant_invalid") from None
        return grant.key

    def _purge(self, now: float) -> None:
        self._pending = [entry for entry in self._pending if entry.expires_at > now]
        self._consumed = [entry for entry in self._consumed if entry.expires_at > now]

    async def issue(self, pair: TrustedPrivateTelegramPair) -> str:
        """Issue one opaque challenge; retain only SHA-256(challenge) and pair."""
        exact_pair = self._pair(pair)
        async with self._lock:
            now = self._now()
            self._purge(now)
            if exact_pair in self._by_pair:
                raise TenantLinkError("tenant_link_already_bound")
            if len(self._pending) >= _MAX_PENDING:
                raise TenantLinkError("tenant_link_registry_full")
            try:
                challenge = self._challenge_factory()
            except Exception:
                raise TenantLinkError("tenant_link_configuration_invalid") from None
            if type(challenge) is not str or not _CHALLENGE_FORMAT.fullmatch(challenge):
                raise TenantLinkError("tenant_link_configuration_invalid")
            digest = hashlib.sha256(challenge.encode("ascii")).digest()
            if (
                any(secrets.compare_digest(digest, entry.digest) for entry in self._pending)
                or any(secrets.compare_digest(digest, entry.digest) for entry in self._consumed)
            ):
                raise TenantLinkError("tenant_link_configuration_invalid")
            self._pending.append(_Pending(digest, exact_pair, now + _CHALLENGE_TTL_SECONDS))
            return challenge

    async def consume_bind(
        self,
        challenge: str,
        pair: TrustedPrivateTelegramPair,
        grant: AuthenticatedTenant,
    ) -> str:
        """Atomically consume a challenge and bind its exact pair to a live grant key."""
        exact_pair = self._pair(pair)
        key = self._grant_key(grant)
        if type(challenge) is not str or not _CHALLENGE_FORMAT.fullmatch(challenge):
            raise TenantLinkError("tenant_link_challenge_invalid")
        digest = hashlib.sha256(challenge.encode("ascii")).digest()
        async with self._lock:
            now = self._now()
            self._grant_key(grant)
            match_index = next(
                (index for index, entry in enumerate(self._pending)
                 if secrets.compare_digest(digest, entry.digest)),
                None,
            )
            if match_index is None:
                self._purge(now)
                raise TenantLinkError("tenant_link_challenge_invalid")
            entry = self._pending[match_index]
            if entry.expires_at <= now:
                self._pending.pop(match_index)
                self._purge(now)
                raise TenantLinkError("tenant_link_challenge_expired")
            self._purge(now)
            match_index = next(
                (index for index, pending in enumerate(self._pending)
                 if secrets.compare_digest(digest, pending.digest)),
                None,
            )
            if match_index is None:
                raise TenantLinkError("tenant_link_challenge_invalid")
            entry = self._pending[match_index]
            if entry.pair != exact_pair:
                raise TenantLinkError("tenant_link_challenge_invalid")
            if key in self._by_tenant or exact_pair in self._by_pair:
                raise TenantLinkError("tenant_link_already_bound")
            if len(self._by_tenant) >= _MAX_BINDINGS:
                raise TenantLinkError("tenant_link_registry_full")
            if len(self._consumed) >= _MAX_CONSUMED_HISTORY:
                raise TenantLinkError("tenant_link_registry_full")
            self._consumed.append(_Consumed(entry.digest, entry.expires_at))
            self._pending.pop(match_index)
            self._by_tenant[key] = exact_pair
            self._by_pair[exact_pair] = key
            self._pending = [pending for pending in self._pending if pending.pair != exact_pair]
            return key

    async def resolve(
        self,
        pair: TrustedPrivateTelegramPair,
        grant: AuthenticatedTenant,
    ) -> str:
        """Return the opaque tenant key only after fresh-grant/pair equality checks."""
        exact_pair = self._pair(pair)
        key = self._grant_key(grant)
        async with self._lock:
            self._now()
            self._grant_key(grant)
            if self._by_tenant.get(key) != exact_pair or self._by_pair.get(exact_pair) != key:
                raise TenantLinkError("tenant_link_not_found")
            return key

    async def unlink(self, grant: AuthenticatedTenant) -> bool:
        """Remove this verified tenant binding and invalidate pending pair challenges."""
        key = self._grant_key(grant)
        async with self._lock:
            self._now()
            self._grant_key(grant)
            pair = self._by_tenant.pop(key, None)
            if pair is None:
                return False
            self._by_pair.pop(pair, None)
            self._pending = [pending for pending in self._pending if pending.pair != pair]
            return True
