"""Offline/injected invitation-only tenant isolation; not a deployed login flow.

No SDK, credential store, persistence, network, or legacy-owner fallback is
constructed here. Existing single-owner production entrypoints remain unchanged.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
import weakref
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Iterator, Mapping

from .aws_prod_runtime import CognitoProdPolicy
from .aws_dev_runtime import CognitoDevPolicy
from .durable_tenants import DurableTenantError, DurableTenantGuard, DurableTenantSnapshot
from .remote_http import FixedRS256TokenVerifier

MAX_INVITED_TENANTS = 16
_TENANT_KEY = re.compile(r"^tenant-[0-9a-f]{64}$")


class TenantIsolationError(ValueError):
    """Fixed diagnostics only; no caller, token, secret or provider exceptions."""

    def __init__(self, category: str):
        allowed = {"tenant_configuration_invalid", "tenant_unauthorized", "tenant_context_missing",
                   "tenant_context_expired", "tenant_context_already_bound", "tenant_provider_failed",
                   "tenant_provider_reused", "tenant_clock_invalid", "tenant_clock_rollback",
                   "tenant_durable_unauthorized", "tenant_durable_store_failed"}
        self.category = category if category in allowed else "tenant_unauthorized"
        super().__init__(self.category)


def _clock_sample(function: Callable[[], float]) -> float:
    try:
        value = function()
        valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
    except Exception:
        raise TenantIsolationError("tenant_clock_invalid") from None
    if not valid:
        raise TenantIsolationError("tenant_clock_invalid")
    return float(value)


def tenant_key(key: bytes, issuer: str, subject: str) -> str:
    """Opaque server-side lookup key; this function grants no authorization."""
    if (type(key) is not bytes or not 32 <= len(key) <= 64
        or any(type(value) is not str or not 1 <= len(value) <= 512
               or any(ord(c) < 32 for c in value) for value in (issuer, subject))):
        raise TenantIsolationError("tenant_configuration_invalid")
    canonical = json.dumps([issuer, subject], ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "tenant-" + hmac.new(key, b"mapit-tenant-v1\0" + canonical, hashlib.sha256).hexdigest()


@dataclass(frozen=True, repr=False)
class AuthenticatedTenant:
    """A short-lived request grant issued only after fixed-policy JWT verification."""

    key: str
    expires_at: int
    _authority_seal: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "AuthenticatedTenant(<redacted>)"


class InvitedTenantAuthority:
    """Verify against a finite explicit invite list before any provider lookup.

    Each policy pins issuer/resource/client/scope and its own subject. No unsigned
    JWT claim is used to select a session. Revocation invalidates existing grants.
    This is a library boundary, not HTTP/OAuth or Telegram account enrollment.
    """

    def __init__(self, policies: Mapping[str, CognitoProdPolicy | CognitoDevPolicy], public_keys: Mapping[str, bytes | str], *, environment: str = "prod"):
        if not isinstance(policies, Mapping) or not 1 <= len(policies) <= MAX_INVITED_TENANTS:
            raise TenantIsolationError("tenant_configuration_invalid")
        if environment not in {"prod", "dev"}:
            raise TenantIsolationError("tenant_configuration_invalid")
        expected_type = CognitoProdPolicy if environment == "prod" else CognitoDevPolicy
        selected = dict(policies)
        if any(type(key) is not str or not _TENANT_KEY.fullmatch(key)
               or type(policy) is not expected_type for key, policy in selected.items()):
            raise TenantIsolationError("tenant_configuration_invalid")
        identities = {(p.issuer_url, p.owner_subject) for p in selected.values()}
        endpoints = {(p.issuer_url, p.audience, p.client_id, p.required_scope) for p in selected.values()}
        if len(identities) != len(selected) or len(endpoints) != 1:
            raise TenantIsolationError("tenant_configuration_invalid")
        try:
            verifiers = {key: FixedRS256TokenVerifier(policy, public_keys) for key, policy in selected.items()}
        except Exception:
            raise TenantIsolationError("tenant_configuration_invalid") from None
        self._policies = MappingProxyType(selected)
        self._verifiers = MappingProxyType(verifiers)
        self._active = set(selected)
        self._seal_key = secrets.token_bytes(32)
        self._environment = environment

    def __repr__(self) -> str:
        return "InvitedTenantAuthority(<redacted>)"

    def revoke(self, key: str) -> None:
        if type(key) is not str or key not in self._policies:
            raise TenantIsolationError("tenant_unauthorized")
        self._active.discard(key)

    def matches_token_policy(self, policy: CognitoProdPolicy | CognitoDevPolicy) -> bool:
        """Check the shared issuer/resource/client/scope without exposing owners."""
        expected_type = CognitoProdPolicy if self._environment == "prod" else CognitoDevPolicy
        if type(policy) is not expected_type or not self._policies:
            return False
        selected = next(iter(self._policies.values()))
        return (
            policy.issuer_url == selected.issuer_url
            and policy.audience == selected.audience
            and policy.client_id == selected.client_id
            and policy.required_scope == selected.required_scope
        )

    def matches_environment(self, environment: str) -> bool:
        """Return whether this authority is explicitly bound to an environment."""
        return type(environment) is str and environment == self._environment

    async def authenticate(self, token: str) -> AuthenticatedTenant:
        for key, verifier in self._verifiers.items():
            if key not in self._active:
                continue
            result = await verifier.verify_token(token)
            policy = self._policies[key]
            if (result is not None and result.subject == policy.owner_subject
                and result.claims.get("iss") == policy.issuer_url
                and result.scopes == [policy.required_scope]
                and type(result.expires_at) is int):
                grant = AuthenticatedTenant(key, result.expires_at, self._proof(key, result.expires_at))
                self.validate(grant)
                return grant
        raise TenantIsolationError("tenant_unauthorized")

    def _proof(self, key: str, expiry: int) -> bytes:
        payload = json.dumps([key, expiry], separators=(",", ":")).encode("ascii")
        return hmac.new(self._seal_key, b"mapit-invitation-grant-v1\0" + payload, hashlib.sha256).digest()

    def validate(self, grant: AuthenticatedTenant) -> None:
        if (type(grant) is not AuthenticatedTenant
            or type(grant.key) is not str or grant.key not in self._active
            or type(grant.expires_at) is not int or grant.expires_at <= _clock_sample(time.time)
            or type(grant._authority_seal) is not bytes or len(grant._authority_seal) != 32
            or not hmac.compare_digest(grant._authority_seal, self._proof(grant.key, grant.expires_at))):
            raise TenantIsolationError("tenant_unauthorized")


@dataclass(repr=False)
class _RequestState:
    grant: AuthenticatedTenant
    deadline: float
    last_mono: float
    last_wall: float
    active: bool = True
    provider: Any = None
    durable_snapshot: DurableTenantSnapshot | None = None


_SERVICE_METHODS = frozenset({
    "get_vehicle_status", "get_vehicle_details", "list_routes", "get_route_detail",
    "get_distance", "compare_distance_periods", "get_route_statistics", "get_distance_breakdown",
    "get_route_extremes", "compare_route_periods", "get_geographic_summary", "get_summer_geographic_summary",
})


class _RequestServices:
    """Non-escaping authorization proxy; every exposed call rechecks its context."""

    def __init__(self, router: "TenantServicesRouter", state: _RequestState, services: Any):
        self._router, self._bound, self._services = router, state, services

    def __repr__(self) -> str:
        return "TenantRequestServices(<redacted>)"

    def _check(self) -> None:
        if self._router._state() is not self._bound:
            raise TenantIsolationError("tenant_context_missing")

    def __getattr__(self, name: str) -> Any:
        if name not in _SERVICE_METHODS:
            raise TenantIsolationError("tenant_unauthorized")
        self._check()
        def invoke(*args: Any, **kwargs: Any) -> Any:
            self._check()
            try:
                result = getattr(self._services, name)(*args, **kwargs)
            except TenantIsolationError:
                raise
            except Exception:
                raise TenantIsolationError("tenant_provider_failed") from None
            self._check()
            return result
        return invoke


class TenantServicesRouter:
    """Fresh request-local providers selected only by a verified invitation grant.

    The injected factory is responsible for an exact tenant-scoped credential
    reader. No provider or business data is cached between contexts. An async
    child retaining a copied ContextVar is denied after its parent context ends.
    """

    def __init__(
        self,
        authority: InvitedTenantAuthority,
        provider_factory: Callable[[str, float], Any],
        *,
        deadline_provider: Callable[[], float] | None = None,
        authorization_guard: DurableTenantGuard | None = None,
    ):
        if type(authority) is not InvitedTenantAuthority or not callable(provider_factory):
            raise TenantIsolationError("tenant_configuration_invalid")
        if deadline_provider is not None and not callable(deadline_provider):
            raise TenantIsolationError("tenant_configuration_invalid")
        if authorization_guard is not None:
            if type(authorization_guard) is not DurableTenantGuard or not authorization_guard.is_bound_to(authority):
                raise TenantIsolationError("tenant_configuration_invalid")
        self._authority = authority
        self._factory = provider_factory
        self._deadline_provider = deadline_provider
        self._authorization_guard = authorization_guard
        self._context: ContextVar[_RequestState | None] = ContextVar("mapit_tenant_request", default=None)
        self._providers: weakref.WeakValueDictionary[int, Any] = weakref.WeakValueDictionary()
        self._provider_lock = threading.Lock()

    def __repr__(self) -> str:
        return "TenantServicesRouter(<redacted>)"

    def is_bound_to(self, authority: InvitedTenantAuthority) -> bool:
        """Return identity equality; a matching policy is not interchangeable."""
        return self._authority is authority

    @contextmanager
    def bind(self, grant: AuthenticatedTenant) -> Iterator[None]:
        self._authority.validate(grant)
        if self._context.get() is not None:
            raise TenantIsolationError("tenant_context_already_bound")
        start_mono, start_wall = _clock_sample(time.monotonic), _clock_sample(time.time)
        remaining = min(14.0, grant.expires_at - start_wall)
        if not math.isfinite(remaining) or remaining <= 0:
            raise TenantIsolationError("tenant_context_expired")
        deadline = start_mono + remaining
        if self._deadline_provider is not None:
            ceiling = _clock_sample(self._deadline_provider)
            deadline = min(deadline, ceiling)
            if not math.isfinite(deadline - start_mono) or deadline <= start_mono:
                raise TenantIsolationError("tenant_context_expired")
        durable_snapshot = None
        if self._authorization_guard is not None:
            try:
                durable_snapshot = self._authorization_guard.capture(grant)
            except DurableTenantError as exc:
                category = ("tenant_durable_store_failed" if exc.category == "durable_store_failed"
                             else "tenant_durable_unauthorized")
                raise TenantIsolationError(category) from None
        if self._authorization_guard is not None:
            mono, wall = _clock_sample(time.monotonic), _clock_sample(time.time)
            if mono < start_mono or wall < start_wall:
                raise TenantIsolationError("tenant_clock_rollback")
            if mono >= deadline or wall >= grant.expires_at:
                raise TenantIsolationError("tenant_context_expired")
        else:
            # Preserve the historical unguarded router seam: its bind clock
            # sample is the initial one, and expiry is checked on first use.
            mono, wall = start_mono, start_wall
        state = _RequestState(grant, deadline, mono, wall, durable_snapshot=durable_snapshot)
        token = self._context.set(state)
        try:
            yield
        finally:
            state.active = False
            state.provider = None
            self._context.reset(token)

    def _state(self) -> _RequestState:
        state = self._context.get()
        if state is None or not state.active:
            raise TenantIsolationError("tenant_context_missing")
        self._authority.validate(state.grant)
        if self._authorization_guard is not None:
            try:
                self._authorization_guard.check(state.grant, state.durable_snapshot)
            except DurableTenantError as exc:
                category = ("tenant_durable_store_failed" if exc.category == "durable_store_failed"
                             else "tenant_durable_unauthorized")
                raise TenantIsolationError(category) from None
        mono, wall = _clock_sample(time.monotonic), _clock_sample(time.time)
        if mono < state.last_mono or wall < state.last_wall:
            raise TenantIsolationError("tenant_clock_rollback")
        state.last_mono, state.last_wall = mono, wall
        if mono >= state.deadline:
            raise TenantIsolationError("tenant_context_expired")
        return state

    def get(self) -> Any:
        state = self._state()
        try:
            if state.provider is None:
                provider = self._factory(state.grant.key, state.deadline)
                if not callable(getattr(provider, "get", None)):
                    raise TenantIsolationError("tenant_provider_failed")
                # Factory work is deliberately outside the lock. Claiming the
                # returned object is atomic so concurrent contexts cannot both
                # pass the reuse check for the same provider instance.
                with self._provider_lock:
                    self._state()
                    if self._providers.get(id(provider)) is provider:
                        raise TenantIsolationError("tenant_provider_reused")
                    self._providers[id(provider)] = provider
                    state.provider = provider
            result = state.provider.get()
            self._state()
            return _RequestServices(self, state, result)
        except TenantIsolationError:
            raise
        except Exception:
            raise TenantIsolationError("tenant_provider_failed") from None
