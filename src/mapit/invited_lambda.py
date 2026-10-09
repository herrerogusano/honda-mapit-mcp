"""Offline opt-in API Gateway v2 handler for an invited-tenant MCP router.

This is a composition library, not a deployment entrypoint. It reuses the
payload-v2 adapter, creates a fresh app per invocation and binds a shared
request-local router to each invocation's fixed deadline. It never constructs
credentials, sessions, providers, or network clients by default.
"""
from __future__ import annotations

import math
from time import monotonic as _monotonic
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from types import MappingProxyType
from typing import Any, Callable

from .aws_prod_runtime import CognitoProdPolicy
from .aws_dev_runtime import CognitoDevPolicy
from .durable_tenants import DurableTenantGuard, TenantAuthorizationStore
from .invited_mcp import create_invited_mcp_app
from .lambda_adapter import _build_synthetic_lambda_handler, _safe_envelope
from .tenant_router import (
    InvitedTenantAuthority,
    TenantIsolationError,
    TenantServicesRouter,
)

_RESERVE_SECONDS = 1.0
_MIN_BUDGET_SECONDS = 0.01


@dataclass(repr=False)
class _InvocationDeadline:
    sampled_at: float
    snapshot_remaining_ms: int
    deadline: float
    clock: Callable[[], float]
    active: bool = True
    last_sample: float = 0.0

    def __repr__(self) -> str:
        return "InvocationDeadline(<redacted>)"

    def sample(self) -> float:
        if not self.active:
            raise TenantIsolationError("tenant_context_expired")
        try:
            now = self.clock()
            if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
                raise ValueError
            now = float(now)
        except Exception:
            raise TenantIsolationError("tenant_clock_invalid") from None
        if now < self.last_sample or now < self.sampled_at:
            raise TenantIsolationError("tenant_clock_rollback")
        self.last_sample = now
        if now >= self.deadline:
            raise TenantIsolationError("tenant_context_expired")
        return now

    def remaining_time_millis(self) -> int:
        try:
            now = self.sample()
        except TenantIsolationError:
            return 0
        elapsed_ms = math.ceil((now - self.sampled_at) * 1000.0)
        source_remaining = max(0, self.snapshot_remaining_ms - elapsed_ms)
        # The reused adapter subtracts its own one-second serialization reserve.
        # This ceiling therefore cannot increase the original Lambda budget.
        ceiling_ms = max(0, math.floor((self.deadline - now + _RESERVE_SECONDS) * 1000.0))
        return min(source_remaining, ceiling_ms)

    def require_deadline(self) -> float:
        self.sample()
        return self.deadline


class _SnapshotContext:
    """Supplies only the already captured Lambda budget to the reused adapter."""

    def __init__(self, state: _InvocationDeadline):
        self._state = state

    def get_remaining_time_in_millis(self) -> int:
        return self._state.remaining_time_millis()


@dataclass(frozen=True, repr=False)
class InvitedLambdaRuntime:
    authority: InvitedTenantAuthority = field(repr=False)
    handler: Callable[[Any, Any], dict[str, Any]] = field(repr=False)

    def __repr__(self) -> str:
        return "InvitedLambdaRuntime(<redacted>)"


def _create_invited_lambda_runtime(
    policy: CognitoProdPolicy | CognitoDevPolicy,
    invited_policies: Mapping[str, CognitoProdPolicy | CognitoDevPolicy],
    public_keys: Mapping[str, bytes | str],
    *,
    provider_factory: Callable[[str, float], Any] | None = None,
    geographic_queries: bool = False,
    contextual_provider_factory: Callable[..., Any] | None = None,
    authorization_store: TenantAuthorizationStore | None = None,
    environment: str = "prod",
) -> InvitedLambdaRuntime:
    """Build an offline handler with a fixed invitation set and lazy providers.

    `provider_factory` receives only an opaque tenant key and an absolute
    monotonic deadline. It is invoked only for an authenticated tool operation.
    The invited policies and public keys are copied by the authority/adapter;
    each Lambda invocation gets a new HTTP/MCP app while the shared router's
    ContextVar scopes each operation and a lock protects provider claims.
    """
    if environment not in {"prod", "dev"}:
        raise ValueError("invited environment is invalid")
    expected_type = CognitoProdPolicy if environment == "prod" else CognitoDevPolicy
    if (
        type(policy) is not expected_type
        or not isinstance(invited_policies, Mapping)
        or not 1 <= len(invited_policies) <= 16
        or any(type(key) is not str or type(value) is not expected_type
               for key, value in invited_policies.items())
        or (provider_factory is None) == (contextual_provider_factory is None)
        or (provider_factory is not None and not callable(provider_factory))
        or (contextual_provider_factory is not None and not callable(contextual_provider_factory))
        or type(geographic_queries) is not bool
        or (authorization_store is not None and (
            not callable(getattr(authorization_store, "get", None))
            or not callable(getattr(authorization_store, "cas", None))
        ))
    ):
        raise ValueError("explicit invited Lambda policy is required")
    if environment == "dev" and (
        authorization_store is None
        or policy.request_deadline_seconds != 14.0
    ):
        raise ValueError("dev invited Lambda requires durable authorization and a 14 second deadline")
    if contextual_provider_factory is not None and (
        environment != "dev" or authorization_store is None or provider_factory is not None
    ):
        raise ValueError("contextual provider factory is DEV-only and requires durable authorization")
    copied_policies = dict(invited_policies)
    policy_snapshot = MappingProxyType(copied_policies)
    if not all(
        policy_snapshot[next(iter(policy_snapshot))].issuer_url == item.issuer_url
        and policy_snapshot[next(iter(policy_snapshot))].audience == item.audience
        and policy_snapshot[next(iter(policy_snapshot))].client_id == item.client_id
        and policy_snapshot[next(iter(policy_snapshot))].required_scope == item.required_scope
        for item in policy_snapshot.values()
    ):
        raise ValueError("invited policies must share one exact token binding")
    first_policy = next(iter(policy_snapshot.values()))
    if (
        policy.issuer_url != first_policy.issuer_url
        or policy.audience != first_policy.audience
        or policy.client_id != first_policy.client_id
        or policy.required_scope != first_policy.required_scope
    ):
        raise ValueError("runtime policy does not match invited token bindings")

    active_deadline: ContextVar[_InvocationDeadline | None] = ContextVar(
        "mapit_invited_lambda_deadline", default=None
    )
    authority_holder: dict[str, InvitedTenantAuthority] = {}
    key_snapshot_holder: dict[str, Mapping[str, bytes | str]] = {}
    router_holder: dict[str, TenantServicesRouter] = {}

    def current_deadline() -> float:
        state = active_deadline.get()
        if state is None:
            raise TenantIsolationError("tenant_context_missing")
        return state.require_deadline()

    def validate_and_build_authority(config: Any, material: Mapping[str, bytes | str]):
        if config is not policy or authority_holder:
            raise ValueError("invited policy changed")
        authority = InvitedTenantAuthority(policy_snapshot, material, environment=environment)
        if not authority.matches_token_policy(policy):
            raise ValueError("invited token binding changed")
        authorization_guard = (
            DurableTenantGuard(authority, authorization_store)
            if authorization_store is not None else None
        )
        router = TenantServicesRouter(
            authority,
            provider_factory,
            contextual_provider_factory=contextual_provider_factory,
            deadline_provider=current_deadline,
            authorization_guard=authorization_guard,
        )
        authority_holder["value"] = authority
        router_holder["value"] = router
        key_snapshot_holder["value"] = material
        return authority

    def build_app(config: Any, material: Mapping[str, bytes | str]):
        authority = authority_holder.get("value")
        router = router_holder.get("value")
        if (
            authority is None
            or router is None
            or material is not key_snapshot_holder.get("value")
            or type(config) is not expected_type
            or replace(config, request_deadline_seconds=policy.request_deadline_seconds) != policy
            or not 0 < config.request_deadline_seconds <= policy.request_deadline_seconds
        ):
            raise ValueError("invited invocation configuration changed")
        state = active_deadline.get()
        if state is None:
            raise TenantIsolationError("tenant_context_missing")
        state.require_deadline()
        return create_invited_mcp_app(
            authority,
            router,
            config,
            geographic_queries=geographic_queries,
        )

    adapter = _build_synthetic_lambda_handler(
        policy,
        public_keys,
        key_validator=validate_and_build_authority,
        app_builder=build_app,
    )
    authority = authority_holder.get("value")
    if authority is None:
        raise ValueError("invited authority initialization failed")

    def handler(event: Any, context: Any) -> dict[str, Any]:
        # Sample monotonic before the one original Lambda-context read. The
        # private shim subtracts all subsequent latency without calling it again.
        try:
            started = _monotonic()
            if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
                return _safe_envelope(504)
            original_remaining = context.get_remaining_time_in_millis()
            sampled_at = _monotonic()
            if (
                type(sampled_at) not in (int, float)
                or not math.isfinite(sampled_at)
                or sampled_at < started
                or type(original_remaining) is not int
                or original_remaining <= 0
            ):
                return _safe_envelope(504)
            budget = min(
                float(policy.request_deadline_seconds),
                original_remaining / 1000.0 - _RESERVE_SECONDS,
            )
            if not math.isfinite(budget) or budget < _MIN_BUDGET_SECONDS:
                return _safe_envelope(504)
            # Anchor once before the potentially slow context getter. Subsequent
            # shim/router checks subtract elapsed time from this fixed endpoint.
            started = float(started)
            deadline = started + budget
            if not math.isfinite(deadline) or float(sampled_at) >= deadline:
                return _safe_envelope(504)
        except Exception:
            return _safe_envelope(504)

        state = _InvocationDeadline(
            sampled_at=started,
            snapshot_remaining_ms=original_remaining,
            deadline=deadline,
            clock=_monotonic,
            last_sample=float(sampled_at),
        )
        marker = active_deadline.set(state)
        try:
            try:
                state.require_deadline()
                result = adapter(event, _SnapshotContext(state))
                state.require_deadline()
                if type(result) is not dict:
                    return _safe_envelope(502)
                return result
            except TenantIsolationError:
                return _safe_envelope(504)
            except Exception:
                return _safe_envelope(500)
        finally:
            state.active = False
            active_deadline.reset(marker)

    return InvitedLambdaRuntime(authority=authority, handler=handler)


def create_invited_lambda_runtime(
    policy: CognitoProdPolicy,
    invited_policies: Mapping[str, CognitoProdPolicy],
    public_keys: Mapping[str, bytes | str],
    *,
    provider_factory: Callable[[str, float], Any],
    geographic_queries: bool = False,
    authorization_store: TenantAuthorizationStore | None = None,
) -> InvitedLambdaRuntime:
    """Build the existing production composition with its historical defaults."""
    return _create_invited_lambda_runtime(
        policy,
        invited_policies,
        public_keys,
        provider_factory=provider_factory,
        geographic_queries=geographic_queries,
        authorization_store=authorization_store,
        environment="prod",
    )


def create_invited_dev_lambda_runtime(
    policy: CognitoDevPolicy,
    invited_policies: Mapping[str, CognitoDevPolicy],
    public_keys: Mapping[str, bytes | str],
    *,
    provider_factory: Callable[[str, float], Any] | None = None,
    authorization_store: TenantAuthorizationStore,
    geographic_queries: bool = False,
    contextual_provider_factory: Callable[..., Any] | None = None,
) -> InvitedLambdaRuntime:
    """Build the explicitly opted-in, durable-authorized DEV composition.

    This factory is intentionally separate from the production entrypoint: it
    accepts only the exact DEV policy type, requires an injected authorization
    store, and never constructs SDK credentials or a default provider.
    """
    return _create_invited_lambda_runtime(
        policy,
        invited_policies,
        public_keys,
        provider_factory=provider_factory,
        contextual_provider_factory=contextual_provider_factory,
        geographic_queries=geographic_queries,
        authorization_store=authorization_store,
        environment="dev",
    )


__all__ = [
    "InvitedLambdaRuntime",
    "create_invited_lambda_runtime",
    "create_invited_dev_lambda_runtime",
]
