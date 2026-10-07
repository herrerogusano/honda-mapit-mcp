"""Opt-in composition of durable enrollment, tenant secrets and cloud services.

Constructed only from an authenticated grant and explicit injected clients.
No deployment entrypoint, default owner session, SDK or credential discovery.
"""
from __future__ import annotations

import time
from typing import Any, Callable

from .aws_tenant_session_reader import AwsTenantSessionReader
from .cloud_provider import CloudServicesProvider
from .durable_tenants import DurableTenantGuard, DurableTenantSnapshot
from .identity_binding import SQLiteIdentityBindingRegistry
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority

_METHODS = frozenset({
    "get_vehicle_status", "get_vehicle_details", "list_routes", "get_route_detail",
    "get_distance", "compare_distance_periods", "get_route_statistics", "get_distance_breakdown",
    "get_route_extremes", "compare_route_periods", "get_geographic_summary", "get_summer_geographic_summary",
})


class EnrolledProviderError(ValueError):
    def __init__(self, category: str):
        self.category = category if type(category) is str and category in {
            "enrolled_configuration_invalid", "enrolled_unauthorized", "enrolled_provider_failed",
        } else "enrolled_provider_failed"
        super().__init__(self.category)


class _CheckedReader:
    def __init__(self, check: Callable[[], None], reader: AwsTenantSessionReader):
        self._check, self._reader = check, reader

    def read_refresh_token(self, *, deadline: float):
        self._check()
        result = self._reader.read_refresh_token(deadline=deadline)
        self._check()
        return result


class _CheckedServices:
    def __init__(self, check: Callable[[], None], services: Any):
        self._check, self._services = check, services

    def __repr__(self) -> str:
        return "EnrolledServices(<redacted>)"

    def __getattr__(self, name: str):
        if name not in _METHODS:
            raise AttributeError(name)
        def call(*args, **kwargs):
            self._check()
            try:
                result = getattr(self._services, name)(*args, **kwargs)
            except Exception:
                raise EnrolledProviderError("enrolled_provider_failed") from None
            self._check()
            return result
        return call


class EnrolledCloudServicesProvider:
    """Request-local provider with binding checks around secret/business access.

    Registry revocation rejects cached services and discards in-flight results.
    It does not cancel already-started wire calls or erase a published secret.
    The surrounding tenant router remains responsible for request context and
    the original MCP authorization. SQLite is a local backend, not shared AWS
    Lambda persistence; this factory is not wired into any deployed handler.
    """

    def __init__(self, registry: SQLiteIdentityBindingRegistry, *,
                 authority: InvitedTenantAuthority, grant: AuthenticatedTenant,
                 durable_guard: DurableTenantGuard, snapshot: DurableTenantSnapshot,
                 ssm_client: Any, account_id: str, auth_transport: Callable,
                 mapit_transport: Callable, deadline: float,
                 monotonic: Callable[[], float] = time.monotonic):
        if (type(registry) is not SQLiteIdentityBindingRegistry
            or not registry.is_bound_to(authority, durable_guard)):
            raise EnrolledProviderError("enrolled_configuration_invalid")
        self._registry, self._grant, self._snapshot = registry, grant, snapshot
        try:
            self._binding = registry.get_binding(grant, snapshot)
            reader = AwsTenantSessionReader(
                authority, grant, ssm_client, account_id=account_id,
                version=self._binding.secret_version, tier="Standard",
                environment=registry.environment, monotonic=monotonic,
            )
            self._provider = CloudServicesProvider(
                registry.config, _CheckedReader(self._check, reader), auth_transport,
                mapit_transport, deadline=deadline, monotonic=monotonic,
                identity_verifier=registry.verifier,
                expected_identity_proof=self._binding.expected_identity_proof,
            )
        except Exception:
            raise EnrolledProviderError("enrolled_configuration_invalid") from None
        self._services = None

    def __repr__(self) -> str:
        return "EnrolledCloudServicesProvider(<redacted>)"

    def _check(self) -> None:
        try:
            self._registry.validate_binding(self._grant, self._snapshot, self._binding)
        except Exception:
            raise EnrolledProviderError("enrolled_unauthorized") from None

    def get(self) -> Any:
        self._check()
        try:
            services = self._provider.get()
        except EnrolledProviderError:
            raise
        except Exception:
            raise EnrolledProviderError("enrolled_provider_failed") from None
        self._check()
        if self._services is None:
            self._services = _CheckedServices(self._check, services)
        return self._services


__all__ = ["EnrolledCloudServicesProvider", "EnrolledProviderError"]
