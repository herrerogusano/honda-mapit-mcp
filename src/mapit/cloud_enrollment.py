"""Lazy, explicit cloud composition for the local private enrollment channel.

No clients or credentials are obtained at construction. The short cloud lease
begins after authenticated form submission. Production/default entrypoints and
historical hosted operators do not import or activate this composition.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import re
import time
from typing import Any, Callable

from .aws_enrollment_clients import create_enrollment_clients
from .aws_identity_binding import DynamoDBIdentityBindingRegistry
from .aws_identity_binding_publisher import AwsIdentityBindingPublisher
from .config import MapitConfig
from .durable_tenants import DurableTenantGuard, DurableTenantSnapshot
from .mapit_identity import MapitIdentityVerifier
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority


@dataclass(frozen=True, repr=False)
class EnrollmentCredentials:
    access_key: str = field(repr=False)
    secret_key: str = field(repr=False)
    session_token: str = field(repr=False)

    def __repr__(self) -> str:
        return "EnrollmentCredentials(<redacted>)"


class CloudEnrollmentFactory:
    """Trusted operator composition, not a public signup/credential endpoint."""

    def __init__(self, *, authority: InvitedTenantAuthority, durable_guard: DurableTenantGuard,
                 environment: str, account_id: str, config: MapitConfig,
                 verifier: MapitIdentityVerifier, binding_key: bytes,
                 auth_transport: Callable[..., Any], clock: Callable[[], datetime],
                 credentials_supplier: Callable[[], EnrollmentCredentials],
                 namespace: str = "synthetic",
                 monotonic: Callable[[], float] = time.monotonic):
        if (type(authority) is not InvitedTenantAuthority or type(durable_guard) is not DurableTenantGuard
            or not durable_guard.is_bound_to(authority) or environment != "dev"
            or not authority.matches_environment(environment)
            or type(namespace) is not str or namespace not in {"synthetic", "mapit"}
            or type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
            or account_id == "000000000000" or type(config) is not MapitConfig
            or type(verifier) is not MapitIdentityVerifier or verifier.config is not config
            or config.email is not None or config.password is not None
            or type(binding_key) is not bytes or not 32 <= len(binding_key) <= 64
            or not all(callable(value) for value in (auth_transport, clock, credentials_supplier, monotonic))):
            raise ValueError("cloud_enrollment_configuration_invalid")
        self._authority, self._guard = authority, durable_guard
        self._environment, self._account, self._namespace = environment, account_id, namespace
        self._config, self._verifier, self._key = config, verifier, bytes(binding_key)
        self._transport, self._clock, self._credentials = auth_transport, clock, credentials_supplier
        self._monotonic = monotonic

    def __repr__(self) -> str:
        return "CloudEnrollmentFactory(<redacted>)"

    def __call__(self, *, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot,
                 deadline: float) -> tuple[DynamoDBIdentityBindingRegistry, AwsIdentityBindingPublisher]:
        try:
            self._authority.validate(grant)
            self._guard.check(grant, snapshot)
            credentials = self._credentials()
            if type(credentials) is not EnrollmentCredentials:
                raise ValueError
            clients = create_enrollment_clients(access_key=credentials.access_key,
                secret_key=credentials.secret_key, session_token=credentials.session_token,
                deadline=deadline, monotonic=self._monotonic, include_dynamodb=True)
            self._authority.validate(grant)
            self._guard.check(grant, snapshot)
            registry = DynamoDBIdentityBindingRegistry(clients.dynamodb, clients.dynamodb,
                table_arn=(f"arn:aws:dynamodb:eu-west-1:{self._account}:table/"
                    + ("honda-mapit-mcp-dev-identity-bindings" if self._namespace == "synthetic"
                       else "honda-mapit-mcp-dev-mapit-identity-bindings")),
                account_id=self._account, authority=self._authority, durable_guard=self._guard,
                environment=self._environment, namespace=self._namespace,
                config=self._config, verifier=self._verifier,
                binding_key=self._key, auth_transport=self._transport, clock=self._clock,
                deadline=deadline, monotonic=self._monotonic,
                account_verifier=clients.dynamodb_account_verifier)
            publisher = AwsIdentityBindingPublisher(clients.ssm, authority=self._authority,
                grant=grant, durable_guard=self._guard, snapshot=snapshot,
                environment=self._environment, account_id=self._account,
                account_verifier=clients.account_verifier, deadline=deadline, monotonic=self._monotonic)
            return registry, publisher
        except Exception:
            raise ValueError("cloud_enrollment_configuration_invalid") from None


__all__ = ["CloudEnrollmentFactory", "EnrollmentCredentials"]
