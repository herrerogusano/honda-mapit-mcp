"""Opt-in invitation-scoped MCP composition for offline/local validation.

This module does not create credentials, providers, persistence, or network
clients. Its injected router must be built from an ``InvitedTenantAuthority``
and a tenant-isolated provider factory.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import ConfigDict, Field

from .aws_prod_runtime import CognitoProdPolicy
from .remote_http import _BoundedHTTPMiddleware
from .tenant_router import (
    AuthenticatedTenant,
    InvitedTenantAuthority,
    TenantIsolationError,
    TenantServicesRouter,
)

_METHODS = frozenset({
    "get_vehicle_status", "get_vehicle_details", "list_routes", "get_route_detail",
    "get_distance", "compare_distance_periods", "get_route_statistics",
    "get_distance_breakdown", "get_route_extremes", "compare_route_periods",
    "get_geographic_summary", "get_summer_geographic_summary",
})


class InvitedAccessToken(AccessToken):
    """SDK context token with private grant/provenance fields excluded on output."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    token: str = Field(repr=False, exclude=True)
    subject: str | None = Field(default=None, repr=False, exclude=True)
    tenant_grant: Any = Field(repr=False, exclude=True)
    dispatch_proof: bytes = Field(repr=False, exclude=True)

    def __repr__(self) -> str:
        return "InvitedAccessToken(<redacted>)"

    def __str__(self) -> str:
        return "InvitedAccessToken(<redacted>)"


class InvitedTokenVerifier(TokenVerifier):
    """Verify through the finite invite authority, then seal the SDK token."""

    def __init__(self, authority: InvitedTenantAuthority, policy: CognitoProdPolicy):
        if (type(authority) is not InvitedTenantAuthority
            or type(policy) is not CognitoProdPolicy
            or not authority.matches_token_policy(policy)):
            raise ValueError("invitation policy binding is invalid")
        self._authority = authority
        self._policy = policy
        self._seal_key = secrets.token_bytes(32)

    def __repr__(self) -> str:
        return "InvitedTokenVerifier(<redacted>)"

    def _payload(self, token: str, grant: AuthenticatedTenant) -> bytes:
        value = [token, grant.key, grant.expires_at, self._policy.client_id,
                 self._policy.audience, self._policy.required_scope]
        return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")

    async def verify_token(self, token: str) -> InvitedAccessToken | None:
        try:
            grant = await self._authority.authenticate(token)
            self._authority.validate(grant)
            proof = hmac.new(
                self._seal_key, b"mapit-invited-access-v1\0" + self._payload(token, grant), hashlib.sha256
            ).digest()
            return InvitedAccessToken(
                token=token,
                client_id=self._policy.client_id,
                scopes=[self._policy.required_scope],
                expires_at=grant.expires_at,
                resource=self._policy.audience,
                subject=grant.key,
                claims={"iss": self._policy.issuer_url},
                tenant_grant=grant,
                dispatch_proof=proof,
            )
        except Exception:
            return None

    def grant_for(self, value: AccessToken | None) -> AuthenticatedTenant:
        if type(value) is not InvitedAccessToken:
            raise TenantIsolationError("tenant_unauthorized")
        grant = value.tenant_grant
        if type(grant) is not AuthenticatedTenant:
            raise TenantIsolationError("tenant_unauthorized")
        self._authority.validate(grant)
        if (
            value.client_id != self._policy.client_id
            or value.scopes != [self._policy.required_scope]
            or value.expires_at != grant.expires_at
            or value.resource != self._policy.audience
            or value.subject != grant.key
            or value.claims != {"iss": self._policy.issuer_url}
            or type(value.token) is not str
            or not value.token
            or len(value.token) > self._policy.max_token_bytes
        ):
            raise TenantIsolationError("tenant_unauthorized")
        try:
            if len(value.token.encode("utf-8")) > self._policy.max_token_bytes:
                raise TenantIsolationError("tenant_unauthorized")
        except UnicodeError:
            raise TenantIsolationError("tenant_unauthorized") from None
        expected = hmac.new(
            self._seal_key, b"mapit-invited-access-v1\0" + self._payload(value.token, grant), hashlib.sha256
        ).digest()
        if type(value.dispatch_proof) is not bytes or not hmac.compare_digest(value.dispatch_proof, expected):
            raise TenantIsolationError("tenant_unauthorized")
        return grant


class _OperationServices:
    """Resolve the SDK's current token anew for every synchronous operation."""

    def __init__(self, authority: InvitedTenantAuthority, router: TenantServicesRouter,
                 verifier: InvitedTokenVerifier):
        self._authority, self._router, self._verifier = authority, router, verifier

    def __repr__(self) -> str:
        return "InvitedOperationServices(<redacted>)"

    def __getattr__(self, name: str):
        if name not in _METHODS:
            raise ToolError("tenant_unauthorized")

        def invoke(*args: Any, **kwargs: Any) -> Any:
            try:
                # Do not close over a grant in the returned callable. MCP's
                # AuthContextMiddleware/AnyIO context propagation supplies the
                # current request token to this synchronous worker invocation.
                grant = self._verifier.grant_for(get_access_token())
                self._authority.validate(grant)
                with self._router.bind(grant):
                    services = self._router.get()
                    operation = getattr(services, name)
                    result = operation(*args, **kwargs)
                    self._authority.validate(grant)
                    return result
            except TenantIsolationError as exc:
                raise ToolError(exc.category) from None
            except ToolError:
                raise
            except Exception:
                raise ToolError("tenant_provider_failed") from None

        return invoke


class _TenantProviderProxy:
    """Minimal provider interface consumed by the existing MCP tool handlers."""

    def __init__(self, authority: InvitedTenantAuthority, router: TenantServicesRouter,
                 verifier: InvitedTokenVerifier):
        self._authority, self._router, self._verifier = authority, router, verifier

    def __repr__(self) -> str:
        return "TenantProviderProxy(<redacted>)"

    def get(self) -> _OperationServices:
        # Early rejection is useful, but no grant is retained; invoke() repeats
        # extraction and validation immediately around the business operation.
        try:
            self._verifier.grant_for(get_access_token())
        except TenantIsolationError as exc:
            raise ToolError(exc.category) from None
        except Exception:
            raise ToolError("tenant_unauthorized") from None
        return _OperationServices(self._authority, self._router, self._verifier)


def create_invited_mcp_app(
    authority: InvitedTenantAuthority,
    router: TenantServicesRouter,
    policy: CognitoProdPolicy,
    *,
    geographic_queries: bool = False,
):
    """Build a stateless, opt-in MCP ASGI app for a fixed invited tenant set.

    The function accepts only canonical Cognito policies and an explicitly
    tenant-scoped router. Tests should use synthetic identifiers and an ASGI
    transport; this is not a deployment or credential-loading entrypoint.
    """
    if (
        type(authority) is not InvitedTenantAuthority
        or type(router) is not TenantServicesRouter
        or type(policy) is not CognitoProdPolicy
        or not router.is_bound_to(authority)
        or not authority.matches_token_policy(policy)
        or type(geographic_queries) is not bool
    ):
        raise ValueError("explicit invited MCP composition is required")
    verifier = InvitedTokenVerifier(authority, policy)
    provider = _TenantProviderProxy(authority, router, verifier)
    # Register exactly the existing tool surface through its provider interface.
    from .mcp_server import create_server
    # Reuse registration without changing the public/default server factory.
    server = create_server(
        provider,  # type: ignore[arg-type]
        auth_settings=AuthSettings(
            issuer_url=policy.issuer_url,
            resource_server_url=policy.resource_url,
            validate_token_resource=True,
            required_scopes=[policy.required_scope],
        ),
        token_verifier=verifier,
        geographic_queries=geographic_queries,
    )
    sdk_app = server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        max_request_body_size=policy.max_request_body_bytes,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(policy.allowed_hosts),
            allowed_origins=list(policy.allowed_origins),
        ),
    )
    wrapped = _BoundedHTTPMiddleware(sdk_app, policy)
    wrapped.router = sdk_app.router
    wrapped.state = sdk_app.state
    wrapped.invited_authority = authority
    return wrapped


__all__ = ["InvitedAccessToken", "InvitedTokenVerifier", "create_invited_mcp_app"]
