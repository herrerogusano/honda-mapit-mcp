"""Explicit single-owner production composition; no SDK or secret-store defaults.

The injected builder must return a fresh, lazy CloudServicesProvider. Identity
validation and HTTP/Lambda request bounds are reused without changing any
synthetic dev factory. No provider is cached across invocations.
"""

from __future__ import annotations

import math
import time
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings

from .aws_dev_runtime import CognitoDevPolicy, parse_cognito_jwks
from .cloud_provider import CloudServicesProvider
from .lambda_adapter import _build_synthetic_lambda_handler
from .mcp_server import create_server
from .remote_http import FixedRS256TokenVerifier, _BoundedHTTPMiddleware

_INVOCATION_DEADLINE: ContextVar[float | None] = ContextVar("mapit_prod_deadline", default=None)


@dataclass(frozen=True)
class CognitoProdPolicy(CognitoDevPolicy):
    """Distinct production type sharing only canonical identity validation.

    Existing dev factories require exact CognitoDevPolicy and reject this type.
    No dev runtime is constructed or activated by this validation reuse.
    """

    request_deadline_seconds: float = 14.0

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.request_deadline_seconds > 14.0:
            raise ValueError("production deadline must leave serialization reserve")

    @property
    def environment(self) -> str:
        return "prod"


@dataclass(frozen=True)
class AwsProdRuntime:
    policy: CognitoProdPolicy
    public_keys: Mapping[str, bytes]
    lambda_handler: Callable[[Any, Any], dict[str, Any]]


def _unavailable() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": '{"error":"service_unavailable"}',
        "isBase64Encoded": False,
    }


def _build_prod_http_app(policy: CognitoProdPolicy, keys: Mapping[str, bytes | str], provider: CloudServicesProvider):
    if type(policy) is not CognitoProdPolicy or type(provider) is not CloudServicesProvider:
        raise ValueError("explicit production policy and cloud provider required")
    server = create_server(
        provider,
        auth_settings=AuthSettings(
            issuer_url=policy.issuer_url,
            resource_server_url=policy.resource_url,
            validate_token_resource=True,
            required_scopes=[policy.required_scope],
        ),
        token_verifier=FixedRS256TokenVerifier(policy, keys),
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
    return wrapped


def create_aws_prod_runtime(
    policy: CognitoProdPolicy,
    jwks_snapshot: bytes | str,
    *,
    provider_builder: Callable[[float], CloudServicesProvider],
) -> AwsProdRuntime:
    """Compose only explicit bindings; construction performs no upstream reads."""
    if type(policy) is not CognitoProdPolicy or not callable(provider_builder):
        raise ValueError("explicit production composition required")
    keys = parse_cognito_jwks(jwks_snapshot)

    def validate_keys(config: Any, material: Mapping[str, bytes | str]):
        if config is not policy:
            raise ValueError("production identity changed")
        return FixedRS256TokenVerifier(config, material)

    def build_app(config: Any, material: Mapping[str, bytes | str]):
        if type(config) is not CognitoProdPolicy:
            raise ValueError("production policy required")
        deadline = _INVOCATION_DEADLINE.get()
        if type(deadline) is not float or not math.isfinite(deadline) or time.monotonic() >= deadline:
            raise ValueError("production invocation deadline unavailable")
        # Builder is trusted operator composition, not an input from an MCP call.
        # The provider itself must remain lazy until an authenticated tool call.
        provider = provider_builder(deadline)
        return _build_prod_http_app(config, material, provider)

    adapter = _build_synthetic_lambda_handler(
        policy, keys, key_validator=validate_keys, app_builder=build_app
    )

    def handler(event: Any, context: Any) -> dict[str, Any]:
        started = time.monotonic()
        try:
            remaining_ms = context.get_remaining_time_in_millis()
            if type(remaining_ms) is not int or remaining_ms <= 1000:
                return _unavailable()
            budget = min(float(policy.request_deadline_seconds), remaining_ms / 1000.0 - 1.0)
            deadline = started + budget
            if not math.isfinite(deadline) or budget <= 0 or time.monotonic() >= deadline:
                return _unavailable()
        except Exception:
            return _unavailable()
        marker = _INVOCATION_DEADLINE.set(deadline)
        try:
            return adapter(event, context)
        finally:
            _INVOCATION_DEADLINE.reset(marker)

    return AwsProdRuntime(policy, keys, handler)


__all__ = ["AwsProdRuntime", "CognitoProdPolicy", "create_aws_prod_runtime"]
