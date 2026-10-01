"""Experimental stateless HTTP transport for fixed synthetic-only MAPIT data."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Mapping
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp, Receive, Scope, Send

from .analytics import (
    DistanceBreakdown,
    RouteExtremes,
    RoutePeriodComparison,
    RouteStatistics,
)
from .mcp_server import create_server
from .services import (
    DateRangeInput,
    DistanceComparison,
    DistanceResult,
    Position,
    RouteDetail,
    RouteList,
    RouteSummary,
    VehicleDetails,
    VehicleStatus,
)

_MAX_REQUEST_BYTES = 2 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_TOKEN_BYTES = 8192
_MAX_KEYS = 8
_MAX_KEY_BYTES = 8192
_MAX_REQUEST_HEADERS = 64
_MAX_REQUEST_HEADER_BYTES = 32 * 1024
_MAX_DEADLINE_SECONDS = 60.0
_REQUIRED_SCOPE = "mapit:read"
_ALLOWED_JWT_HEADER_FIELDS = frozenset({"alg", "typ", "kid"})
_SAFE_ERRORS = {
    400: b'{"error":"invalid_request"}',
    403: b'{"error":"insufficient_scope"}',
    405: b'{"error":"method_not_allowed"}',
    413: b'{"error":"request_too_large"}',
    500: b'{"error":"internal_error"}',
    502: b'{"error":"response_too_large"}',
    504: b'{"error":"request_timed_out"}',
}


@dataclass(frozen=True)
class RemoteHTTPConfig:
    environment: Literal["dev", "prod"]
    issuer_url: str
    resource_url: str
    audience: str
    client_id: str
    owner_subject: str
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    required_scope: str = _REQUIRED_SCOPE
    max_request_body_bytes: int = _MAX_REQUEST_BYTES
    max_response_body_bytes: int = _MAX_RESPONSE_BYTES
    max_token_bytes: int = _MAX_TOKEN_BYTES
    request_deadline_seconds: float = 15.0

    def __post_init__(self) -> None:
        presets = {
            "dev": (
                "https://issuer.dev.example.invalid",
                "https://mapit.dev.example.invalid/mcp",
                "synthetic-dev-client",
                "synthetic-dev-owner",
                ("mapit.dev.example.invalid",),
                ("https://mapit.dev.example.invalid",),
            ),
            "prod": (
                "https://issuer.prod.example.invalid",
                "https://mapit.prod.example.invalid/mcp",
                "synthetic-prod-client",
                "synthetic-prod-owner",
                ("mapit.prod.example.invalid",),
                ("https://mapit.prod.example.invalid",),
            ),
        }
        if self.environment not in presets:
            raise ValueError("unsupported HTTP environment")
        issuer, resource, client, subject, hosts, origins = presets[self.environment]
        if (
            self.issuer_url != issuer
            or self.resource_url != resource
            or self.audience != resource
            or self.client_id != client
            or self.owner_subject != subject
            or self.allowed_hosts != hosts
            or self.allowed_origins != origins
            or self.required_scope != _REQUIRED_SCOPE
        ):
            raise ValueError("HTTP environment configuration does not match its immutable preset")
        _validate_url(self.issuer_url, origin_only=False)
        _validate_url(self.resource_url, origin_only=False)
        if self.allowed_hosts != tuple(self.allowed_hosts) or not self.allowed_hosts:
            raise ValueError("invalid allowed hosts")
        for host in self.allowed_hosts:
            if not isinstance(host, str) or not host or "*" in host or "/" in host or "@" in host:
                raise ValueError("invalid allowed hosts")
        if not isinstance(self.allowed_origins, tuple) or not self.allowed_origins:
            raise ValueError("invalid allowed origins")
        for origin in self.allowed_origins:
            _validate_url(origin, origin_only=True)
        if not all(isinstance(item, str) and 1 <= len(item) <= 256 for item in (self.client_id, self.owner_subject)):
            raise ValueError("invalid HTTP identity configuration")
        if type(self.max_request_body_bytes) is not int or not 1024 <= self.max_request_body_bytes <= _MAX_REQUEST_BYTES:
            raise ValueError("request body limit is outside the allowed bounds")
        if type(self.max_response_body_bytes) is not int or not 1024 <= self.max_response_body_bytes <= _MAX_RESPONSE_BYTES:
            raise ValueError("response body limit is outside the allowed bounds")
        if type(self.max_token_bytes) is not int or not 512 <= self.max_token_bytes <= _MAX_TOKEN_BYTES:
            raise ValueError("token limit is outside the allowed bounds")
        try:
            deadline = float(self.request_deadline_seconds)
        except (TypeError, ValueError, OverflowError):
            raise ValueError("request deadline is outside the allowed bounds") from None
        if (
            isinstance(self.request_deadline_seconds, bool)
            or not isinstance(self.request_deadline_seconds, (int, float))
            or not math.isfinite(deadline)
            or not 0.01 <= deadline <= _MAX_DEADLINE_SECONDS
        ):
            raise ValueError("request deadline is outside the allowed bounds")


def _validate_url(value: str, *, origin_only: bool) -> None:
    if not isinstance(value, str) or len(value) > 512:
        raise ValueError("invalid HTTP URL setting")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or "\r" in value
        or "\n" in value
        or (origin_only and parsed.path not in {"", "/"})
    ):
        raise ValueError("invalid HTTP URL setting")


def dev_http_config(**bounded_overrides: Any) -> RemoteHTTPConfig:
    """Return the immutable synthetic development policy."""
    from dataclasses import replace

    selected = RemoteHTTPConfig(
        environment="dev",
        issuer_url="https://issuer.dev.example.invalid",
        resource_url="https://mapit.dev.example.invalid/mcp",
        audience="https://mapit.dev.example.invalid/mcp",
        client_id="synthetic-dev-client",
        owner_subject="synthetic-dev-owner",
        allowed_hosts=("mapit.dev.example.invalid",),
        allowed_origins=("https://mapit.dev.example.invalid",),
    )
    return replace(selected, **bounded_overrides) if bounded_overrides else selected


def prod_http_config(**bounded_overrides: Any) -> RemoteHTTPConfig:
    """Return the immutable synthetic production-isolation policy (not a deployment profile)."""
    from dataclasses import replace

    selected = RemoteHTTPConfig(
        environment="prod",
        issuer_url="https://issuer.prod.example.invalid",
        resource_url="https://mapit.prod.example.invalid/mcp",
        audience="https://mapit.prod.example.invalid/mcp",
        client_id="synthetic-prod-client",
        owner_subject="synthetic-prod-owner",
        allowed_hosts=("mapit.prod.example.invalid",),
        allowed_origins=("https://mapit.prod.example.invalid",),
    )
    return replace(selected, **bounded_overrides) if bounded_overrides else selected


class FixedRS256TokenVerifier:
    """Verify tokens offline against a fixed injected public-key set."""

    def __init__(self, config: RemoteHTTPConfig, public_keys: Mapping[str, bytes | str]) -> None:
        if not isinstance(public_keys, Mapping) or not 1 <= len(public_keys) <= _MAX_KEYS:
            raise ValueError("invalid public key set")
        parsed: dict[str, RSAPublicKey] = {}
        for kid, pem in public_keys.items():
            if not isinstance(kid, str) or not kid or len(kid) > 128 or "\r" in kid or "\n" in kid:
                raise ValueError("invalid public key identifier")
            if not isinstance(pem, (bytes, str)):
                raise ValueError("invalid public key material")
            encoded = pem.encode("ascii", errors="strict") if isinstance(pem, str) else pem
            if len(encoded) > _MAX_KEY_BYTES:
                raise ValueError("public key material exceeds the bound")
            try:
                key = serialization.load_pem_public_key(encoded)
            except (TypeError, ValueError):
                raise ValueError("public key material is invalid") from None
            if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                raise ValueError("public key must be RSA with at least 2048 bits")
            parsed[kid] = key
        self._config = config
        self._keys = MappingProxyType(parsed)

    async def verify_token(self, token: str) -> AccessToken | None:
        if (
            not isinstance(token, str)
            or not token
            or len(token) > self._config.max_token_bytes
            or len(token.encode("utf-8", errors="ignore")) > self._config.max_token_bytes
        ):
            return None
        try:
            header = jwt.get_unverified_header(token)
            if (
                not isinstance(header, dict)
                or set(header) - _ALLOWED_JWT_HEADER_FIELDS
                or header.get("alg") != "RS256"
                or header.get("typ") not in {None, "JWT"}
                or not isinstance(header.get("kid"), str)
            ):
                return None
            key = self._keys.get(header["kid"])
            if key is None:
                return None
            claims = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                options={
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "require": ["iss", "aud", "sub", "client_id", "token_use", "exp", "iat"],
                },
            )
            if (
                not isinstance(claims, dict)
                or claims.get("iss") != self._config.issuer_url
                or type(claims.get("aud")) is not str
                or claims["aud"] != self._config.audience
                or claims.get("client_id") != self._config.client_id
                or claims.get("sub") != self._config.owner_subject
                or claims.get("token_use") != "access"
            ):
                return None
            now = int(time.time())
            exp, issued = claims.get("exp"), claims.get("iat")
            nbf = claims.get("nbf")
            if (
                type(exp) is not int
                or type(issued) is not int
                or not 0 <= exp <= 253402300799
                or not 0 <= issued <= 253402300799
                or exp <= now
                or issued > now
                or exp <= issued
                or ("nbf" in claims and (type(nbf) is not int or not 0 <= nbf <= 253402300799 or nbf > now))
            ):
                return None
            raw_scope = claims.get("scope")
            scopes = [self._config.required_scope] if raw_scope == self._config.required_scope else []
            return AccessToken(
                token=token,
                client_id=self._config.client_id,
                scopes=scopes,
                expires_at=exp,
                resource=self._config.audience,
                subject=self._config.owner_subject,
                claims={"iss": self._config.issuer_url},
            )
        except Exception:
            # Deliberately suppress JWT parser/signature diagnostics and token material.
            return None


class SyntheticServicesProvider:
    """Fixed offline service provider; intentionally has no client/provider injection."""

    def __init__(self) -> None:
        self.dispatch_count = 0

    def get(self) -> SyntheticServicesProvider:
        return self

    def _record(self) -> None:
        self.dispatch_count += 1

    def get_vehicle_status(self) -> VehicleStatus:
        self._record()
        return VehicleStatus(status="SYNTHETIC", position=Position())

    def get_vehicle_details(self) -> VehicleDetails:
        self._record()
        return VehicleDetails()

    def list_routes(self, from_time: str, to_time: str) -> RouteList:
        self._record()
        route = RouteSummary(route_id="synthetic-route", started_at="2026-01-01T00:00:00Z", distance=0.0)
        return RouteList(
            from_time=from_time,
            to_time=to_time,
            routes=[route],
            matched_routes=1,
            returned_routes=1,
            truncated=False,
        )

    def get_route_detail(self, route_id: str) -> RouteDetail:
        self._record()
        return RouteDetail(route_id=route_id, geojson={"type": "FeatureCollection", "features": []})

    def get_distance(self, from_time: str, to_time: str) -> DistanceResult:
        self._record()
        return DistanceResult(from_time=from_time, to_time=to_time, distance=0.0, distance_km=0.0, route_count=0)

    def compare_distance_periods(self, period_a: DateRangeInput, period_b: DateRangeInput) -> DistanceComparison:
        self._record()
        first = self.get_distance(period_a.from_time, period_a.to_time)
        second = self.get_distance(period_b.from_time, period_b.to_time)
        return DistanceComparison(
            period_a=first,
            period_b=second,
            absolute_difference=0.0,
            absolute_difference_km=0.0,
            signed_difference=0.0,
            signed_difference_km=0.0,
            percentage_difference=None,
        )

    def get_route_statistics(self, from_time: str, to_time: str) -> RouteStatistics:
        self._record()
        return RouteStatistics(
            from_time=from_time,
            to_time=to_time,
            total_distance=0.0,
            total_distance_km=0.0,
            observed_route_count=0,
            average_route_distance=None,
            average_route_distance_km=None,
            elapsed_duration_seconds=0.0,
            maximum_speed=None,
        )

    def get_distance_breakdown(self, from_time: str, to_time: str, group_by: str) -> DistanceBreakdown:
        self._record()
        return DistanceBreakdown(from_time=from_time, to_time=to_time, group_by=group_by, buckets=[])

    def get_route_extremes(self, from_time: str, to_time: str) -> RouteExtremes:
        self._record()
        return RouteExtremes(
            from_time=from_time,
            to_time=to_time,
            longest_route=None,
            most_distance_day=None,
            most_distance_month=None,
            maximum_speed=None,
        )

    def compare_route_periods(self, period_a: DateRangeInput, period_b: DateRangeInput) -> RoutePeriodComparison:
        self._record()
        first = self.get_route_statistics(period_a.from_time, period_a.to_time)
        second = self.get_route_statistics(period_b.from_time, period_b.to_time)
        return RoutePeriodComparison(
            period_a=first,
            period_b=second,
            distance_difference=0.0,
            distance_difference_km=0.0,
            distance_percentage_change=None,
            observed_route_count_difference=0,
            observed_route_count_percentage_change=None,
            elapsed_duration_difference_seconds=0.0,
            elapsed_duration_percentage_change=None,
        )


class _BoundedHTTPMiddleware:
    def __init__(self, app: ASGIApp, config: RemoteHTTPConfig) -> None:
        self.app = app
        self.config = config
        self.allowed_hosts = frozenset(host.casefold() for host in config.allowed_hosts)
        self.allowed_origins = frozenset(config.allowed_origins)

    async def _safe_response(self, send: Send, status: int) -> None:
        body = _SAFE_ERRORS.get(status, _SAFE_ERRORS[500])
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"cache-control", b"no-store"),
        ]
        if status == 405:
            headers.append((b"allow", b"POST"))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": headers,
            }
        )
        await send({"type": "http.response.body", "body": body, "more_body": False})

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        raw_headers = scope.get("headers", [])
        if not isinstance(raw_headers, list) or len(raw_headers) > _MAX_REQUEST_HEADERS:
            await self._safe_response(send, 400)
            return
        headers: dict[bytes, list[bytes]] = {}
        header_bytes = 0
        for name, value in raw_headers:
            if not isinstance(name, bytes) or not isinstance(value, bytes):
                await self._safe_response(send, 400)
                return
            header_bytes += len(name) + len(value)
            if header_bytes > _MAX_REQUEST_HEADER_BYTES:
                await self._safe_response(send, 400)
                return
            headers.setdefault(name.lower(), []).append(value)
        hosts = headers.get(b"host", [])
        origins = headers.get(b"origin", [])
        auth_headers = headers.get(b"authorization", [])
        lengths = headers.get(b"content-length", [])
        if (
            len(hosts) != 1
            or hosts[0].decode("latin-1").casefold() not in self.allowed_hosts
            or len(origins) > 1
            or (origins and origins[0].decode("latin-1") not in self.allowed_origins)
            or len(auth_headers) > 1
            or len(lengths) > 1
        ):
            await self._safe_response(send, 400)
            return
        if auth_headers and len(auth_headers[0]) > self.config.max_token_bytes + 7:
            await self._safe_response(send, 400)
            return
        if lengths:
            try:
                declared_length = int(lengths[0])
            except (TypeError, ValueError):
                await self._safe_response(send, 400)
                return
            if declared_length < 0 or declared_length > self.config.max_request_body_bytes:
                await self._safe_response(send, 413)
                return

        deadline = asyncio.get_running_loop().time() + float(self.config.request_deadline_seconds)
        body = bytearray()
        try:
            async with asyncio.timeout(max(0.001, deadline - asyncio.get_running_loop().time())):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        await self._safe_response(send, 400)
                        return
                    if message["type"] != "http.request":
                        continue
                    chunk = message.get("body", b"")
                    if not isinstance(chunk, bytes):
                        await self._safe_response(send, 400)
                        return
                    if len(chunk) > self.config.max_request_body_bytes - len(body):
                        await self._safe_response(send, 413)
                        return
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await self._safe_response(send, 504)
            return
        except Exception:
            await self._safe_response(send, 400)
            return
        if lengths and int(lengths[0]) != len(body):
            await self._safe_response(send, 400)
            return
        if scope.get("path") == "/mcp" and scope.get("method") != "POST":
            await self._safe_response(send, 405)
            return

        delivered_body = False

        async def buffered_receive() -> dict[str, Any]:
            nonlocal delivered_body
            if not delivered_body:
                delivered_body = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        response_events: list[dict[str, Any]] = []
        response_bytes = 0

        async def buffered_send(message: dict[str, Any]) -> None:
            nonlocal response_bytes
            if message["type"] == "http.response.body":
                response_bytes += len(message.get("body", b""))
                if response_bytes > self.config.max_response_body_bytes:
                    raise OverflowError
            if len(response_events) >= 1024:
                raise OverflowError
            response_events.append(message)

        try:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError
            async with asyncio.timeout(remaining):
                await self.app(scope, buffered_receive, buffered_send)
        except TimeoutError:
            await self._safe_response(send, 504)
            return
        except OverflowError:
            await self._safe_response(send, 502)
            return
        except Exception:
            await self._safe_response(send, 500)
            return
        if not response_events or response_events[0].get("type") != "http.response.start":
            await self._safe_response(send, 500)
            return
        if asyncio.get_running_loop().time() >= deadline:
            await self._safe_response(send, 504)
            return
        for event in response_events:
            await send(event)


def create_synthetic_http_app(
    config: RemoteHTTPConfig,
    public_keys: Mapping[str, bytes | str],
):
    """Create an offline-only, authenticated stateless MCP ASGI app."""
    if type(config) is not RemoteHTTPConfig:
        raise ValueError("a validated synthetic HTTP config is required")
    provider = SyntheticServicesProvider()
    verifier = FixedRS256TokenVerifier(config, public_keys)
    server = create_server(
        provider,
        auth_settings=AuthSettings(
            issuer_url=config.issuer_url,
            resource_server_url=config.resource_url,
            validate_token_resource=True,
            required_scopes=[config.required_scope],
        ),
        token_verifier=verifier,
    )
    sdk_app = server.streamable_http_app(
        json_response=True,
        stateless_http=True,
        max_request_body_size=config.max_request_body_bytes,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.allowed_hosts),
            allowed_origins=list(config.allowed_origins),
        ),
    )
    sdk_app.state.synthetic_services_provider = provider
    wrapped = _BoundedHTTPMiddleware(sdk_app, config)
    wrapped.synthetic_services_provider = provider
    wrapped.router = sdk_app.router
    wrapped.state = sdk_app.state
    return wrapped


__all__ = [
    "FixedRS256TokenVerifier",
    "RemoteHTTPConfig",
    "SyntheticServicesProvider",
    "create_synthetic_http_app",
    "dev_http_config",
    "prod_http_config",
]
