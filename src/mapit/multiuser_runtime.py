"""Invitation-only multiuser MCP composition (docs/multiuser-production.md).

Every authenticated request carries an opaque ``mapit_tenant`` claim added by
the pool's pre-token-generation trigger. A per-request proxy builds that
tenant's lazy MAPIT provider through an injected factory; nothing tenant
specific is cached across invocations. Construction performs no AWS call; the
only network access is the injected JWKS fetcher.
"""

from __future__ import annotations

import asyncio
import math
import re
import threading
import time
import urllib.error
import urllib.request
from contextvars import ContextVar
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import ToolAnnotations

from .aws_dev_runtime import parse_cognito_jwks
from .http_transport import ResponseTooLargeError, open_direct, read_bounded
from .lambda_adapter import _build_synthetic_lambda_handler
from .mcp_server import create_server
from .multiuser_common import ENVIRONMENTS, REGION, TENANT_CLAIM, TENANT_ID_RE
from .public_web_service import (
    DELETE_DONE, DELETE_FAILED, DELETE_NO_SESSION, FAILED_DELETE, FAILED_LOGOUT,
    MSG_PUBLIC_DELETE_FAILED, MSG_PUBLIC_DELETE_NO_SESSION, MSG_PUBLIC_EXPIRED,
    MSG_LOGOUT_DONE, MSG_LOGOUT_FAILED, MSG_PUBLIC_DELETE_DONE, MSG_PUBLIC_DELETE_PREVIEW,
    MSG_PUBLIC_LIMIT, MSG_PUBLIC_PAUSED, MSG_PUBLIC_RATE, PUBLIC_READ_TOOLS, PUBLIC_TOOLS,
    REFUSED_EXPIRED, REFUSED_LIMIT, REFUSED_PAUSED, REFUSED_RATE, REFUSED_UNAVAILABLE,
    PublicSessionGate, PublicSessionRefused,
)
from .remote_http import _BoundedHTTPMiddleware
from .services import ServiceError

MSG_NOT_LINKED = (
    "Tu cuenta no está vinculada o se ha dado de baja. Abre de nuevo tu enlace "
    "de invitación o pide uno nuevo."
)
MSG_SESSION_EXPIRED = (
    "Tu sesión de MAPIT ha caducado. Desconecta y vuelve a conectar el conector "
    "e inicia sesión con tu contraseña actual de MAPIT."
)
MSG_UNAVAILABLE = "El servicio no está disponible en este momento. Inténtalo de nuevo más tarde."
MSG_DELETE_PREVIEW = (
    "No se ha borrado nada. Si llamas a borrar_mis_datos con confirmar=true se "
    "borrarán de inmediato tu sesión de MAPIT guardada (cifrada), tu invitación y "
    "tu usuario de este servicio. Tus datos en MAPIT no se modifican. Para volver "
    "a usar el servicio necesitarás una invitación nueva."
)
MSG_DELETE_DONE = (
    "Hecho: se han borrado tu sesión de MAPIT guardada, tu invitación y tu usuario "
    "de este servicio. Desconecta el conector; las próximas peticiones fallarán."
)
MSG_DELETE_FAILED = (
    "No se han podido borrar tus datos ahora mismo. Inténtalo de nuevo más tarde "
    "o pide al administrador que los borre."
)

_INVOCATION_DEADLINE: ContextVar[float | None] = ContextVar("mapit_multiuser_deadline", default=None)
_ISSUER_RE = re.compile(r"^https://cognito-idp\.eu-west-1\.amazonaws\.com/eu-west-1_[A-Za-z0-9]{9,64}$")
_RESOURCE_RE = re.compile(r"^https://([a-z0-9]{10}\.execute-api\.eu-west-1\.amazonaws\.com)/mcp$")
_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9]{1,128}$")
_HOST_RE = re.compile(r"^[a-z0-9.-]{1,253}$")
# An exact browser origin: HTTPS host without port, or the loopback name used by
# a local development server. Never a wildcard, "null", a path or credentials.
_ORIGIN_RE = re.compile(
    r"^(?:https://[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|http://localhost:[1-9][0-9]{3,4})$"
)
_MAX_WEB_ORIGINS = 2
_MAX_BODY = 2 * 1024 * 1024
_MAX_TOKEN = 8192
_MAX_DEADLINE = 14.0
_ALLOWED_JWT_HEADER_FIELDS = frozenset({"alg", "typ", "kid"})
_MAX_EPOCH = 253402300799
_JWKS_MAX_BYTES = 32 * 1024
_JWKS_TIMEOUT_SECONDS = 2.0
_JWKS_REFETCH_SECONDS = 300.0
_DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=True)


class TenantSessionMissing(RuntimeError):
    """The tenant's MAPIT session parameter does not exist (not linked/deleted)."""

    def __init__(self) -> None:
        super().__init__("session_missing")


def _bounded_int(value: Any, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _valid_origin(value: Any) -> bool:
    if type(value) is not str or not _ORIGIN_RE.fullmatch(value):
        return False
    return value.startswith("https://") or 1024 <= int(value.rsplit(":", 1)[1]) <= 65535


@dataclass(frozen=True)
class MultiuserPolicy:
    """Validated identity and HTTP bounds for one multiuser environment."""

    environment: str
    issuer_url: str
    resource_url: str
    client_ids: tuple[str, ...]
    allowed_hosts: tuple[str, ...]
    allowed_origins: tuple[str, ...]
    max_request_body_bytes: int = _MAX_BODY
    max_response_body_bytes: int = _MAX_BODY
    max_token_bytes: int = _MAX_TOKEN
    request_deadline_seconds: float = _MAX_DEADLINE

    def __post_init__(self) -> None:
        if type(self.environment) is not str or self.environment not in ENVIRONMENTS:
            raise ValueError("invalid multiuser environment")
        if type(self.issuer_url) is not str or not _ISSUER_RE.fullmatch(self.issuer_url):
            raise ValueError("invalid issuer")
        match = _RESOURCE_RE.fullmatch(self.resource_url) if type(self.resource_url) is str else None
        if match is None:
            raise ValueError("invalid resource")
        if (
            type(self.client_ids) is not tuple
            or not 1 <= len(self.client_ids) <= 4
            or len(set(self.client_ids)) != len(self.client_ids)
            or any(type(item) is not str or not _CLIENT_ID_RE.fullmatch(item) for item in self.client_ids)
        ):
            raise ValueError("invalid client set")
        if (
            type(self.allowed_hosts) is not tuple
            or not 1 <= len(self.allowed_hosts) <= 4
            or any(type(item) is not str or not _HOST_RE.fullmatch(item) for item in self.allowed_hosts)
            or match.group(1) not in self.allowed_hosts
        ):
            raise ValueError("invalid allowed hosts")
        if (
            type(self.allowed_origins) is not tuple
            or not 1 <= len(self.allowed_origins) <= 4
            or len(set(self.allowed_origins)) != len(self.allowed_origins)
            or any(not _valid_origin(item) for item in self.allowed_origins)
        ):
            raise ValueError("invalid allowed origins")
        if not _bounded_int(self.max_request_body_bytes, 1024, _MAX_BODY):
            raise ValueError("request body limit is outside the allowed bounds")
        if not _bounded_int(self.max_response_body_bytes, 1024, _MAX_BODY):
            raise ValueError("response body limit is outside the allowed bounds")
        if not _bounded_int(self.max_token_bytes, 512, _MAX_TOKEN):
            raise ValueError("token limit is outside the allowed bounds")
        deadline = self.request_deadline_seconds
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or not math.isfinite(deadline)
            or not 0.01 <= deadline <= _MAX_DEADLINE
        ):
            raise ValueError("request deadline is outside the allowed bounds")

    @property
    def audience(self) -> str:
        return self.resource_url

    @property
    def required_scope(self) -> str:
        return f"{self.resource_url}/use"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer_url}/.well-known/jwks.json"


def multiuser_policy(*, environment: str, user_pool_id: str, resource_url: str,
                     client_ids: tuple[str, ...], web_origins: tuple[str, ...] = ()) -> MultiuserPolicy:
    """Derive issuer/host/origin bindings canonically from the pool and MCP URL.

    ``web_origins`` are the exact origins of the static web client (at most two:
    the published site and a local development server). A browser always sends
    ``Origin``; without them every browser request is rejected.
    """
    match = _RESOURCE_RE.fullmatch(resource_url) if type(resource_url) is str else None
    if match is None or type(user_pool_id) is not str:
        raise ValueError("invalid multiuser bindings")
    if type(web_origins) is not tuple or len(web_origins) > _MAX_WEB_ORIGINS:
        raise ValueError("invalid web origins")
    host = match.group(1)
    return MultiuserPolicy(
        environment=environment,
        issuer_url=f"https://cognito-idp.{REGION}.amazonaws.com/{user_pool_id}",
        resource_url=resource_url,
        client_ids=client_ids,
        allowed_hosts=(host,),
        allowed_origins=(f"https://{host}",) + web_origins,
    )


def fetch_jwks_https(url: str) -> bytes:
    """Default JWKS fetcher: direct HTTPS GET, no proxies/redirects, 2 s, 32 KiB."""
    parsed = urlsplit(url) if type(url) is str else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.hostname != f"cognito-idp.{REGION}.amazonaws.com"
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
    ):
        raise ValueError("jwks_url_invalid")
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    response = None
    try:
        response = open_direct(request, timeout=_JWKS_TIMEOUT_SECONDS)
        status = getattr(response, "status", None)
        if status != 200:
            raise ValueError("jwks_fetch_failed")
        return read_bounded(response, _JWKS_MAX_BYTES)
    except (urllib.error.URLError, OSError, ResponseTooLargeError, TimeoutError):
        raise ValueError("jwks_fetch_failed") from None
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass


class JwksCache:
    """Process-wide cache of the pool's public keys with throttled refetch."""

    def __init__(
        self,
        issuer_url: str,
        *,
        fetcher: Callable[[str], bytes] = fetch_jwks_https,
        monotonic: Callable[[], float] = time.monotonic,
        refetch_seconds: float = _JWKS_REFETCH_SECONDS,
    ) -> None:
        if type(issuer_url) is not str or not _ISSUER_RE.fullmatch(issuer_url):
            raise ValueError("invalid issuer")
        if not callable(fetcher) or not callable(monotonic):
            raise ValueError("invalid JWKS cache dependencies")
        self.issuer_url = issuer_url
        self.url = f"{issuer_url}/.well-known/jwks.json"
        self._fetcher = fetcher
        self._monotonic = monotonic
        self._refetch_seconds = float(refetch_seconds)
        self._lock = threading.Lock()
        self._keys: Mapping[str, RSAPublicKey] = MappingProxyType({})
        self._pems: Mapping[str, bytes] = MappingProxyType({})
        self._last_fetch: float | None = None
        self.fetch_count = 0

    def _fetch_locked(self) -> None:
        self._last_fetch = self._monotonic()
        self.fetch_count += 1
        raw = self._fetcher(self.url)
        if type(raw) is not bytes or len(raw) > _JWKS_MAX_BYTES:
            raise ValueError("jwks_invalid")
        pems = parse_cognito_jwks(raw)
        loaded: dict[str, RSAPublicKey] = {}
        for kid, pem in pems.items():
            key = serialization.load_pem_public_key(pem)
            if not isinstance(key, RSAPublicKey) or key.key_size < 2048:
                raise ValueError("jwks_invalid")
            loaded[kid] = key
        self._keys = MappingProxyType(loaded)
        self._pems = MappingProxyType(dict(pems))

    def load(self) -> Mapping[str, bytes]:
        """Fetch once at cold start; later calls return the cached PEM mapping."""
        with self._lock:
            if not self._keys:
                self._fetch_locked()
            return self._pems

    def cached_key(self, kid: str) -> RSAPublicKey | None:
        return self._keys.get(kid)

    def key_for(self, kid: str) -> RSAPublicKey | None:
        """Return a key; on an unknown kid refetch at most once per interval."""
        key = self._keys.get(kid)
        if key is not None:
            return key
        with self._lock:
            key = self._keys.get(kid)
            if key is not None:
                return key
            now = self._monotonic()
            if self._last_fetch is not None and now - self._last_fetch < self._refetch_seconds:
                return None
            try:
                self._fetch_locked()
            except Exception:
                return None
            return self._keys.get(kid)


class MultiuserTokenVerifier:
    """Re-verify the pool access token; every failure is an anonymous ``None``."""

    def __init__(self, policy: MultiuserPolicy, jwks: JwksCache, *, require_auth_time: bool = False) -> None:
        if type(policy) is not MultiuserPolicy or not isinstance(jwks, JwksCache):
            raise ValueError("explicit multiuser policy and JWKS cache required")
        if jwks.issuer_url != policy.issuer_url:
            raise ValueError("JWKS issuer mismatch")
        if type(require_auth_time) is not bool:
            raise ValueError("require_auth_time must be a boolean")
        self._policy = policy
        self._jwks = jwks
        # Public web mode: the login time (auth_time) is required and passed on.
        self._require_auth_time = require_auth_time

    async def verify_token(self, token: str) -> AccessToken | None:
        policy = self._policy
        if (
            not isinstance(token, str)
            or not token
            or len(token) > policy.max_token_bytes
            or len(token.encode("utf-8", errors="ignore")) > policy.max_token_bytes
        ):
            return None
        try:
            header = jwt.get_unverified_header(token)
            if (
                not isinstance(header, dict)
                or set(header) - _ALLOWED_JWT_HEADER_FIELDS
                or header.get("alg") != "RS256"
                or header.get("typ") not in {None, "JWT"}
                or type(header.get("kid")) is not str
                or not 1 <= len(header["kid"]) <= 128
            ):
                return None
            kid = header["kid"]
            key = self._jwks.cached_key(kid)
            if key is None:
                key = await asyncio.to_thread(self._jwks.key_for, kid)
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
                    "require": ["iss", "aud", "sub", "client_id", "token_use", "exp", "iat",
                                "scope", TENANT_CLAIM, "username"],
                },
            )
            if not isinstance(claims, dict):
                return None
            subject, client_id = claims.get("sub"), claims.get("client_id")
            tenant, username, scope = claims.get(TENANT_CLAIM), claims.get("username"), claims.get("scope")
            if (
                claims.get("iss") != policy.issuer_url
                or type(claims.get("aud")) is not str
                or claims["aud"] != policy.audience
                or claims.get("token_use") != "access"
                or type(client_id) is not str
                or client_id not in policy.client_ids
                or type(subject) is not str
                or not 1 <= len(subject) <= 256
                or type(scope) is not str
                or len(scope) > 2048
                or policy.required_scope not in scope.split(" ")
                or type(tenant) is not str
                or not TENANT_ID_RE.fullmatch(tenant)
                or type(username) is not str
                or not 1 <= len(username) <= 128
            ):
                return None
            now = int(time.time())
            exp, issued, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
            if (
                not _bounded_int(exp, 0, _MAX_EPOCH)
                or not _bounded_int(issued, 0, _MAX_EPOCH)
                or exp <= now
                or issued > now
                or exp <= issued
                or ("nbf" in claims and (not _bounded_int(nbf, 0, _MAX_EPOCH) or nbf > now))
            ):
                return None
            passed = {"iss": policy.issuer_url, TENANT_CLAIM: tenant, "username": username}
            if self._require_auth_time:
                auth_time = claims.get("auth_time")
                if not _bounded_int(auth_time, 0, _MAX_EPOCH) or auth_time > issued:
                    return None
                passed["auth_time"] = auth_time
            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=[policy.required_scope],
                expires_at=exp,
                resource=policy.audience,
                subject=subject,
                claims=passed,
            )
        except Exception:
            # Suppress parser/signature diagnostics and token material.
            return None


def _current_identity() -> tuple[str, str]:
    """Tenant and username of the verified request token, or a tool error."""
    try:
        access = get_access_token()
        claims = access.claims if access is not None else None
        tenant = claims.get(TENANT_CLAIM) if isinstance(claims, dict) else None
        username = claims.get("username") if isinstance(claims, dict) else None
    except Exception:
        tenant = username = None
    if (
        type(tenant) is not str
        or not TENANT_ID_RE.fullmatch(tenant)
        or type(username) is not str
        or not 1 <= len(username) <= 128
    ):
        raise ToolError(MSG_UNAVAILABLE)
    return tenant, username


def _current_auth_time() -> int:
    """Login time of the verified request token (public web mode only)."""
    try:
        access = get_access_token()
        claims = access.claims if access is not None else None
        auth_time = claims.get("auth_time") if isinstance(claims, dict) else None
    except Exception:
        auth_time = None
    if not _bounded_int(auth_time, 0, _MAX_EPOCH):
        raise _public_tool_error(REFUSED_UNAVAILABLE)
    return auth_time


_PUBLIC_REFUSAL_MESSAGES = MappingProxyType({
    REFUSED_EXPIRED: MSG_PUBLIC_EXPIRED,
    REFUSED_LIMIT: MSG_PUBLIC_LIMIT,
    REFUSED_RATE: MSG_PUBLIC_RATE,
    REFUSED_PAUSED: MSG_PUBLIC_PAUSED,
    REFUSED_UNAVAILABLE: MSG_UNAVAILABLE,
    FAILED_LOGOUT: MSG_LOGOUT_FAILED,
    FAILED_DELETE: MSG_PUBLIC_DELETE_FAILED,
})


def _public_tool_error(code: str, message: str | None = None) -> ToolError:
    """Public web mode tool error: ``"<code>: <message>"`` (fixed code first)."""
    if code not in _PUBLIC_REFUSAL_MESSAGES:
        code, message = REFUSED_UNAVAILABLE, None
    return ToolError(f"{code}: {message if message is not None else _PUBLIC_REFUSAL_MESSAGES[code]}")


def _public_identity() -> tuple[str, str]:
    try:
        return _current_identity()
    except ToolError:
        raise _public_tool_error(REFUSED_UNAVAILABLE) from None


class _TenantOperations:
    def __init__(self, proxy: "_TenantProxy", tenant: str, username: str) -> None:
        self._proxy, self._tenant, self._username = proxy, tenant, username

    def __repr__(self) -> str:
        return "TenantOperations(<redacted>)"

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)

        def invoke(*args: Any, **kwargs: Any) -> Any:
            return self._proxy._run(self._tenant, self._username, name, args, kwargs)

        return invoke


class _TenantProxy:
    """Per-request provider: one lazily built tenant provider, never shared."""

    def __init__(self, deadline: float, services_factory: Callable[[str, float], Any],
                 relink: Callable[[str, str], Any], gate: Any | None = None) -> None:
        self._deadline = deadline
        self._factory = services_factory
        self._relink = relink
        # Public web mode: admission (age, pause, limits) once per request and tenant.
        self._gate = gate
        self._admitted: set[str] = set()
        self._providers: dict[str, Any] = {}
        self._relinked: set[str] = set()
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return "TenantProxy(<redacted>)"

    def get(self) -> _TenantOperations:
        tenant, username = _public_identity() if self._gate is not None else _current_identity()
        return _TenantOperations(self, tenant, username)

    def _expired(self, tenant: str, username: str) -> ToolError:
        with self._lock:
            first = tenant not in self._relinked
            self._relinked.add(tenant)
        if first:
            try:
                self._relink(tenant, username)
            except Exception:
                pass
        if self._gate is not None:
            return _public_tool_error(REFUSED_EXPIRED)
        return ToolError(MSG_SESSION_EXPIRED)

    def _admit(self, tenant: str, username: str) -> None:
        with self._lock:
            if tenant in self._admitted:
                return
        try:
            self._gate.admit(tenant, username, _current_auth_time())
        except PublicSessionRefused as refused:
            raise _public_tool_error(refused.code) from None
        except ToolError:
            raise
        except Exception:
            raise _public_tool_error(REFUSED_UNAVAILABLE) from None
        with self._lock:
            self._admitted.add(tenant)

    def _run(self, tenant: str, username: str, name: str, args: tuple, kwargs: dict) -> Any:
        # Re-check that the operation still belongs to the current token.
        public = self._gate is not None
        if (_public_identity() if public else _current_identity()) != (tenant, username):
            raise _public_tool_error(REFUSED_UNAVAILABLE) if public else ToolError(MSG_UNAVAILABLE)
        if public:
            self._admit(tenant, username)
        provider = None
        try:
            with self._lock:
                provider = self._providers.get(tenant)
                if provider is None:
                    provider = self._factory(tenant, self._deadline)
                    self._providers[tenant] = provider
            services = provider.get()
            return getattr(services, name)(*args, **kwargs)
        except TenantSessionMissing:
            if self._gate is not None:
                raise self._expired(tenant, username) from None
            raise ToolError(MSG_NOT_LINKED) from None
        except ToolError:
            raise
        except ServiceError:
            if _session_rejected(provider):
                raise self._expired(tenant, username) from None
            raise
        except Exception:
            if _session_rejected(provider):
                raise self._expired(tenant, username) from None
            if public:
                raise _public_tool_error(REFUSED_UNAVAILABLE) from None
            raise ToolError(MSG_UNAVAILABLE) from None


def _session_rejected(provider: Any) -> bool:
    try:
        return provider is not None and getattr(provider, "session_rejected", False) is True
    except Exception:
        return False


def _register_delete_tool(server: Any, delete_account: Callable[[str, str], Any]) -> None:
    @server.tool(name="borrar_mis_datos", annotations=_DESTRUCTIVE)
    def borrar_mis_datos(confirmar: bool) -> str:
        """Borra tu sesión de MAPIT guardada, tu invitación y tu usuario de este servicio (solo con confirmar=true)."""
        tenant, username = _current_identity()
        if confirmar is not True:
            return MSG_DELETE_PREVIEW
        try:
            done = delete_account(tenant, username)
        except Exception:
            done = False
        if done is not True:
            raise ToolError(MSG_DELETE_FAILED)
        return MSG_DELETE_DONE


def _register_public_tools(server: Any, gate: Any) -> None:
    """Public web mode: keep only the web's read tools and add the two account tools."""
    for name in [tool.name for tool in server._tool_manager.list_tools()]:
        if name not in PUBLIC_READ_TOOLS:
            server.remove_tool(name)

    @server.tool(name="cerrar_sesion", annotations=_DESTRUCTIVE)
    def cerrar_sesion() -> str:
        """Cierra tu sesión: borra al momento tu sesión de MAPIT guardada y tu usuario de este servicio."""
        tenant, username = _public_identity()
        try:
            done = gate.end_session(tenant, username)
        except Exception:
            done = False
        if done is not True:
            raise _public_tool_error(FAILED_LOGOUT)
        return MSG_LOGOUT_DONE

    @server.tool(name="borrar_mis_datos", annotations=_DESTRUCTIVE)
    def borrar_mis_datos(confirmar: bool) -> str:
        """Borra tu sesión de MAPIT guardada, tu usuario de este servicio y el registro de tus entradas (solo con confirmar=true)."""
        tenant, username = _public_identity()
        if confirmar is not True:
            return MSG_PUBLIC_DELETE_PREVIEW
        try:
            outcome = gate.delete_account(tenant, username)
        except Exception:
            outcome = DELETE_FAILED
        if outcome == DELETE_NO_SESSION:
            raise _public_tool_error(FAILED_DELETE, MSG_PUBLIC_DELETE_NO_SESSION)
        if outcome != DELETE_DONE:
            raise _public_tool_error(FAILED_DELETE)
        return MSG_PUBLIC_DELETE_DONE

    names = {tool.name for tool in server._tool_manager.list_tools()}
    if names != set(PUBLIC_TOOLS):
        raise ValueError("public tool set mismatch")


@dataclass(frozen=True)
class MultiuserRuntime:
    policy: MultiuserPolicy
    jwks: JwksCache
    lambda_handler: Callable[[Any, Any], dict[str, Any]]


def _unavailable() -> dict[str, Any]:
    return {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": '{"error":"service_unavailable"}',
        "isBase64Encoded": False,
    }


def create_multiuser_runtime(
    policy: MultiuserPolicy,
    jwks_cache: JwksCache,
    *,
    services_factory: Callable[[str, float], Any],
    relink: Callable[[str, str], Any],
    delete_account: Callable[[str, str], Any],
    geographic_queries: bool = False,
    public_gate: PublicSessionGate | None = None,
) -> MultiuserRuntime:
    """Compose the Lambda handler; fetches the JWKS once if not yet cached.

    ``public_gate`` (public web mode only) adds the session age, pause and call
    limits, the short tool list and ``cerrar_sesion``; without it nothing changes.
    """
    if (
        type(policy) is not MultiuserPolicy
        or not isinstance(jwks_cache, JwksCache)
        or jwks_cache.issuer_url != policy.issuer_url
        or not callable(services_factory)
        or not callable(relink)
        or not callable(delete_account)
        or type(geographic_queries) is not bool
        or (public_gate is not None and (not isinstance(public_gate, PublicSessionGate) or geographic_queries))
    ):
        raise ValueError("explicit multiuser composition required")
    initial_keys = jwks_cache.load()
    verifier = MultiuserTokenVerifier(policy, jwks_cache, require_auth_time=public_gate is not None)

    def validate_keys(config: Any, _material: Mapping[str, bytes | str]) -> None:
        if config is not policy:
            raise ValueError("multiuser policy changed")

    def build_app(config: Any, _material: Mapping[str, bytes | str]):
        if type(config) is not MultiuserPolicy or replace(
            config, request_deadline_seconds=policy.request_deadline_seconds
        ) != policy:
            raise ValueError("multiuser policy required")
        deadline = _INVOCATION_DEADLINE.get()
        if type(deadline) is not float or not math.isfinite(deadline) or time.monotonic() >= deadline:
            raise ValueError("invocation deadline unavailable")
        proxy = _TenantProxy(deadline, services_factory, relink, public_gate)
        server = create_server(
            proxy,
            auth_settings=AuthSettings(
                issuer_url=policy.issuer_url,
                resource_server_url=policy.resource_url,
                validate_token_resource=True,
                required_scopes=[policy.required_scope],
            ),
            token_verifier=verifier,
            geographic_queries=geographic_queries,
        )
        if public_gate is None:
            _register_delete_tool(server, delete_account)
        else:
            _register_public_tools(server, public_gate)
        sdk_app = server.streamable_http_app(
            json_response=True,
            stateless_http=True,
            max_request_body_size=config.max_request_body_bytes,
            transport_security=TransportSecuritySettings(
                enable_dns_rebinding_protection=True,
                allowed_hosts=list(policy.allowed_hosts),
                allowed_origins=list(policy.allowed_origins),
            ),
        )
        wrapped = _BoundedHTTPMiddleware(sdk_app, config)
        wrapped.router = sdk_app.router
        wrapped.state = sdk_app.state
        return wrapped

    adapter = _build_synthetic_lambda_handler(
        policy, initial_keys, key_validator=validate_keys, app_builder=build_app
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

    return MultiuserRuntime(policy, jwks_cache, handler)


__all__ = [
    "JwksCache", "MSG_DELETE_DONE", "MSG_DELETE_FAILED", "MSG_DELETE_PREVIEW", "MSG_NOT_LINKED",
    "MSG_SESSION_EXPIRED", "MSG_UNAVAILABLE", "MultiuserPolicy", "MultiuserRuntime",
    "MultiuserTokenVerifier", "TenantSessionMissing", "create_multiuser_runtime",
    "fetch_jwks_https", "multiuser_policy",
]
