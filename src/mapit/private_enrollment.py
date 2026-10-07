"""Single-use, loopback-only operator-assisted enrollment channel.

No signup, credential discovery, remote bind, analytics or access logging.
The operator explicitly supplies a reviewed registry and publisher factory.
Credentials are POST bodies only and are never returned in a response.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import math
import secrets
import threading
import time
from typing import Any, Callable
from urllib.parse import parse_qsl

from .durable_tenants import DurableTenantGuard
from .tenant_router import InvitedTenantAuthority


@dataclass(frozen=True)
class EnrollmentResponse:
    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...]


_HEADERS = (
    ("Content-Type", "text/html; charset=utf-8"),
    ("Cache-Control", "no-store"), ("Pragma", "no-cache"),
    ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
)
_STYLE = """html{color-scheme:dark}body{margin:0;background:#171918;color:#f1ecdf;font-family:Georgia,serif}main{max-width:620px;margin:8vh auto;padding:32px;border-top:5px solid #e35136}small,label,button{font-family:Bahnschrift,'Trebuchet MS',sans-serif}small{letter-spacing:.16em;color:#b6b8ac}h1{font-size:clamp(32px,6vw,52px);font-weight:400;line-height:1.05}p{line-height:1.6;color:#c7c7bb}label{display:block;margin:24px 0 8px}input[type=password]{box-sizing:border-box;width:100%;padding:14px;border:1px solid #777d70;background:#222622;color:#fff;font-size:16px}input:focus{outline:2px solid #e35136;outline-offset:3px}button{margin-top:28px;padding:15px 24px;background:#e35136;color:#171918;border:0;font-size:16px;cursor:pointer}.note{border-left:2px solid #777d70;padding-left:16px;font-size:14px}@media(max-width:660px){main{margin:3vh 16px;padding:20px}}"""


def _page(content: str) -> bytes:
    return ("<!doctype html><html lang='es'><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
            "<title>MAPIT · Conectar cuenta</title><style>" + _STYLE + "</style><main><small>HONDA / MAPIT MCP · ALTA PRIVADA</small>"
            + content + "</main></html>").encode("utf-8")


class PrivateEnrollmentChannel:
    """An explicit ten-minute window, one POST, only an invited signed caller.

    This is an assisted local channel, not a public/password login or delegated
    MAPIT OAuth implementation. A refresh session is supplied privately by its
    owner; no username/password is requested or stored here.
    """

    def __init__(self, *, authority: InvitedTenantAuthority, durable_guard: DurableTenantGuard,
                 registry: Any = None, publisher_factory: Callable[..., Any] | None = None,
                 enrollment_factory: Callable[..., tuple[Any, Any]] | None = None, port: int,
                 deadline: float, monotonic: Callable[[], float] = time.monotonic):
        try:
            # Concrete registry validation happens without constructing clients.
            from .identity_binding import SQLiteIdentityBindingRegistry
            allowed = [SQLiteIdentityBindingRegistry]
            try:
                from .aws_identity_binding import DynamoDBIdentityBindingRegistry
                allowed.append(DynamoDBIdentityBindingRegistry)
            except ImportError:
                pass
            now = monotonic()
            if (type(authority) is not InvitedTenantAuthority or type(durable_guard) is not DurableTenantGuard
                or not durable_guard.is_bound_to(authority)
                or not ((enrollment_factory is None and type(registry) in allowed
                         and registry.is_bound_to(authority, durable_guard) and callable(publisher_factory))
                        or (callable(enrollment_factory) and registry is None and publisher_factory is None))
                or type(port) is not int or not 1024 <= port <= 65535
                or type(now) not in (int, float) or not math.isfinite(now)
                or type(deadline) not in (int, float) or not math.isfinite(deadline)
                or not 0 <= now < deadline <= now + 600):
                raise ValueError
        except Exception:
            raise ValueError("enrollment_channel_invalid") from None
        self._authority, self._guard, self._registry = authority, durable_guard, registry
        self._publisher_factory = publisher_factory
        self._enrollment_factory, self._registry_types = enrollment_factory, tuple(allowed)
        self._clock, self._deadline, self._last_clock = monotonic, float(deadline), float(now)
        self._origin = f"http://127.0.0.1:{port}"
        self._host, self._port = f"127.0.0.1:{port}", port
        self._csrf = secrets.token_urlsafe(32)
        self._used, self._lock = False, threading.Lock()

    def __repr__(self) -> str:
        return "PrivateEnrollmentChannel(<redacted>)"

    def _live(self) -> bool:
        try:
            now = self._clock()
            if type(now) not in (int, float) or not math.isfinite(now) or not self._last_clock <= now < self._deadline:
                return False
            self._last_clock = float(now)
            return True
        except Exception:
            return False

    def _response(self, status: int, content: str) -> EnrollmentResponse:
        return EnrollmentResponse(status, _page(content), _HEADERS)

    async def request(self, method: str, target: str, headers: list[tuple[str, str]],
                      body: bytes = b"", *, peer: str = "") -> EnrollmentResponse:
        reject = lambda: self._response(400, "<h1>Solicitud rechazada</h1><p>Consulta al operador antes de otro intento. No vuelvas a enviar tu sesión.</p>")
        if peer != "127.0.0.1" or not self._live() or self._used:
            return reject()
        try:
            normalized = {}
            for key, value in headers:
                name = key.lower()
                if name in normalized or not isinstance(value, str) or "\r" in value or "\n" in value:
                    return reject()
                normalized[name] = value
            if normalized.get("host") != self._host or "transfer-encoding" in normalized:
                return reject()
            if method == "GET" and target == "/" and not body:
                return self._response(200, "<h1>Tu cuenta.<br>Tu recorrido.</h1><p>Conecta una sesión MAPIT a tu identidad MCP invitada. Esta ventana local se cierra tras un intento.</p>"
                    "<p class='note'>Solo en este ordenador y con asistencia del operador. No pegues contraseñas ni códigos MFA. No envíes los tokens al chat ni aceptes guardarlos en el navegador.</p>"
                    "<form method='post' action='/enroll' autocomplete='off'><input type='hidden' name='csrf' value='" + self._csrf + "'>"
                    "<label for='mcp'>Token de acceso MCP de tu identidad invitada</label><input id='mcp' type='password' name='mcp' required autocomplete='off' maxlength='16384'>"
                    "<label for='mapit'>Sesión de actualización MAPIT (refresh token)</label><input id='mapit' type='password' name='mapit' required autocomplete='off' maxlength='4096'>"
                    "<label><input type='checkbox' name='consent' value='yes' required> Autorizo guardar mi sesión cifrada y vincular esta cuenta para consultar mis datos. Puedo pedir su revocación.</label>"
                    "<button type='submit'>Conectar mi cuenta →</button></form>")
            if (method != "POST" or target != "/enroll" or normalized.get("origin") != self._origin
                or normalized.get("content-type") != "application/x-www-form-urlencoded"
                or normalized.get("sec-fetch-site") not in (None, "same-origin")
                or type(body) is not bytes or not 0 < len(body) <= 32768
                or normalized.get("content-length") != str(len(body))):
                return reject()
            fields = parse_qsl(body.decode("ascii", errors="strict"), keep_blank_values=True,
                               strict_parsing=True, encoding="utf-8", errors="strict", max_num_fields=4)
            values = dict(fields)
            if (len(fields) != 4 or len(values) != 4 or set(values) != {"csrf", "mcp", "mapit", "consent"}
                or not hmac.compare_digest(values["csrf"], self._csrf) or values["consent"] != "yes"
                or not 0 < len(values["mcp"].encode("utf-8")) <= 16384
                or not 0 < len(values["mapit"].encode("utf-8")) <= 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in values["mcp"] + values["mapit"])):
                return reject()
        except Exception:
            return reject()
        with self._lock:
            if self._used or not self._live():
                return reject()
            self._used = True
        try:
            grant = await self._authority.authenticate(values["mcp"])
            snapshot = self._guard.capture(grant)
            if not self._live():
                return reject()
            if self._enrollment_factory is None:
                registry = self._registry
                publisher = self._publisher_factory(grant=grant, snapshot=snapshot)
            else:
                # The cloud operation clock starts after the user submits, not
                # while they read the form. No eager SDK/14-second lease expires.
                registry, publisher = self._enrollment_factory(grant=grant, snapshot=snapshot,
                    deadline=min(self._deadline, self._last_clock + 14))
                if type(registry) not in self._registry_types or not registry.is_bound_to(self._authority, self._guard):
                    raise ValueError
            registry.enroll(grant, snapshot, values["mapit"], publisher=publisher)
            self._guard.check(grant, snapshot)
            if not self._live():
                return self._response(409, "<h1>Resultado por comprobar</h1><p>La ventana ha caducado. El operador debe comprobar el estado; no vuelvas a enviar tu sesión.</p>")
        except Exception:
            # Includes unknown publication: never expose SDK/JWT/body details or
            # automatically retry/delete a possibly created secret.
            return self._response(409, "<h1>Alta no confirmada</h1><p>El operador debe revisar el estado antes de otro intento. No vuelvas a enviar tu sesión.</p>")
        finally:
            values.clear()
        return self._response(200, "<h1>Cuenta conectada</h1><p>La identidad y la publicación de la sesión se han verificado. Puedes cerrar esta ventana.</p>")


class _LoopbackServer(HTTPServer):
    def get_request(self):
        connection, address = super().get_request()
        # Bound header parsing too, before BaseHTTPRequestHandler starts. A
        # timeout set only in do_POST would leave a slow local header unbounded.
        connection.settimeout(2)
        return connection, address


def serve_private_enrollment(channel: PrivateEnrollmentChannel) -> None:
    """Explicit blocking operator entrypoint; closes on POST or time expiry.

    No access/body logging. HTTP is restricted to local loopback; this server
    must never be proxied, exposed on a LAN, or used as a hosted guest portal.
    """
    if type(channel) is not PrivateEnrollmentChannel:
        raise ValueError("enrollment_channel_invalid")

    class Handler(BaseHTTPRequestHandler):
        server_version = "PrivateEnrollment"
        sys_version = ""

        def log_message(self, format, *args):
            pass

        def _handle(self):
            self.connection.settimeout(2)
            try:
                lengths = self.headers.get_all("Content-Length", [])
                size = int(lengths[0]) if len(lengths) == 1 else 0
                if not 0 <= size <= 32768 or len(lengths) > 1:
                    self.send_error(400)
                    return
                body = self.rfile.read(size) if size else b""
                result = asyncio.run(channel.request(self.command, self.path,
                    list(self.headers.items()), body, peer=self.client_address[0]))
                self.send_response(result.status)
                for key, value in result.headers:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(result.body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(result.body)
            except Exception:
                self.close_connection = True

        do_GET = _handle
        do_POST = _handle

    with _LoopbackServer(("127.0.0.1", channel._port), Handler) as server:
        server.timeout = 1
        while channel._live() and not channel._used:
            server.handle_request()


__all__ = ["PrivateEnrollmentChannel", "EnrollmentResponse", "serve_private_enrollment"]
