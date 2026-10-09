"""Bounded, local-only OAuth code/PKCE callback for the isolated DEV owner client.

This module performs no work at import time. It does not create users, enroll
MFA, publish sessions, or persist tokens. The only successful consumer input is
an access token that passed the fixed Cognito RS256 verifier and an exact scope
check.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import math
import secrets
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Mapping, Sequence

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.http_transport import open_direct
from mapit.remote_http import FixedRS256TokenVerifier

OWNER_DOMAIN = "hm-honda-mapit-mcp-identity.auth.eu-west-1.amazoncognito.com"
CALLBACK_URL = "http://127.0.0.1:8787/callback"
CALLBACK_HOST = "127.0.0.1:8787"
CALLBACK_ORIGIN = "http://127.0.0.1:8787"
TOKEN_URL = f"https://{OWNER_DOMAIN}/oauth2/token"
AUTHORIZE_URL = f"https://{OWNER_DOMAIN}/oauth2/authorize"
LOOPBACK_HOST = "127.0.0.1"
LOOPBACK_PORT = 8787
MAX_WINDOW_SECONDS = 600.0
MAX_EXCHANGE_SECONDS = 15.0
MAX_REQUEST_LINE = 4096
MAX_HEADER_COUNT = 32
MAX_HEADER_BYTES = 8192
MAX_QUERY_BYTES = 8192
MAX_CODE_CHARS = 4096
MAX_STATE_CHARS = 128
MAX_TOKEN_RESPONSE_BYTES = 16 * 1024
_ALLOWED_HEADER_NAME = frozenset(b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ALLOWED_HEADER_NAME_CHARS = frozenset(chr(byte) for byte in _ALLOWED_HEADER_NAME)
_B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_ERROR_BODY = b"Login could not be verified. Close this tab."
_SUCCESS_BODY = b"Login verified. You may close this tab."
_ROOT_PAGE_PREFIX = b"<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer><title>Owner sign-in</title><form method=get action=/start><input type=hidden name=cap value=\""
_ROOT_PAGE_SUFFIX = b"\"><button type=submit>Continue to owner sign-in</button></form>"


class AssistedLoginError(RuntimeError):
    """A fixed-category error; it never contains a code, token or URL."""

    def __init__(self, category: str) -> None:
        allowed = {"configuration_invalid", "request_rejected", "window_expired", "exchange_failed", "token_invalid", "consumer_failed", "listener_failed"}
        self.category = category if type(category) is str and category in allowed else "login_failed"
        super().__init__(self.category)


@dataclass(frozen=True)
class LoginResponse:
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)
    location: str | None = field(default=None, repr=False)
    category: str = "response"

    def __repr__(self) -> str:
        return f"LoginResponse(status={self.status}, category={self.category!r})"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _finite_clock(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AssistedLoginError("window_expired")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise AssistedLoginError("window_expired")
    return number


def _json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _parse_token_body(body: bytes, expected_scope: str | None = None, *, minimum_lifetime: int = 1) -> str:
    if type(body) is not bytes or not 1 <= len(body) <= MAX_TOKEN_RESPONSE_BYTES:
        raise AssistedLoginError("exchange_failed")
    try:
        value = json.loads(body.decode("utf-8", "strict"), object_pairs_hook=_json_no_duplicates,
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except Exception:
        raise AssistedLoginError("exchange_failed") from None
    if type(value) is not dict or not {"access_token", "token_type", "expires_in"} <= set(value):
        raise AssistedLoginError("exchange_failed")
    if set(value) - {"access_token", "token_type", "expires_in", "refresh_token", "id_token", "scope"}:
        raise AssistedLoginError("exchange_failed")
    token = value.get("access_token")
    if (type(token) is not str or not token or len(token.encode("utf-8", "strict")) > 8192
            or any(ord(ch) < 0x21 or ord(ch) > 0x7e for ch in token)):
        raise AssistedLoginError("exchange_failed")
    if value.get("token_type") != "Bearer":
        raise AssistedLoginError("exchange_failed")
    lifetime = value.get("expires_in")
    if (type(minimum_lifetime) is not int or not 1 <= minimum_lifetime <= 600
            or type(lifetime) is not int or not minimum_lifetime <= lifetime <= 600):
        raise AssistedLoginError("exchange_failed")
    # Response metadata is not authority, but reject contradictions instead of
    # silently treating an unexpected scope as harmless.
    if expected_scope is not None and "scope" in value and value["scope"] != expected_scope:
        raise AssistedLoginError("exchange_failed")
    for optional in ("refresh_token", "id_token"):
        item = value.get(optional)
        if item is not None and (type(item) is not str or not item or len(item.encode("utf-8", "strict")) > 8192):
            raise AssistedLoginError("exchange_failed")
    return token


def _strict_target(target: Any) -> tuple[str, str]:
    if type(target) is not str or not target or len(target) > MAX_REQUEST_LINE or not target.startswith("/"):
        raise AssistedLoginError("request_rejected")
    try:
        raw = target.encode("ascii", "strict")
    except UnicodeError:
        raise AssistedLoginError("request_rejected") from None
    if any(byte < 0x20 or byte == 0x7f for byte in raw) or b"#" in raw or b"\\" in raw or target.startswith("//"):
        raise AssistedLoginError("request_rejected")
    if "%" in target:
        import re
        if re.search(r"%(?![0-9A-Fa-f]{2})", target):
            raise AssistedLoginError("request_rejected")
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.fragment or parsed.path not in {"/", "/start", "/callback"}:
        raise AssistedLoginError("request_rejected")
    return parsed.path, parsed.query


def _single_query(query: str, allowed: frozenset[str], *, max_bytes: int) -> dict[str, str]:
    try:
        raw = query.encode("ascii", "strict")
    except UnicodeError:
        raise AssistedLoginError("request_rejected") from None
    if len(raw) > max_bytes:
        raise AssistedLoginError("request_rejected")
    import re
    if re.search(r"%(?![0-9A-Fa-f]{2})", query):
        raise AssistedLoginError("request_rejected")
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True, strict_parsing=True,
                                       encoding="utf-8", errors="strict", max_num_fields=4)
    except Exception:
        raise AssistedLoginError("request_rejected") from None
    result: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed or key in result or not value or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
            raise AssistedLoginError("request_rejected")
        result[key] = value
    return result


class DevOwnerAssistedLogin:
    """One human owner OAuth attempt, fixed to the 8787 loopback callback.

    `token_opener` is an optional test seam for urllib's opener object. The
    production default is direct TLS with proxies disabled and redirects
    rejected. `consumer` is called once with a verified AccessToken in memory.
    """

    def __init__(self, policy: CognitoDevPolicy, public_keys: Mapping[str, bytes | str],
                 token_consumer: Callable[[Any], Any], *, token_opener: Any | None = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time,
                 random_bytes: Callable[[int], bytes] = secrets.token_bytes,
                 window_seconds: float = MAX_WINDOW_SECONDS) -> None:
        try:
            if type(policy) is not CognitoDevPolicy or not callable(token_consumer):
                raise ValueError
            if not callable(monotonic) or not callable(wall_clock) or not callable(random_bytes):
                raise ValueError
            if isinstance(window_seconds, bool) or not isinstance(window_seconds, (int, float)):
                raise ValueError
            window = float(window_seconds)
            if not math.isfinite(window) or not 1 <= window <= MAX_WINDOW_SECONDS:
                raise ValueError
            verifier = FixedRS256TokenVerifier(policy, public_keys)
            started = _finite_clock(monotonic())
            wall = _finite_clock(wall_clock())
            capability = _b64url(random_bytes(32))
            if len(capability) != 43:
                raise ValueError
        except Exception:
            raise AssistedLoginError("configuration_invalid") from None
        self._policy = policy
        self._verifier = verifier
        self._consumer = token_consumer
        self._opener = token_opener
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._last_mono = started
        self._wall_started = wall
        self._window_end = started + window
        self._random_bytes = random_bytes
        self._capability = capability
        self._state: str | None = None
        self._verifier_text: str | None = None
        self._started = False
        self._terminal = False
        self._lock = threading.Lock()
        self._outcome = "pending"
        self._done = threading.Event()

    @property
    def terminal(self) -> bool:
        with self._lock:
            return self._terminal

    @property
    def outcome(self) -> str:
        with self._lock:
            return self._outcome

    def _sample(self) -> float:
        try:
            current = _finite_clock(self._monotonic())
            if current < self._last_mono:
                raise AssistedLoginError("window_expired")
            self._last_mono = current
            if current >= self._window_end:
                raise AssistedLoginError("window_expired")
            return current
        except AssistedLoginError:
            raise
        except Exception:
            raise AssistedLoginError("window_expired") from None

    def _sample_until(self, deadline: float) -> float:
        current = self._sample()
        if current >= deadline:
            raise AssistedLoginError("window_expired")
        return current

    @staticmethod
    def _headers(headers: Sequence[tuple[str, str]]) -> dict[str, str]:
        if not isinstance(headers, (list, tuple)) or len(headers) > MAX_HEADER_COUNT:
            raise AssistedLoginError("request_rejected")
        result: dict[str, str] = {}
        total = 0
        for row in headers:
            if (not isinstance(row, (list, tuple)) or len(row) != 2
                    or type(row[0]) is not str or type(row[1]) is not str):
                raise AssistedLoginError("request_rejected")
            name, value = row
            total += len(name) + len(value)
            lname = name.casefold()
            if (total > MAX_HEADER_BYTES or not name or any(ord(c) > 127 or c not in _ALLOWED_HEADER_NAME_CHARS for c in name)
                    or lname in result or any(ord(c) < 0x20 and c != "\t" or ord(c) == 0x7f for c in value)):
                raise AssistedLoginError("request_rejected")
            result[lname] = value.strip(" \t")
        if result.get("host") != CALLBACK_HOST:
            raise AssistedLoginError("request_rejected")
        if "origin" in result and result["origin"] != CALLBACK_ORIGIN:
            raise AssistedLoginError("request_rejected")
        if "transfer-encoding" in result:
            raise AssistedLoginError("request_rejected")
        if "content-length" in result and result["content-length"] not in {"0", "00"}:
            raise AssistedLoginError("request_rejected")
        return result

    def handle(self, method: str, target: str, headers: Sequence[tuple[str, str]],
               peer: str, body: bytes = b"") -> LoginResponse:
        """Handle one strict origin-form GET. Every response is fixed and redacted."""
        try:
            self._sample()
            self._headers(headers)
            if (type(peer) is not str or peer != LOOPBACK_HOST or method != "GET"
                    or type(body) is not bytes or body):
                raise AssistedLoginError("request_rejected")
            path, query = _strict_target(target)
            if path == "/":
                if query:
                    raise AssistedLoginError("request_rejected")
                with self._lock:
                    if self._terminal or self._started:
                        return self._reply(410, _ERROR_BODY, "terminal")
                    page = _ROOT_PAGE_PREFIX + self._capability.encode("ascii") + _ROOT_PAGE_SUFFIX
                return self._reply(200, page, "root", content_type="text/html; charset=utf-8")
            if path == "/start":
                params = _single_query(query, frozenset({"cap"}), max_bytes=256)
                if set(params) != {"cap"}:
                    raise AssistedLoginError("request_rejected")
                location = self._start(params["cap"])
                return self._reply(302, b"", "authorize", location=location,
                                   extra=(("Referrer-Policy", "no-referrer"),))
            if path == "/callback":
                # A callback endpoint is one-shot even for malformed or
                # mismatched callbacks; no supplied value can trigger a retry.
                with self._lock:
                    if self._terminal or not self._started:
                        return self._reply(410, _ERROR_BODY, "terminal")
                    self._terminal = True
                    state = self._state
                    verifier = self._verifier_text
                    self._state = None
                    self._verifier_text = None
                try:
                    params = _single_query(query, frozenset({"code", "state", "error", "error_description"}),
                                           max_bytes=MAX_QUERY_BYTES)
                    if "error" in params or "error_description" in params or set(params) != {"code", "state"}:
                        raise AssistedLoginError("request_rejected")
                    code, returned_state = params["code"], params["state"]
                    if (len(code) > MAX_CODE_CHARS or not code.isascii()
                            or any(ord(c) < 0x21 or ord(c) > 0x7e for c in code)
                            or len(returned_state) > MAX_STATE_CHARS
                            or any(char not in _B64URL for char in returned_state)
                            or state is None or verifier is None or not hmac.compare_digest(returned_state, state)):
                        raise AssistedLoginError("request_rejected")
                    exchange_start = self._sample()
                    exchange_deadline = min(self._window_end, exchange_start + MAX_EXCHANGE_SECONDS)
                    token = self._exchange(code, verifier, exchange_deadline)
                    self._sample_until(exchange_deadline)
                    verified = asyncio.run(self._verifier.verify_token(token))
                    wall_now = _finite_clock(self._wall_clock())
                    if (verified is None or verified.subject != self._policy.owner_subject
                            or verified.client_id != self._policy.client_id
                            or verified.resource != self._policy.audience
                            or wall_now < self._wall_started
                            or type(verified.expires_at) is not int or verified.expires_at - wall_now < 15
                            or type(verified.scopes) is not list
                            or verified.scopes != [self._policy.required_scope]):
                        raise AssistedLoginError("token_invalid")
                    self._sample_until(exchange_deadline)
                    try:
                        self._consumer(verified)
                    except Exception:
                        raise AssistedLoginError("consumer_failed") from None
                    self._sample_until(exchange_deadline)
                    with self._lock:
                        self._outcome = "verified"
                    return self._reply(200, _SUCCESS_BODY, "verified")
                except AssistedLoginError as exc:
                    with self._lock:
                        self._outcome = exc.category
                    return self._reply(400, _ERROR_BODY, exc.category)
                except Exception:
                    with self._lock:
                        self._outcome = "login_failed"
                    return self._reply(400, _ERROR_BODY, "login_failed")
                finally:
                    self._done.set()
            raise AssistedLoginError("request_rejected")
        except AssistedLoginError as exc:
            if exc.category == "window_expired":
                with self._lock:
                    self._terminal = True
                    self._outcome = "window_expired"
                    self._state = None
                    self._verifier_text = None
                self._done.set()
            return self._reply(400, _ERROR_BODY, exc.category)
        except Exception:
            return self._reply(400, _ERROR_BODY, "request_rejected")

    def _start(self, capability: str) -> str:
        with self._lock:
            if (self._terminal or self._started or len(capability) != 43
                    or any(char not in _B64URL for char in capability)
                    or not hmac.compare_digest(capability, self._capability)):
                raise AssistedLoginError("request_rejected")
            self._sample()
            state = _b64url(self._random_bytes(32))
            verifier = _b64url(self._random_bytes(32))
            if len(state) != 43 or not 43 <= len(verifier) <= 128:
                raise AssistedLoginError("request_rejected")
            challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
            params = urllib.parse.urlencode({
                "response_type": "code",
                "client_id": self._policy.client_id,
                "redirect_uri": CALLBACK_URL,
                "scope": self._policy.required_scope,
                "resource": self._policy.resource_url,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            })
            self._state = state
            self._verifier_text = verifier
            self._started = True
            self._capability = ""
            return AUTHORIZE_URL + "?" + params

    def _exchange(self, code: str, verifier: str, deadline: float) -> str:
        start = self._sample_until(deadline)
        timeout = min(MAX_EXCHANGE_SECONDS, self._window_end - start, deadline - start)
        if not math.isfinite(timeout) or timeout <= 0:
            raise AssistedLoginError("window_expired")
        body = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "client_id": self._policy.client_id,
            "code": code,
            "redirect_uri": CALLBACK_URL,
            "code_verifier": verifier,
        }).encode("ascii")
        request = urllib.request.Request(
            TOKEN_URL, data=body,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
                     "Cache-Control": "no-store"},
            method="POST",
        )
        try:
            before_open = self._sample_until(deadline)
            timeout = min(MAX_EXCHANGE_SECONDS, self._window_end - before_open, deadline - before_open)
            response = open_direct(request, timeout=timeout, opener=self._opener)
            try:
                status = getattr(response, "status", None)
                if status is None and callable(getattr(response, "getcode", None)):
                    status = response.getcode()
                if type(status) is not int or status != 200:
                    raise AssistedLoginError("exchange_failed")
                headers = getattr(response, "headers", None)
                lengths = headers.get_all("Content-Length") if headers is not None and callable(getattr(headers, "get_all", None)) else None
                if lengths is not None and (len(lengths) != 1 or not lengths[0].isdigit()
                                             or int(lengths[0]) > MAX_TOKEN_RESPONSE_BYTES):
                    raise AssistedLoginError("exchange_failed")
                content_types = headers.get_all("Content-Type") if headers is not None and callable(getattr(headers, "get_all", None)) else None
                if (content_types is None or len(content_types) != 1
                        or content_types[0].split(";", 1)[0].strip().casefold() != "application/json"):
                    raise AssistedLoginError("exchange_failed")
                reader = getattr(response, "read1", None)
                if not callable(reader):
                    reader = getattr(response, "read", None)
                if not callable(reader):
                    raise AssistedLoginError("exchange_failed")
                chunks: list[bytes] = []
                total = 0
                sock = None
                try:
                    sock = response.fp.raw._sock
                except Exception:
                    pass
                while True:
                    before_read = self._sample_until(deadline)
                    remaining = min(self._window_end - before_read, deadline - before_read)
                    if not math.isfinite(remaining) or remaining <= 0:
                        raise AssistedLoginError("window_expired")
                    if sock is not None:
                        settimeout = getattr(sock, "settimeout", None)
                        if callable(settimeout):
                            settimeout(remaining)
                    chunk = reader(min(4096, MAX_TOKEN_RESPONSE_BYTES + 1 - total))
                    self._sample_until(deadline)
                    if type(chunk) is not bytes:
                        raise AssistedLoginError("exchange_failed")
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_TOKEN_RESPONSE_BYTES:
                        raise AssistedLoginError("exchange_failed")
                    chunks.append(chunk)
                return _parse_token_body(
                    b"".join(chunks), self._policy.required_scope, minimum_lifetime=15
                )
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except AssistedLoginError:
            raise
        except Exception:
            raise AssistedLoginError("exchange_failed") from None

    @staticmethod
    def _reply(status: int, body: bytes, category: str, *, location: str | None = None,
               content_type: str = "text/plain; charset=utf-8",
               extra: tuple[tuple[str, str], ...] = ()) -> LoginResponse:
        headers = (("Content-Type", content_type), ("Content-Length", str(len(body))),
                   ("Cache-Control", "no-store"), ("Pragma", "no-cache"),
                   ("Referrer-Policy", "no-referrer"), ("X-Content-Type-Options", "nosniff"),
                   ("X-Frame-Options", "DENY"),
                   ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"),
                   ("Connection", "close"), *extra)
        if location is not None:
            headers += (("Location", location),)
        return LoginResponse(status, headers, body, location, category)

    def serve(self, *, ready_callback: Callable[[str], Any] | None = None) -> str:
        """Serve one attempt on the exact callback socket until terminal/deadline."""
        if ready_callback is not None and not callable(ready_callback):
            raise AssistedLoginError("configuration_invalid")
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = ""
            sys_version = ""

            def log_message(self, _format: str, *args: Any) -> None:
                return

            def handle_one_request(self) -> None:
                self.close_connection = True
                try:
                    header_deadline = time.monotonic() + 2.0
                    self.request.settimeout(2.0)
                    self.raw_requestline = self.rfile.readline(MAX_REQUEST_LINE + 1)
                    if (len(self.raw_requestline) > MAX_REQUEST_LINE or not self.raw_requestline.endswith(b"\r\n")):
                        response = owner._reply(400, _ERROR_BODY, "request_rejected")
                    else:
                        parts = self.raw_requestline[:-2].split(b" ")
                        if len(parts) != 3 or parts[2] != b"HTTP/1.1":
                            response = owner._reply(400, _ERROR_BODY, "request_rejected")
                        else:
                            self.request_version = "HTTP/1.1"
                            method = parts[0].decode("ascii", "strict")
                            target = parts[1].decode("ascii", "strict")
                            headers: list[tuple[str, str]] = []
                            count = total = 0
                            while True:
                                remaining = header_deadline - time.monotonic()
                                if remaining <= 0:
                                    raise ValueError
                                self.request.settimeout(min(2.0, remaining))
                                line = self.rfile.readline(MAX_HEADER_BYTES + 1)
                                if not line or len(line) > MAX_HEADER_BYTES or not line.endswith(b"\r\n"):
                                    raise ValueError
                                total += len(line)
                                if total > MAX_HEADER_BYTES:
                                    raise ValueError
                                if line == b"\r\n":
                                    break
                                if line[:1] in b" \t" or b":" not in line:
                                    raise ValueError
                                key, value = line[:-2].split(b":", 1)
                                if not key or any(byte not in _ALLOWED_HEADER_NAME for byte in key):
                                    raise ValueError
                                count += 1
                                if count > MAX_HEADER_COUNT:
                                    raise ValueError
                                headers.append((key.decode("ascii"), value.decode("latin-1")))
                            response = owner.handle(method, target, headers, self.client_address[0], b"")
                except Exception:
                    response = owner._reply(400, _ERROR_BODY, "request_rejected")
                try:
                    self.send_response_only(response.status)
                    for key, value in response.headers:
                        self.send_header(key, value)
                    self.end_headers()
                    if response.body:
                        self.wfile.write(response.body)
                    self.wfile.flush()
                except Exception:
                    pass

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            allow_reuse_address = False

            def handle_error(self, _request: Any, _client_address: Any) -> None:
                return

            def get_request(self):
                sock, addr = super().get_request()
                sock.settimeout(2.0)
                return sock, addr

        try:
            with Server((LOOPBACK_HOST, LOOPBACK_PORT), Handler) as server:
                if ready_callback is not None:
                    ready_callback(CALLBACK_ORIGIN + "/")
                while not self._done.is_set():
                    try:
                        now = self._sample()
                    except AssistedLoginError:
                        with self._lock:
                            self._terminal = True
                            self._outcome = "window_expired"
                            self._state = None
                            self._verifier_text = None
                        break
                    server.timeout = min(0.25, max(0.0, self._window_end - now))
                    server.handle_request()
                # The non-daemon callback worker is joined by server_close so
                # serve() cannot return before its final response is written.
                return self.outcome
        except Exception:
            with self._lock:
                self._terminal = True
                self._outcome = "listener_failed"
                self._state = None
                self._verifier_text = None
                self._done.set()
            raise AssistedLoginError("listener_failed") from None


__all__ = [
    "AssistedLoginError", "CALLBACK_URL", "DevOwnerAssistedLogin", "LoginResponse",
    "OWNER_DOMAIN", "TOKEN_URL",
]
