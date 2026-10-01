"""Offline-only API Gateway HTTP API v2 adapter for the synthetic MCP app."""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import replace
from types import MappingProxyType
from typing import Any

from .remote_http import RemoteHTTPConfig, create_synthetic_http_app

_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
_ALLOWED_PATHS = frozenset({"/mcp", _METADATA_PATH})
_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_SINGLETON_HEADERS = frozenset({"host", "authorization", "origin", "content-type", "content-length"})
_FORWARDED_HEADERS = frozenset(
    {"host", "authorization", "origin", "content-type", "content-length", "accept", "mcp-protocol-version"}
)
_MAX_HEADERS = 64
_MAX_HEADER_BYTES = 32 * 1024
_TIME_RESERVE_SECONDS = 1.0
_MIN_DISPATCH_SECONDS = 0.01
_ERRORS = {
    400: b'{"error":"invalid_request"}',
    401: b'{"error":"unauthorized"}',
    403: b'{"error":"insufficient_scope"}',
    404: b'{"error":"not_found"}',
    405: b'{"error":"method_not_allowed"}',
    413: b'{"error":"request_too_large"}',
    500: b'{"error":"internal_error"}',
    502: b'{"error":"invalid_upstream_response"}',
    504: b'{"error":"request_timed_out"}',
}


class _RequestError(Exception):
    def __init__(self, status: int) -> None:
        self.status = status


class _ASGIResponseLimit(Exception):
    """Stop a cooperative ASGI sender after a hard event-count bound."""


def _safe_envelope(status: int, challenge: str | None = None, allow: str | None = None) -> dict[str, Any]:
    headers = {"content-type": "application/json", "cache-control": "no-store"}
    if challenge is not None:
        headers["www-authenticate"] = challenge
    if allow is not None:
        headers["allow"] = allow
    return {"statusCode": status, "headers": headers, "body": _ERRORS[status].decode("ascii"), "isBase64Encoded": False}


def _exact_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise _RequestError(400)
    return value


def _valid_header_value(value: bytes) -> bool:
    return all(byte not in {0, 10, 13} and (byte >= 32 or byte == 9) and byte != 127 for byte in value)


def _event_scope(event: Any, body_cap: int) -> tuple[dict[str, Any], bytes]:
    root = _exact_mapping(event)
    if root.get("version") != "2.0":
        raise _RequestError(400)
    context = _exact_mapping(root.get("requestContext"))
    http = _exact_mapping(context.get("http"))
    if "stage" in context and context.get("stage") != "$default":
        raise _RequestError(400)
    raw_path, context_path = root.get("rawPath"), http.get("path")
    if not isinstance(raw_path, str) or raw_path != context_path or raw_path not in _ALLOWED_PATHS:
        raise _RequestError(404)
    if "?" in raw_path or "#" in raw_path:
        raise _RequestError(400)
    method = http.get("method")
    if not isinstance(method, str) or method not in {"GET", "POST", "HEAD", "PUT", "PATCH", "DELETE", "OPTIONS"}:
        raise _RequestError(400)
    if root.get("rawQueryString", "") != "" or root.get("queryStringParameters") not in (None, {}) or root.get("multiValueQueryStringParameters") not in (None, {}):
        raise _RequestError(400)
    cookies = root.get("cookies", [])
    if not isinstance(cookies, list) or any(not isinstance(item, str) for item in cookies) or cookies:
        raise _RequestError(400)

    encoded_body = root.get("body", "")
    if encoded_body is None:
        encoded_body = ""
    if not isinstance(encoded_body, str):
        raise _RequestError(400)
    is_base64 = root.get("isBase64Encoded", False)
    if type(is_base64) is not bool:
        raise _RequestError(400)
    if is_base64:
        max_encoded = 4 * ((body_cap + 2) // 3)
        if len(encoded_body) > max_encoded:
            raise _RequestError(413)
        try:
            body = base64.b64decode(encoded_body, validate=True)
        except (binascii.Error, ValueError):
            raise _RequestError(400) from None
    else:
        if len(encoded_body) > body_cap:
            raise _RequestError(413)
        try:
            body = encoded_body.encode("utf-8", errors="strict")
        except UnicodeError:
            raise _RequestError(400) from None
    if len(body) > body_cap:
        raise _RequestError(413)

    raw_headers = root.get("headers", {})
    headers_map = _exact_mapping(raw_headers)
    if len(headers_map) > _MAX_HEADERS:
        raise _RequestError(400)
    seen: set[str] = set()
    forwarded: list[tuple[bytes, bytes]] = []
    header_bytes = 0
    for name, value in headers_map.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise _RequestError(400)
        if len(name) > _MAX_HEADER_BYTES or len(value) > _MAX_HEADER_BYTES - len(name):
            raise _RequestError(400)
        try:
            name_bytes = name.encode("ascii", errors="strict")
            value_bytes = value.encode("latin-1", errors="strict")
        except UnicodeError:
            raise _RequestError(400) from None
        header_bytes += len(name_bytes) + len(value_bytes)
        if header_bytes > _MAX_HEADER_BYTES or not _HEADER_NAME.fullmatch(name_bytes) or not _valid_header_value(value_bytes):
            raise _RequestError(400)
        folded = name.casefold()
        if folded in seen:
            raise _RequestError(400)
        seen.add(folded)
        if folded == "cookie" and value:
            raise _RequestError(400)
        if folded in _SINGLETON_HEADERS and "," in value:
            raise _RequestError(400)
        if folded == "content-length":
            if (
                not value.isascii()
                or not value.isdecimal()
                or len(value) > len(str(body_cap))
                or int(value) != len(body)
            ):
                raise _RequestError(400)
        if folded in _FORWARDED_HEADERS:
            forwarded.append((folded.encode("ascii"), value_bytes))

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "https",
        "path": raw_path,
        "raw_path": raw_path.encode("ascii"),
        "root_path": "",
        "query_string": b"",
        "headers": forwarded,
        "client": None,
        "server": ("synthetic.invalid", 443),
        "state": {},
    }
    return scope, body


def _serialize_response(status: int, headers: list[tuple[bytes, bytes]], body: bytearray, cap: int) -> dict[str, Any]:
    if not 100 <= status <= 599 or len(body) > cap:
        raise _RequestError(502)
    projected: dict[str, str] = {"cache-control": "no-store"}
    for name_bytes, value_bytes in headers:
        if not isinstance(name_bytes, bytes) or not isinstance(value_bytes, bytes):
            raise _RequestError(502)
        if not _HEADER_NAME.fullmatch(name_bytes):
            raise _RequestError(502)
        try:
            name = name_bytes.decode("ascii").lower()
            value = value_bytes.decode("latin-1")
        except UnicodeError:
            raise _RequestError(502) from None
        if not _valid_header_value(value_bytes):
            raise _RequestError(502)
        if name in {"set-cookie", "mcp-session-id", "mcp-session-id-expires"}:
            raise _RequestError(502)
        if name in projected:
            projected[name] += ", " + value
        else:
            projected[name] = value
    try:
        text = bytes(body).decode("utf-8", errors="strict")
    except UnicodeError:
        raise _RequestError(502) from None
    result = {"statusCode": status, "headers": projected, "body": text, "isBase64Encoded": False}
    try:
        serialized = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise _RequestError(502) from None
    if len(serialized) > cap:
        raise _RequestError(502)
    return result


def create_synthetic_lambda_handler(config: RemoteHTTPConfig, public_keys: Mapping[str, bytes | str]):
    """Build a synchronous, offline-only API Gateway v2 handler for synthetic MCP data."""
    if type(config) is not RemoteHTTPConfig:
        raise ValueError("a validated synthetic HTTP config is required")
    from .remote_http import FixedRS256TokenVerifier

    return _build_synthetic_lambda_handler(
        config,
        public_keys,
        key_validator=FixedRS256TokenVerifier,
        app_builder=lambda selected_config, selected_keys: create_synthetic_http_app(selected_config, selected_keys),
    )


def _build_synthetic_lambda_handler(
    config: Any,
    public_keys: Mapping[str, bytes | str],
    *,
    key_validator: Any,
    app_builder: Any,
):
    """Private adapter seam for separately validated fixed synthetic policies."""
    if not isinstance(public_keys, Mapping) or not 1 <= len(public_keys) <= 8:
        raise ValueError("a fixed public key mapping is required")
    copied: dict[str, bytes | str] = {}
    for kid, material in public_keys.items():
        if not isinstance(kid, str) or not kid or len(kid) > 128 or "\r" in kid or "\n" in kid:
            raise ValueError("invalid public key identifier")
        if isinstance(material, bytes):
            if len(material) > 8192:
                raise ValueError("public key material exceeds the bound")
            copied[kid] = bytes(material)
        elif isinstance(material, str):
            if len(material) > 8192:
                raise ValueError("public key material exceeds the bound")
            try:
                material.encode("ascii", errors="strict")
            except UnicodeError:
                raise ValueError("invalid public key material") from None
            copied[kid] = str(material)
        else:
            raise ValueError("invalid public key mapping")
    frozen_keys = MappingProxyType(copied)
    # Validate and parse the key set once before returning a callable.
    key_validator(config, frozen_keys)

    def handler(event: Any, context: Any) -> dict[str, Any]:
        # Context is intentionally the first user-controlled input accessed.
        try:
            remaining_ms = context.get_remaining_time_in_millis()
        except Exception:
            return _safe_envelope(504)
        if type(remaining_ms) is not int or remaining_ms <= 0:
            return _safe_envelope(504)
        started = time.monotonic()
        try:
            lambda_budget = remaining_ms / 1000.0 - _TIME_RESERVE_SECONDS
        except OverflowError:
            return _safe_envelope(504)
        budget = min(float(config.request_deadline_seconds), lambda_budget)
        if not math.isfinite(budget) or budget < _MIN_DISPATCH_SECONDS:
            return _safe_envelope(504)
        deadline = started + budget

        def remaining() -> float:
            return deadline - time.monotonic()

        try:
            scope, request_body = _event_scope(event, config.max_request_body_bytes)
            if remaining() < _MIN_DISPATCH_SECONDS:
                raise _RequestError(504)
            path, method = scope["path"], scope["method"]
            if (path == "/mcp" and method != "POST") or (path == _METADATA_PATH and method != "GET"):
                return _safe_envelope(405, allow="POST" if path == "/mcp" else "GET")
            captured_remaining = remaining()
            if captured_remaining < _MIN_DISPATCH_SECONDS:
                raise _RequestError(504)
            invocation_config = replace(
                config,
                request_deadline_seconds=min(float(config.request_deadline_seconds), captured_remaining),
            )
            if remaining() < _MIN_DISPATCH_SECONDS:
                raise _RequestError(504)
            app = app_builder(invocation_config, frozen_keys)

            async def invoke() -> dict[str, Any]:
                response_started = False
                response_complete = False
                response_error: int | None = None
                response_status = 500
                response_headers: list[tuple[bytes, bytes]] = []
                response_body = bytearray()
                body_delivered = False
                response_event_count = 0

                async def receive() -> dict[str, Any]:
                    nonlocal body_delivered
                    if body_delivered:
                        return {"type": "http.disconnect"}
                    body_delivered = True
                    return {"type": "http.request", "body": request_body, "more_body": False}

                async def send(message: dict[str, Any]) -> None:
                    nonlocal response_started, response_complete, response_error, response_status, response_headers, response_event_count
                    response_event_count += 1
                    if response_event_count > 1024:
                        response_error = 502
                        raise _ASGIResponseLimit
                    if response_error is not None:
                        return
                    if not isinstance(message, dict):
                        response_error = 502
                        return
                    kind = message.get("type")
                    if kind == "http.response.start":
                        status_value = message.get("status")
                        if response_started or isinstance(status_value, bool) or not isinstance(status_value, int):
                            response_error = 502
                            return
                        headers = message.get("headers", [])
                        if not isinstance(headers, list) or len(headers) > _MAX_HEADERS:
                            response_error = 502
                            return
                        header_size = 0
                        for header in headers:
                            if not isinstance(header, (tuple, list)) or len(header) != 2:
                                response_error = 502
                                return
                            name, value = header
                            if not isinstance(name, bytes) or not isinstance(value, bytes):
                                response_error = 502
                                return
                            header_size += len(name) + len(value)
                            if header_size > _MAX_HEADER_BYTES or not _HEADER_NAME.fullmatch(name) or not _valid_header_value(value):
                                response_error = 502
                                return
                            lowered = name.lower()
                            if lowered in {b"set-cookie", b"mcp-session-id", b"mcp-session-id-expires"}:
                                response_error = 502
                                return
                            if lowered == b"content-type" and value.lower().startswith(b"text/event-stream"):
                                response_error = 502
                                return
                        response_status = message["status"]
                        response_headers = headers
                        response_started = True
                    elif kind == "http.response.body":
                        if not response_started or response_complete:
                            response_error = 502
                            return
                        chunk = message.get("body", b"")
                        if not isinstance(chunk, bytes) or len(chunk) > config.max_response_body_bytes - len(response_body):
                            response_error = 502
                            return
                        response_body.extend(chunk)
                        more_body = message.get("more_body", False)
                        if type(more_body) is not bool:
                            response_error = 502
                            return
                        response_complete = not more_body
                    elif kind in {"http.response.trailers", "http.response.pathsend"}:
                        response_error = 502
                    else:
                        response_error = 502

                async def run_app() -> None:
                    async with app.router.lifespan_context(app):
                        if remaining() < _MIN_DISPATCH_SECONDS:
                            raise TimeoutError
                        async with asyncio.timeout(max(0.001, remaining())):
                            try:
                                await app(scope, receive, send)
                            except _ASGIResponseLimit:
                                pass

                try:
                    await asyncio.wait_for(run_app(), timeout=max(0.001, remaining()))
                except TimeoutError:
                    raise _RequestError(504) from None
                if response_error is not None:
                    raise _RequestError(response_error)
                if remaining() < _MIN_DISPATCH_SECONDS:
                    raise _RequestError(504)
                if not response_started or not response_complete:
                    raise _RequestError(502)
                result = _serialize_response(response_status, response_headers, response_body, config.max_response_body_bytes)
                if remaining() < 0:
                    raise _RequestError(504)
                return result

            return asyncio.run(invoke())
        except _RequestError as exc:
            return _safe_envelope(exc.status)
        except Exception:
            return _safe_envelope(500)

    return handler


__all__ = ["create_synthetic_lambda_handler"]
