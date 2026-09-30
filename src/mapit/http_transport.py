"""Small direct-only HTTP primitives with bounded response reads."""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any, Callable


READ_CHUNK_BYTES = 64 * 1024
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class ResponseTooLargeError(RuntimeError):
    """A response exceeded a configured byte ceiling."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def direct_opener() -> Any:
    """Create an opener which neither consults environment proxies nor follows redirects."""
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirectHandler())


def open_direct(request: Any, *, timeout: float, opener: Any | None = None) -> Any:
    selected = opener if opener is not None else direct_opener()
    response = selected.open(request, timeout=timeout)
    status = getattr(response, "status", None)
    if status is None:
        getcode = getattr(response, "getcode", None)
        status = getcode() if callable(getcode) else None
    if type(status) is int and status in REDIRECT_STATUSES:
        close = getattr(response, "close", None)
        if callable(close):
            close()
        raise urllib.error.HTTPError(getattr(request, "full_url", ""), status, "redirect rejected", None, None)
    return response


def read_bounded(response: Any, limit: int, *, on_chunk: Callable[[int], None] | None = None) -> bytes:
    """Read at most limit+1 bytes using bounded requests, rejecting overflow."""
    chunks: list[bytes] = []
    total = 0
    reader = getattr(response, "read1", None)
    if not callable(reader):
        reader = response.read
    while True:
        request_size = min(READ_CHUNK_BYTES, limit + 1 - total)
        chunk = reader(request_size)
        if not isinstance(chunk, bytes):
            raise TypeError("response body is not bytes")
        if not chunk:
            break
        total += len(chunk)
        if on_chunk is not None:
            on_chunk(len(chunk))
        if total > limit:
            raise ResponseTooLargeError("response exceeds configured limit")
        chunks.append(chunk)
    return b"".join(chunks)
