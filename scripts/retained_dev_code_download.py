"""One direct-TLS bounded download of the initial dev recovery ZIP.

No proxy, redirect, credential chain or network activity at import time.
The AWS-issued URL is private and never appears in exceptions or results.
"""
from __future__ import annotations

import http.client
import math
import ssl
import time
from typing import Callable
from urllib.parse import urlsplit

HOST = "awslambda-eu-west-1-tasks.s3.eu-west-1.amazonaws.com"
MAX_BYTES = 1024 * 1024


class CodeDownloadError(ValueError):
    def __init__(self):
        super().__init__("code_download_failed")


def download_initial_code(url: str, maximum_bytes: int, remaining_seconds: float,
                          *, monotonic: Callable[[], float] = time.monotonic,
                          connection_factory=None) -> bytes:
    """Download once, refusing every redirect and oversized/late response."""
    connection = response = None
    try:
        if (type(url) is not str or not 1 <= len(url) <= 16384
                or any(ord(char) <= 32 or ord(char) >= 127 for char in url)
                or type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_BYTES
                or type(remaining_seconds) not in (int, float)
                or not math.isfinite(remaining_seconds) or not 0 < remaining_seconds <= 30):
            raise CodeDownloadError()
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.hostname != HOST
                or parts.port not in (None, 443) or parts.username is not None
                or parts.password is not None or parts.fragment
                or not parts.path.startswith("/") or not parts.query):
            raise CodeDownloadError()
        started = monotonic()
        last = started
        if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
            raise CodeDownloadError()

        def budget():
            nonlocal last
            now = monotonic()
            if (type(now) not in (int, float) or not math.isfinite(now)
                    or now < last or now - started >= remaining_seconds):
                raise CodeDownloadError()
            last = now
            return min(3.0, remaining_seconds - (now - started))

        factory = connection_factory or http.client.HTTPSConnection
        connection = factory(HOST, port=443, timeout=budget(), context=ssl.create_default_context())

        def set_timeout():
            timeout = budget()
            connection.timeout = timeout
            if connection.sock is not None:
                connection.sock.settimeout(timeout)

        set_timeout()
        connection.request("GET", parts.path + "?" + parts.query,
                           headers={"Accept-Encoding": "identity", "Connection": "close"})
        set_timeout()
        response = connection.getresponse()
        budget()
        if type(response.status) is not int or response.status != 200:
            raise CodeDownloadError()
        lengths = response.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or not 1 <= int(lengths[0]) <= maximum_bytes
                or response.headers.get_all("Transfer-Encoding", [])
                or response.headers.get("Content-Encoding", "identity") != "identity"):
            raise CodeDownloadError()
        expected = int(lengths[0])
        chunks = []
        size = 0
        while size < expected:
            set_timeout()
            chunk = response.read(min(65536, expected - size))
            budget()
            if type(chunk) is not bytes or not chunk or len(chunk) > expected - size:
                raise CodeDownloadError()
            chunks.append(chunk)
            size += len(chunk)
        budget()
        return b"".join(chunks)
    except Exception:
        raise CodeDownloadError() from None
    finally:
        for item in (response, connection):
            if item is not None:
                try:
                    item.close()
                except Exception:
                    pass


__all__ = ["CodeDownloadError", "download_initial_code"]
