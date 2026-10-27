"""Bounded in-memory Managed Login cookies backed by :mod:`http.cookiejar`.

The standard library owns cookie parsing, expiry, deletion, domain, path and
secure handling. This wrapper adds only probe-specific bounds and an exact
host fence; it never persists cookies or exposes raw headers.
"""

from __future__ import annotations

from collections.abc import Iterable
import copy
from email.message import Message
import http.cookiejar
import re
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request


_COOKIE_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}\Z")
_MAX_HEADERS = 32
_MAX_HEADER_BYTES = 4096
_MAX_VALUE_BYTES = 4096
_MAX_OUTGOING_BYTES = 16 * 1024


class CookiePolicyError(ValueError):
    """A bounded cookie input is malformed or outside the exact host policy."""


def _safe_text(value: Any, maximum: int) -> bool:
    if type(value) is not str or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= maximum
    except UnicodeEncodeError:
        return False


def _headers(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes, bytearray)):
        raise CookiePolicyError("cookie_headers_invalid")
    try:
        iterator = iter(values)
    except Exception:
        raise CookiePolicyError("cookie_headers_invalid") from None
    result: list[Any] = []
    for _ in range(_MAX_HEADERS + 1):
        try:
            result.append(next(iterator))
        except StopIteration:
            break
        except Exception:
            raise CookiePolicyError("cookie_headers_invalid") from None
    if len(result) > _MAX_HEADERS:
        raise CookiePolicyError("cookie_headers_invalid")
    for value in result:
        if not _safe_text(value, _MAX_HEADER_BYTES):
            raise CookiePolicyError("cookie_header_invalid")
    return result


def _pair_name(raw: str) -> str:
    first = raw.split(";", 1)[0]
    if "=" not in first:
        raise CookiePolicyError("cookie_header_invalid")
    name = first.split("=", 1)[0].strip()
    if _COOKIE_NAME.fullmatch(name) is None:
        raise CookiePolicyError("cookie_header_invalid")
    return name


class _ExactHostPolicy(http.cookiejar.DefaultCookiePolicy):
    def __init__(self, domain: str):
        super().__init__(allowed_domains=(domain, "." + domain), strict_domain=True, secure_protocols=("https",))
        self.domain = domain

    def _exact(self, cookie: http.cookiejar.Cookie) -> bool:
        return cookie.domain.lstrip(".").casefold() == self.domain.casefold()

    def set_ok(self, cookie: http.cookiejar.Cookie, request: Any) -> bool:
        return bool(super().set_ok(cookie, request) and self._exact(cookie))

    def return_ok(self, cookie: http.cookiejar.Cookie, request: Any) -> bool:
        return bool(super().return_ok(cookie, request) and self._exact(cookie))


class _ResponseInfo:
    def __init__(self, values: Iterable[str]):
        self._headers = Message()
        for value in values:
            self._headers.add_header("Set-Cookie", value)

    def info(self) -> Message:
        return self._headers


class BoundedCookieStore:
    """Memory-only exact-host cookie store with a dict compatibility view."""

    def __init__(self, domain: str):
        if type(domain) is not str or not domain or any(ord(char) < 33 for char in domain):
            raise CookiePolicyError("cookie_domain_invalid")
        self.domain = domain
        self._policy = _ExactHostPolicy(domain)
        self._jar = http.cookiejar.CookieJar(policy=self._policy)

    def _validate_url(self, url: str) -> None:
        try:
            if not _safe_text(url, 4096):
                raise ValueError
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or parsed.hostname != self.domain
                or parsed.port not in (None, 443) or parsed.username
                or parsed.password or parsed.fragment):
                raise ValueError
        except Exception:
            raise CookiePolicyError("cookie_url_invalid") from None

    def _clone(self) -> http.cookiejar.CookieJar:
        clone = http.cookiejar.CookieJar(policy=self._policy)
        for cookie in self._jar:
            clone.set_cookie(copy.copy(cookie))
        return clone

    def _validate_jar(self, jar: http.cookiejar.CookieJar) -> None:
        cookies = list(jar)
        if len(cookies) > _MAX_HEADERS:
            raise CookiePolicyError("cookie_jar_limit")
        for cookie in cookies:
            if (
                not _COOKIE_NAME.fullmatch(cookie.name)
                or not _safe_text(cookie.value, _MAX_VALUE_BYTES)
                or cookie.domain.lstrip(".").casefold() != self.domain.casefold()
                or not isinstance(cookie.path, str)
                or not cookie.path.startswith("/")
            ):
                raise CookiePolicyError("cookie_value_invalid")

    def update(self, url: str, values: Iterable[str]) -> None:
        self._validate_url(url)
        headers = _headers(values)
        candidate = self._clone()
        request = Request(url)
        for raw in headers:
            _pair_name(raw)
            candidate.extract_cookies(_ResponseInfo((raw,)), request)
        self._validate_jar(candidate)
        self._jar = candidate

    def header(self, url: str) -> str | None:
        self._validate_url(url)
        request = Request(url)
        self._jar.add_cookie_header(request)
        value = request.get_header("Cookie")
        if value is not None and not _safe_text(value, _MAX_OUTGOING_BYTES):
            raise CookiePolicyError("cookie_header_invalid")
        return value

    def values(self, url: str) -> dict[str, str]:
        value = self.header(url)
        if not value:
            return {}
        result: dict[str, str] = {}
        for pair in value.split("; "):
            if "=" not in pair:
                raise CookiePolicyError("cookie_header_invalid")
            name, cookie_value = pair.split("=", 1)
            if _COOKIE_NAME.fullmatch(name) is None or not _safe_text(cookie_value, _MAX_VALUE_BYTES):
                raise CookiePolicyError("cookie_header_invalid")
            result[name] = cookie_value
        return result

__all__ = ["BoundedCookieStore", "CookiePolicyError"]
