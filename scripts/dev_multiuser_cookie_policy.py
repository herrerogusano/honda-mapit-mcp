"""Strict, bounded Set-Cookie updates for the private Managed Login probe.

This helper deliberately supports only the deletion form needed by the
diagnostic hypothesis: an empty value for an already-known cookie with an
explicit ``Max-Age`` value less than or equal to zero.  Expiry-only deletion,
unknown empty cookies, and malformed attributes fail closed.  It does not
prove that Cognito emitted any particular header in a live run.
"""

from __future__ import annotations

from collections.abc import Iterable, MutableMapping
import re
from typing import Any


_COOKIE_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}\Z")
_MAX_AGE = re.compile(r"-?(?:0|[1-9][0-9]*)\Z")
_MAX_HEADERS = 32
_MAX_HEADER_BYTES = 4096
_MAX_VALUE_BYTES = 2048


class CookiePolicyError(ValueError):
    """A bounded cookie update is malformed or unsafe to apply."""


def _text(value: Any, maximum: int) -> bool:
    if type(value) is not str or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= maximum
    except UnicodeEncodeError:
        return False


def _parse(raw: Any) -> tuple[str, str, dict[str, str | None]]:
    if not _text(raw, _MAX_HEADER_BYTES) or not raw.strip():
        raise CookiePolicyError("cookie_header_invalid")
    parts = [part.strip() for part in raw.split(";")]
    first = parts.pop(0)
    if "=" not in first:
        raise CookiePolicyError("cookie_header_invalid")
    name, value = first.split("=", 1)
    if _COOKIE_NAME.fullmatch(name) is None or not _text(value, _MAX_VALUE_BYTES):
        raise CookiePolicyError("cookie_header_invalid")
    if value and any(char in value for char in ",;"):
        raise CookiePolicyError("cookie_header_invalid")
    attributes: dict[str, str | None] = {}
    for attribute in parts:
        if not attribute or "=" not in attribute:
            # Flag attributes such as Secure/HttpOnly are valid Set-Cookie
            # syntax and irrelevant to this in-memory jar.
            if attribute:
                key = attribute.casefold()
                if key in attributes:
                    raise CookiePolicyError("cookie_header_invalid")
                attributes[key] = None
            continue
        key, attr_value = attribute.split("=", 1)
        key = key.strip().casefold()
        attr_value = attr_value.strip()
        if not key or key in attributes or not _text(attr_value, 256):
            raise CookiePolicyError("cookie_header_invalid")
        attributes[key] = attr_value
    max_age = attributes.get("max-age")
    if max_age is not None and (_MAX_AGE.fullmatch(max_age) is None or len(max_age) > 20):
        raise CookiePolicyError("cookie_header_invalid")
    return name, value, attributes


def apply_set_cookie_updates(jar: MutableMapping[str, str], headers: Iterable[str]) -> None:
    """Apply bounded cookie updates atomically to an in-memory jar.

    Non-empty values retain the existing probe's behavior.  Empty values are
    accepted only for a cookie already present in the jar and only with an
    explicit integer ``Max-Age <= 0``; the cookie is then removed.  An
    ``Expires`` attribute alone is intentionally unsupported because this
    helper does not make wall-clock decisions.
    """
    if not isinstance(jar, MutableMapping):
        raise CookiePolicyError("cookie_jar_invalid")
    if isinstance(headers, (str, bytes, bytearray)):
        raise CookiePolicyError("cookie_headers_invalid") from None
    try:
        iterator = iter(headers)
    except Exception:
        raise CookiePolicyError("cookie_headers_invalid") from None
    values: list[Any] = []
    for _ in range(_MAX_HEADERS + 1):
        try:
            values.append(next(iterator))
        except StopIteration:
            break
        except Exception:
            raise CookiePolicyError("cookie_headers_invalid") from None
    if len(values) > _MAX_HEADERS:
        raise CookiePolicyError("cookie_headers_invalid")
    known = set(jar)
    if len(known) > _MAX_HEADERS or any(
        type(name) is not str or _COOKIE_NAME.fullmatch(name) is None
        or not _text(value, _MAX_VALUE_BYTES) or any(char in value for char in ",;")
        for name, value in jar.items()
    ):
        raise CookiePolicyError("cookie_jar_invalid")
    updates: dict[str, str | None] = {}
    for raw in values:
        name, value, attributes = _parse(raw)
        if value == "":
            max_age = attributes.get("max-age")
            if name not in known or max_age is None or int(max_age) > 0:
                raise CookiePolicyError("cookie_deletion_invalid")
            updates[name] = None
            known.discard(name)
        else:
            updates[name] = value
            known.add(name)
    for name, value in updates.items():
        if value is None:
            jar.pop(name, None)
        else:
            jar[name] = value


__all__ = ["CookiePolicyError", "apply_set_cookie_updates"]
