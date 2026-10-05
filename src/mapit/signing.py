"""Minimal AWS Signature Version 4 signing for MAPIT GET requests."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urlparse

from .auth import TemporaryCredentials


def _amz_time(now: datetime) -> tuple[str, str]:
    current = now.astimezone(timezone.utc) if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return current.strftime("%Y%m%dT%H%M%SZ"), current.strftime("%Y%m%d")


def canonical_query(query: str) -> str:
    """Return the AWS-canonical query, sorted after URI encoding.

    Query strings are not form data for SigV4 purposes: ``+`` is a literal
    plus and must become ``%2B``.  Sorting must also use the encoded key and
    value, not their decoded Unicode forms.
    """
    encoded: list[tuple[str, str]] = []
    for component in query.split("&"):
        if not component:
            continue
        key, separator, value = component.partition("=")
        # Decode existing escapes once, then apply AWS's URI encoding.  This
        # avoids double-encoding ordinary escaped octets while preserving a
        # literal plus as a plus.
        encoded_key = quote(unquote(key), safe="-_.~")
        encoded_value = quote(unquote(value if separator else ""), safe="-_.~")
        encoded.append((encoded_key, encoded_value))
    return "&".join(f"{key}={value}" for key, value in sorted(encoded))


def canonical_uri(path: str) -> str:
    """Return an AWS-safe URI and reject dot-segment traversal."""
    decoded_path = path or "/"
    # Reject traversal hidden behind encoded separators, including one extra
    # encoding layer that a proxy/gateway might decode before routing.
    for _ in range(len(decoded_path) + 1):
        if any(segment in {".", ".."} for segment in decoded_path.split("/")):
            raise ValueError("URI path cannot contain dot segments")
        unescaped = unquote(decoded_path)
        if unescaped == decoded_path:
            break
        decoded_path = unescaped
    return quote(path or "/", safe="/-_.~")


def _canonical_headers(headers: dict[str, str]) -> tuple[str, str]:
    normalized = {key.strip().lower(): " ".join(str(value).strip().split()) for key, value in headers.items()}
    canonical = "".join(f"{key}:{normalized[key]}\n" for key in sorted(normalized))
    return canonical, ";".join(sorted(normalized))


def canonical_request(method: str, url: str, headers: dict[str, str], payload: bytes = b"") -> tuple[str, str]:
    parsed = urlparse(url)
    path = canonical_uri(parsed.path)
    canonical_headers, signed_headers = _canonical_headers(headers)
    body_hash = hashlib.sha256(payload).hexdigest()
    request = "\n".join((method.upper(), path, canonical_query(parsed.query), canonical_headers, signed_headers, body_hash))
    return request, signed_headers


def _signature_key(secret: str, date: str, region: str, service: str) -> bytes:
    key = hmac.new(("AWS4" + secret).encode(), date.encode(), hashlib.sha256).digest()
    key = hmac.new(key, region.encode(), hashlib.sha256).digest()
    key = hmac.new(key, service.encode(), hashlib.sha256).digest()
    return hmac.new(key, b"aws4_request", hashlib.sha256).digest()


def sign_get(
    url: str,
    credentials: TemporaryCredentials,
    id_token: str,
    *,
    region: str,
    now: datetime | None = None,
    service: str = "execute-api",
) -> dict[str, str]:
    """Return signed headers for one GET; the input credentials are not mutated."""
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError("SigV4 requests require an HTTPS URL")
    amz_date, date = _amz_time(now or datetime.now(timezone.utc))
    headers = {
        "Accept": "application/json",
        "Host": parsed.netloc,
        "X-Amz-Date": amz_date,
        "X-Amz-Security-Token": credentials.session_token,
        "X-Id-Token": id_token,
    }
    canonical, signed_headers = canonical_request("GET", url, headers)
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()))
    signature = hmac.new(_signature_key(credentials.secret_access_key, date, region, service), string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = f"AWS4-HMAC-SHA256 Credential={credentials.access_key_id}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    return headers


class SigV4Signer:
    """Small state-free wrapper useful for dependency injection."""

    def __init__(self, *, region: str, service: str = "execute-api", clock=None) -> None:
        self.region = region
        self.service = service
        self.clock = clock

    def sign_get(self, url: str, credentials: TemporaryCredentials, id_token: str) -> dict[str, str]:
        now = self.clock() if self.clock else None
        return sign_get(url, credentials, id_token, region=self.region, now=now, service=self.service)
