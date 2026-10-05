"""Direct-only bounded HTTP transport for one injected production invocation.

The caller supplies a pinned ``MapitConfig`` and absolute monotonic deadline.
No client, session, credential source, network request, or environment setting
is created or read at import time.
"""

from __future__ import annotations

import json
import math
import re
import time
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any, Callable
from urllib.parse import urlparse

from .auth import CognitoHTTPError, CognitoTransportError
from .client import (
    MAX_MAPIT_RESPONSE_BYTES,
    MapitHTTPError,
    MapitResponseTooLarge,
    MapitTransportError,
)
from .config import MapitConfig
from .http_transport import open_direct

_REGION = "eu-west-1"
_CORE_HOST = "core.prod.mapit.me"
_GEO_HOST = "geo.prod.mapit.me"
_MAX_AUTH_BYTES = 256 * 1024
_MAX_ATTEMPTS = 24
_MAX_WINDOW_SECONDS = 14.0
_READ_CHUNK_BYTES = 64 * 1024
_IDENTITY_RE = re.compile(r"^eu-west-1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TOKEN_RE = re.compile(r"^[\x21-\x7e]{1,8192}$")


class CloudTransportError(RuntimeError):
    """Fixed-category transport failure with no URL, body, or exception text."""

    def __init__(self, category: str):
        self.category = category if category in {
            "configuration_invalid", "deadline_invalid", "deadline_expired", "clock_invalid",
            "clock_rollback", "attempt_limit", "request_invalid", "response_invalid",
            "response_too_large", "transport_failed", "redirect_rejected",
        } else "transport_failed"
        super().__init__(self.category)


def _is_finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def validate_cloud_config(config: Any) -> MapitConfig:
    """Require the explicit, fixed production target without discovering it."""
    if type(config) is not MapitConfig:
        raise CloudTransportError("configuration_invalid")
    timeout = config.http_timeout
    if (
        config.region != _REGION
        or config.core_api_url != f"https://{_CORE_HOST}"
        or config.geo_api_url != f"https://{_GEO_HOST}"
        or config.discovery_enabled is not False
        or config.email is not None
        or config.password is not None
        or not _is_finite_number(timeout)
        or timeout <= 0
        or timeout > 2
        or type(config.user_pool_id) is not str
        or not re.fullmatch(r"eu-west-1_[A-Za-z0-9]{9,64}", config.user_pool_id)
        or type(config.user_pool_client_id) is not str
        or not re.fullmatch(r"[A-Za-z0-9]{1,128}", config.user_pool_client_id)
        or type(config.identity_pool_id) is not str
        or not _IDENTITY_RE.fullmatch(config.identity_pool_id)
    ):
        raise CloudTransportError("configuration_invalid")
    return config


class CloudDirectTransport:
    """Shared 24-attempt budget for fixed Cognito POSTs and Core/Geo GETs."""

    def __init__(
        self,
        config: MapitConfig,
        *,
        deadline: float,
        opener: Any | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.config = validate_cloud_config(config)
        if not callable(monotonic):
            raise CloudTransportError("configuration_invalid")
        self._monotonic = monotonic
        self._opener = opener
        self._attempts = 0
        if not _is_finite_number(deadline) or deadline <= 0:
            raise CloudTransportError("deadline_invalid")
        self._deadline = float(deadline)
        self._last_clock = self._clock()
        if self._deadline <= self._last_clock or self._deadline - self._last_clock > _MAX_WINDOW_SECONDS:
            raise CloudTransportError("deadline_invalid")

    @property
    def attempts(self) -> int:
        return self._attempts

    def _clock(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            raise CloudTransportError("clock_invalid") from None
        if not _is_finite_number(value) or value < 0:
            raise CloudTransportError("clock_invalid")
        return float(value)

    def check_deadline(self) -> float:
        now = self._clock()
        if now < self._last_clock:
            raise CloudTransportError("clock_rollback")
        self._last_clock = now
        remaining = self._deadline - now
        if remaining <= 0:
            raise CloudTransportError("deadline_expired")
        return remaining

    def _reserve_attempt(self) -> float:
        remaining = self.check_deadline()
        if self._attempts >= _MAX_ATTEMPTS:
            raise CloudTransportError("attempt_limit")
        self._attempts += 1
        return min(float(self.config.http_timeout), remaining)

    @staticmethod
    def _header(headers: Mapping[str, Any], name: str) -> Any:
        matches = [value for key, value in headers.items() if isinstance(key, str) and key.casefold() == name.casefold()]
        return matches[0] if len(matches) == 1 else None

    def _validate_cognito(self, url: Any, headers: Any, payload: Any) -> tuple[str, str]:
        if (
            type(url) is not str
            or not isinstance(headers, Mapping)
            or not isinstance(payload, Mapping)
            or any(type(key) is not str or type(value) is not str for key, value in headers.items())
            or len(headers) != 2
        ):
            raise CloudTransportError("request_invalid")
        try:
            parsed = urlparse(url)
        except Exception:
            raise CloudTransportError("request_invalid") from None
        if parsed.scheme != "https" or parsed.path != "/" or parsed.query or parsed.fragment or parsed.username or parsed.password:
            raise CloudTransportError("request_invalid")
        if parsed.netloc == f"cognito-idp.{_REGION}.amazonaws.com":
            endpoint = "user_pool"
        elif parsed.netloc == f"cognito-identity.{_REGION}.amazonaws.com":
            endpoint = "identity"
        else:
            raise CloudTransportError("request_invalid")
        if self._header(headers, "Content-Type") != "application/x-amz-json-1.1":
            raise CloudTransportError("request_invalid")
        target = self._header(headers, "X-Amz-Target")
        provider_login = f"cognito-idp.{_REGION}.amazonaws.com/{self.config.user_pool_id}"
        if endpoint == "user_pool":
            if target != "AWSCognitoIdentityProviderService.InitiateAuth":
                raise CloudTransportError("request_invalid")
            auth_parameters = payload.get("AuthParameters")
            if (
                set(payload) != {"AuthFlow", "ClientId", "AuthParameters", "ClientMetadata"}
                or payload.get("AuthFlow") != "REFRESH_TOKEN_AUTH"
                or payload.get("ClientId") != self.config.user_pool_client_id
                or payload.get("ClientMetadata") != {}
                or not isinstance(auth_parameters, Mapping)
                or set(auth_parameters) != {"REFRESH_TOKEN"}
                or type(auth_parameters.get("REFRESH_TOKEN")) is not str
                or not _TOKEN_RE.fullmatch(auth_parameters["REFRESH_TOKEN"])
            ):
                raise CloudTransportError("request_invalid")
        elif target == "AWSCognitoIdentityService.GetId":
            logins = payload.get("Logins")
            if (
                set(payload) != {"IdentityPoolId", "Logins"}
                or payload.get("IdentityPoolId") != self.config.identity_pool_id
                or not isinstance(logins, Mapping)
                or set(logins) != {provider_login}
                or type(logins.get(provider_login)) is not str
                or not _TOKEN_RE.fullmatch(logins[provider_login])
            ):
                raise CloudTransportError("request_invalid")
        elif target == "AWSCognitoIdentityService.GetCredentialsForIdentity":
            logins = payload.get("Logins")
            identity_id = payload.get("IdentityId")
            if (
                set(payload) != {"IdentityId", "Logins"}
                or type(identity_id) is not str
                or not _IDENTITY_RE.fullmatch(identity_id)
                or not isinstance(logins, Mapping)
                or set(logins) != {provider_login}
                or type(logins.get(provider_login)) is not str
                or not _TOKEN_RE.fullmatch(logins[provider_login])
            ):
                raise CloudTransportError("request_invalid")
        else:
            raise CloudTransportError("request_invalid")
        return endpoint, target

    def cognito_json(self, url: str, headers: Mapping[str, str], payload: Mapping[str, Any]) -> Mapping[str, Any]:
        endpoint, _target = self._validate_cognito(url, headers, payload)
        try:
            body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        except Exception:
            raise CloudTransportError("request_invalid") from None
        if len(body) > _MAX_AUTH_BYTES:
            raise CloudTransportError("request_invalid")
        raw = self._send("POST", url, headers, body, _MAX_AUTH_BYTES)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise CloudTransportError("response_invalid") from None
        if not isinstance(parsed, Mapping):
            raise CloudTransportError("response_invalid")
        self.check_deadline()
        return parsed

    def mapit_request(self, method: str, url: str, headers: Mapping[str, str]) -> bytes:
        if type(method) is not str or method != "GET" or not isinstance(headers, Mapping):
            raise CloudTransportError("request_invalid")
        if any(type(key) is not str or type(value) is not str for key, value in headers.items()):
            raise CloudTransportError("request_invalid")
        try:
            parsed = urlparse(url)
        except Exception:
            raise CloudTransportError("request_invalid") from None
        if (
            parsed.scheme != "https"
            or parsed.netloc not in {_CORE_HOST, _GEO_HOST}
            or parsed.hostname not in {_CORE_HOST, _GEO_HOST}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
            or parsed.fragment
        ):
            raise CloudTransportError("request_invalid")
        return self._send("GET", url, headers, None, MAX_MAPIT_RESPONSE_BYTES)

    def _send(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, limit: int) -> bytes:
        self._reserve_attempt()
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        response = None
        try:
            # Request construction and header copying take place after budget
            # reservation; recalculate the per-socket timeout immediately
            # before dispatch so that work in this layer cannot overrun it.
            timeout = min(float(self.config.http_timeout), self.check_deadline())
            response = open_direct(request, timeout=timeout, opener=self._opener)
            self.check_deadline()
            status = getattr(response, "status", None)
            if status is None:
                getcode = getattr(response, "getcode", None)
                status = getcode() if callable(getcode) else None
            if type(status) is not int or not 100 <= status <= 599:
                raise CloudTransportError("response_invalid")
            if status != 200:
                self._raise_http(status, method, url)
            chunks: list[bytes] = []
            total = 0
            reader = getattr(response, "read1", None)
            if not callable(reader):
                reader = getattr(response, "read", None)
            if not callable(reader):
                raise CloudTransportError("response_invalid")
            while True:
                self.check_deadline()
                chunk = reader(min(_READ_CHUNK_BYTES, limit + 1 - total))
                self.check_deadline()
                if type(chunk) is not bytes:
                    raise CloudTransportError("response_invalid")
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    if method == "GET":
                        raise MapitResponseTooLarge()
                    raise CloudTransportError("response_too_large")
                chunks.append(chunk)
            result = b"".join(chunks)
            self.check_deadline()
            return result
        except CloudTransportError:
            raise
        except CognitoHTTPError:
            raise
        except MapitHTTPError:
            raise
        except MapitResponseTooLarge:
            raise
        except urllib.error.HTTPError as exc:
            status = exc.code if type(exc.code) is int else 0
            try:
                exc.close()
            except Exception:
                pass
            self._raise_http(status, method, url)
        except Exception:
            if method == "GET":
                raise MapitTransportError() from None
            raise CognitoTransportError() from None
        finally:
            if response is not None:
                close = getattr(response, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

    @staticmethod
    def _raise_http(status: int, method: str, url: str) -> None:
        if status in {301, 302, 303, 307, 308}:
            raise CloudTransportError("redirect_rejected") from None
        if method == "GET":
            # The existing MapitClient relies on this exact class for its one
            # bounded 401/403 auth recovery; the URL is deliberately blank.
            raise MapitHTTPError(status, "") from None
        raise CognitoHTTPError(status) from None


__all__ = ["CloudDirectTransport", "CloudTransportError", "validate_cloud_config"]
