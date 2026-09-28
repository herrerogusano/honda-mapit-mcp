"""Read-only, allowlisted MAPIT Core/Geo HTTP client."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Mapping
from urllib.parse import quote, urlparse

from .auth import MapitSession
from .config import MapitConfig
from .signing import SigV4Signer, canonical_uri


class MapitHTTPError(RuntimeError):
    def __init__(self, status: int, url: str, message: str = "MAPIT request failed") -> None:
        super().__init__(f"{message}: HTTP {status}")
        self.status = status
        self.url = url


class MapitTransportError(RuntimeError):
    """A MAPIT request failed before a response was available."""

    def __init__(self, _detail: str | None = None) -> None:
        super().__init__("MAPIT transport failed")


class MapitResponseError(RuntimeError):
    """A MAPIT response could not be decoded as the expected JSON."""

    def __init__(self, _detail: str | None = None) -> None:
        super().__init__("MAPIT response is invalid JSON")


class MapitResponseTooLarge(RuntimeError):
    """A response exceeded the caller's hard byte limit before JSON parsing."""

    def __init__(self) -> None:
        super().__init__("MAPIT response exceeds the configured byte limit")


Transport = Callable[[str, str, Mapping[str, str]], Any]


@dataclass
class MapitClient:
    config: MapitConfig
    session: MapitSession
    transport: Transport | None = None
    signer: SigV4Signer | None = None

    def __post_init__(self) -> None:
        if self.signer is None:
            self.signer = SigV4Signer(region=self.config.region)
        self._allowed_hosts = {urlparse(self.config.core_api_url).netloc.lower(), urlparse(self.config.geo_api_url).netloc.lower()}
        self._base_urls = {
            "core": self.config.core_api_url.rstrip("/"),
            "geo": self.config.geo_api_url.rstrip("/"),
        }

    def get(
        self,
        url_or_path: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_response_bytes: int | None = None,
    ) -> Any:
        if max_response_bytes is not None and (
            not isinstance(max_response_bytes, int)
            or isinstance(max_response_bytes, bool)
            or max_response_bytes < 0
        ):
            raise ValueError("max_response_bytes must be a non-negative integer")
        url = self._resolve_url(url_or_path, params=params)
        recovered = False
        while True:
            self.session.refresh_if_needed()
            headers = self.signer.sign_get(url, self.session.credentials, self.session.id_token)
            try:
                return self._send_get(url, headers, max_response_bytes=max_response_bytes)
            except MapitHTTPError as exc:
                if exc.status not in (401, 403) or recovered:
                    raise
                recovered = True
                self.session.refresh_if_needed(force=True)

    def get_core(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_response_bytes: int | None = None,
    ) -> Any:
        return self.get(
            self._base_urls["core"] + "/" + path.lstrip("/"),
            params=params,
            max_response_bytes=max_response_bytes,
        )

    def get_geo(
        self,
        path: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_response_bytes: int | None = None,
    ) -> Any:
        return self.get(
            self._base_urls["geo"] + "/" + path.lstrip("/"),
            params=params,
            max_response_bytes=max_response_bytes,
        )

    def _resolve_url(self, value: str, *, params: Mapping[str, Any] | None) -> str:
        parsed = urlparse(value)
        if not parsed.scheme:
            raise ValueError("get() requires an absolute HTTPS Core/Geo URL")
        if parsed.scheme != "https" or parsed.username or parsed.password or parsed.netloc.lower() not in self._allowed_hosts:
            raise ValueError("URL is outside the HTTPS Core/Geo allowlist")
        canonical_uri(parsed.path)
        if params:
            query = "&".join(
                f"{quote(str(key), safe='-_.~')}={quote(str(item), safe='-_.~')}"
                for key, value in params.items()
                for item in (value if isinstance(value, (list, tuple)) else [value])
            )
            value += ("&" if parsed.query else "?") + query
        return value

    def _send_get(
        self,
        url: str,
        headers: Mapping[str, str],
        *,
        max_response_bytes: int | None = None,
    ) -> Any:
        if self.transport:
            try:
                result = self.transport("GET", url, headers)
                if max_response_bytes is not None:
                    if isinstance(result, bytes):
                        if len(result) > max_response_bytes:
                            raise MapitResponseTooLarge()
                        return json.loads(result.decode("utf-8")) if result else None
                    if isinstance(result, str):
                        raw = result.encode("utf-8")
                        if len(raw) > max_response_bytes:
                            raise MapitResponseTooLarge()
                        return json.loads(result) if result else None
                return result
            except MapitHTTPError:
                raise
            except urllib.error.HTTPError as exc:
                # HTTPError inherits URLError, so this must remain first.
                raise MapitHTTPError(exc.code, url) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                raise MapitTransportError("MAPIT transport failed") from None
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise MapitResponseError("MAPIT response is invalid JSON") from None
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with urllib.request.urlopen(request, timeout=self.config.http_timeout) as response:  # noqa: S310 - URL is allowlisted before this call.
                if max_response_bytes is None:
                    raw = response.read()
                else:
                    chunks: list[bytes] = []
                    total = 0
                    while True:
                        chunk = response.read(min(64 * 1024, max_response_bytes + 1 - total))
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_response_bytes:
                            raise MapitResponseTooLarge()
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # HTTPError inherits URLError, so this must remain first.
            raise MapitHTTPError(exc.code, url) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise MapitTransportError("MAPIT transport failed") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MapitResponseError("MAPIT response is invalid JSON") from None
