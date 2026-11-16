"""Read-only, allowlisted MAPIT Core/Geo HTTP client."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import quote, urlparse

from .auth import MapitSession
from .config import MapitConfig
from .http_transport import ResponseTooLargeError, open_direct, read_bounded
from .signing import SigV4Signer, canonical_uri


# --- Per-tool-call read meter ------------------------------------------------
# One line per tool call goes to stderr (stdout is the stdio MCP channel). The
# line holds only the fixed tool name, the number of GETs sent to MAPIT Core/Geo
# and a fixed outcome word: no identifiers, parameters, URLs, dates or content.


class ReadMeter:
    """Mutable read count for one tool call."""

    __slots__ = ("reads",)

    def __init__(self) -> None:
        self.reads = 0


_ACTIVE_METER: ContextVar[ReadMeter | None] = ContextVar("mapit_read_meter", default=None)


def _stderr_sink(line: str) -> None:
    print(line, file=sys.stderr, flush=True)


_meter_sink: Callable[[str], None] = _stderr_sink


def set_read_meter_sink(sink: Callable[[str], None] | None) -> None:
    """Replace the read-count log sink (tests); ``None`` restores stderr."""
    global _meter_sink
    _meter_sink = sink if sink is not None else _stderr_sink


def record_mapit_read() -> None:
    """Count one GET sent to MAPIT Core/Geo in the active tool call, if any."""
    meter = _ACTIVE_METER.get()
    if meter is not None:
        meter.reads += 1


@contextmanager
def metered_tool_call(tool: str) -> Iterator[ReadMeter]:
    """Count MAPIT reads made while the block runs and log one count line."""
    meter = ReadMeter()
    token = _ACTIVE_METER.set(meter)
    outcome = "error"
    try:
        yield meter
        outcome = "ok"
    finally:
        _ACTIVE_METER.reset(token)
        try:
            _meter_sink(
                json.dumps(
                    {"event": "mapit_reads", "tool": tool, "reads": meter.reads, "outcome": outcome},
                    separators=(",", ":"),
                )
            )
        except Exception:  # noqa: BLE001 - a log failure must never change a tool result.
            pass


class MapitHTTPError(RuntimeError):
    def __init__(self, status: int, url: str, message: str = "MAPIT request failed") -> None:
        super().__init__(f"{message}: HTTP {status}")
        self.status = status
        self.url = url


class MapitTransportError(RuntimeError):
    """A MAPIT request failed before a response was available."""

    def __init__(self, _detail: str | None = None) -> None:
        super().__init__("MAPIT transport failed")


class MapitTimeout(MapitTransportError):
    """MAPIT accepted the connection but did not answer within the read timeout.

    Raised only for a timeout while waiting for the response or its body, never
    for a connect timeout (``URLError`` wrapping a timeout), which signals an
    unreachable service rather than a slow answer.
    """


class MapitResponseError(RuntimeError):
    """A MAPIT response could not be decoded as the expected JSON."""

    def __init__(self, _detail: str | None = None) -> None:
        super().__init__("MAPIT response is invalid JSON")


class MapitResponseTooLarge(RuntimeError):
    """A response exceeded the caller's hard byte limit before JSON parsing."""

    def __init__(self) -> None:
        super().__init__("MAPIT response exceeds the configured byte limit")


Transport = Callable[[str, str, Mapping[str, str]], Any]
MAX_MAPIT_RESPONSE_BYTES = 2 * 1024 * 1024


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
        effective_limit = min(max_response_bytes, MAX_MAPIT_RESPONSE_BYTES) if max_response_bytes is not None else MAX_MAPIT_RESPONSE_BYTES
        url = self._resolve_url(url_or_path, params=params)
        recovered = False
        while True:
            self.session.refresh_if_needed()
            headers = self.signer.sign_get(url, self.session.credentials, self.session.id_token)
            # Every GET sent to Core/Geo counts, including the one auth-recovery retry.
            record_mapit_read()
            try:
                return self._send_get(url, headers, max_response_bytes=effective_limit)
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
        if max_response_bytes is not None and (
            not isinstance(max_response_bytes, int)
            or isinstance(max_response_bytes, bool)
            or max_response_bytes < 0
        ):
            raise ValueError("max_response_bytes must be a non-negative integer")
        max_response_bytes = min(max_response_bytes, MAX_MAPIT_RESPONSE_BYTES) if max_response_bytes is not None else MAX_MAPIT_RESPONSE_BYTES
        if self.transport:
            try:
                result = self.transport("GET", url, headers)
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
            except TimeoutError:
                raise MapitTimeout() from None
            except (urllib.error.URLError, OSError):
                raise MapitTransportError("MAPIT transport failed") from None
            except (UnicodeError, json.JSONDecodeError):
                raise MapitResponseError("MAPIT response is invalid JSON") from None
        request = urllib.request.Request(url, headers=dict(headers), method="GET")
        try:
            with open_direct(request, timeout=self.config.http_timeout) as response:  # noqa: S310 - allowlisted host, direct opener.
                raw = read_bounded(response, max_response_bytes or 0)
                if not raw:
                    return None
                return json.loads(raw.decode("utf-8"))
        except ResponseTooLargeError:
            raise MapitResponseTooLarge() from None
        except urllib.error.HTTPError as exc:
            # HTTPError inherits URLError, so this must remain first.
            raise MapitHTTPError(exc.code, url) from None
        except TimeoutError:
            raise MapitTimeout() from None
        except (urllib.error.URLError, OSError):
            raise MapitTransportError("MAPIT transport failed") from None
        except (UnicodeError, json.JSONDecodeError):
            raise MapitResponseError("MAPIT response is invalid JSON") from None
