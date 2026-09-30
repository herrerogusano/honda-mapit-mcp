"""Typed runtime configuration and public frontend discovery."""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field, replace
from html.parser import HTMLParser
from typing import Callable, Mapping
from urllib.parse import urljoin, urlparse
from urllib.request import Request

from .http_transport import ResponseTooLargeError, open_direct, read_bounded


DEFAULT_REGION = "eu-west-1"
DEFAULT_FRONTEND_URL = "https://app.mapit.me/"
DEFAULT_CORE_API_URL = "https://core.prod.mapit.me"
DEFAULT_GEO_API_URL = "https://geo.prod.mapit.me"
MAX_DISCOVERY_HTML_BYTES = 1024 * 1024
MAX_DISCOVERY_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_DISCOVERY_BUNDLES = 32
MAX_DISCOVERY_TOTAL_BYTES = 16 * 1024 * 1024
DISCOVERY_BUDGET_SECONDS = 60.0


class RuntimeConfigDiscoveryError(RuntimeError):
    """Safe hard-stop category for bounded frontend discovery."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def validate_api_endpoint(url: str, role: str) -> str:
    """Validate a Core/Geo base URL; reject unsafe overrides and discovery."""
    if role not in {"core", "geo"}:
        raise ValueError("API role must be core or geo")
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    expected = rf"^{role}(?:\.[a-z0-9-]+)*\.mapit\.me$"
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
        or not re.fullmatch(expected, host)
    ):
        raise ValueError(f"invalid {role} API endpoint")
    return f"https://{host}"


@dataclass(frozen=True)
class RuntimeConfig:
    """Values discovered from a public HTML document and its JS bundles."""

    region: str | None = None
    user_pool_id: str | None = None
    user_pool_client_id: str | None = None
    identity_pool_id: str | None = None
    core_api_url: str | None = None
    geo_api_url: str | None = None

    def __post_init__(self) -> None:
        if self.core_api_url is not None:
            object.__setattr__(self, "core_api_url", validate_api_endpoint(self.core_api_url, "core"))
        if self.geo_api_url is not None:
            object.__setattr__(self, "geo_api_url", validate_api_endpoint(self.geo_api_url, "geo"))


@dataclass(frozen=True)
class MapitConfig:
    """Application configuration. Password fields never appear in ``repr``."""

    region: str = DEFAULT_REGION
    user_pool_id: str | None = None
    user_pool_client_id: str | None = None
    identity_pool_id: str | None = None
    core_api_url: str = DEFAULT_CORE_API_URL
    geo_api_url: str = DEFAULT_GEO_API_URL
    frontend_url: str = DEFAULT_FRONTEND_URL
    discovery_enabled: bool = True
    http_timeout: float = 20.0
    email: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "core_api_url", validate_api_endpoint(self.core_api_url, "core"))
        object.__setattr__(self, "geo_api_url", validate_api_endpoint(self.geo_api_url, "geo"))

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "MapitConfig":
        env = os.environ if environ is None else environ

        def value(name: str, default: str | None = None) -> str | None:
            raw = env.get(name, default)
            return raw.strip() if raw is not None and raw.strip() else None

        def boolean(name: str, default: bool) -> bool:
            raw = value(name)
            return default if raw is None else raw.lower() in {"1", "true", "yes", "on"}

        timeout_raw = value("MAPIT_HTTP_TIMEOUT")
        try:
            timeout = float(timeout_raw) if timeout_raw else 20.0
        except ValueError as exc:
            raise ValueError("MAPIT_HTTP_TIMEOUT must be a number") from exc
        if timeout <= 0:
            raise ValueError("MAPIT_HTTP_TIMEOUT must be positive")
        return cls(
            region=value("MAPIT_REGION", DEFAULT_REGION) or DEFAULT_REGION,
            user_pool_id=value("MAPIT_USER_POOL_ID"),
            user_pool_client_id=value("MAPIT_USER_POOL_CLIENT_ID"),
            identity_pool_id=value("MAPIT_IDENTITY_POOL_ID"),
            core_api_url=value("MAPIT_CORE_API_URL", DEFAULT_CORE_API_URL) or DEFAULT_CORE_API_URL,
            geo_api_url=value("MAPIT_GEO_API_URL", DEFAULT_GEO_API_URL) or DEFAULT_GEO_API_URL,
            frontend_url=value("MAPIT_FRONTEND_URL", DEFAULT_FRONTEND_URL) or DEFAULT_FRONTEND_URL,
            discovery_enabled=boolean("MAPIT_DISCOVERY_ENABLED", True),
            http_timeout=timeout,
            email=value("MAPIT_EMAIL"),
            password=value("MAPIT_PASSWORD"),
        )

    def with_runtime(self, runtime: RuntimeConfig) -> "MapitConfig":
        """Apply discovered values only where explicit values are absent."""
        return replace(
            self,
            region=self.region if self.region != DEFAULT_REGION else (runtime.region or self.region),
            user_pool_id=self.user_pool_id or runtime.user_pool_id,
            user_pool_client_id=self.user_pool_client_id or runtime.user_pool_client_id,
            identity_pool_id=self.identity_pool_id or runtime.identity_pool_id,
            core_api_url=self.core_api_url if self.core_api_url != DEFAULT_CORE_API_URL else (runtime.core_api_url or self.core_api_url),
            geo_api_url=self.geo_api_url if self.geo_api_url != DEFAULT_GEO_API_URL else (runtime.geo_api_url or self.geo_api_url),
        )


class _ScriptParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.resources: list[str] = []
        self._inline_script: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key.lower(): value for key, value in attrs}
        if tag.lower() == "script":
            src = attributes.get("src")
            if src:
                self.resources.append(src)
            else:
                self._inline_script = []
            return
        if tag.lower() != "link":
            return
        href = attributes.get("href")
        rel = {item.lower() for item in (attributes.get("rel") or "").split()}
        is_script = "modulepreload" in rel or ("preload" in rel and (attributes.get("as") or "").lower() == "script")
        if href and is_script:
            self.resources.append(href)

    def handle_data(self, data: str) -> None:
        if self._inline_script is not None:
            self._inline_script.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script" or self._inline_script is None:
            return
        inline = "".join(self._inline_script)
        self.resources.extend(re.findall(r"import\s*\(\s*[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']\s*\)", inline, re.I))
        self._inline_script = None


def bundle_urls(html: str, frontend_url: str = DEFAULT_FRONTEND_URL) -> list[str]:
    """Extract safe HTTPS script URLs, prioritising main/index bundles."""
    parser = _ScriptParser()
    parser.feed(html)
    frontend_host = urlparse(frontend_url).netloc.lower()
    urls = [urljoin(frontend_url, src) for src in parser.resources]
    urls = [url for url in urls if urlparse(url).scheme == "https" and urlparse(url).netloc.lower() == frontend_host]
    return sorted(dict.fromkeys(urls), key=lambda u: (0 if re.search(r"/(?:main|index)[^/]*\.js(?:$|\?)", u, re.I) else 1, u))


def _first(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.I | re.S)
        if match:
            return match.group(1)
    return None


def extract_runtime_config(*bundles: str) -> RuntimeConfig:
    """Extract known non-secret runtime fields from one or more JS bundles."""
    text = "\n".join(bundles)
    region = _first([r"[\"']region[\"']\s*:\s*[\"']([^\"']+)", r"cognito-idp\.([a-z0-9-]+)\.amazonaws\.com"], text)
    user_pool_id = _first([
        r"[\"']?userPoolId[\"']?\s*:\s*[\"']([^\"']+)",
        r"(?:[\"']?VITE_COGNITO_USER_POOL_ID[\"']?)\s*[:=]\s*[\"']([^\"']+)",
    ], text)
    client_id = _first([
        r"[\"']?userPoolClientId[\"']?\s*:\s*[\"']([^\"']+)",
        r"(?:[\"']?VITE_COGNITO_CLIENT_ID[\"']?)\s*[:=]\s*[\"']([^\"']+)",
    ], text)
    identity_id = _first([
        r"[\"']?identityPoolId[\"']?\s*:\s*[\"']([^\"']+)",
        r"(?:[\"']?VITE_COGNITO_IDENTITY_POOL_ID[\"']?)\s*[:=]\s*[\"']([^\"']+)",
    ], text)
    core = _first([r"(https://core\.[a-z0-9.-]+(?:/[a-z0-9_./-]*)?)"], text)
    geo = _first([r"(https://geo\.[a-z0-9.-]+(?:/[a-z0-9_./-]*)?)"], text)
    if region is None and user_pool_id and "_" in user_pool_id:
        region = user_pool_id.split("_", 1)[0]
    return RuntimeConfig(region, user_pool_id, client_id, identity_id, core.rstrip("/") if core else None, geo.rstrip("/") if geo else None)


def discover_runtime_config(
    html: str,
    bundles: Mapping[str, str] | None = None,
    *,
    overrides: RuntimeConfig | None = None,
    fallback: RuntimeConfig | None = None,
) -> RuntimeConfig:
    """Combine bundle evidence with explicit overrides and safe fallback values."""
    bundle_text = list((bundles or {}).values())
    discovered = extract_runtime_config(html, *bundle_text)
    fallback = fallback or RuntimeConfig(DEFAULT_REGION, core_api_url=DEFAULT_CORE_API_URL, geo_api_url=DEFAULT_GEO_API_URL)

    def choose(field: str) -> str | None:
        override_value = getattr(overrides, field, None) if overrides else None
        return override_value or getattr(discovered, field) or getattr(fallback, field)

    return RuntimeConfig(*(choose(field) for field in RuntimeConfig.__dataclass_fields__))


def fetch_public_runtime_config(
    frontend_url: str = DEFAULT_FRONTEND_URL,
    *,
    timeout: float = 20.0,
    fetcher: Callable[[str, float], str] | None = None,
    overrides: RuntimeConfig | None = None,
    fallback: RuntimeConfig | None = None,
) -> RuntimeConfig:
    """Fetch public HTML/bundles only; no credentials or API calls are used."""
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout < float("inf"):
        raise ValueError("discovery timeout must be positive and finite")
    if urlparse(frontend_url).scheme != "https":
        raise ValueError("frontend discovery requires HTTPS")
    started = time.monotonic()
    deadline = started + DISCOVERY_BUDGET_SECONDS
    aggregate_bytes = 0

    def remaining() -> float:
        value = deadline - time.monotonic()
        if value <= 0:
            raise RuntimeConfigDiscoveryError("discovery_budget_exceeded")
        return value

    def fetch(url: str, limit: int) -> str:
        nonlocal aggregate_bytes
        request_timeout = min(float(timeout), remaining())
        remaining_bytes = max(0, MAX_DISCOVERY_TOTAL_BYTES - aggregate_bytes)
        effective_limit = min(limit, remaining_bytes)
        if fetcher:
            value = fetcher(url, request_timeout)
            remaining()
            if not isinstance(value, str):
                raise RuntimeConfigDiscoveryError("discovery_invalid_response")
            try:
                raw = value.encode("utf-8")
            except UnicodeError:
                raise RuntimeConfigDiscoveryError("discovery_invalid_response") from None
            if len(raw) > effective_limit:
                raise RuntimeConfigDiscoveryError("discovery_size_limit_exceeded")
            aggregate_bytes += len(raw)
            if aggregate_bytes > MAX_DISCOVERY_TOTAL_BYTES:
                raise RuntimeConfigDiscoveryError("discovery_size_limit_exceeded")
            return value
        request = Request(url, headers={"Accept": "text/html,application/javascript"})
        def account_chunk(size: int) -> None:
            nonlocal aggregate_bytes
            aggregate_bytes += size
            remaining()
            if aggregate_bytes > MAX_DISCOVERY_TOTAL_BYTES:
                raise RuntimeConfigDiscoveryError("discovery_size_limit_exceeded")
        try:
            with open_direct(request, timeout=request_timeout) as response:  # noqa: S310 - HTTPS frontend URL only.
                raw = read_bounded(response, effective_limit, on_chunk=account_chunk)
        except ResponseTooLargeError:
            raise RuntimeConfigDiscoveryError("discovery_size_limit_exceeded") from None
        remaining()
        return raw.decode("utf-8", errors="replace")

    try:
        html = fetch(frontend_url, MAX_DISCOVERY_HTML_BYTES)
    except RuntimeConfigDiscoveryError:
        raise
    except Exception:
        remaining()
        raise RuntimeConfigDiscoveryError("discovery_fetch_failed") from None
    urls = bundle_urls(html, frontend_url)
    bundle_map: dict[str, str] = {}
    bundle_attempts = 0
    frontend_host = urlparse(frontend_url).netloc.lower()
    for url in urls:
        if urlparse(url).netloc.lower() != frontend_host:
            continue
        if bundle_attempts >= MAX_DISCOVERY_BUNDLES:
            raise RuntimeConfigDiscoveryError("discovery_bundle_limit_exceeded")
        bundle_attempts += 1
        try:
            bundle_map[url] = fetch(url, MAX_DISCOVERY_BUNDLE_BYTES)
        except RuntimeConfigDiscoveryError:
            raise
        except Exception:
            remaining()
            continue
    return discover_runtime_config(html, bundle_map, overrides=overrides, fallback=fallback)
