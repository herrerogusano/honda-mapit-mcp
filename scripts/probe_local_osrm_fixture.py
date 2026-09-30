"""Run a bounded synthetic route/match probe against loopback-only OSRM.

The probe contains no MAPIT integration and never prints or persists a raw
route, match response, URL, coordinate, name, or exception detail.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.osrm import (  # noqa: E402
    MAX_JSON_BYTES,
    OSRMAnalysisError,
    classify_match_json,
    classify_match_response,
    safe_osrm_result,
    validate_payload_budget,
)

DEFAULT_BASE_URL = "http://127.0.0.1:5000"
MAX_SAMPLE_POINTS = 12
MAX_ROUTE_POINTS = 10_000
TIMEOUT_SECONDS = 5.0

Transport = Callable[[str, str, float], Any]


def _loopback_base_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 256:
        raise ValueError("invalid loopback URL")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("invalid loopback URL")
    if parsed.path not in ("", "/"):
        raise ValueError("invalid loopback URL")
    host = parsed.hostname
    if host is None:
        raise ValueError("invalid loopback URL")
    host_lower = host.lower().rstrip(".")
    try:
        address = ipaddress.ip_address(host_lower)
    except ValueError:
        address = None
    is_loopback = bool(
        address is not None
        and ((address.version == 4 and address in ipaddress.ip_network("127.0.0.0/8"))
             or (address.version == 6 and address == ipaddress.IPv6Address("::1")))
    )
    if not is_loopback:
        raise ValueError("invalid loopback URL")
    try:
        parsed.port
    except ValueError:
        raise ValueError("invalid loopback URL") from None
    return value.rstrip("/")


class _ProbeError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class _NoRedirectHandler(HTTPRedirectHandler):
    """Reject redirects so a loopback request cannot be redirected elsewhere."""

    def redirect_request(self, req, fp, newurl, code=None, msg=None, headers=None):  # type: ignore[override]
        return None


_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler)


def _urllib_transport(method: str, url: str, timeout: float) -> bytes:
    request = Request(url, method=method, headers={"Accept": "application/json"})
    with _NO_REDIRECT_OPENER.open(request, timeout=timeout) as response:  # noqa: S310 - URL is loopback-validated.
        status = response.getcode()
        if status is not None and 300 <= status < 400:
            raise _ProbeError("engine_unavailable")
        raw = response.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise _ProbeError("resource_limit")
    return raw


def _decode_payload(value: Any) -> Any:
    if isinstance(value, (bytes, str)):
        try:
            if isinstance(value, bytes) and len(value) > MAX_JSON_BYTES:
                raise _ProbeError("resource_limit")
            if isinstance(value, str) and len(value.encode("utf-8")) > MAX_JSON_BYTES:
                raise _ProbeError("resource_limit")
            decoded = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
            try:
                validate_payload_budget(decoded)
            except OSRMAnalysisError as exc:
                raise _ProbeError(exc.category) from None
            return decoded
        except _ProbeError:
            raise
        except RecursionError:
            raise _ProbeError("resource_limit") from None
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
            raise _ProbeError("invalid_input") from None
    if isinstance(value, dict):
        try:
            if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) > MAX_JSON_BYTES:
                raise _ProbeError("resource_limit")
        except _ProbeError:
            raise
        except RecursionError:
            raise _ProbeError("resource_limit") from None
        except (TypeError, ValueError, OverflowError):
            raise _ProbeError("invalid_input") from None
        try:
            validate_payload_budget(value)
        except OSRMAnalysisError as exc:
            raise _ProbeError(exc.category) from None
        return value
    raise _ProbeError("invalid_input")


def _finite_coordinate(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _sample_route_points(route_payload: Any) -> list[tuple[float, float]]:
    payload = _decode_payload(route_payload)
    if not isinstance(payload, dict) or payload.get("code") != "Ok":
        raise _ProbeError("invalid_input")
    routes = payload.get("routes")
    if not isinstance(routes, list) or not routes:
        raise _ProbeError("invalid_input")
    geometry = routes[0].get("geometry") if isinstance(routes[0], dict) else None
    if not isinstance(geometry, dict) or geometry.get("type") != "LineString":
        raise _ProbeError("invalid_input")
    coordinates = geometry.get("coordinates")
    if not isinstance(coordinates, list) or not coordinates:
        raise _ProbeError("invalid_input")
    if len(coordinates) > MAX_ROUTE_POINTS:
        raise _ProbeError("resource_limit")
    normalized: list[tuple[float, float]] = []
    for coordinate in coordinates:
        if (
            not isinstance(coordinate, list)
            or len(coordinate) < 2
            or len(coordinate) > 3
            or not _finite_coordinate(coordinate[0])
            or not _finite_coordinate(coordinate[1])
            or not -180 <= float(coordinate[0]) <= 180
            or not -90 <= float(coordinate[1]) <= 90
        ):
            raise _ProbeError("invalid_input")
        normalized.append((float(coordinate[0]), float(coordinate[1])))
    if len(normalized) < 2:
        raise _ProbeError("invalid_input")
    if len(normalized) <= MAX_SAMPLE_POINTS:
        return normalized
    indexes = sorted({round(index * (len(normalized) - 1) / (MAX_SAMPLE_POINTS - 1)) for index in range(MAX_SAMPLE_POINTS)})
    return [normalized[index] for index in indexes]


def _coordinate_path(points: list[tuple[float, float]]) -> str:
    return ";".join(f"{lon:.7f},{lat:.7f}" for lon, lat in points)


def run_local_osrm_fixture_probe(
    *,
    base_url: str = DEFAULT_BASE_URL,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Generate a synthetic route and classify one bounded local Match."""
    try:
        base = _loopback_base_url(base_url)
    except (TypeError, ValueError):
        return safe_osrm_result("invalid_input")
    sender = transport or _urllib_transport
    synthetic_points = [(7.4165, 43.7304), (7.4320, 43.7420)]
    try:
        route_url = f"{base}/route/v1/driving/{_coordinate_path(synthetic_points)}?{urlencode({'overview': 'full', 'geometries': 'geojson', 'steps': 'false'})}"
        route_payload = sender("GET", route_url, TIMEOUT_SECONDS)
        sampled = _sample_route_points(route_payload)
        match_url = f"{base}/match/v1/driving/{quote(_coordinate_path(sampled), safe=',;.-')}?{urlencode({'overview': 'false', 'steps': 'true', 'annotations': 'true', 'tidy': 'true'})}"
        match_payload = sender("GET", match_url, TIMEOUT_SECONDS)
        if isinstance(match_payload, (bytes, str)):
            return classify_match_json(match_payload)
        return classify_match_response(match_payload)
    except _ProbeError as exc:
        return safe_osrm_result(exc.category)
    except (TimeoutError, OSError, ValueError, TypeError):
        return safe_osrm_result("engine_unavailable")
    except Exception:
        return safe_osrm_result("engine_unavailable")
    finally:
        route_payload = None
        match_payload = None
        sampled = None
        synthetic_points = None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Bounded loopback-only synthetic OSRM route/match probe")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args(argv)
    result = run_local_osrm_fixture_probe(base_url=args.base_url)
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True))
    return 0 if result["category"] == "matched" else 1


if __name__ == "__main__":
    raise SystemExit(main())
