"""Opt-in geographic MCP tools backed by one fixed public area registry."""

from __future__ import annotations

from functools import lru_cache
from importlib import resources
from typing import Literal

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .geography_engine import (
    MENORCA_GEOJSON_MAX_BYTES,
    GeographyEngineError,
    PreparedPublicArea,
    load_frozen_menorca_area,
)
from .geography import GeographyError, summer_window_utc
from .services import GeographicRouteSummary, ServiceError, _validated_period

AREA_SOURCE = "ign_menorca_municipalities_union_2026_10_03"
_READ_ONLY_IDEMPOTENT = ToolAnnotations(readOnlyHint=True, idempotentHint=True)


@lru_cache(maxsize=1)
def _load_menorca_area() -> PreparedPublicArea:
    """Load and cache only the bounded, digest-pinned public boundary."""
    try:
        asset = resources.files("mapit").joinpath("data", "menorca-ign-20261003.geojson")
        with asset.open("rb") as stream:
            raw = stream.read(MENORCA_GEOJSON_MAX_BYTES + 1)
    except Exception:
        raise ServiceError("geographic_area_unavailable", "the fixed public area asset is unavailable") from None
    try:
        return load_frozen_menorca_area(raw)
    except GeographyEngineError:
        raise ServiceError("geographic_area_unavailable", "the fixed public area asset failed validation") from None


def _resolve_area(area_name: str) -> PreparedPublicArea:
    if type(area_name) is not str or len(area_name) > 32 or area_name.strip().casefold() != "menorca":
        raise ServiceError("unknown_geographic_area", "only the fixed Menorca area is currently supported")
    return _load_menorca_area()


def _validate_interval(from_time: str, to_time: str) -> None:
    start, end = _validated_period(from_time, to_time)
    from datetime import timedelta

    if end - start > timedelta(days=93):
        raise ServiceError("geographic_period_too_large", "area analysis is limited to 93 days")


def _validate_summer(year: int | None) -> None:
    if year is not None and type(year) is not int:
        raise ServiceError("unsupported_summer_year", "the selected summer window is unsupported")
    try:
        summer_window_utc(year)
    except GeographyError:
        raise ServiceError("unsupported_summer_year", "the selected summer window is unsupported") from None


def _safe_tool_call(operation):
    try:
        return operation()
    except ServiceError as exc:
        raise ToolError(f"{exc.code}: {exc.public_message}") from None
    except GeographyEngineError:
        raise ToolError("geographic_area_unavailable: the fixed public area asset failed validation") from None


def register_geographic_tools(server, provider) -> None:
    """Register geographic tools only for an explicitly opted-in server."""

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def geographic_summary(
        area_name: Literal["menorca", "Menorca"],
        from_time: str,
        to_time: str,
    ) -> GeographicRouteSummary:
        """Classify bounded embedded route lines against the fixed Menorca municipal union.

        Returns whole-route source-geometry categories and native-distance plus
        the existing unconfirmed kilometre interpretation for fully-contained
        routes only. No clipping, proration, detail fan-out, or completeness claim.
        """
        def run():
            _validate_interval(from_time, to_time)
            area = _resolve_area(area_name)
            return provider.get().get_geographic_summary(
                from_time,
                to_time,
                area,
                AREA_SOURCE,
            )

        return _safe_tool_call(run)

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def summer_geographic_summary(
        area_name: Literal["menorca", "Menorca"],
        year: int | None = None,
    ) -> GeographicRouteSummary:
        """Summarize June 1–September 1 (local Europe/Madrid, half-open) for a supported year.

        The fixed summer convention is version-bounded; route history, MAPIT
        coordinate semantics, streets visited, and GPS accuracy remain unverified.
        """
        def run():
            _validate_summer(year)
            area = _resolve_area(area_name)
            return provider.get().get_summer_geographic_summary(
                area,
                year,
                area_source=AREA_SOURCE,
            )

        return _safe_tool_call(run)
