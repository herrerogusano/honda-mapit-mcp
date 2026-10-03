"""Opt-in geographic MCP tools backed by one fixed public area registry."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
import unicodedata

from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from .geography_engine import (
    AMB_FEATURE_CODES,
    AMB_GEOJSON_MAX_BYTES,
    GeographyEngineError,
    PreparedPublicArea,
    load_frozen_amb_area,
    load_frozen_menorca_area,
)
from .geography import GeographyError, summer_window_utc
from .services import GeographicRouteSummary, ServiceError, _validated_period

AREA_SOURCE = "ign_menorca_municipalities_union_2026_10_03"
_READ_ONLY_IDEMPOTENT = ToolAnnotations(readOnlyHint=True, idempotentHint=True)


@dataclass(frozen=True)
class _AreaSelection:
    key: str
    codes: frozenset[str] | None
    source: str


_AMB_MUNICIPALITIES = (
    ("Badalona", "34090808015"), ("Badia del Vallès", "34090808904"),
    ("Barberà del Vallès", "34090808252"), ("Barcelona", "34090808019"),
    ("Begues", "34090808020"), ("Castellbisbal", "34090808054"),
    ("Castelldefels", "34090808056"), ("Cerdanyola del Vallès", "34090808266"),
    ("Cervelló", "34090808068"), ("Corbera de Llobregat", "34090808072"),
    ("Cornellà de Llobregat", "34090808073"), ("Esplugues de Llobregat", "34090808077"),
    ("Gavà", "34090808089"), ("L'Hospitalet de Llobregat", "34090808101"),
    ("Molins de Rei", "34090808123"), ("Montcada i Reixac", "34090808125"),
    ("Montgat", "34090808126"), ("Pallejà", "34090808157"), ("El Papiol", "34090808158"),
    ("El Prat de Llobregat", "34090808169"), ("Ripollet", "34090808180"),
    ("Sant Adrià de Besòs", "34090808194"), ("Sant Andreu de la Barca", "34090808196"),
    ("Sant Boi de Llobregat", "34090808200"), ("Sant Climent de Llobregat", "34090808204"),
    ("Sant Cugat del Vallès", "34090808205"), ("Sant Feliu de Llobregat", "34090808211"),
    ("Sant Joan Despí", "34090808217"), ("Sant Just Desvern", "34090808221"),
    ("Santa Coloma de Cervelló", "34090808244"), ("Santa Coloma de Gramenet", "34090808245"),
    ("Sant Vicenç dels Horts", "34090808263"), ("Tiana", "34090808282"),
    ("Torrelles de Llobregat", "34090808289"), ("Viladecans", "34090808301"),
    ("La Palma de Cervelló", "34090808905"),
)
_AMB_ALL = frozenset(code for _, code in _AMB_MUNICIPALITIES)
if _AMB_ALL != AMB_FEATURE_CODES:
    raise RuntimeError("fixed geographic registry does not match the frozen AMB asset")

_AREA_REGISTRY_BUILD: dict[str, _AreaSelection] = {}


def _normalize_area_name(value: str) -> str:
    folded = unicodedata.normalize("NFKD", value.strip().casefold())
    return "".join(character for character in folded if not unicodedata.combining(character))


def _register(selection: _AreaSelection, *names: str) -> None:
    for name in names:
        normalized = _normalize_area_name(name)
        existing = _AREA_REGISTRY_BUILD.get(normalized)
        if existing is not None and existing != selection:
            raise RuntimeError("fixed geographic registry alias collision")
        _AREA_REGISTRY_BUILD[normalized] = selection


_register(_AreaSelection("menorca", None, AREA_SOURCE), "Menorca")
_register(
    _AreaSelection("amb", _AMB_ALL, "ign_amb_36_municipalities_union_2026_10_03"),
    "AMB", "Àrea Metropolitana de Barcelona", "Area Metropolitana de Barcelona",
)
for _name, _code in _AMB_MUNICIPALITIES:
    _register(
        _AreaSelection(f"amb-{_code}", frozenset({_code}), f"ign_amb_municipality_{_code}_2026_10_03"),
        _name,
    )
_AREA_BY_NORMALIZED_NAME = MappingProxyType(dict(_AREA_REGISTRY_BUILD))


@lru_cache(maxsize=2)
def _load_selected_area(key: str, codes: frozenset[str] | None, source: str) -> PreparedPublicArea:
    """Cache no more than two selected, fixed public geometries."""
    try:
        filename = "menorca-ign-20261003.geojson" if key == "menorca" else "amb-ign-20261003.geojson"
        asset = resources.files("mapit").joinpath("data", filename)
        with asset.open("rb") as stream:
            raw = stream.read((AMB_GEOJSON_MAX_BYTES if key != "menorca" else 1024 * 1024) + 1)
    except Exception:
        raise ServiceError("geographic_area_unavailable", "the fixed public area asset is unavailable") from None
    try:
        if key == "menorca":
            return load_frozen_menorca_area(raw)
        if codes is None:
            raise GeographyEngineError("public_selection_invalid")
        return load_frozen_amb_area(raw, codes)
    except GeographyEngineError:
        raise ServiceError("geographic_area_unavailable", "the fixed public area asset failed validation") from None


def _resolve_area(area_name: str) -> tuple[PreparedPublicArea, str]:
    if type(area_name) is not str or not area_name.strip() or len(area_name) > 80:
        raise ServiceError("unknown_geographic_area", "only named areas in the fixed public registry are supported")
    selection = _AREA_BY_NORMALIZED_NAME.get(_normalize_area_name(area_name))
    if selection is None:
        raise ServiceError("unknown_geographic_area", "only named areas in the fixed public registry are supported")
    return _load_selected_area(selection.key, selection.codes, selection.source), selection.source


def _load_menorca_area() -> PreparedPublicArea:
    """Compatibility wrapper for the previously fixed Menorca selection."""
    return _load_selected_area("menorca", None, AREA_SOURCE)


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
        area_name: str,
        from_time: str,
        to_time: str,
    ) -> GeographicRouteSummary:
        """Classify bounded embedded route lines against Menorca, Barcelona municipality,
        the 36-municipality AMB union, or one of its 36 named municipalities.

        Returns whole-route source-geometry categories and native-distance plus
        the existing unconfirmed kilometre interpretation for fully-contained
        routes only. The registry is fixed: no arbitrary radius, bbox, or generic
        “surroundings” area is inferred. No clipping, proration, detail fan-out,
        or completeness claim.
        """
        def run():
            _validate_interval(from_time, to_time)
            area, area_source = _resolve_area(area_name)
            return provider.get().get_geographic_summary(
                from_time,
                to_time,
                area,
                area_source,
            )

        return _safe_tool_call(run)

    @server.tool(annotations=_READ_ONLY_IDEMPOTENT)
    def summer_geographic_summary(
        area_name: str,
        year: int | None = None,
    ) -> GeographicRouteSummary:
        """Summarize June 1–September 1 (local Europe/Madrid, half-open) for a supported year.

        The fixed summer convention is version-bounded; route history, MAPIT
        coordinate semantics, streets visited, and GPS accuracy remain unverified.
        """
        def run():
            _validate_summer(year)
            area, area_source = _resolve_area(area_name)
            return provider.get().get_summer_geographic_summary(
                area,
                year,
                area_source=area_source,
            )

        return _safe_tool_call(run)
