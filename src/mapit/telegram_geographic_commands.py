"""Deterministic offline geographic command dispatcher (not a Telegram transport).

The caller supplies an already authenticated grant. Every dispatch binds it to
the tenant router, including help; replies contain typed summary metrics only.
"""
from __future__ import annotations
import math
import re
from .geographic_tools import _AREA_BY_NORMALIZED_NAME, _normalize_area_name, _resolve_area, _validate_interval
from .geography import GeographyError, summer_window_utc
from .services import GeographicRouteSummary, ServiceError, _iso, _validated_period
from .tenant_router import AuthenticatedTenant, TenantIsolationError, TenantServicesRouter

_MAX_COMMAND_LENGTH = 2048
_HELP = (
    "Comandos disponibles:\n"
    "/verano <zona> [año] — resumen geográfico del verano (1 jun–1 sep).\n"
    "/kms <zona> | <desde ISO> | <hasta ISO> — resumen de hasta 93 días.\n"
    "Zonas: Menorca, Barcelona, AMB y municipios nombrados del AMB."
)
_KMS_RE = re.compile(r"^/kms\s+([^|\r\n]{1,80})\s*\|\s*([^|\r\n]{1,64})\s*\|\s*([^|\r\n]{1,64})\s*$")
_SUMMER_RE = re.compile(r"^/verano\s+(.{1,80}?)(?:\s+([0-9]{4}))?\s*$")

class GeographicCommandError(ValueError):
    """Safe closed-category command error."""
    def __init__(self, category: str):
        allowed = {"command_invalid", "unknown_area", "invalid_period", "unsupported_year", "summary_unavailable", "tenant_context_invalid"}
        self.category = category if category in allowed else "command_invalid"
        super().__init__(self.category)

def _registered(name: str) -> bool:
    return type(name) is str and 1 <= len(name.strip()) <= 80 and _normalize_area_name(name) in _AREA_BY_NORMALIZED_NAME

def _format_summary(
    summary: GeographicRouteSummary,
    *,
    expected_source: str,
    expected_from: str,
    expected_to: str,
) -> str:
    if type(summary) is not GeographicRouteSummary:
        raise GeographicCommandError("summary_unavailable")
    if type(expected_source) is not str or summary.area_source != expected_source:
        raise GeographicCommandError("summary_unavailable")
    counts = (summary.matched_routes, summary.fully_inside_routes, summary.outside_routes, summary.crossing_routes, summary.unknown_routes, summary.inferred_marked_inside_routes, summary.not_marked_inferred_inside_routes, summary.inference_unknown_inside_routes)
    if any(type(value) is not int or not 0 <= value <= 2000 for value in counts):
        raise GeographicCommandError("summary_unavailable")
    if (summary.fully_inside_routes + summary.outside_routes + summary.crossing_routes + summary.unknown_routes != summary.matched_routes
        or summary.inferred_marked_inside_routes + summary.not_marked_inferred_inside_routes + summary.inference_unknown_inside_routes != summary.fully_inside_routes):
        raise GeographicCommandError("summary_unavailable")
    distance = summary.fully_inside_distance_km
    if isinstance(distance, bool) or not isinstance(distance, (int, float)) or not math.isfinite(float(distance)) or distance < 0:
        raise GeographicCommandError("summary_unavailable")
    if type(summary.from_time) is not str or type(summary.to_time) is not str:
        raise GeographicCommandError("summary_unavailable")
    try:
        start, end = _validated_period(summary.from_time, summary.to_time)
        expected_start, expected_end = _validated_period(expected_from, expected_to)
    except ServiceError:
        raise GeographicCommandError("summary_unavailable") from None
    from datetime import timedelta
    if end - start > timedelta(days=93):
        raise GeographicCommandError("summary_unavailable")
    if start != expected_start or end != expected_end:
        raise GeographicCommandError("summary_unavailable")
    safe_from, safe_to = _iso(start), _iso(end)
    response = (
        f"Periodo: {safe_from} → {safe_to}\n"
        f"Rutas: {summary.matched_routes}; dentro: {summary.fully_inside_routes}; fuera: {summary.outside_routes}; "
        f"cruzando: {summary.crossing_routes}; desconocidas: {summary.unknown_routes}.\n"
        f"Distancia de rutas completamente dentro: {float(distance):.2f} km (conversión UI-correlacionada, no confirmada).\n"
        f"Rutas dentro con marca de segmentos inferidos: {summary.inferred_marked_inside_routes}; "
        f"sin marca: {summary.not_marked_inferred_inside_routes}; "
        f"desconocido {summary.inference_unknown_inside_routes}.\n"
        "La ausencia de marca no garantiza GPS. La geometría fuente no demuestra cobertura física, precisión GPS ni historial completo."
    )
    if len(response) > 4096:
        raise GeographicCommandError("summary_unavailable")
    return response

def dispatch_geographic_command(command: str, grant: AuthenticatedTenant, router: TenantServicesRouter) -> str:
    """Run /ayuda, /verano or /kms under one authenticated tenant binding."""
    if (type(command) is not str or not command or len(command) > _MAX_COMMAND_LENGTH
        or any(ord(ch) < 32 and ch not in "\t\n\r" for ch in command)):
        raise GeographicCommandError("command_invalid")
    if type(router) is not TenantServicesRouter:
        raise GeographicCommandError("tenant_context_invalid")
    try:
        with router.bind(grant):
            text = command.strip()
            if text == "/ayuda":
                return _HELP
            match = _SUMMER_RE.fullmatch(text)
            if match:
                area_name, year_text = match.groups()
                year = int(year_text) if year_text is not None else None
                try:
                    expected_from, expected_to = summer_window_utc(year)
                except GeographyError:
                    raise GeographicCommandError("unsupported_year") from None
                year = int(expected_from[:4])
                if not _registered(area_name):
                    raise GeographicCommandError("unknown_area")
                area, source = _resolve_area(area_name)
                result = router.get().get_summer_geographic_summary(area, year, area_source=source)
                return _format_summary(result, expected_source=source, expected_from=expected_from, expected_to=expected_to)
            match = _KMS_RE.fullmatch(text)
            if match:
                area_name, from_time, to_time = (item.strip() for item in match.groups())
                if not _registered(area_name):
                    raise GeographicCommandError("unknown_area")
                try:
                    _validate_interval(from_time, to_time)
                except ServiceError:
                    raise GeographicCommandError("invalid_period") from None
                start, end = _validated_period(from_time, to_time)
                from_time, to_time = _iso(start), _iso(end)
                area, source = _resolve_area(area_name)
                result = router.get().get_geographic_summary(from_time, to_time, area, source)
                return _format_summary(result, expected_source=source, expected_from=from_time, expected_to=to_time)
            raise GeographicCommandError("command_invalid")
    except GeographicCommandError:
        raise
    except TenantIsolationError:
        raise GeographicCommandError("tenant_context_invalid") from None
    except ServiceError as exc:
        safe = {"unknown_geographic_area": "unknown_area", "geographic_period_too_large": "invalid_period", "unsupported_summer_year": "unsupported_year", "geometry_budget_exceeded": "summary_unavailable"}
        raise GeographicCommandError(safe.get(exc.code, "summary_unavailable")) from None
    except Exception:
        raise GeographicCommandError("summary_unavailable") from None
