"""Bounded, read-only application services for MAPIT MCP tools."""

from __future__ import annotations

import math
from calendar import monthrange
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta, timezone
from threading import Lock
from typing import TYPE_CHECKING, Any, Callable, Literal, Mapping
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict, Field

from .analytics import (
    AnalyticsError,
    DistanceBreakdown,
    GroupBy,
    RouteExtremes,
    RoutePeriodComparison,
    RouteStatistics,
    compare_route_periods as analytics_compare_route_periods,
    distance_breakdown,
    route_extremes,
    route_statistics,
)
from .client import MapitClient, MapitHTTPError, MapitResponseError, MapitResponseTooLarge, MapitTransportError
from .distance_units import DISTANCE_CONVERSION_BASIS, native_distance_to_km
from .geography import (
    GeographyError,
    MAX_GEOGRAPHIC_ROUTE_COORDINATES,
    MAX_GEOGRAPHIC_ROUTE_FEATURES,
    MAX_ROUTE_COORDINATES,
    MAX_ROUTE_FEATURES,
    classify_route_geojson_with_work,
    sanitize_route_geojson,
    summer_window_utc,
    validate_area,
)
from .session import SessionManager, WindowsKeyringRefreshTokenStore

if TYPE_CHECKING:
    from .geography_engine import PreparedPublicArea

MAX_PERIOD_DAYS = 366
MAX_RETURNED_ROUTES = 500
MAX_ROUTE_LIST_BYTES = 2 * 1024 * 1024
MAX_ROUTE_DETAIL_BYTES = 1024 * 1024
MAX_ANALYTIC_ROUTES = 10_000
MAPIT_NATIVE_UNIT = "mapit_native_unconfirmed"
MAX_QUALITY_FEATURES = 4096
MAX_QUALITY_COORDINATES = 100_000
MAX_GEOGRAPHIC_BATCH_COORDINATES = MAX_GEOGRAPHIC_ROUTE_COORDINATES
MAX_GEOGRAPHIC_BATCH_OPERATIONS = 5_000_000
MAX_GEOGRAPHIC_BATCH_FEATURES = MAX_GEOGRAPHIC_ROUTE_FEATURES
MAX_GEOGRAPHIC_ROUTES = 2_000
_QUALITY_WARNINGS = {
    "inferred_present": "At least one LineString is marked inferred; this does not establish real-street coverage or GPS accuracy.",
    "none_marked_inferred": "No inspected LineString is marked inferred; this does not guarantee GPS accuracy.",
    "partial_unknown": "Some LineString inference flags are unavailable or malformed; startsAtLastKnown is a separate hint.",
    "unknown": "Inference status is unknown because usable LineString flags are unavailable; startsAtLastKnown is a separate hint.",
}


def _line_inference_quality(geojson: Any) -> tuple[bool | None, str, str, str]:
    """Summarize strict LineString inference flags after bounded shape validation."""
    if not isinstance(geojson, Mapping) or geojson.get("type") != "FeatureCollection":
        return None, "unknown", "unavailable", _QUALITY_WARNINGS["unknown"]
    features = geojson.get("features")
    if not isinstance(features, list) or not features or len(features) > MAX_QUALITY_FEATURES:
        return None, "unknown", "unavailable", _QUALITY_WARNINGS["unknown"]
    flags: list[bool] = []
    uncertain = False
    inspected_coordinates = 0
    def finite_coordinate(value: Any) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        try:
            return math.isfinite(float(value))
        except OverflowError:
            return False

    for feature in features:
        if not isinstance(feature, Mapping):
            uncertain = True
            continue
        if feature.get("type") != "Feature":
            uncertain = True
            continue
        geometry = feature.get("geometry")
        if not isinstance(geometry, Mapping):
            uncertain = True
            continue
        geometry_type = geometry.get("type")
        if not isinstance(geometry_type, str):
            uncertain = True
            continue
        if geometry_type in {"Point", "MultiPoint", "MultiLineString", "Polygon", "MultiPolygon"}:
            continue
        if geometry_type != "LineString":
            uncertain = True
            continue
        coordinates = geometry.get("coordinates")
        if isinstance(coordinates, list):
            inspected_coordinates += len(coordinates)
        if (
            not isinstance(coordinates, list)
            or len(coordinates) < 2
            or len(coordinates) > 8192
            or inspected_coordinates > MAX_QUALITY_COORDINATES
            or any(
                not isinstance(position, list)
                or len(position) < 2
                or any(not finite_coordinate(coordinate) for coordinate in position[:2])
                for position in coordinates
            )
        ):
            uncertain = True
            continue
        properties = feature.get("properties")
        flag = properties.get("inferred") if isinstance(properties, Mapping) else None
        if type(flag) is bool:
            flags.append(flag)
        else:
            uncertain = True
    if not flags:
        status = "unknown"
        has_inferred = None
        source = "unavailable"
    elif uncertain:
        status = "partial_unknown"
        has_inferred = True if any(flags) else None
        source = "geojson_linestring_properties"
    elif any(flags):
        status = "inferred_present"
        has_inferred = True
        source = "geojson_linestring_properties"
    else:
        status = "none_marked_inferred"
        has_inferred = False
        source = "geojson_linestring_properties"
    warning_key = status if status in _QUALITY_WARNINGS else "unknown"
    return has_inferred, status, source, _QUALITY_WARNINGS[warning_key]


class ServiceError(RuntimeError):
    """A stable, redacted error safe to expose through MCP."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.public_message = message
        super().__init__(f"{code}: {message}")


class OutputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DateRangeInput(OutputModel):
    from_time: str = Field(description="Inclusive ISO 8601 date or timezone-aware datetime.")
    to_time: str = Field(description="Exclusive ISO 8601 date or timezone-aware datetime.")


class Position(OutputModel):
    latitude: float | None = None
    longitude: float | None = None
    label: str | None = None
    gps_accuracy: float | None = None


class VehicleStatus(OutputModel):
    status: str | None = None
    speed: float | None = None
    battery: float | None = None
    voltage: float | None = None
    last_communication: float | None = None
    last_coordinate_update: float | None = None
    position: Position
    odometer: float | None = None
    units_confirmed: bool = False


class DealerContact(OutputModel):
    name: str | None = None
    telephone: str | None = None
    email: str | None = None
    address: str | None = None
    opening_hours: list[str] = Field(default_factory=list)


class VehicleDetails(OutputModel):
    model: str | None = None
    registration: str | None = None
    vin: str | None = None
    mileage: float | None = None
    product: str | None = None
    plan: str | None = None
    branch: str | None = None
    dealer: DealerContact | None = None
    units_confirmed: bool = False


class RouteSummary(OutputModel):
    route_id: str
    started_at: str | None = None
    ended_at: str | None = None
    distance: float | None = None
    distance_km: float | None = None
    conversion_basis: Literal["ui_correlated_meter_interpretation_unconfirmed"] = DISTANCE_CONVERSION_BASIS
    has_inferred_segments: bool | None = None
    inference_quality_status: Literal["inferred_present", "none_marked_inferred", "partial_unknown", "unknown"] = "unknown"
    inference_quality_source: str = "unavailable"
    inference_quality_warning: str = _QUALITY_WARNINGS["unknown"]
    average_speed: float | None = None
    maximum_speed: float | None = None
    complete: bool | None = None
    timezone: str | None = None
    odometer_start: float | None = None
    odometer_end: float | None = None


class RouteList(OutputModel):
    from_time: str
    to_time: str
    routes: list[RouteSummary]
    matched_routes: int
    returned_routes: int
    truncated: bool
    completeness: Literal["unverified"] = "unverified"
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    conversion_basis: Literal["ui_correlated_meter_interpretation_unconfirmed"] = DISTANCE_CONVERSION_BASIS


class RouteDetail(RouteSummary):
    merged: bool | None = None
    starts_at_last_known: bool | None = None
    geojson: dict[str, Any] | None = None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT


class DistanceResult(OutputModel):
    from_time: str
    to_time: str
    distance: float
    distance_km: float | None = None
    conversion_basis: Literal["ui_correlated_meter_interpretation_unconfirmed"] = DISTANCE_CONVERSION_BASIS
    route_count: int
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    completeness: Literal["unverified"] = "unverified"


class GeographicRouteSummary(OutputModel):
    """Area relation for embedded route geometry; never a clipped-distance estimate."""

    from_time: str
    to_time: str
    area_source: Literal[
        "caller_supplied_geojson",
        "ign_menorca_municipalities_union_2026_10_03",
    ] = "caller_supplied_geojson"
    area_type: Literal["Polygon", "MultiPolygon"]
    matched_routes: int
    fully_inside_routes: int
    outside_routes: int
    crossing_routes: int
    unknown_routes: int
    fully_inside_distance: float
    fully_inside_distance_km: float | None = None
    inferred_marked_inside_routes: int
    not_marked_inferred_inside_routes: int
    inference_unknown_inside_routes: int
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    conversion_basis: Literal["ui_correlated_meter_interpretation_unconfirmed"] = DISTANCE_CONVERSION_BASIS
    completeness: Literal["unverified"] = "unverified"
    interpretation_warning: str = (
        "Classification assumes supplied area and MAPIT coordinates are longitude/latitude; MAPIT CRS semantics "
        "remain unverified. Bounded source geometry does not prove physical area coverage, street matching, "
        "GPS accuracy, or complete route history. Distances include fully-contained routes only; "
        "crossing routes are never clipped or prorated."
    )


class DistanceComparison(OutputModel):
    period_a: DistanceResult
    period_b: DistanceResult
    absolute_difference: float
    absolute_difference_km: float | None = None
    signed_difference: float | None = None
    signed_difference_km: float | None = None
    percentage_difference: float | None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    conversion_basis: Literal["ui_correlated_meter_interpretation_unconfirmed"] = DISTANCE_CONVERSION_BASIS


@dataclass(frozen=True, repr=False)
class _RouteFact:
    route: RouteSummary
    geojson: Any = field(repr=False)


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        result = float(value)
    except OverflowError:
        return None
    return result if math.isfinite(result) else None


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _parse_boundary(value: str, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ServiceError("invalid_date_range", f"{field} must be an ISO 8601 date or datetime")
    text = value.strip()
    try:
        if len(text) == 10:
            parsed_date = date.fromisoformat(text)
            return datetime.combine(parsed_date, time.min, tzinfo=timezone.utc)
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ServiceError("invalid_date_range", f"{field} must be an ISO 8601 date or datetime") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ServiceError("invalid_date_range", f"{field} datetime must include a timezone")
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _validated_period(from_time: str, to_time: str) -> tuple[datetime, datetime]:
    start = _parse_boundary(from_time, "from_time")
    end = _parse_boundary(to_time, "to_time")
    if start >= end:
        raise ServiceError("invalid_date_range", "from_time must be earlier than to_time")
    if end - start > timedelta(days=MAX_PERIOD_DAYS):
        raise ServiceError("period_too_large", f"a period may not exceed {MAX_PERIOD_DAYS} days")
    return start, end


def split_month_windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    """Split a UTC interval at calendar-month boundaries."""
    windows: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        days = monthrange(cursor.year, cursor.month)[1]
        next_month = (cursor.replace(day=days, hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1))
        boundary = min(next_month, end)
        windows.append((cursor, boundary))
        cursor = boundary
    return windows


def _map_http_error(exc: MapitHTTPError) -> ServiceError:
    status = exc.status
    if status in {401, 403}:
        return ServiceError("authentication_failed", "the saved MAPIT session was rejected")
    if status == 404:
        return ServiceError("not_found", "the requested MAPIT resource was not found")
    if status == 429:
        return ServiceError("rate_limited", "MAPIT rate-limited the request")
    if 500 <= status <= 599:
        return ServiceError("mapit_unavailable", "MAPIT is temporarily unavailable")
    return ServiceError("mapit_request_failed", "MAPIT rejected the request")


def _translate_error(exc: Exception) -> ServiceError:
    if isinstance(exc, ServiceError):
        return exc
    if isinstance(exc, MapitHTTPError):
        return _map_http_error(exc)
    if isinstance(exc, MapitResponseTooLarge):
        return ServiceError("response_too_large", "MAPIT returned more data than the safety limit allows")
    if isinstance(exc, MapitTransportError):
        return ServiceError("mapit_unavailable", "MAPIT could not be reached")
    if isinstance(exc, MapitResponseError):
        return ServiceError("invalid_response", "MAPIT returned an invalid response")
    return ServiceError("internal_error", "the request could not be completed")


class MapitServices:
    """Business logic used by MCP handlers; all upstream calls are GET-only."""

    def __init__(self, client: MapitClient) -> None:
        self.client = client

    def _account_and_vehicle(self) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        try:
            payload = self.client.get_core("/v1/account-summary", max_response_bytes=MAX_ROUTE_LIST_BYTES)
        except Exception as exc:
            raise _translate_error(exc) from None
        if not isinstance(payload, Mapping) or not isinstance(payload.get("vehicles"), list):
            raise ServiceError("invalid_response", "MAPIT account summary has an unexpected shape")
        fallback: Mapping[str, Any] | None = None
        for item in payload["vehicles"]:
            if not isinstance(item, Mapping) or _string(item.get("id")) is None:
                continue
            fallback = fallback or item
            if item.get("device") is not None:
                return payload, item
        if fallback is not None:
            return payload, fallback
        raise ServiceError("vehicle_not_found", "no eligible vehicle is available in the MAPIT account")

    def get_vehicle_status(self) -> VehicleStatus:
        _, vehicle = self._account_and_vehicle()
        state = _mapping(_mapping(vehicle.get("device")).get("state"))
        state_odometer = _number(state.get("odometer"))
        return VehicleStatus(
            status=_string(state.get("status")),
            speed=_number(state.get("speed")),
            battery=_number(state.get("battery")),
            voltage=_number(state.get("voltage")),
            last_communication=_number(state.get("lastTs")),
            last_coordinate_update=_number(state.get("lastCoordTs")),
            position=Position(
                latitude=_number(state.get("lat")),
                longitude=_number(state.get("lng")),
                label=_string(state.get("location")),
                gps_accuracy=_number(state.get("hdop")),
            ),
            odometer=state_odometer if state_odometer is not None else _number(vehicle.get("km")),
        )

    def get_vehicle_details(self) -> VehicleDetails:
        _, summary_vehicle = self._account_and_vehicle()
        vehicle_id = _string(summary_vehicle.get("id"))
        assert vehicle_id is not None
        try:
            payload = self.client.get_core(
                f"/v1/vehicles/{quote(vehicle_id, safe='')}",
                max_response_bytes=MAX_ROUTE_LIST_BYTES,
            )
        except Exception as exc:
            raise _translate_error(exc) from None
        if not isinstance(payload, Mapping):
            raise ServiceError("invalid_response", "MAPIT vehicle detail has an unexpected shape")
        dealer_data = _mapping(summary_vehicle.get("dealerData"))
        shop = _mapping(dealer_data.get("shop"))
        address_data = _mapping(shop.get("address"))
        address_parts = [
            _string(address_data.get(key))
            for key in ("streetAddress", "postalCode", "addressLocality", "addressRegion", "addressCountry")
        ]
        hours = shop.get("openingHours")
        dealer = None
        if dealer_data or shop:
            dealer = DealerContact(
                name=_string(dealer_data.get("name")) or _string(shop.get("name")),
                telephone=_string(shop.get("telephone")),
                email=_string(shop.get("email")),
                address=", ".join(part for part in address_parts if part) or None,
                opening_hours=[item for item in hours if isinstance(item, str)] if isinstance(hours, list) else [],
            )
        product = payload.get("products")
        product_text = ", ".join(item for item in product if isinstance(item, str)) if isinstance(product, list) else None
        return VehicleDetails(
            model=_string(payload.get("model")),
            registration=_string(payload.get("registrationNumber")),
            vin=_string(payload.get("vin")),
            mileage=_number(payload.get("km")),
            product=product_text or _string(summary_vehicle.get("product")),
            plan=_string(payload.get("productPlanName")),
            branch=_string(payload.get("branch")),
            dealer=dealer,
        )

    @staticmethod
    def _normalize_route(raw: Mapping[str, Any]) -> RouteSummary | None:
        route_id = _string(raw.get("id"))
        if route_id is None:
            return None
        geojson = raw.get("geoJSON", raw.get("geojson"))
        inferred, quality_status, quality_source, quality_warning = _line_inference_quality(geojson)
        native_distance = _number(raw.get("distance"))
        return RouteSummary(
            route_id=route_id,
            started_at=_string(raw.get("startedAt")),
            ended_at=_string(raw.get("endedAt")),
            distance=native_distance,
            distance_km=native_distance_to_km(native_distance),
            has_inferred_segments=inferred,
            inference_quality_status=quality_status,
            inference_quality_source=quality_source,
            inference_quality_warning=quality_warning,
            average_speed=_number(raw.get("avgSpeed")),
            maximum_speed=_number(raw.get("maxSpeed")),
            complete=raw.get("complete") if isinstance(raw.get("complete"), bool) else None,
            timezone=_string(raw.get("startTz")),
            odometer_start=_number(raw.get("odometerStart")),
            odometer_end=_number(raw.get("odometerEnd")),
        )

    def _collect_routes(
        self,
        from_time: str,
        to_time: str,
        *,
        include_geojson: bool = False,
        route_visitor: Callable[[_RouteFact], None] | None = None,
    ) -> tuple[str, str, list[_RouteFact]]:
        start, end = _validated_period(from_time, to_time)
        _, vehicle = self._account_and_vehicle()
        vehicle_id = _string(vehicle.get("id"))
        assert vehicle_id is not None
        routes: dict[str, _RouteFact] = {}
        aggregate_features = 0
        aggregate_coordinates = 0
        for window_start, window_end in split_month_windows(start, end):
            try:
                payload = self.client.get_geo(
                    "/v1/routes",
                    params={"vehicleId": vehicle_id, "from": _iso(window_start), "to": _iso(window_end)},
                    max_response_bytes=MAX_ROUTE_LIST_BYTES,
                )
            except Exception as exc:
                raise _translate_error(exc) from None
            if not isinstance(payload, Mapping) or not isinstance(payload.get("data"), list):
                raise ServiceError("invalid_response", "MAPIT route history has an unexpected shape")
            if payload.get("lastEvaluatedKey") is not None:
                raise ServiceError("pagination_unsupported", "MAPIT returned an unsupported route-history cursor")
            for item in payload["data"]:
                if not isinstance(item, Mapping):
                    raise ServiceError("invalid_response", "MAPIT route history contains an invalid route")
                route = self._normalize_route(item)
                if route is None:
                    raise ServiceError("invalid_response", "MAPIT route history contains a route without an ID")
                if include_geojson:
                    try:
                        started_at = route.started_at
                        if not isinstance(started_at, str) or len(started_at) <= 10:
                            raise ValueError
                        parsed_start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
                        if parsed_start.tzinfo is None or parsed_start.utcoffset() is None:
                            raise ValueError
                        parsed_start = parsed_start.astimezone(timezone.utc)
                    except (OverflowError, ValueError):
                        raise ServiceError(
                            "invalid_route_timestamp", "one or more MAPIT routes have invalid start timestamps"
                        ) from None
                    if not start <= parsed_start < end:
                        raise ServiceError(
                            "route_outside_requested_interval",
                            "MAPIT returned a route outside the requested half-open interval",
                        )
                    if route.distance is None or route.distance < 0 or not math.isfinite(route.distance):
                        raise ServiceError("distance_unavailable", "one or more MAPIT routes do not provide valid distance")
                existing = routes.get(route.route_id)
                if include_geojson and existing is None and len(routes) >= MAX_GEOGRAPHIC_ROUTES:
                    raise ServiceError("geographic_route_limit", "too many routes for bounded area analysis")
                geometry = item.get("geoJSON", item.get("geojson")) if include_geojson else None
                feature_count = coordinate_count = 0
                if include_geojson:
                    try:
                        geometry, feature_count, coordinate_count = sanitize_route_geojson(
                            geometry,
                            remaining_features=(
                                MAX_ROUTE_FEATURES
                                if existing is not None
                                else MAX_GEOGRAPHIC_BATCH_FEATURES - aggregate_features
                            ),
                            remaining_coordinates=(
                                MAX_ROUTE_COORDINATES
                                if existing is not None
                                else MAX_GEOGRAPHIC_BATCH_COORDINATES - aggregate_coordinates
                            ),
                        )
                    except GeographyError as exc:
                        raise ServiceError(exc.category, "route geometry exceeded geographic analysis limits") from None
                if existing is not None:
                    if existing.route != route or (include_geojson and existing.geojson != geometry):
                        raise ServiceError(
                            "duplicate_route_conflict",
                            "MAPIT returned conflicting normalized data for one route ID",
                        )
                    continue
                if include_geojson:
                    aggregate_features += feature_count
                    aggregate_coordinates += coordinate_count
                fact = _RouteFact(route=route, geojson=geometry)
                if route_visitor is not None:
                    route_visitor(fact)
                routes[route.route_id] = fact
                if len(routes) > MAX_ANALYTIC_ROUTES:
                    raise ServiceError("route_limit_exceeded", "MAPIT returned more routes than the safety limit")
        ordered = sorted(routes.values(), key=lambda item: (item.route.started_at or "", item.route.route_id))
        return _iso(start), _iso(end), ordered

    def _all_routes(self, from_time: str, to_time: str) -> tuple[str, str, list[RouteSummary]]:
        normalized_from, normalized_to, facts = self._collect_routes(from_time, to_time)
        return normalized_from, normalized_to, [fact.route for fact in facts]

    def get_geographic_summary(
        self,
        from_time: str,
        to_time: str,
        area_geojson: Mapping[str, Any] | PreparedPublicArea,
        area_source: str = "caller_supplied_geojson",
    ) -> GeographicRouteSummary:
        """Summarize routes against caller geometry without detail GETs or clipping."""
        try:
            start, end = _validated_period(from_time, to_time)
            if end - start > timedelta(days=93):
                raise ServiceError("geographic_period_too_large", "area analysis is limited to 93 days")
            # Keep the optional GEOS/Shapely engine out of the default/dev ZIP.
            from .geography_engine import (
                GeographyEngineError,
                PreparedPublicArea,
                classify_public_area_route,
                is_valid_prepared_public_area,
            )

            if isinstance(area_geojson, PreparedPublicArea):
                if not is_valid_prepared_public_area(area_geojson):
                    raise GeographyError("invalid_prepared_area")
                if area_source != "ign_menorca_municipalities_union_2026_10_03":
                    raise GeographyError("unsupported_area_source")
                area = area_geojson
                classify = classify_public_area_route
                area_type = "MultiPolygon"
            else:
                area = validate_area(area_geojson, source=area_source)
                classify = classify_route_geojson_with_work
                area_type = area_geojson.get("type")
        except ServiceError:
            raise
        except GeographyError as exc:
            raise ServiceError(exc.category, "the supplied geographic area is invalid or unsupported") from None
        relations: dict[str, int] = {key: 0 for key in ("fully_inside", "outside", "crossing", "unknown")}
        inside_distance_values: list[float] = []
        inferred_true = inferred_false = inferred_unknown = 0
        remaining_operations = MAX_GEOGRAPHIC_BATCH_OPERATIONS

        def visit_route(fact: _RouteFact) -> None:
            nonlocal remaining_operations
            nonlocal inferred_true, inferred_false, inferred_unknown
            route = fact.route
            if remaining_operations <= 0:
                raise ServiceError("geometry_budget_exceeded", "geographic analysis exceeded its work budget")
            if isinstance(area, PreparedPublicArea):
                try:
                    relation = classify(fact.geojson, area)
                except GeographyEngineError:
                    raise ServiceError("geometry_budget_exceeded", "geographic analysis exceeded its work budget") from None
            else:
                relation, work_used, coordinates_used = classify(
                    fact.geojson,
                    area,
                    max_segment_edge_tests=remaining_operations,
                )
                if work_used > remaining_operations or coordinates_used > MAX_GEOGRAPHIC_BATCH_COORDINATES:
                    raise ServiceError("geometry_budget_exceeded", "geographic analysis exceeded its work budget")
                remaining_operations -= work_used
            relations[relation] += 1
            if relation == "fully_inside":
                inside_distance_values.append(route.distance)
                if route.has_inferred_segments is True:
                    inferred_true += 1
                elif route.has_inferred_segments is False:
                    inferred_false += 1
                else:
                    inferred_unknown += 1

        normalized_from, normalized_to, facts = self._collect_routes(
            from_time,
            to_time,
            include_geojson=True,
            route_visitor=visit_route,
        )
        total_inside = sum(inside_distance_values)
        if not math.isfinite(total_inside):
            raise ServiceError("numeric_overflow", "area distance total exceeded finite numeric bounds")
        if area_type not in {"Polygon", "MultiPolygon"}:
            # validate_area already checks this; retain a strict output invariant.
            raise ServiceError("invalid_area", "the supplied geographic area is invalid or unsupported")
        return GeographicRouteSummary(
            from_time=normalized_from,
            to_time=normalized_to,
            area_source=area_source,
            area_type=area_type,
            matched_routes=len(facts),
            fully_inside_routes=relations["fully_inside"],
            outside_routes=relations["outside"],
            crossing_routes=relations["crossing"],
            unknown_routes=relations["unknown"],
            fully_inside_distance=total_inside,
            fully_inside_distance_km=native_distance_to_km(total_inside),
            inferred_marked_inside_routes=inferred_true,
            not_marked_inferred_inside_routes=inferred_false,
            inference_unknown_inside_routes=inferred_unknown,
        )

    def get_summer_geographic_summary(
        self,
        area_geojson: Mapping[str, Any] | PreparedPublicArea,
        year: int | None = None,
        *,
        area_source: str = "caller_supplied_geojson",
        now: datetime | None = None,
    ) -> GeographicRouteSummary:
        """Use the bounded fixed-CEST June–September reporting window."""
        try:
            summer_from, summer_to = summer_window_utc(year, now=now)
        except GeographyError as exc:
            raise ServiceError(exc.category, "the selected summer window is unsupported") from None
        return self.get_geographic_summary(summer_from, summer_to, area_geojson, area_source)

    def list_routes(self, from_time: str, to_time: str) -> RouteList:
        normalized_from, normalized_to, routes = self._all_routes(from_time, to_time)
        returned = routes[:MAX_RETURNED_ROUTES]
        return RouteList(
            from_time=normalized_from,
            to_time=normalized_to,
            routes=returned,
            matched_routes=len(routes),
            returned_routes=len(returned),
            truncated=len(returned) < len(routes),
        )

    def get_route_detail(self, route_id: str) -> RouteDetail:
        normalized_id = _string(route_id)
        if normalized_id is None or len(normalized_id) > 256:
            raise ServiceError("invalid_route_id", "route_id must be a non-empty string of at most 256 characters")
        _, vehicle = self._account_and_vehicle()
        vehicle_id = _string(vehicle.get("id"))
        assert vehicle_id is not None
        try:
            payload = self.client.get_geo(
                f"/v1/vehicles/{quote(vehicle_id, safe='')}/routes/{quote(normalized_id, safe='')}",
                params={"includeStats": "true"},
                max_response_bytes=MAX_ROUTE_DETAIL_BYTES,
            )
        except Exception as exc:
            raise _translate_error(exc) from None
        if not isinstance(payload, Mapping):
            raise ServiceError("invalid_response", "MAPIT route detail has an unexpected shape")
        base = self._normalize_route(payload)
        if base is None:
            raise ServiceError("invalid_response", "MAPIT route detail is missing its route ID")
        geojson = payload.get("geoJSON")
        if geojson is not None and not isinstance(geojson, dict):
            raise ServiceError("invalid_response", "MAPIT route detail contains invalid GeoJSON")
        inferred, quality_status, quality_source, quality_warning = _line_inference_quality(geojson)
        detail_data = base.model_dump()
        detail_data.update(
            merged=payload.get("merged") if isinstance(payload.get("merged"), bool) else None,
            starts_at_last_known=(
                payload.get("startsAtLastKnown") if isinstance(payload.get("startsAtLastKnown"), bool) else None
            ),
            geojson=geojson,
            has_inferred_segments=inferred,
            inference_quality_status=quality_status,
            inference_quality_source=quality_source,
            inference_quality_warning=quality_warning,
        )
        return RouteDetail(**detail_data)

    def get_distance(self, from_time: str, to_time: str) -> DistanceResult:
        normalized_from, normalized_to, routes = self._all_routes(from_time, to_time)
        if any(route.distance is None or route.distance < 0 for route in routes):
            raise ServiceError("distance_unavailable", "one or more MAPIT routes do not provide distance")
        total_distance = sum(route.distance for route in routes)
        if not math.isfinite(total_distance):
            raise ServiceError("numeric_overflow", "MAPIT distance total exceeded finite numeric bounds")
        return DistanceResult(
            from_time=normalized_from,
            to_time=normalized_to,
            distance=total_distance,
            distance_km=native_distance_to_km(total_distance),
            route_count=len(routes),
        )

    @staticmethod
    def _analytics_error(exc: AnalyticsError) -> ServiceError:
        return ServiceError(exc.code, exc.public_message)

    def get_route_statistics(self, from_time: str, to_time: str) -> RouteStatistics:
        normalized_from, normalized_to, routes = self._all_routes(from_time, to_time)
        try:
            return route_statistics(routes, normalized_from, normalized_to)
        except AnalyticsError as exc:
            raise self._analytics_error(exc) from None

    def get_distance_breakdown(self, from_time: str, to_time: str, group_by: GroupBy) -> DistanceBreakdown:
        normalized_from, normalized_to, routes = self._all_routes(from_time, to_time)
        try:
            return distance_breakdown(routes, normalized_from, normalized_to, group_by)
        except AnalyticsError as exc:
            raise self._analytics_error(exc) from None

    def get_route_extremes(self, from_time: str, to_time: str) -> RouteExtremes:
        normalized_from, normalized_to, routes = self._all_routes(from_time, to_time)
        try:
            return route_extremes(routes, normalized_from, normalized_to)
        except AnalyticsError as exc:
            raise self._analytics_error(exc) from None

    def compare_route_periods(self, period_a: DateRangeInput, period_b: DateRangeInput) -> RoutePeriodComparison:
        normalized_a_from, normalized_a_to, routes_a = self._all_routes(period_a.from_time, period_a.to_time)
        normalized_b_from, normalized_b_to, routes_b = self._all_routes(period_b.from_time, period_b.to_time)
        try:
            return analytics_compare_route_periods(
                routes_a,
                normalized_a_from,
                normalized_a_to,
                routes_b,
                normalized_b_from,
                normalized_b_to,
            )
        except AnalyticsError as exc:
            raise self._analytics_error(exc) from None

    def compare_distance_periods(self, period_a: DateRangeInput, period_b: DateRangeInput) -> DistanceComparison:
        first = self.get_distance(period_a.from_time, period_a.to_time)
        second = self.get_distance(period_b.from_time, period_b.to_time)
        difference = second.distance - first.distance
        percentage = None if first.distance == 0 else difference / first.distance * 100.0
        difference_magnitude_km = native_distance_to_km(abs(difference))
        return DistanceComparison(
            period_a=first,
            period_b=second,
            absolute_difference=abs(difference),
            absolute_difference_km=native_distance_to_km(abs(difference)),
            signed_difference=difference,
            signed_difference_km=(
                math.copysign(difference_magnitude_km, difference) if difference_magnitude_km is not None else None
            ),
            percentage_difference=percentage,
        )


class ServiceProvider:
    """Lazily create and cache services backed by the saved Windows session."""

    def __init__(self, factory: Callable[[], MapitServices] | None = None) -> None:
        self._factory = factory or self._from_saved_session
        self._value: MapitServices | None = None
        self._lock = Lock()

    @staticmethod
    def _from_saved_session() -> MapitServices:
        try:
            store = WindowsKeyringRefreshTokenStore()
            manager = SessionManager(store=store)
            managed = manager.login_saved()
        except Exception:
            raise ServiceError("credential_store_failed", "the saved MAPIT session could not be loaded") from None
        if managed is None:
            category = manager.last_error_category or "session_missing"
            messages = {
                "session_missing": "no saved MAPIT session is available",
                "discovery_failed": "MAPIT configuration discovery failed",
                "authentication_rejected": "the saved MAPIT session was rejected",
                "authentication_failed": "MAPIT authentication failed",
                "credential_store_failed": "the saved MAPIT session could not be loaded",
            }
            code = category if category in messages else "authentication_failed"
            raise ServiceError(code, messages[code])
        return MapitServices(MapitClient(managed.config, managed.session))

    def get(self) -> MapitServices:
        if self._value is not None:
            return self._value
        with self._lock:
            if self._value is None:
                self._value = self._factory()
        return self._value
