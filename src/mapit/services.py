"""Bounded, read-only application services for MAPIT MCP tools."""

from __future__ import annotations

import math
from calendar import monthrange
from datetime import date, datetime, time, timedelta, timezone
from threading import Lock
from typing import Any, Callable, Literal, Mapping
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
from .session import SessionManager, WindowsKeyringRefreshTokenStore

MAX_PERIOD_DAYS = 366
MAX_RETURNED_ROUTES = 500
MAX_ROUTE_LIST_BYTES = 2 * 1024 * 1024
MAX_ROUTE_DETAIL_BYTES = 1024 * 1024
MAX_ANALYTIC_ROUTES = 10_000
MAPIT_NATIVE_UNIT = "mapit_native_unconfirmed"


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


class RouteDetail(RouteSummary):
    merged: bool | None = None
    starts_at_last_known: bool | None = None
    geojson: dict[str, Any] | None = None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT


class DistanceResult(OutputModel):
    from_time: str
    to_time: str
    distance: float
    route_count: int
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    completeness: Literal["unverified"] = "unverified"


class DistanceComparison(OutputModel):
    period_a: DistanceResult
    period_b: DistanceResult
    absolute_difference: float
    percentage_difference: float | None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT


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
        return RouteSummary(
            route_id=route_id,
            started_at=_string(raw.get("startedAt")),
            ended_at=_string(raw.get("endedAt")),
            distance=_number(raw.get("distance")),
            average_speed=_number(raw.get("avgSpeed")),
            maximum_speed=_number(raw.get("maxSpeed")),
            complete=raw.get("complete") if isinstance(raw.get("complete"), bool) else None,
            timezone=_string(raw.get("startTz")),
            odometer_start=_number(raw.get("odometerStart")),
            odometer_end=_number(raw.get("odometerEnd")),
        )

    def _all_routes(self, from_time: str, to_time: str) -> tuple[str, str, list[RouteSummary]]:
        start, end = _validated_period(from_time, to_time)
        _, vehicle = self._account_and_vehicle()
        vehicle_id = _string(vehicle.get("id"))
        assert vehicle_id is not None
        routes: dict[str, RouteSummary] = {}
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
                existing = routes.get(route.route_id)
                if existing is not None:
                    if existing != route:
                        raise ServiceError(
                            "duplicate_route_conflict",
                            "MAPIT returned conflicting normalized data for one route ID",
                        )
                    continue
                routes[route.route_id] = route
                if len(routes) > MAX_ANALYTIC_ROUTES:
                    raise ServiceError("route_limit_exceeded", "MAPIT returned more routes than the safety limit")
        ordered = sorted(routes.values(), key=lambda item: (item.started_at or "", item.route_id))
        return _iso(start), _iso(end), ordered

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
        return RouteDetail(
            **base.model_dump(),
            merged=payload.get("merged") if isinstance(payload.get("merged"), bool) else None,
            starts_at_last_known=(
                payload.get("startsAtLastKnown") if isinstance(payload.get("startsAtLastKnown"), bool) else None
            ),
            geojson=geojson,
        )

    def get_distance(self, from_time: str, to_time: str) -> DistanceResult:
        normalized_from, normalized_to, routes = self._all_routes(from_time, to_time)
        if any(route.distance is None for route in routes):
            raise ServiceError("distance_unavailable", "one or more MAPIT routes do not provide distance")
        return DistanceResult(
            from_time=normalized_from,
            to_time=normalized_to,
            distance=sum(route.distance for route in routes),
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
        return DistanceComparison(
            period_a=first,
            period_b=second,
            absolute_difference=abs(difference),
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
