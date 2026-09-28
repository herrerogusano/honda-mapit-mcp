"""Pure route-history analytics for the bounded Phase 2 service layer."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Mapping, Sequence

from pydantic import BaseModel, ConfigDict, Field

MAPIT_NATIVE_UNIT = "mapit_native_unconfirmed"
BUCKET_TIMEZONE = "UTC"
COMPLETENESS = "unverified"
GroupBy = Literal["day", "month", "year"]


class AnalyticsError(ValueError):
    """Validation failure with a stable public category."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.public_message = message
        super().__init__(message)


class AnalyticsModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class RouteStatistics(AnalyticsModel):
    from_time: str
    to_time: str
    total_distance: float
    observed_route_count: int
    average_route_distance: float | None
    elapsed_duration_seconds: float
    maximum_speed: float | None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    bucket_timezone: Literal["UTC"] = BUCKET_TIMEZONE
    completeness: Literal["unverified"] = COMPLETENESS


class DistanceBucket(AnalyticsModel):
    bucket: str
    distance: float
    observed_route_count: int
    elapsed_duration_seconds: float


class ExtremeBucket(AnalyticsModel):
    bucket: str
    distance: float
    observed_route_count: int


class DistanceBreakdown(AnalyticsModel):
    from_time: str
    to_time: str
    group_by: GroupBy
    buckets: list[DistanceBucket] = Field(default_factory=list)
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    bucket_timezone: Literal["UTC"] = BUCKET_TIMEZONE
    completeness: Literal["unverified"] = COMPLETENESS


class RouteExtreme(AnalyticsModel):
    route_id: str
    distance: float
    started_at: str


class RouteExtremes(AnalyticsModel):
    from_time: str
    to_time: str
    longest_route: RouteExtreme | None
    most_distance_day: ExtremeBucket | None
    most_distance_month: ExtremeBucket | None
    maximum_speed: float | None
    ties_observed: bool = False
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    bucket_timezone: Literal["UTC"] = BUCKET_TIMEZONE
    completeness: Literal["unverified"] = COMPLETENESS


class RoutePeriodComparison(AnalyticsModel):
    period_a: RouteStatistics
    period_b: RouteStatistics
    distance_difference: float
    distance_percentage_change: float | None
    observed_route_count_difference: int
    observed_route_count_percentage_change: float | None
    elapsed_duration_difference_seconds: float
    elapsed_duration_percentage_change: float | None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    bucket_timezone: Literal["UTC"] = BUCKET_TIMEZONE
    completeness: Literal["unverified"] = COMPLETENESS


@dataclass(frozen=True)
class _PreparedRoute:
    route_id: str
    distance: float
    started_at: datetime
    ended_at: datetime | None
    maximum_speed: float | None


def _value(route: Any, model_name: str, raw_name: str) -> Any:
    if isinstance(route, Mapping):
        return route.get(model_name, route.get(raw_name))
    return getattr(route, model_name, None)


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        result = float(value)
    except OverflowError:
        return None
    return result if math.isfinite(result) else None


def _safe_sum(values: Sequence[float]) -> float:
    total = 0.0
    for value in values:
        total += value
        if not math.isfinite(total):
            raise AnalyticsError("numeric_overflow", "MAPIT analytics exceeded finite numeric bounds")
    return total


def _safe_difference(second: float, first: float) -> float:
    difference = second - first
    if not math.isfinite(difference):
        raise AnalyticsError("numeric_overflow", "MAPIT analytics exceeded finite numeric bounds")
    return difference


def _utc_timestamp(value: Any, code: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise AnalyticsError(code, "MAPIT route timestamps must be timezone-aware ISO 8601 values")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise AnalyticsError(code, "MAPIT route timestamps must be timezone-aware ISO 8601 values") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AnalyticsError(code, "MAPIT route timestamps must be timezone-aware ISO 8601 values")
    return parsed.astimezone(timezone.utc)


def _iso_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _prepare(
    routes: Sequence[Any], *, require_duration: bool = True, require_speed: bool = True
) -> list[_PreparedRoute]:
    if not routes:
        return []
    prepared: list[_PreparedRoute] = []
    for route in routes:
        route_id = _value(route, "route_id", "id")
        if not isinstance(route_id, str) or not route_id.strip():
            raise AnalyticsError("invalid_response", "MAPIT route history contains a route without an ID")
        distance = _finite_number(_value(route, "distance", "distance"))
        if distance is None or distance < 0:
            raise AnalyticsError("distance_unavailable", "one or more MAPIT routes do not provide distance")
        started_at = _utc_timestamp(_value(route, "started_at", "startedAt"), "timestamp_unavailable")
        ended_at = None
        if require_duration:
            ended_at = _utc_timestamp(_value(route, "ended_at", "endedAt"), "duration_unavailable")
            if ended_at < started_at:
                raise AnalyticsError("duration_unavailable", "MAPIT route duration is invalid")
        maximum_speed = _finite_number(_value(route, "maximum_speed", "maxSpeed"))
        if maximum_speed is not None and maximum_speed < 0:
            raise AnalyticsError("speed_unavailable", "one or more MAPIT routes do not provide maximum speed")
        if require_speed and maximum_speed is None:
            raise AnalyticsError("speed_unavailable", "one or more MAPIT routes do not provide maximum speed")
        prepared.append(_PreparedRoute(route_id, distance, started_at, ended_at, maximum_speed))
    return prepared


def _percentage_change(first: float, second: float) -> float | None:
    if first == 0:
        return None
    difference = _safe_difference(second, first)
    percentage = difference / first * 100.0
    if not math.isfinite(percentage):
        raise AnalyticsError("numeric_overflow", "MAPIT analytics exceeded finite numeric bounds")
    return percentage


def route_statistics(routes: Sequence[Any], from_time: str, to_time: str) -> RouteStatistics:
    prepared = _prepare(routes, require_speed=True)
    count = len(prepared)
    total_distance = _safe_sum([route.distance for route in prepared])
    elapsed = _safe_sum(
        [(route.ended_at - route.started_at).total_seconds() for route in prepared if route.ended_at]
    )
    maximum_speed = max((route.maximum_speed for route in prepared), default=None)
    average_route_distance = None if count == 0 else total_distance / count
    if average_route_distance is not None and not math.isfinite(average_route_distance):
        raise AnalyticsError("numeric_overflow", "MAPIT analytics exceeded finite numeric bounds")
    return RouteStatistics(
        from_time=from_time,
        to_time=to_time,
        total_distance=total_distance,
        observed_route_count=count,
        average_route_distance=average_route_distance,
        elapsed_duration_seconds=elapsed,
        maximum_speed=maximum_speed,
    )


def _bucket_key(value: datetime, group_by: GroupBy) -> str:
    if group_by == "day":
        return value.strftime("%Y-%m-%d")
    if group_by == "month":
        return value.strftime("%Y-%m")
    if group_by == "year":
        return value.strftime("%Y")
    raise AnalyticsError("invalid_group_by", "group_by must be day, month, or year")


def distance_breakdown(
    routes: Sequence[Any], from_time: str, to_time: str, group_by: GroupBy
) -> DistanceBreakdown:
    if group_by not in {"day", "month", "year"}:
        raise AnalyticsError("invalid_group_by", "group_by must be day, month, or year")
    prepared = _prepare(routes, require_speed=False)
    buckets: dict[str, list[_PreparedRoute]] = {}
    for route in prepared:
        buckets.setdefault(_bucket_key(route.started_at, group_by), []).append(route)
    return DistanceBreakdown(
        from_time=from_time,
        to_time=to_time,
        group_by=group_by,
        buckets=[
            DistanceBucket(
                bucket=key,
                distance=_safe_sum([route.distance for route in bucket_routes]),
                observed_route_count=len(bucket_routes),
                elapsed_duration_seconds=_safe_sum(
                    [(route.ended_at - route.started_at).total_seconds() for route in bucket_routes if route.ended_at]
                ),
            )
            for key, bucket_routes in sorted(buckets.items())
        ],
    )


def route_extremes(routes: Sequence[Any], from_time: str, to_time: str) -> RouteExtremes:
    prepared = _prepare(routes, require_duration=False, require_speed=True)
    if not prepared:
        return RouteExtremes(
            from_time=from_time,
            to_time=to_time,
            longest_route=None,
            most_distance_day=None,
            most_distance_month=None,
            maximum_speed=None,
        )

    longest_distance = max(route.distance for route in prepared)
    longest_candidates = [route for route in prepared if route.distance == longest_distance]
    longest = min(longest_candidates, key=lambda route: (route.started_at, route.route_id))

    def aggregate(group_by: GroupBy) -> list[ExtremeBucket]:
        grouped: dict[str, list[_PreparedRoute]] = {}
        for route in prepared:
            grouped.setdefault(_bucket_key(route.started_at, group_by), []).append(route)
        return [
            ExtremeBucket(
                bucket=key,
                distance=_safe_sum([route.distance for route in bucket_routes]),
                observed_route_count=len(bucket_routes),
            )
            for key, bucket_routes in sorted(grouped.items())
        ]

    day_buckets = aggregate("day")
    month_buckets = aggregate("month")
    max_day_distance = max(bucket.distance for bucket in day_buckets)
    max_month_distance = max(bucket.distance for bucket in month_buckets)
    most_day = min((bucket for bucket in day_buckets if bucket.distance == max_day_distance), key=lambda item: item.bucket)
    most_month = min(
        (bucket for bucket in month_buckets if bucket.distance == max_month_distance), key=lambda item: item.bucket
    )
    speed_max = max(route.maximum_speed for route in prepared)
    ties = (
        len(longest_candidates) > 1
        or sum(bucket.distance == max_day_distance for bucket in day_buckets) > 1
        or sum(bucket.distance == max_month_distance for bucket in month_buckets) > 1
        or sum(route.maximum_speed == speed_max for route in prepared) > 1
    )
    return RouteExtremes(
        from_time=from_time,
        to_time=to_time,
        longest_route=RouteExtreme(
            route_id=longest.route_id,
            distance=longest.distance,
            started_at=_iso_timestamp(longest.started_at),
        ),
        most_distance_day=most_day,
        most_distance_month=most_month,
        maximum_speed=speed_max,
        ties_observed=ties,
    )


def compare_route_periods(
    routes_a: Sequence[Any],
    from_time_a: str,
    to_time_a: str,
    routes_b: Sequence[Any],
    from_time_b: str,
    to_time_b: str,
) -> RoutePeriodComparison:
    first = route_statistics(routes_a, from_time_a, to_time_a)
    second = route_statistics(routes_b, from_time_b, to_time_b)
    count_difference = second.observed_route_count - first.observed_route_count
    if not math.isfinite(float(count_difference)):
        raise AnalyticsError("numeric_overflow", "MAPIT analytics exceeded finite numeric bounds")
    return RoutePeriodComparison(
        period_a=first,
        period_b=second,
        distance_difference=_safe_difference(second.total_distance, first.total_distance),
        distance_percentage_change=_percentage_change(first.total_distance, second.total_distance),
        observed_route_count_difference=count_difference,
        observed_route_count_percentage_change=_percentage_change(
            first.observed_route_count, second.observed_route_count
        ),
        elapsed_duration_difference_seconds=_safe_difference(
            second.elapsed_duration_seconds, first.elapsed_duration_seconds
        ),
        elapsed_duration_percentage_change=_percentage_change(
            first.elapsed_duration_seconds, second.elapsed_duration_seconds
        ),
    )
