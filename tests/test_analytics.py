from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from mapit.analytics import (
    AnalyticsError,
    RouteStatistics,
    compare_route_periods,
    distance_breakdown,
    route_extremes,
    route_statistics,
)


def _route(route_id, started, ended, distance, speed=30):
    return {
        "route_id": route_id,
        "started_at": started,
        "ended_at": ended,
        "distance": distance,
        "maximum_speed": speed,
    }


ROUTES = [
    _route("b", "2026-01-02T01:00:00+01:00", "2026-01-02T02:00:00+01:00", 10, 40),
    _route("a", "2026-01-01T23:30:00Z", "2026-01-02T00:30:00Z", 10, 40),
    _route("c", "2026-02-03T00:00:00Z", "2026-02-03T00:30:00Z", 5, 20),
]


def test_statistics_normalizes_duration_and_keeps_native_units():
    result = route_statistics(ROUTES, "2026-01-01", "2026-03-01")

    assert result.total_distance == 25
    assert result.observed_route_count == 3
    assert result.average_route_distance == pytest.approx(25 / 3)
    assert result.elapsed_duration_seconds == 9000
    assert result.maximum_speed == 40
    assert result.metric_unit == "mapit_native_unconfirmed"
    assert result.bucket_timezone == "UTC"
    assert result.completeness == "unverified"
    assert "average_speed" not in result.model_dump()


@pytest.mark.parametrize(
    ("group_by", "buckets"),
    [
        ("day", ["2026-01-02", "2026-02-03"]),
        ("month", ["2026-01", "2026-02"]),
        ("year", ["2026"]),
    ],
)
def test_breakdown_orders_utc_buckets_and_does_not_require_speed(group_by, buckets):
    routes = [
        _route("a", "2026-01-02T00:00:00Z", "2026-01-02T00:01:00Z", 1, None),
        _route("b", "2026-02-03T00:00:00Z", "2026-02-03T00:02:00Z", 2, None),
    ]

    result = distance_breakdown(routes, "2026-01-01", "2026-03-01", group_by)

    assert [bucket.bucket for bucket in result.buckets] == buckets
    assert [bucket.distance for bucket in result.buckets] == ([3] if group_by == "year" else [1, 2])


def test_extremes_choose_earliest_route_and_bucket_on_ties():
    routes = [
        _route("later", "2026-01-02T00:00:00Z", "2026-01-02T01:00:00Z", 10, 50),
        _route("earlier", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 10, 50),
    ]

    result = route_extremes(routes, "2026-01-01", "2026-02-01")

    assert result.longest_route.route_id == "earlier"
    assert result.most_distance_day.bucket == "2026-01-01"
    assert result.most_distance_month.bucket == "2026-01"
    assert result.maximum_speed == 50
    assert result.ties_observed is True


def test_empty_period_returns_zero_and_null_extremes():
    stats = route_statistics([], "2026-01-01", "2026-02-01")
    extremes = route_extremes([], "2026-01-01", "2026-02-01")

    assert stats.total_distance == 0
    assert stats.observed_route_count == 0
    assert stats.elapsed_duration_seconds == 0
    assert stats.average_route_distance is None
    assert stats.maximum_speed is None
    assert extremes.longest_route is None
    assert extremes.most_distance_day is None
    assert extremes.most_distance_month is None
    assert extremes.maximum_speed is None
    assert extremes.ties_observed is False


@pytest.mark.parametrize(
    ("routes", "code"),
    [
        ([_route("r", "2026-01-01", "2026-01-01T01:00:00Z", 1)], "timestamp_unavailable"),
        ([_route("r", "2026-01-01T01:00:00Z", "2026-01-01T00:00:00Z", 1)], "duration_unavailable"),
        ([_route("r", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", None)], "distance_unavailable"),
        ([_route("r", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 1, None)], "speed_unavailable"),
    ],
)
def test_analytics_fail_closed_for_unavailable_metrics(routes, code):
    with pytest.raises(AnalyticsError) as error:
        route_statistics(routes, "2026-01-01", "2026-02-01")

    assert error.value.code == code


def test_breakdown_requires_valid_group_by():
    with pytest.raises(AnalyticsError) as error:
        distance_breakdown([], "2026-01-01", "2026-02-01", "week")

    assert error.value.code == "invalid_group_by"


def test_comparison_uses_signed_changes_and_null_zero_denominators():
    first = [_route("a", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 0, 10)]
    second = [_route("b", "2026-02-01T00:00:00Z", "2026-02-01T02:00:00Z", 5, 20)]

    result = compare_route_periods(first, "2026-01-01", "2026-02-01", second, "2026-02-01", "2026-03-01")

    assert result.distance_difference == 5
    assert result.distance_percentage_change is None
    assert result.observed_route_count_difference == 0
    assert result.observed_route_count_percentage_change == 0
    assert result.elapsed_duration_difference_seconds == 3600
    assert result.elapsed_duration_percentage_change == 100


@pytest.mark.parametrize(
    ("operation", "routes", "code"),
    [
        (route_statistics, [_route("r", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", -1)], "distance_unavailable"),
        (route_extremes, [_route("r", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 1, -1)], "speed_unavailable"),
    ],
)
def test_negative_analytics_metrics_fail_closed(operation, routes, code):
    with pytest.raises(AnalyticsError) as error:
        operation(routes, "2026-01-01", "2026-02-01")

    assert error.value.code == code


def test_negative_max_speed_is_rejected_even_without_speed_aggregate():
    routes = [_route("r", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 1, -1)]

    with pytest.raises(AnalyticsError) as error:
        distance_breakdown(routes, "2026-01-01", "2026-02-01", "day")

    assert error.value.code == "speed_unavailable"


def test_stats_sum_overflow_is_categorized_before_model_construction():
    routes = [
        _route("a", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 1e308),
        _route("b", "2026-01-01T02:00:00Z", "2026-01-01T03:00:00Z", 1e308),
    ]

    with pytest.raises(AnalyticsError) as error:
        route_statistics(routes, "2026-01-01", "2026-02-01")

    assert error.value.code == "numeric_overflow"


def test_breakdown_and_extremes_bucket_overflow_is_categorized():
    routes = [
        _route("a", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 1e308),
        _route("b", "2026-01-01T02:00:00Z", "2026-01-01T03:00:00Z", 1e308),
    ]

    with pytest.raises(AnalyticsError, match="MAPIT analytics") as breakdown_error:
        distance_breakdown(routes, "2026-01-01", "2026-02-01", "day")
    with pytest.raises(AnalyticsError) as extremes_error:
        route_extremes(routes, "2026-01-01", "2026-02-01")

    assert breakdown_error.value.code == "numeric_overflow"
    assert extremes_error.value.code == "numeric_overflow"


def test_comparison_percentage_overflow_is_categorized():
    first = [_route("a", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", 1e-308)]
    second = [_route("b", "2026-02-01T00:00:00Z", "2026-02-01T01:00:00Z", 1e308)]

    with pytest.raises(AnalyticsError) as error:
        compare_route_periods(first, "2026-01-01", "2026-02-01", second, "2026-02-01", "2026-03-01")

    assert error.value.code == "numeric_overflow"


def test_analytics_models_reject_non_finite_numbers():
    with pytest.raises(ValidationError):
        RouteStatistics(
            from_time="2026-01-01",
            to_time="2026-02-01",
            total_distance=math.inf,
            observed_route_count=0,
            average_route_distance=None,
            elapsed_duration_seconds=0,
            maximum_speed=None,
        )
