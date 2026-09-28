# Phase 2 route analytics contracts

Status: implemented and validated with the bounded live MCP gate on 2026-09-28.

## Evidence boundary

Phase 0 confirmed route fields named `distance`, `avgSpeed`, `maxSpeed`,
`startedAt`, and `endedAt`, but not their metric units, semantic stability, or
historical completeness. Phase 2 therefore does not label values as kilometres
or km/h and does not expose an aggregate average speed. It calls a timestamp
difference `elapsed_duration_seconds`, not riding or engine-on time.

All results retain:

- `metric_unit="mapit_native_unconfirmed"` for distance and speed values;
- `bucket_timezone="UTC"` for calendar grouping;
- `completeness="unverified"` for route-history coverage;
- `observed_route_count` rather than an unqualified total route count.

## Retrieval and safety

Analytics reuse the Phase 1 monthly `from`/`to` route retrieval. They never use
the unsafe unfiltered global history read or route-detail/GeoJSON calls.

- One period is limited to 366 days, 13 monthly Geo reads, and 2 MiB per
  monthly response.
- A comparison is limited to two such periods and at most 26 Geo reads.
- At most 10,000 normalized routes may be accumulated per period.
- Route IDs are deduplicated. Byte-for-byte-equivalent normalized duplicates
  are ignored; duplicates whose analytical fields conflict fail with
  `duplicate_route_conflict`.
- A non-null cursor, oversized response, invalid envelope, or route-limit
  overflow fails closed.
- Tool results are private local stdio output and are never logged or persisted.

## Validation rules

- Every analytical route needs a finite `distance`; otherwise
  `distance_unavailable`.
- Negative `distance` is also rejected as `distance_unavailable`; negative
  `maxSpeed` is rejected as `speed_unavailable` because neither value has a
  meaningful signed interpretation in this contract.
- Calendar grouping needs a valid timezone-aware `startedAt`; otherwise
  `timestamp_unavailable`.
- Duration needs valid timezone-aware `startedAt` and `endedAt`, with end not
  earlier than start; otherwise `duration_unavailable`.
- Maximum speed is returned only when every observed route has a finite
  `maxSpeed`; otherwise `speed_unavailable`.
- Each route belongs wholly to the UTC bucket containing its `startedAt`; a
  route is not split across buckets.
- Empty periods return zero distance/count/duration and null averages/extremes.
- Percentage changes use `(B-A)/A*100` and are null when A is zero.
- Compared periods may overlap; the tool reports the caller's two independent
  observed windows and does not infer a comparison type.
- Every aggregate sum, difference, average, and percentage is checked for a
  finite result. A non-finite intermediate or output fails closed as
  `numeric_overflow`; analytics models reject NaN and infinity as well.

## MCP tools

### `get_route_statistics(from_time, to_time)`

Returns total native distance, observed route count, average native distance
per route, accumulated elapsed duration in seconds, and maximum native route
speed. It intentionally omits aggregate average speed.

### `get_distance_breakdown(from_time, to_time, group_by)`

`group_by` is one of `day`, `month`, or `year`. Returns ordered UTC buckets with
native distance, observed route count, and elapsed duration seconds.

### `get_route_extremes(from_time, to_time)`

Returns one deterministic longest observed route, one deterministic UTC day
with most native distance, one deterministic UTC month with most native
distance, and the maximum native route speed. Ties select the earliest bucket
or earliest route by start timestamp and ID, while reporting `ties_observed`.
No GeoJSON is returned.

### `compare_route_periods(period_a, period_b)`

Returns statistics for both periods plus signed differences and safe percentage
changes for native distance, observed route count, and elapsed duration. This
single contract supports year-over-year and month-over-month questions without
special endpoints.

The existing Phase 1 `get_distance` remains unchanged and uses the same guarded
retrieval path.
