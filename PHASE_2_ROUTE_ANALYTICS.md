# Phase 2 — Route Analytics & Aggregations

## Goal
Turn route history into reusable analytical capabilities.

## Capabilities
Implement service operations for:
- total distance by period;
- distance by month;
- distance by year;
- route count;
- total riding duration;
- average route distance;
- longest route;
- day with most distance;
- month with most distance;
- average speed where semantically valid;
- maximum route speed;
- period comparison;
- year-over-year comparison;
- month-over-month comparison.

## Candidate MCP tools
Prefer flexible tools instead of one tool per question:
- `get_route_statistics(from, to)`
- `get_distance_breakdown(from, to, group_by)`
- `get_route_extremes(from, to)`
- `compare_route_periods(period_a, period_b)`

Keep existing `get_distance`.

## Rules
- use safe monthly windows;
- never rely on the unsafe global unfiltered route read;
- document units;
- avoid double counting;
- handle zero denominators safely;
- do not infer unavailable metrics.

## Exit criteria
The MCP can support questions such as:
- yearly km;
- month with most km;
- longest route;
- number of routes;
- comparison between periods.
