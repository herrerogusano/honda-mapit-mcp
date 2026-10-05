# Phase 1 MCP contracts

Status: implemented and validated against MCP Python SDK 2.2 and the bounded
live MAPIT smoke gate on 2026-09-28.

## Architecture and transport

```text
MCP tool -> MapitServices -> MapitClient -> MAPIT Core/Geo GET
```

`src/mapit/mcp_server.py` is an adapter only. Selection, validation,
normalization, splitting, deduplication, aggregation, and error mapping live in
`src/mapit/services.py`. Phase 1 supports local stdio only. It does not expose
HTTP, OAuth, AWS infrastructure, an agent, Telegram, a database, or writes.

The project supports `mcp>=2.2,<2.3`. Contract tests use the SDK's real
in-memory `Client`, so tool discovery, JSON schemas, invocation, structured
results, and tool errors pass through the MCP implementation rather than a
permissive mock.

## Authentication and privacy

The service provider lazily opens the existing fail-closed Windows Credential
Manager refresh-token store. Credentials, refresh tokens, ID tokens, AWS keys,
signed URLs, response bodies, and exception details are never arguments or
results of an MCP tool and are not logged.

Tool results are intentionally private account data and may contain position,
VIN, registration, dealer contact information, route identifiers, and GeoJSON.
That is permitted only as an on-demand local result for the account owner. No
tool result is persisted by the server. A remote/shared transport requires a
separate authentication and privacy design in a later phase.

## Shared rules

- Every tool is annotated `readOnlyHint=true` and `idempotentHint=true`.
- The service layer calls only `MapitClient.get_core()` and `get_geo()`.
- The first vehicle with a non-empty string ID and a non-null device is used;
  otherwise the first vehicle with a usable ID is used.
- Multi-vehicle selection is not part of the Phase 1 input contract.
- IDs used in URL paths are encoded as one path segment.
- Errors are stable categories with fixed public messages. MAPIT URLs, bodies,
  identifiers, headers, and exception text are discarded.

## Time-range contract

`from_time` is inclusive and `to_time` is exclusive in the local service
contract. Inputs may be `YYYY-MM-DD` (UTC midnight) or a timezone-aware ISO
8601 datetime. Naive datetimes, reversed/empty periods, and periods longer than
366 days are rejected before a MAPIT data call.

The normalized interval is converted to UTC and split at UTC month boundaries.
One period therefore makes at most 13 Geo route-list requests; a comparison of
two maximum periods makes at most 26. The upstream inclusivity and timezone
semantics remain unconfirmed, so duplicate route IDs across adjacent windows
are removed and completeness is never inferred.

## Tools

### `get_vehicle_status()`

Returns an allowlisted subset of the embedded device state: status, speed,
battery, voltage, communication and coordinate timestamps, position label and
coordinates, GPS accuracy, and odometer. A device odometer of zero is retained;
vehicle `km` is only a fallback when the device odometer is absent.

### `get_vehicle_details()`

Uses account summary for vehicle selection and dealer contact metadata, then
reads the current Core vehicle-detail endpoint. It returns model, registration,
VIN, mileage, product, plan, branch, and available dealer information.

### `list_routes(from_time, to_time)`

Reads each monthly window, validates `{data: [...]}`, rejects any non-null
`lastEvaluatedKey`, normalizes route fields, deduplicates by route ID, and sorts
by start timestamp then ID. It returns no more than 500 routes and reports both
the matched and returned counts plus `truncated`.

### `get_route_detail(route_id)`

Uses the current vehicle-scoped Geo endpoint with `includeStats=true`. The
response contains normalized route metrics and available GeoJSON, bounded by a
1 MiB upstream response limit. The precise effect of `includeStats=true`
remains unconfirmed.

### `get_distance(from_time, to_time)`

Sums the native `distance` values after the same monthly retrieval and
deduplication as `list_routes`. If any returned route lacks a finite distance,
the tool fails with `distance_unavailable` instead of treating it as zero.

### `compare_distance_periods(period_a, period_b)`

Runs the bounded distance calculation for both periods and returns both totals,
the absolute difference, and the signed percentage change `(B-A)/A*100`.
Percentage is null when period A is zero.

## Honest metadata and limits

MAPIT metric units, route pagination, historical completeness, upstream date
inclusivity, and cross-account stability were not established in Phase 0.
Accordingly:

- route/distance outputs use `metric_unit="mapit_native_unconfirmed"`;
- route/distance outputs use `completeness="unverified"`;
- route-list responses are capped at 2 MiB per monthly window;
- route-detail responses are capped at 1 MiB;
- a non-null upstream cursor fails closed because pagination is not understood.

These fields must not be relabelled as kilometres or complete history without
new primary evidence and a separately reviewed contract change.
