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
- Vehicle selection follows "Vehicle selection" below.
- IDs used in URL paths are encoded as one path segment.
- Errors are stable categories with fixed public messages. MAPIT URLs, bodies,
  identifiers, headers, and exception text are discarded.

## Vehicle selection

Each vehicle-scoped tool reads `account-summary` once and works on one vehicle.

1. **Eligible vehicles** are those the official dashboard shows: `id` is a
   non-empty string, `device.id` is not null, `pending` is not set and
   `subscription.id` is present. Repeated ids are kept once, in MAPIT order.
2. **Fallback.** If no vehicle passes that filter, the previous rule picks one
   vehicle (the first with a non-null `device`, else the first with a usable
   `id`), so an account that worked before keeps working. With nothing at all
   the tool fails with `vehicle_not_found`.
3. **Optional `vehicle_id`** on every vehicle-scoped tool (all tools except
   `list_vehicles`, including `geographic_summary` and
   `summer_geographic_summary`):
   - given and eligible: that vehicle is used;
   - given but not eligible, unknown, blank or longer than 256 characters:
     `vehicle_not_found` (a malformed value fails before any MAPIT read);
   - omitted with exactly one eligible vehicle: it is used, with output
     identical to the single-vehicle behaviour before this contract;
   - omitted with several: `vehicle_selection_required`, before any route or
     detail read. The message gives only the number of vehicles and points
     to `list_vehicles`; it carries no vehicle identifier, model or
     registration, because MCP server frameworks log tool error text.
4. **Agents** call `list_vehicles`, ask the
   user when it is not obvious, and keep passing the chosen `vehicle_id` for
   the rest of the conversation. The tool descriptions and server
   instructions say so.
5. **Cancelled vehicles** (`cancelled: true`) stay selectable for routes,
   distance and details. Their status keeps the last values MAPIT stored and
   adds `vehicle_cancelled: true` and a fixed `state_warning` saying it is not
   live state. Both fields are left out for every other vehicle, so
   active-vehicle output is unchanged; the tool output schema gains them as
   optional properties.
6. **Logs** never carry `vehicle_id`, model or registration: the read meter
   line keeps its four fixed fields, and the selection line ("Vehicle
   selection log" below) holds only bucketed counts and fixed words.

The local distance ledger has no vehicle argument: with several eligible
vehicles its import stops with category `vehicle_selection_required` before
any route read or local write.

## Time-range contract

`from_time` is inclusive and `to_time` is exclusive in the local service
contract. Inputs may be `YYYY-MM-DD` (UTC midnight) or a timezone-aware ISO
8601 datetime. Naive datetimes, reversed/empty periods, and periods longer than
366 days are rejected before a MAPIT data call.

The normalized interval is converted to UTC. A period of at most 366 days
touches at most 14 calendar months in UTC (for example
`2025-01-31T12:00Z` to `2026-02-01T12:00Z`); "Period reads" below gives the
route-list read bounds. The upstream inclusivity and timezone semantics remain
unconfirmed, so duplicate route IDs across adjacent windows are removed and
completeness is never inferred.

## Tools

Every tool below except `list_vehicles` also takes the optional `vehicle_id`
described in "Vehicle selection".

### `list_vehicles()`

One `account-summary` read and no other request. Returns `vehicles`, one entry
per eligible vehicle (or the single fallback vehicle) with `vehicle_id` (the
MAPIT vehicle `id`), `model`, `registration` (`registrationNumber`),
`cancelled` and `status` (the same fields as `get_vehicle_status`, native
units, `units_confirmed=false`); plus `vehicle_count`, `selection_required`
(more than one vehicle), `selection_basis` (`mapit_dashboard_filter` or
`legacy_single_vehicle_fallback`) and a fixed `selection_hint`.

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

Reads the whole requested period with one `from`/`to` route-list request (see
"Period reads" below), validates `{data: [...]}`, normalizes route fields,
deduplicates by route ID, and sorts by start timestamp then ID. It returns no
more than 500 routes and reports both the matched and returned counts plus
`truncated`.

### `get_route_detail(route_id)`

Uses the current vehicle-scoped Geo endpoint with `includeStats=true`. The
response contains normalized route metrics and available GeoJSON, bounded by a
1 MiB upstream response limit. The precise effect of `includeStats=true`
remains unconfirmed.

### `get_distance(from_time, to_time)`

Sums the native `distance` values after the same period retrieval and
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
- route-list responses are capped at 2 MiB per request window;
- route-detail responses are capped at 1 MiB;
- a non-null upstream cursor is never followed; on a single calendar month it
  fails closed because pagination is not understood.

## Period reads

Every route-list tool reads one bounded period (at most 366 days) for the
selected vehicle:

1. It sends one `GET /v1/routes` with the whole period as `from`/`to`.
2. If that response exceeds the 2 MiB ceiling or carries a non-null
   `lastEvaluatedKey`, the response is discarded and the window is read again
   as two halves split at a calendar-month boundary, earlier half first. Each
   half follows the same rule, recursively.
3. If MAPIT accepts the connection but does not answer a multi-month window
   within the read timeout (`http_timeout`), that window is replaced directly
   by its single months, read oldest first. Only a timeout while waiting for
   the response or its body counts; a connect timeout does not. In the cloud
   transport, a socket timeout that was shortened by the request deadline does
   not count either.
4. A window of one calendar month (or the partial month at either end of the
   request) is never split. There the original failure stands:
   `response_too_large`, `pagination_unsupported` or, for a timeout,
   `mapit_unavailable`. Any other failure in any window (connection failure,
   HTTP status including 5xx, invalid envelope) stops the whole call without a
   split; no partial result is returned.

The month windows that end the recursion are exactly the windows the earlier
month-by-month reads used, so a period that fails here also failed before,
apart from the extra time spent on a window that timed out. The results are
merged with the existing route-ID deduplication and the same sort, so routes,
order, fields and truncation do not depend on how the period was split. A
period whose list fits in one response costs one route-list read instead of
one per month. Bounds per period of `n` months:

- the worst case over all causes stays `2n - 1` route-list reads (27 for a
  366-day period, which touches at most 14 calendar months): falling back to
  months after a timeout never reads more than halving would;
- a timeout on the whole period costs `1 + n` route-list reads (15 for a
  366-day period) and one wasted wait of at most `http_timeout`;
- halving after a timeout was rejected because each halving level could spend
  another full timeout, which a multi-month request may not afford inside its
  per-request deadline (14 s and 24 attempts in the multiuser runtime).

These are read bounds, not time bounds: they do not guarantee that a period
completes inside the 14 s deadline. Single months can also exceed the read
timeout or the request deadline. When the deadline expires before the next
read, the cloud transport raises its own deadline error and the call fails
with `internal_error`. When it shortens a socket wait that then times out, the
call fails with `mapit_unavailable`. Both stop without a partial result.

Observed in a test deployment: a six-month window starting months before the
first route sometimes exceeded a 2 s timeout. That is the case the timeout
fallback covers; that each single month of such a window answers in time is
assumed, not measured.

Why the rule changed: month-by-month reads were adopted because one unfiltered
whole-history read exceeded the 2 MiB ceiling. A bounded `from`/`to` period
with automatic splitting keeps the same ceiling and falls back to the same
month windows, while sending fewer reads when the list fits.

Contract as read here, not verified against MAPIT: `from`/`to` filter routes by
start time on a half-open interval, a multi-month window returns the union of
its months, and an over-ceiling or cursor response can be discarded and re-read
in smaller windows. Offline tests prove the code against this reading only.

Also not verified: why MAPIT is slow on some long windows, and whether every
single month of such a window answers within the timeout. If one month times
out too, the call fails with `mapit_unavailable`, as the month-by-month reads
would. A 503/504 or a dropped connection on a long window still fails the whole
call without a split, where a one-month window might have succeeded; splitting
on those is deliberately left out because during an outage it would multiply
the reads. The read meter's `outcome:"error"` lines, and `reads` above 2 for a
single period, are how this is watched.

## Read meter

Each MCP tool call writes one line to stderr (stdout carries the stdio MCP
protocol):

```json
{"event":"mapit_reads","tool":"list_routes","reads":2,"outcome":"ok"}
```

`reads` counts every GET sent to MAPIT Core/Geo during the call, including the
single auth-recovery retry; Cognito authentication calls are not counted.
`outcome` is `ok` or `error`. The line carries no identifiers, parameters,
dates, URLs or response content. When each period fits in one response the
counts are: `list_vehicles` 1, `get_vehicle_status` 1, `get_vehicle_details` 2,
`get_route_detail` 2, every single-period route tool (`list_routes`,
`get_distance`, `get_route_statistics`, `get_distance_breakdown`,
`get_route_extremes`, `geographic_summary`, `summer_geographic_summary`) 2, and
each two-period comparison 4. Before this change a single-period route tool
cost one account-summary read plus one read per calendar month (7 for a
semester, up to 15 for 366 days).

## Vehicle selection log

Each tool call that resolves a vehicle (`list_vehicles` and every
vehicle-scoped tool, on success and on the `vehicle_selection_required` /
`vehicle_not_found` error paths) writes one more line to the same sink, just
before its read meter line:

```json
{"event":"vehicle_selection","tool":"get_distance","vehicles":"2","cancelled":"0","excluded":"1","basis":"dashboard_filter","vehicle_id_given":false,"outcome":"selection_required"}
```

| Field | Values | Meaning |
|---|---|---|
| `vehicles` | `0`, `1`, `2`, `3+` | selectable vehicles (after the dashboard filter, or the one fallback vehicle) |
| `cancelled` | `0`, `1`, `2+` | selectable vehicles with `cancelled: true` |
| `excluded` | `0`, `1`, `2+` | distinct vehicle ids in `account-summary` that are not selectable (no device, null `device.id`, `pending`, no subscription): a sold or transferred vehicle shows here |
| `basis` | `dashboard_filter`, `legacy_fallback`, `none`, `not_read` | how the vehicles were chosen; `none`: nothing usable; `not_read`: `account-summary` was not read (malformed `vehicle_id`) or its read failed |
| `vehicle_id_given` | `true`, `false` | whether the call passed a `vehicle_id` (never its value) |
| `outcome` | `ok`, `selection_required`, `not_found`, `read_failed` | the resolution result |

Rules:

- Exactly one line per tool call. A two-period comparison resolves the
  vehicle once per period with the same arguments; the last resolution is
  logged.
- Only bucketed counts, fixed words and one boolean: no vehicle id, model,
  registration, device or subscription id, tenant, user, email, coordinates,
  vehicle timestamps or MAPIT text.
- Nothing is logged outside a tool call (the local ledger import, tests).
- A log failure never changes a tool result; tool outputs and error texts
  are unchanged.
- In the Lambda functions (invitation-only multiuser `…-mcp` and public web
  `…-web-mcp`) the line, like the read meter line, is a plain `print` to
  stderr. The functions use the default text log format with no
  `LoggingConfig`, so every stderr line becomes one CloudWatch log event
  regardless of log level; the Python `logging` level does not apply.

Read-only Logs Insights query over one log group (`/aws/lambda/<function>`)
and a chosen period:

```text
filter @message like /"event":"vehicle_selection"/
| parse @message /"vehicles":"(?<vehicles>[0-9+]+)","cancelled":"(?<cancelled>[0-9+]+)","excluded":"(?<excluded>[0-9+]+)","basis":"(?<basis>[a-z_]+)","vehicle_id_given":(?<vehicle_id_given>true|false),"outcome":"(?<outcome>[a-z_]+)"/
| stats count(*) as events by vehicles, excluded, cancelled, basis, outcome, vehicle_id_given
```

The `parse` step relies on the fixed key order of the line, so it does not
depend on Logs Insights discovering JSON fields. For one dimension only,
replace the last line with, for example, `| stats count(*) by outcome`, or
add `| filter excluded != "0"` before it for the events with excluded
vehicles. `python -m scripts.mcp_users --env dev|prod vehicle-stats
[--days 7]` runs this query on both MCP log groups of the environment and
prints only the counts per field value (see `docs/public-web.md`, "Operation
commands").

These fields must not be relabelled as kilometres or complete history without
new primary evidence and a separately reviewed contract change.
