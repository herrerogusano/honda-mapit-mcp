# Phase 2 status

Status: COMPLETE (2026-09-28).

## Delivered

- Pure route-analytics layer separated from MCP and MAPIT transport code.
- `get_route_statistics` for native distance, observed route count, average
  route distance, elapsed timestamp duration, and maximum route speed.
- `get_distance_breakdown` by UTC day, month, or year.
- `get_route_extremes` with deterministic tie handling.
- `compare_route_periods` with signed differences and safe percentage changes.
- Existing Phase 1 tools retained; the stdio server now exposes ten tools.
- Maximum 10,000 accumulated normalized routes per period.
- Identical duplicate IDs deduplicated and conflicting duplicates rejected.
- Fail-closed validation for missing, negative, non-finite, or overflowing
  metrics and for missing/invalid timestamps.
- Explicit `mapit_native_unconfirmed`, `UTC`, and `unverified` metadata; no
  invented kilometres, km/h, aggregate average speed, or history completeness.

## Verification

- Offline suite: `219 passed` on Windows.
- Compile and diff checks passed.
- MCP in-memory contract tests invoke all four analytics tools and verify their
  schemas, structured results, read-only/idempotent annotations, and redacted
  errors.
- `scripts/smoke_mcp_phase2.py` completed through the real MCP client and saved
  session over a bounded 31-day window. It required at least one observed live
  route and all four analytics tools returned success.
- The smoke output contained only per-tool success booleans. No dates, route
  IDs, vehicle data, timestamps, metrics, payloads, tokens, signed URLs, or
  exception details were printed or persisted.
- A separate stdio subprocess negotiation reported server `honda-mapit`,
  version `0.3.0`, with exactly ten tools.

## Accepted limitations

- MAPIT distance and speed units remain unconfirmed.
- Historical completeness and upstream date-boundary semantics remain
  unverified.
- Elapsed duration is only `endedAt - startedAt`; it is not claimed to be
  engine-on or riding time.
- Calendar buckets use UTC and assign a whole route by its start timestamp.
- Multi-vehicle selection remains outside the current contract.

These limitations remain explicit inputs to later phases. Phase 3 must not
reinterpret them while adding realtime state and events.
