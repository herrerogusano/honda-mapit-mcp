# Phase 6 status

Status: **ACTIVE — measure-first decision gate; no persistence implementation**.

Phase 5 is complete. Phase 6 follows `PHASE_6_PERSISTENCE.md`: first determine
whether bounded MAPIT reads are sufficiently fast and reliable, and whether
local history provides measurable value beyond on-demand queries. No database,
durable event history, synchronization worker, migration, or retention policy
has been implemented.

## Current boundary

- MAPIT remains read-only; no new live probe is authorized by this status.
- No credentials, raw route bodies, identifiers, locations, or Telegram data
  are stored for Phase 6.
- Any measurement must be separately approved, bounded, redacted, and recorded
  as safe metadata only before a persistence design is proposed.

The bounded research protocol and proposed quantitative thresholds are recorded
in [`phase-6-measurement-plan.md`](phase-6-measurement-plan.md). It confirms
that the current no-persistence route path is the baseline: one Core
`account-summary` read plus one Geo read per UTC month window for a one-month
analytics operation, with the existing 2 MiB/window and 366-day limits. Phase 0
confirmed two bounded monthly windows but historical coverage remains
`PARTIAL`; the unfiltered read exceeded 2 MiB before decoding. No latency,
reliability, byte, or API-read-reduction measurement has yet been collected.
The proposed filtered sample separates six logical Geo reads from a maximum of
12 wire Geo GETs (one possible 401/403 recovery each), and one logical Core
account-summary read from a maximum of two wire Core GETs. Its coverage output
is restricted to `PARTIAL` or `UNKNOWN`; the stricter complete label requires a
separate unfiltered-plus-controls gate.

The separate route-reconstruction research is recorded in
[`phase-6-route-reconstruction-research.md`](phase-6-route-reconstruction-research.md).
It inventories the confirmed MAPIT route/detail GeoJSON shape and concludes
that map matching is only a candidate capability: the retained evidence has no
coordinate values, order/density, per-point timestamps, accuracy, heading, or
road identifiers. The pure `route_input_analyzer` and bounded
`probe_route_input_sufficiency.py` are implemented and covered by offline
synthetic tests; the pure analyzer tests make no network calls. The probe is
live-capable but has not been run with a saved session or live network and
requires separate authorization. Its saved-session preparation may perform
public discovery, Cognito authentication/refresh, and atomically rotate the
existing secure refresh token; it does not persist route data or probe output.
The reverse-geocoding path is documented as a distinct coordinate-to-label
read, not as route reconstruction. No external matcher, paid call, OSM import,
city-coverage calculation, or persistence is authorized by this status.

## Next gate

Research and supervisor approval must establish a measurable benefit over the
existing stateless MAPIT/MCP path. Only then may a separate implementation
task define idempotent ingestion, deduplication, migrations, retention, source
versus derived data, and the explicit no-secrets-in-storage invariant.

Until that gate passes, the default decision is **keep stateless**. Offline
synthetic benchmarks may measure current call formulas, normalization,
aggregation, and safety limits. A future live sample, if separately approved,
must remain one account/vehicle, bounded monthly reads, no unfiltered retry,
coarse redacted metrics only, and no durable route/event payloads.
