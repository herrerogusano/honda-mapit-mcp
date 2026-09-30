# Phase 6 status

Status: **ACTIVE — measure-first decision gate; no persistence implementation**.

Phase 5 is complete. Phase 6 follows `PHASE_6_PERSISTENCE.md`: first determine
whether bounded MAPIT reads are sufficiently fast and reliable, and whether
local history provides measurable value beyond on-demand queries. No database,
durable event history, synchronization worker, migration, or retention policy
has been implemented.

## Current boundary

- MAPIT remains read-only. Bounded, necessary research executions are allowed
  only with explicit scope and authorization; this status does not authorize
  unbounded live polling or data collection.
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
that map matching remains only a candidate capability. One authorized
redacted run classified the input as `candidate` with `Point` + `LineString`,
dimension `3`, nested/pair-like shapes, valid WGS84 range, density `many`,
names `many`, labels `few`, partial `inferred`, and no per-point
time/accuracy/heading/speed. No coordinate values or raw body were retained.
The first live redacted result reported only a global maximum gap band of
`long`; it did not retain provenance. A second authorized run reported
`medium` for the internal LineString gap, `long` for between-features and
Point-stream gaps, and `multiple` under the then-current boundary semantics.
A third authorized run populated the current structural fields: LineString
coordinate density `many`, Point density `few`, feature density `few` for both,
name presence `few` for both, label presence `none`/`few` for LineString/Point,
distinct name bands `few`/`few`, distinct label bands `none`/`few`, name-order
pattern `transitions_present`, and inferred coverage `partial`/`all` for
LineString/Point. These facts show structural differences but do not prove
that MAPIT segments streets, that names are canonical road names, or that
Points are auxiliary. The pure
`route_input_analyzer` and bounded
`probe_route_input_sufficiency.py` are implemented and covered by offline
synthetic tests; the pure analyzer tests make no network calls. The probe is
live-capable and three bounded authorized runs are complete. Its saved-session preparation may perform
public discovery, Cognito authentication/refresh, and atomically rotate the
existing secure refresh token; it does not persist route data or probe output.
Offline analysis now separates gap bands for LineString interiors, feature
boundaries, and consecutive Point features, and also emits feature-object and
coordinate density bands plus geometry-specific name/label bands and
structural name transition/repetition classes. The bounded synthetic OSRM POC
is implemented and observed locally: it exercises `/route` then `/match` over
loopback using a synthetic in-memory route, with raw responses discarded. Its
reproducible fixture uses two fixed synthetic endpoints and a hard cap of 12
equidistant points; the classifier follows the real `null` tracepoint,
empty-step-name, and `leg.annotation` shapes.
The redacted result was `osrm-local`, `matched`, few matchings, all tracepoints,
medium confidence, and steps/annotations/names present. The harness validates
the local engine boundary only; it does not validate MAPIT or choose a
matcher. It retains only allowlisted source classifications; a third ordinate
remains opaque.
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
