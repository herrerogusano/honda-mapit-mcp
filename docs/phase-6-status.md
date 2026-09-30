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
`PARTIAL`; the unfiltered read exceeded 2 MiB before decoding. One bounded
monthly latency/reliability/body-size sample is now complete; no persisted
path or API-read-reduction benchmark has been measured.
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
read, not as route reconstruction. The user subsequently identified Barcelona
and authorized necessary bounded research executions. A public Cataluña map
has been locally cropped to a fixed Barcelona-area box and prepared for the
separate protocol in
[`phase-6-barcelona-local-probe.md`](phase-6-barcelona-local-probe.md).
This permits one ephemeral MAPIT LineString-to-loopback matcher experiment
after independent offline acceptance, not city-coverage calculation or
persistence. No external matcher or paid call is in scope.
The bounded client harness is now implemented and one live run is complete: it
reuses the saved-session flow for exactly three MAPIT reads, selects one
LineString without sampling, enforces the fixed box and 500-point limit, and
sends at most one proxy-free/no-redirect local `/match` request. Output is
restricted to OSRM bands plus an allowlisted stage category; no route data or
request details are printed or persisted.
Independent offline acceptance preceded the real read (450 tests passing).
The real selected LineString returned `matched`, all tracepoints, high
confidence and steps/annotations/names present. This establishes one-line
input feasibility only, not ground-truth street accuracy, full-route turns,
city coverage or a persistence decision. The temporary matcher container was
stopped and removed; only public map files remain outside the repository.
The subsequent bounded all-LineString assessment returned `partial_lines`:
all source lines checked, partial tracepoint association, lowest confidence
low, mixed source inferred flags and excluded Point features. Full-route
reconstruction and city street coverage are not established. Neither run
retained private values; see the Barcelona protocol for safe evidence.

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

## Current decision checkpoint

The authorized five-plus-one monthly sample completed successfully:
five of five repeated reads, p50 <1 second, p95 1–5 seconds, maximum monthly
body 64–256 KiB, one logical/wire Core read and six logical/wire Geo reads.
The adjacent control was disjoint and no pagination key was observed.
History coverage remains `PARTIAL`. See
[`phase-6-monthly-measurement-result.md`](phase-6-monthly-measurement-result.md).
The small sample does not demonstrate a persistence performance benefit or
loss of MAPIT history. The measured default remains stateless.

The next user gate is a separate product decision: whether to implement a
minimal local distance ledger and explicitly approve its private fields,
HMAC identity scope, retention and local unencrypted-storage risks. The
proposal is in [`phase-6-persistence-proposal.md`](phase-6-persistence-proposal.md).
No database, private ingestion, background collection or AWS resources have
been created. Phases 7 and 8 remain planned; Phase 6 is not marked complete.
