# Phase 6 status

Status: **COMPLETE — approved minimal local ledger accepted, including bounded
live import, no-op deduplication and zero-upstream local queries**.

Phase 5 is complete. Phase 6 follows `PHASE_6_PERSISTENCE.md`: first determine
whether bounded MAPIT reads are sufficiently fast and reliable, and whether
local history provides measurable value beyond on-demand queries. The user
accepted the minimal ledger without additional encryption on 2026-09-30.
Its opt-in implementation and offline read-reduction proof are accepted;
the ordinary MCP remains stateless. The private database now exists outside
Git and OneDrive and contains only the approved minimal current-month facts.
See [ledger contract](phase-6-ledger-contract.md) and
[acceptance result](phase-6-ledger-result.md).

## Current boundary

- MAPIT remains read-only. Bounded, necessary research executions are allowed
  only with explicit scope and authorization; this status does not authorize
  unbounded live polling or data collection.
- No credentials, raw route bodies, direct identifiers, locations, or Telegram
  data belong in the ledger. Its approved private fields and retention are
  defined in the contract; the initial blocked executions stored none.
- Any measurement must be separately approved, bounded, redacted, and recorded
  as safe metadata only before a persistence design is proposed.

The bounded research protocol and proposed quantitative thresholds are recorded
in [`phase-6-measurement-plan.md`](phase-6-measurement-plan.md). It confirms
that the current no-persistence route path is the baseline: one Core
`account-summary` read plus one Geo read per UTC month window for a one-month
analytics operation, with the existing 2 MiB/window and 366-day limits. Phase 0
confirmed two bounded monthly windows but historical coverage remains
`PARTIAL`; the unfiltered read exceeded 2 MiB before decoding. One bounded
monthly latency/reliability/body-size sample is now complete. The fixed offline
ledger read-reduction workload is also complete; live persisted latency
remains unmeasured.
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

## Original measure-first gate (historical)

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

The user accepted the separate minimal-ledger product/privacy decision;
see [`phase-6-persistence-proposal.md`](phase-6-persistence-proposal.md).
Implementation and independent offline acceptance are complete. The fixed
synthetic workload records 20 logical GETs for ten stateless queries, two
for import setup, and zero for ten reopened local queries. This demonstrates
local capability/read reduction, not a measured live latency advantage.

The first authorized current-month import stopped before directory, key or
database creation because at least one source route has `complete=false`.
Only the field's boolean schema is confirmed; false is not proof of an active
trip. The initial misleading `route_in_progress` category was corrected to
`route_not_confirmed_complete`. No automatic retry or filtering was performed.

## Route-flag gate (resolved) and current checkpoint

Choose the explicit treatment of those flags before another live import:
the user chose investigation, and the authorized one-Core/three-Geo comparison
is now complete. All variants returned the same IDs and selected fact
signatures; all sampled routes were false-marked, including an observation with
coherent end timestamp more than 24 hours old. Exact backend flag semantics
remain unknown. Requiring `complete=true` would exclude this entire sample.
See [flag investigation](phase-6-route-flags-investigation.md).

The user approved the revised admission contract: ignore `complete`; require
valid IDs, finite nonnegative distance and aware, coherent, nonfuture start/end
timestamps. Reject the entire batch on invalid facts or conflicts, with no
silent exclusions. End timestamps are validated only in memory, not stored.
Implementation and independent review are accepted; the full offline suite
has 592 passed and 3 skipped.

An earlier authorized current-month import passed route validation but stopped
at `history_permissions_failed`, with `facts_committed=false`. It did not
authorize an automatic additional live retry. The user explicitly authorized
correction and a new bounded import allowance. The exact Python subprocess
failure was reproduced as incompatible inherited PowerShell module paths;
isolating the child environment fixes it without changing the ACL policy.

Independent review accepted the correction (603 offline tests passed, three
skipped). Actual local read-only and apply/readback checks passed before MAPIT
was consulted. One current-month import succeeded; its conditional second
import added no facts and recognized duplicates. Local day/month/year queries
then succeeded with authentication and MAPIT calls disabled: zero upstream
attempts, consistent aggregates and unverified labels preserved. See the
[acceptance result](phase-6-ledger-result.md).

Phase 6 is complete for this approved opt-in scope. It demonstrates reusable
local capability and read reduction, not improved live latency, comprehensive
history, confirmed distance units or street reconstruction. No automatic
sync, other-month ingestion, live deletion, Telegram operation or AWS resource
was added. Phase 7 is at the explicit network-policy compatibility gate in
[audit preparation](phase-7-audit-preparation.md); Phase 8 remains planned.

A separate authorized July 2025 availability read confirmed pre-August routes,
using one Core and one Geo logical/wire GET. This does not establish earliest
history, complete coverage or why the app's visible history starts later; see
[route investigation](mapit-routes-investigation.md).
