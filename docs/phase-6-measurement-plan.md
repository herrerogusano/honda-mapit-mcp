# Phase 6 — Measurement and Persistence Decision Gate

Status: **RESEARCH ONLY — no persistence implementation**.

This document defines the smallest evidence needed before adding a database,
snapshot store, synchronization worker, or durable realtime history. Thresholds
below are proposed product decisions, not observed MAPIT guarantees.

## Evidence boundary

Phase 0 establishes a read-only route contract, not complete history:

- Geo `GET /v1/routes?vehicleId=...` returned a schema-only observed
  `{data: Route[]}` envelope for one authorized account/vehicle.
- Two bounded monthly `from`/`to` reads with `limit=1` were accepted and no
  `lastEvaluatedKey` was observed in those responses.
- The unfiltered historical read exceeded the accepted 2 MiB safety limit and
  stopped before JSON decoding. No count, oldest/newest route, pagination
  behavior, or complete-history claim was obtained.
- The dashboard loads one calendar month at a time and filters selected days in
  memory. `month`, `day`, and `includeInProgress` are frontend query-builder
  evidence only; their server semantics remain unknown.
- WebSocket state was confirmed only as a bounded, process-local, memory-only
  observation. No durable event/history contract or event semantics is
  confirmed.

Therefore historical coverage is **PARTIAL**. Persistence must not be used to
turn a partial read into a claim of complete history.

## No-persistence baseline

The current stateless `MapitServices` path is the baseline to measure:

| Operation | Upstream pattern for a one-month period | Current bound |
|---|---|---|
| Vehicle status | one Core `account-summary` read | response bound applies |
| Vehicle details | `account-summary` plus one Core vehicle-detail read | response bound applies |
| Route list/analytics | one Core `account-summary` plus one Geo read per UTC month window | 2 MiB/window; 366-day period; 10,000 normalized routes; 500 returned summaries |
| Period comparison | one route-history aggregation per period | same monthly split and limits per period |
| Route detail | one Core `account-summary` plus one current Geo detail read | 1 MiB detail bound |

These formulas are derived from `src/mapit/services.py`; they are not live
latency measurements. Each analytics call re-reads the account and route
windows, so repeated identical queries are the only clear candidate for read
reduction. A single query has no demonstrated persistence benefit.

## Offline measurements allowed now

Use synthetic route objects and injected `RecordingClient`/fake transports only.
No credentials, network, MAPIT bodies, real identifiers, or database are
needed. Measure with `time.perf_counter()` around the existing service and
pure analytics functions, without changing production code.

The offline matrix should cover empty input, one route, 10/100/500/10,000
normalized routes, multiple month windows, nullable metrics, duplicate IDs,
conflicting duplicates, malformed timestamps, missing distance/speed, overflow,
unsupported pagination metadata, and transport/HTTP error categories. Record
only aggregate test metadata such as pass/fail, operation name, synthetic input
class, call count, and bounded duration buckets.

Offline results can establish deterministic aggregation cost, current upstream
call formulas, serialization/normalization cost, and safety-limit behavior.
They cannot establish MAPIT latency, rate limiting, real response size,
authentication refresh reliability, route depth, or historical coverage.

## Separately authorized live measurement

No live measurement is authorized by this document. If the supervisor opens a
new gate, use one account and the first eligible vehicle selected in memory.
Do not repeat the rejected unfiltered read, increase the 2 MiB cap, or scan
month-by-month.

Minimal proposed sample:

1. Five bounded repetitions of one fixed, frontend-shaped monthly `from`/`to`
   read, using the in-memory vehicle ID and existing 2 MiB limit.
2. One adjacent monthly control read using the same in-memory ID. This is only
   a bounded consistency signal, not a completeness proof.
3. Count logical reads separately from actual wire GET attempts. The sample
   has exactly six logical Geo reads (five repetitions plus one adjacent
   monthly control). Each logical Geo read may use the client's one 401/403
   recovery, so actual wire Geo GETs are capped at **12** (initial attempt plus
   one recovery for each logical read). Stop and fail closed before any read
   that would exceed either cap; no other retry is allowed.
4. The sample requires one logical Core `account-summary` read to select the
   in-memory vehicle, and at least one successful wire Core GET. Its hard cap
   is two wire Core GETs, accounting for that same one 401/403 recovery; no
   additional Core reads are part of this sample. Count and report Core and
   Geo logical/wire totals separately as redacted metadata only.

Retain only aggregate, redacted metadata:

```text
operation_class, repetitions, successful_repetitions,
core_logical_reads, core_wire_gets, geo_logical_reads, geo_wire_gets,
latency_p50_bucket, latency_p95_bucket,
response_size_bucket, error_categories,
monthly_control_class, pagination_metadata_observed,
coverage_class
```

Use coarse buckets rather than exact durations, byte counts, dates, route
counts, or timestamps. Route IDs may be compared ephemerally inside one run if
needed for a control classification, then must be discarded; do not persist,
print, hash, or log them. Never retain coordinates, GeoJSON, labels, VINs,
dealer/payment data, headers, signed URLs, tokens, or raw bodies.

`coverage_class` may be only `PARTIAL` or `UNKNOWN` for this filtered monthly
sample. Do not emit `COMPLETE_FOR_RETURNED_RESPONSE`: that stricter label
requires the separate unfiltered-read plus monthly-controls criterion, which
this sample intentionally does not use and cannot establish.

## Proposed decision thresholds

These are gates for a later supervisor decision, not current results.

### Keep stateless

Keep the current on-demand design when the representative bounded monthly
sample has at least 95% successful reads, no response exceeds 2 MiB, and the
measured p95 remains below the product's agreed interactive target (proposed
default: 5 seconds). Persistence is not justified solely by repeated reads.

### Persistence has measurable performance value

A candidate store must reduce upstream GETs by at least 50% across a fixed
representative workload of at least ten repeated logical queries **and** either:

- reduce p95 end-to-end latency by at least 30% and at least one second; or
- prevent a repeatable safety-limit failure that the on-demand path cannot
  avoid without changing accepted byte/call limits.

The persisted path must not reduce successful-result rate by more than two
percentage points, introduce duplicate/conflicting records, or weaken
fail-closed handling. A one-off query or offline-only CPU improvement does not
meet this gate.

### Persistence has measurable historical value

Performance is not required if a separately approved observation protocol
demonstrates a capability unavailable from bounded on-demand reads, such as a
confirmed historical state transition. That requires a stable response/event
contract and at least two separated observations whose value would otherwise be
lost; current WebSocket evidence does not meet that requirement.

If the only result is that unfiltered history is too large or pagination is
unknown, classify persistence value as **UNPROVEN**, not improved coverage.

## Candidate datasets only if a gate passes

The likely minimum, subject to a separate implementation decision, is:

1. normalized route metadata sufficient for dedupe and analytics, excluding
   GeoJSON/coordinates by default; route identity storage strategy remains an
   explicit privacy decision;
2. UTC day/month/year derived aggregates, marked with
   `metric_unit=mapit_native_unconfirmed` and `completeness=unverified`;
3. synchronization metadata containing schema version, bounded scope alias,
   last outcome category, and retention state, but no tokens or raw URLs;
4. realtime state transitions only after event semantics and retention are
   confirmed. Location should remain excluded by default.

The no-persistence baseline remains the default until a quantitative
performance or historical-value gate passes. Any later implementation must add
idempotency, deduplication, migrations, retention, source/derived separation,
and an explicit no-secrets-in-storage test contract.

## Open questions

- What real user workload and interactive latency target should define the
  representative ten-query benchmark?
- Is route identity allowed in local durable storage, or must it use an opaque
  local mapping with a separate protection policy?
- What retention period and deletion operation are acceptable?
- Does the supervisor authorize the six-read redacted live sample at all?
- Can a future primary contract establish pagination or historical event
  semantics without raising the current byte cap?
