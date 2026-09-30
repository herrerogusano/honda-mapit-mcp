# Proposed persistence decision — awaiting user approval

This is a decision proposal, not permission to create a database or ingest
private facts. Phase 6 remains active until the decision is recorded and any
accepted scope is implemented and independently tested.

## Evidence and limits

- Single-line local matching worked, but the all-LineString assessment produced
  partial associations, low minimum confidence, mixed inferred flags and
  excluded Point features. Exact streets/turns and city coverage are unproven.
- Historical MAPIT coverage remains partial; unknown pagination and an
  oversized unfiltered response are not evidence that routes are lost.
- No persisted-versus-stateless ten-query benchmark has been measured. A
  possible reduction in reads is not a demonstrated latency improvement.
- One bounded monthly run succeeded: 5/5 repetitions, p50 <1 second,
  p95 1–5 seconds, maximum monthly response 64–256 KiB, one wire Core read
  and six wire Geo reads including the adjacent control. See
  [measurement result](phase-6-monthly-measurement-result.md).
  This supports the current stateless performance baseline for the sample,
  not a DB performance advantage or complete history.

## Recommended bounded first implementation, if approved

Use a local SQLite file outside the Git checkout and OneDrive workspace,
under the user's local application-data directory. One application owns
writes; no background polling, managed DB, cloud backup or AWS provisioning.
The file is not automatically encrypted by SQLite; OS access controls and
local disk protection must be evaluated, not advertised as encryption.

Persist only facts needed for distance history:

- a per-route pseudonymous HMAC alias, scoped locally, for idempotent import;
- UTC day (not exact trip time) and distance in the source's native units;
- source/normalization version, `metric_unit=mapit_native_unconfirmed` until
  independently confirmed, and partial/
  unknown completeness scope;
- derived daily/monthly/yearly aggregates, rebuildable from route facts.

The HMAC key stays in the OS credential store, outside the database. The alias
must incorporate a protected account/vehicle namespace in memory so route-ID
collisions or a credential/account switch do not merge unrelated histories;
the implementation must confirm stable scope without persisting direct IDs.
It is still sensitive pseudonymous data, not anonymous. Do not store raw route,
account, vehicle or Telegram IDs, coordinates, GeoJSON, street names, road
sequences, speeds, exact timestamps, tokens, passwords or signed URLs. Do not
persist experimental matching classifications in the first version.
Do not label an unconfirmed native distance as kilometres.

Implement only explicit bounded imports using the existing accepted read
limits. Do not sum overlapping snapshots, silently overwrite conflicts or
claim complete history. Include schema migrations, transactional deduplication,
source/derived separation, local deletion, rebuild and security regression
tests. If a month is oversized or pagination remains unsupported, stop and
report incomplete scope; a DB cannot invent the missing data.

## Benefit and acceptance

The product benefit under consideration is a reusable local distance ledger
and rebuildable aggregates without recalculating previously accepted facts.
This is an explicitly chosen product direction, not proof that MAPIT has
deleted history or that measured performance thresholds have passed.
Keep ordinary on-demand reads available. Compare a fixed ten-query workload
offline and, if subsequently authorized, against a bounded measured live
baseline. Report actual read reduction and end-to-end timing; do not assert
improvement merely because SQLite is present.

## Choices requiring the user

1. Approve the minimal route-facts dataset and HMAC alias, or keep stateless.
2. Retention: recommended **until explicit deletion** for distance history;
   alternatively a fixed 12-month limit. Neither is silently selected.
3. Accept local unencrypted SQLite under OS controls, or require a separate
   encryption design before storing private facts.

Deletion must address the database, its WAL/journal and owned local backups,
and aggregates derived from deleted facts. No automatic external backup is
authorized. Precise deletion/rollback mechanics are an implementation contract,
not a promise that previously synced cloud copies can be erased.

## Engine choice

SQLite is a candidate for the initial single-owner local application.
PostgreSQL should be reconsidered if a later approved remote architecture has
multiple writers or a shared database service. Do not implement two backends
now or assume that a local SQLite file can safely be shared through a network
drive or synced concurrently.

Primary guidance: [SQLite appropriate uses](https://www.sqlite.org/whentouse.html),
[SQLite transactions](https://www.sqlite.org/transactional.html),
[PostgreSQL MVCC](https://www.postgresql.org/docs/current/mvcc-intro.html).
