# Distance ledger acceptance checkpoint — 2026-09-30

## Accepted offline implementation

Independent worker review accepted the scoped ledger, orchestration, CLI and
tests. Final local suite: **568 passed, 3 skipped**. Skips are Windows symlink
creation limitations; simulated reparse-attribute rejection is separately
covered. Compilation succeeded. GitHub CI is recorded separately once run.

Coverage includes scoped HMAC identity, missing/wrong key, unknown schema
preservation, transactional conflict rollback, deduplication, finite sums,
UTC/date grouping, native units, local deletion, isolated Credential Manager
service, ACL verification failure, body/wire limits, no redirects/proxies and
safe CLI failures. ACL tests use subprocess doubles, not an actual private
directory. Deletion tests use synthetic temporary fixtures only.

The fixed synthetic ten-query workload executes 20 stateless logical GETs.
Its ledger setup executes two synthetic GETs, then ten local queries reopen
the database with zero additional GETs. An additional orchestration test
prohibits both session login and MAPIT GET during local queries. All results
use synthetic data. This demonstrates reusable offline facts and read
reduction, **not** live timing/latency improvement or complete MAPIT history.

## Bounded live import: stopped before storage

The supervisor invoked the explicit current-UTC-month import once. It reached
route validation and stopped on an explicit `complete=false` flag:

- success: false;
- normalized category: `route_not_confirmed_complete`;
- facts committed: false;
- private values printed: false;
- private database exists: false;
- application history directory exists: false.

The initial code emitted `route_in_progress`. Local evidence review confirmed
that this interpretation is unsupported: only the boolean schema is known;
the `includeInProgress` behavior remains unverified. The category and tests
were corrected without another live read. No route bodies, IDs, dates,
distances or exact route counts were retained. The key-creation code was not
reached. No second import, filtering or automatic retry occurred.

## Cross-platform CI regression

The first CI run found that SQLite 3.45.1 can return SQL `NULL` for two large
positive finite values whose total overflows, whereas local SQLite 3.50.4
returns infinity. The import now checks `SUM(distance)` together with
`COUNT(*)`: a nonempty scope with a NULL/nonfinite total is rejected and
rolled back. A regression forces the NULL case; independent review accepted
the fix. A separate standard-library-only WSL/SQLite 3.45.1 synthetic smoke
confirmed `numeric_overflow` and that the first fact was preserved. No private
data or network was involved. This is distinct from the live route-flag gate.

## Historical route-flag decision

Investigate that flag with a separately bounded schema-only read, or explicitly
approve a partial import limited to `complete=true` routes. Excluded routes
must be visible as bands and totals must remain partial. The ledger cannot
silently equate missing routes with zero activity. Phase 6 is not declared
fully operational or complete at this checkpoint.

Follow-up: the user chose investigation and its one bounded comparison is
complete; see [flag investigation](phase-6-route-flags-investigation.md).
All sampled routes were false-marked, including coherent old end timestamps,
and all three query variants returned the same selected facts. The proposal
to import only `complete=true` would therefore exclude this entire sample.
The user subsequently approved the revised admission policy. The ledger now
ignores `complete` and requires aware, coherent, nonfuture start/end timestamps
alongside valid identifiers and finite nonnegative distance. No end timestamp
is persisted. Independent review accepted the changes; the complete offline
suite has 592 passed and 3 skipped.

## Revised-policy live attempt

The one authorized current-month import passed source validation, then stopped
at `history_permissions_failed`, with `facts_committed=false` and
`private_values_printed=false`. No successful import or live deduplication is
claimed. The conditional second import was not executed because the first did
not succeed. Local permission diagnosis is read-only; another live retry needs
an explicit bounded allowance.
