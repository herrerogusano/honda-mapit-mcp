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

Read-only inspection confirmed the application directory is empty, its ACL
is protected and no unexpected allow principal is present; the private DB
does not exist. This does not yet establish why the verification subprocess
failed. No ACL mutation or extra MAPIT read followed the failure.

GitHub CI for commit `ff89b94` passed on Python 3.11, 3.12 and 3.13
([run 36773127212](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/36773127212)).

## Renewed bounded allowance

The user explicitly authorized correcting local permission verification and
one further current-month import, with a second permitted only after success
for deduplication. Local checks must precede those MAPIT reads. Independent
read-only reproduction of the exact verifier now succeeds in Windows
PowerShell 5.1 and PowerShell 7; both expose a Boolean protected-root property
and no unexpected allow entries. The original failure is not reproducible;
that shell-only check did not reproduce Python's inherited environment.
The researcher subsequently reproduced the exact Python subprocess failure:
inherited environment rejects module autoload; a copied child environment
excluding `PSModulePath` case-insensitively makes identity and verification
succeed. This is not a missing/false ACL property. Microsoft's
[PSModulePath documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath?view=powershell-7.6)
describes this PowerShell 7 → Python → Windows PowerShell compatibility case.
The bounded correction isolates only the PowerShell child environment, adds
stage-specific safe diagnostics and separates
read-only verification from ACL application without relaxing the policy.

## Accepted live and local checkpoint

Independent review accepted the correction. Full offline suite: **603 passed,
3 skipped**. The supervisor's real local preflight passed read-only verification
and the existing exact-policy apply/readback, with zero MAPIT reads and no DB
yet present. Two authorized imports then completed:

| Check | Success | Added band | Duplicate band | Coverage |
|---|---|---|---|---|
| Current-month import | true | many | none | PARTIAL |
| Conditional deduplication import | true | none | many | PARTIAL |

Both retained `mapit_native_unconfirmed` and reported facts committed without
printing private values. Each keeps the contract's one Core/one Geo logical
read and maximum four wire GETs; no different month or detail was queried.
Actual wire counts were not instrumented by this CLI and are not claimed.

The real local day/month/year queries were executed with `MapitClient.get`
and `SessionManager.login_saved` replaced by rejecting guards. All succeeded,
with zero upstream attempts, consistent aggregate totals/counts checked only
in memory and unverified labels preserved. No dates, distances, exact counts,
aliases, keys or raw payloads were printed or committed. The private SQLite
file and its alias key now exist only in their approved local stores.

**Phase 6 accepted** for the minimal opt-in ledger. No claim of complete
historical coverage, latency superiority, confirmed native units, safe street
reconstruction, automatic sync or remote deployment follows. Actual history
deletion remains unexecuted; its tests use synthetic fixtures only.
