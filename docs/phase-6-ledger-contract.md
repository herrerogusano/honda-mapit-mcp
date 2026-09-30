# Opt-in distance ledger — approved local boundary

The user accepted the minimal ledger without additional encryption on
2026-09-30. This is not a claim that MAPIT loses history or that SQLite is
faster than the measured live baseline. The stateless MCP remains unchanged.

## Private storage and identity

The Windows default is `%LOCALAPPDATA%\HondaMapitMCP\distance-history.sqlite3`,
outside this checkout and OneDrive. The app directory is reserved for this
application. Its protected ACL allows the current user, SYSTEM and local
administrators; existing children with broader allow entries are rejected.
This is access control, not encryption. Someone with filesystem privileges,
or a user-created backup, can read UTC dates and native distances in plaintext.

Facts contain only account/vehicle-scoped HMAC route aliases, UTC day,
finite nonnegative native distance, source version, unknown unit and unverified
completeness. Daily/monthly/yearly SQL views are rebuilt from facts rather than
additional copies. Raw IDs, coordinates, street names, exact times and secrets
are never columns. The authenticated `account-summary.account.id`, Core base
URL and selected vehicle ID provide the namespace in memory, not JWT decoding.
The random 32-byte HMAC key and current scope alias are independent native
Windows Credential Manager entries. Missing/wrong keys fail closed; there is
no plaintext fallback and no deletion of existing MAPIT refresh entries.

## Explicit import and query

`mapit-history import-current-month` reads one Core account summary and one
Geo current UTC month, each limited to 2 MiB. Auth recovery is at most one per
logical GET (four wire GETs total). The ledger transport disables proxies and
redirects; each socket operation has at most a 20-second timeout. Saved-login
discovery/Cognito calls remain separate from the MAPIT GET budget. A socket
timeout is not an end-to-end cancellation deadline.

The whole batch is validated before key/DB creation: at most 10,000 routes,
required stable ID, timezone-aware coherent start/end (`start <= end`),
neither in the future at the validation reference time, accepted start month,
finite nonnegative distance and no pagination key. The user approved this
revised admission contract after the flag investigation: `complete` does not
affect admission and is not persisted. Its semantic meaning is unconfirmed;
neither false nor true proves active/finished status or tracking quality.
Missing/malformed/inconsistent/future timing rejects the entire batch before
storage, not silently skips a route. End times are used only in memory for
validation and are never stored. The runtime uses one validation reference
captured after receiving the response (or an injected aware clock in tests),
so a timestamp created during the read is not spuriously ahead of that check.
Identical facts are no-ops;
conflicting facts reject the whole transaction. There is no automatic sync,
polling, last-month fallback, unfiltered read or road reconstruction.

`mapit-history summary --group-by day|month|year` uses only local facts and the
native alias key, with no authentication or MAPIT call. Its output is private
aggregate data intended for the user, not a redacted probe or CI log. Distances
are **not labelled kilometres** while the source unit remains unconfirmed.
Results are observed history, never a complete-city or complete-history claim.

An exclusive empty operation lock serializes local operations. A crash can
leave a stale lock; the application stops instead of automatically breaking
it. Stop all history commands and verify no writer remains before manually
removing that specific empty lock. Symlink/reparse DB and sidecars are rejected.
SQLite schema v1 is identified and verified; unknown/future schemas are
preserved and rejected, not destructively migrated.

## Retention, failures and deletion

Facts remain until explicit deletion. There are no app-created backups.
`mapit-history forget --confirm` deletes only the owned DB and its known
SQLite journal/WAL/SHM sidecars, then the two ledger credential entries.
Unknown DB ownership is rejected. The application directory and unrelated
files are preserved. This is ordinary file deletion, not forensic erasure of
disk snapshots, external backups or previously copied files. A partial deletion
failure is reported and must be resolved, not hidden.

If import commits but saving the active scope fails, safe output reports
`facts_committed=true` with failure; a subsequent explicit retry is idempotent.
Import output contains safe categories/count bands only. No live private
aggregate values, raw payloads or identifiers belong in this repository.

## Bounded acceptance execution

After independent offline review, the supervisor may run at most two explicit
current-month imports: one to establish the ledger and one to check no-op
deduplication. Each has the above GET/body limits. No automatic retry after
failure, no different month/detail read, no Telegram write or paid model call.
The follow-up local query records only success/zero-upstream-read booleans;
private dates, counts and distances are not printed or committed. Actual
deletion is tested only on synthetic temporary fixtures, not on user history.
