# Honda MAPIT read-only MCP

Phase 0 produced the standalone synchronous client. Phase 1 now adds a local
stdio MCP server with ten read-only tools over a separate application-service
layer. Phase 2 adds bounded route analytics over the same monthly retrieval
path, and Phase 3 adds a reusable in-process realtime state service without a
new MCP tool. The project discovers public runtime configuration, performs
the Cognito authentication flow when explicitly requested, obtains temporary
Identity Pool credentials, signs Core/Geo `GET` requests with AWS SigV4, and
recovers one time from an expired/invalid session.

The reusable client and MCP server do not implement account/routing writes.
Realtime support is the reusable in-process state service plus an optional
bounded WebSocket gate; it is not exposed as an MCP realtime tool and does not
define persistence or application event semantics. See the [Phase 3
contract](docs/phase-3-realtime-contracts.md) and [status](docs/phase-3-status.md).
The test suite makes no real MAPIT requests. The explicit local read-only probe scripts are separate from the normal client workflow. The reusable library
reads environment credentials only when explicitly requested, while the local
session setup GUI keeps them in memory and persists only a refresh token in the
approved Windows store. Credentials are never logged. Cognito identifiers may
be supplied as environment overrides; no real identifiers belong in this
repository.
Core/Geo endpoint overrides are fail-closed: only HTTPS `core*.mapit.me` and
`geo*.mapit.me` base hosts without userinfo, non-standard ports, query strings,
fragments, or base paths are accepted.

## Local use

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[test]"
pytest
```

## MCP server (Phase 1)

The server uses the refresh token already held in Windows Credential Manager;
it never asks an MCP client or model for an email, password, token, or AWS key.
Install the Windows credential-store extra and start the stdio server with:

```powershell
pip install -e ".[windows-auth]"
mapit-mcp
```

Exposed tools:

- `get_vehicle_status`
- `get_vehicle_details`
- `list_routes`
- `get_route_detail`
- `get_distance`
- `compare_distance_periods`
- `get_route_statistics`
- `get_distance_breakdown`
- `get_route_extremes`
- `compare_route_periods`

All ten tools carry MCP `readOnlyHint` and `idempotentHint` annotations.

Phase 2 analytics group native distance by UTC day, month, or year and report
observed counts, elapsed durations, deterministic extremes, and bounded period
comparisons. Original values remain in native units; explicit `*_km` companions
use the UI-correlated metre-scale interpretation described below. It does not
label native speed as km/h, does not
aggregate average speed, and fails closed when required distance, timestamp, or
speed fields are unavailable. Negative distances/speeds and non-finite
aggregates fail closed. At most 10,000 normalized routes are retained per
period; conflicting duplicate IDs fail closed. See the
[Phase 2 analytics contract](docs/phase-2-analytics-contracts.md).

Date ranges accept ISO 8601 dates or timezone-aware datetimes, use an inclusive
`from_time` and exclusive `to_time`, and are limited to 366 days. Route reads
are split into at most 13 monthly UTC windows; a two-period comparison can make
at most 26 Geo reads. Route lists return at most 500 normalized routes.

This phase intentionally reports route metric units as
`mapit_native_unconfirmed` and history completeness as `unverified`. It fails
closed on an upstream cursor, an oversized response, or a route whose distance
is missing when calculating totals. The server currently selects the first
eligible vehicle in the account. MCP outputs can contain private vehicle data
(including position, VIN, registration, route geometry, and dealer contact
details), so the supported deployment in this phase is local stdio only; the
server does not log or persist tool results.

### Kilometre presentation and inferred segments (2026-10-01)

Two authorized same-route UI/API comparisons supported a metre-scale source
distance. Kilometre companions divide native distance by 1,000, without replacing
original fields or changing SQLite facts/schema. Their conversion basis remains
UI-correlated, not a universal provider guarantee or an accuracy measurement.
Use the explicit kilometre field rather than relabelling the native distance.
GPS-derived route totals are distinct from a calibrated app counter and the
physical motorcycle odometer; no automatic correction to either is performed.

Route detail can summarize strict boolean `inferred` flags on existing GeoJSON
LineStrings. `has_inferred_segments` is true when a line is explicitly marked
inferred, false only when nonempty inspected lines are all strictly false, and
null when the evidence is insufficient. `inference_quality_status` and a warning
retain partial/unknown cases. These source marks indicate possible estimated
connections, not proof of streets travelled. Missing/malformed flags remain
unknown, and false flags do
not prove GPS accuracy. `starts_at_last_known` stays a separate source hint.
No new per-route detail reads, route reconstruction, automatic collection or
extra live test is implied by these presentation changes.
The conversion metadata is
`conversion_basis="ui_correlated_meter_interpretation_unconfirmed"`; speed and
vehicle odometer fields are not converted.

See [the Phase 1 contracts](docs/phase-1-mcp-contracts.md) and
[implementation status](docs/phase-1-status.md).

The separate Phase 2 analytics gate uses the saved session, calls only the four
analytics tools over a maximum 31-day window, and prints only safe per-tool
status categories. It requires `get_route_statistics` to observe at least one
route and does not print or persist dates, IDs, metrics, payloads, or exception
details:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\smoke_mcp_phase2.py
```

See the [Phase 2 analytics contract](docs/phase-2-analytics-contracts.md) and
[Phase 2 completion status](docs/phase-2-status.md).

Public runtime discovery does not use credentials:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\discover_frontend.py
```

For a future authorized manual probe, set `MAPIT_EMAIL` and `MAPIT_PASSWORD` in
the process environment or use a local secret loader. `.env.example` documents
the accepted names, but the library deliberately does not parse `.env` files or
persist credentials. For an interactive Windows probe, prefer the secure
wrapper, which prompts for both values without echoing them:

```powershell
.\scripts\run_auth_probe.ps1
```

The probe performs public discovery and Cognito authentication only, then
prints a redacted JSON summary (success, region, expiration timestamps, and
availability booleans). It never prints email, IDs, tokens, AWS keys, headers,
or exception payloads. It restores any pre-existing environment variables when
it exits and does not persist credentials.

On a desktop with Tk available, the equivalent local GUI keeps both fields
masked and clears them as soon as authentication starts:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\auth_prompt_gui.py
```

The GUI performs the same redacted probe in a daemon worker and updates its
widgets only on the Tk main thread. Closing the window does not persist input.

To establish the reusable saved session for the data probes, use the dedicated
setup GUI:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\session_setup_gui.py
```

It performs only public discovery plus `USER_PASSWORD_AUTH`, persists only the
refresh token in the fail-closed Windows Credential Manager store, and prints
only `{"success":true,"saved":true}` on success. Failures are categorized
without exception text or tokens. To validate an existing saved session
without any Core/Geo call, run `py scripts\check_saved_session.py`.

To make the first authorized, read-only account-summary inspection, use the
schema-only GUI:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\account_summary_prompt_gui.py
```

It authenticates, performs exactly one `GET /v1/account-summary` (apart from
the client's single controlled 401/403 recovery), immediately discards the
response values, and atomically writes only the recursive schema to
`samples/anonymized/account-summary.schema.json`. The UI shows only success or
categorized failure, safe top-level keys, and the output path.

For the next authorized read-only step, the vehicle-detail GUI selects the
first in-memory vehicle whose `id` is a non-empty string and whose `device` is
not null:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\vehicle_detail_prompt_gui.py
```

It performs the account-summary GET, then exactly one
`GET /v1/vehicles/{encodedId}` with the ID encoded as one path segment. It
persists only `samples/anonymized/vehicle-detail.schema.json`; no account
summary schema, raw payload, vehicle ID, or count is stored. If no valid
vehicle is present, it makes no detail request and reports a categorized error.

For the bounded routes-list probe, use:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\routes_list_prompt_gui.py
```

It selects a vehicle in memory, performs one Geo `GET /v1/routes` with only
`vehicleId` and `limit=1`, and writes only
`samples/anonymized/routes-list.schema.json`. It does not follow cursors,
request route detail, persist IDs/counts/raw payloads, or print signed URLs.
HTTP, transport, and invalid-response failures are reduced to safe allowlisted
categories without URL, body, header, or ID details; schema and persistence
failures are also categorized without payload details.
On Windows, install the optional `.[windows-auth]` extra to enable the
fail-closed native Credential Manager backend. The GUI first tries the saved
refresh token and, if none is available, tells you to run
`session_setup_gui.py`; it never asks for credentials or enrolls a session.
It provides `Borrar sesión guardada` and makes no data call without a valid
saved session.
Failures are shown only as stable categories such as `discovery_failed`,
`authentication_rejected`/`authentication_failed`, or
`credential_store_failed`; exception text, response bodies, and URLs are never
shown. A native Credential Manager size/backend failure is fail-closed and has
no file-storage fallback.
The Windows store uses a bounded UTF-8-fragmented `mapit-refresh-v1` manifest
with up to eight 1024-byte chunks and an alternate staging bank; legacy
single-entry data is migrated only after the new set is verified.

For a non-interactive route-detail probe using only the saved session, run:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\probe_route_detail.py
```

It reads `account-summary` once, lists routes once with only `vehicleId` and
`limit=1`, then reads exactly one current
`/v1/vehicles/{vehicleId}/routes/{routeId}` with `includeStats=true`. IDs are
encoded as single path segments. The response is converted immediately to a
schema-only document and written atomically to
`samples/anonymized/route-detail.schema.json`; raw data, IDs, values, counts,
URLs, headers, and bodies are never printed or persisted. Without a valid
saved session the script makes no Core/Geo request.

To compare the current and immediately previous calendar month using the
frontend's paired UTC `from`/`to` boundaries, run the non-persisting probe:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\probe_route_history_filters.py
```

It performs exactly two bounded Geo reads after the single account-summary
selection. It checks only that each response is an object with a `data` array
and whether the allowlisted `lastEvaluatedKey` field is present. It never
follows that field, saves dates, IDs, counts, values, or payloads, and emits
only safe status metadata.

The historical coverage gate has one authorized live result. It performed the
unfiltered Geo read with an accepted 2 MiB stream cap and failed closed as
`response_too_large` before JSON decoding. No monthly controls ran and no
counts, dates, IDs, coordinates, values, or payloads were persisted. The
supervisor accepted no larger cap and no month-by-month sweep, so history is
`PARTIAL`; the two bounded monthly windows remain separately confirmed.

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
py scripts\probe_route_history_coverage.py
```

The gate is fail-closed: it uses one saved-session account lookup, one
unfiltered route read capped at 2 MiB, and at most two monthly controls only if
the unfiltered response is below the cap. It retains no response/schema/body;
its successful output is limited to the observed route count, UTC oldest and
newest months, pagination-metadata presence, and an allowlisted coverage class.

The account-level WebSocket probe is optional and does not install realtime
support by default. After installing `.[realtime]`, run:

```powershell
py scripts\probe_websocket.py
```

It uses the saved session, reads `account-summary` once for the in-memory
account ID, opens only `wss://dsw.prod.mapit.me/accounts/{encodedId}` with the
Cognito ID token as its sole subprotocol, sends no messages, and receives at
most three text frames within ten seconds. Valid frames are converted and
merged immediately into a schema-only artifact at
`samples/anonymized/websocket-message.schema.json`; invalid/binary frames are
ignored. No fixture is written when no valid frame arrives, and output never
contains the URL, subprotocol, IDs, values, close reason, or raw frame.
The bounded authorized run connected successfully and produced the current
schema-only fixture; this is one-account evidence, not a universal realtime
contract.

The reusable Phase 3 realtime component is available to later local layers as
`mapit.realtime.RealtimeService`. It uses only the allowlisted account-level
`wss://dsw.prod.mapit.me/accounts/{encodedAccountId}` endpoint, checks token
freshness before each handshake and refreshes only if needed, sends no
application messages, keeps an immutable in-memory cache of at most 64
normalized identities, and reconnects with bounded backoff. It exposes
lifecycle categories and snapshots but does not add an MCP tool or persist
realtime state.

The bounded Phase 3 live gate can be run locally after installing `.[realtime]`:

```powershell
py scripts\smoke_realtime_phase3.py
```

It waits at most ten seconds for one valid normalized state, always stops the
service, and prints only booleans and allowlisted categories. It never prints
or persists realtime state, IDs, frames, URLs, or credentials. A successful
gate is evidence for the local saved-session account only; see the [Phase 3
status](docs/phase-3-status.md) for the recorded result and limitations.

## Optional conversational agent (Phase 4, complete)

For normal interactive use, Codex can launch the local `mapit-mcp` stdio server
directly. The registered local server is started on demand by Codex and uses the
saved MAPIT session; it does not need an OpenAI API key. Model usage follows the
signed-in Codex account's normal allowance. The 2026-09-29 live E2E confirmed a
grounded `get_vehicle_status` call with GPT-6 Sol at medium reasoning. A separate
Codex-path failure reports for `get_distance` were traced to model argument
variation rather than an MCP failure; a separate completed call used the
correct arguments. The reproducible no-argument current-status checker passed
its bounded supervisor gate. See the [Phase 4 status](docs/phase-4-status.md).

The optional Agents SDK adapter is lazy: the base client and MCP server do not
require `openai-agents` or an OpenAI key. Install the compatible extras for
local work:

```powershell
pip install -e ".[test,realtime,agent]"
py scripts\evaluate_agent_dataset.py
```

The evaluator is deterministic, synthetic, model-free, and network-free. The
optional live gate requires the saved MAPIT session plus process environment
values `OPENAI_API_KEY` and `MAPIT_AGENT_MODEL`; it runs one bounded read-only
question and prints only booleans, safe categories, and actual allowlisted tool
names:

```powershell
py scripts\smoke_agent_phase4.py
```

The subscription-backed Codex-to-local-MCP gate is separate from the optional
Agents SDK gate. It verifies ChatGPT login, runs one bounded current-status
call (the checker expects `get_vehicle_status`) with `codex exec`, and prints
only safe booleans, category, model, and tool name. It is never run by CI:

```powershell
py scripts\smoke_codex_mcp_phase4.py
```

The adapter uses an explicit no-shell `mapit-mcp` subprocess, disables tracing,
limits the run to six turns and 60 seconds, and never passes provider or MAPIT
credentials to the child. See the [Phase 4 contract](docs/phase-4-agent-contracts.md)
and [Phase 4 status](docs/phase-4-status.md).

## Phase 5 Telegram prototype (completed bounded scope)

Phase 5 includes a private local polling contract, offline prototype,
Credential Manager setup, and injectable bounded Bot API transport; “no polling”
means no persistent polling service. Bot creation and the bounded E2E gate were
authorized and completed by the supervisor on 2026-09-29; the recorded result
contains only safe booleans/categories, and this worktree does not read tokens
or real IDs. Safe evidence was `success=true`, `category=success`,
`cycles=1`, `update_processed=true`, and `message_sent=true`; a direct
allowlisted current-status backend check also succeeded. No runtime, event,
update, or history state is persisted by the polling prototype; its credential
envelope is intentionally stored in Windows Credential Manager. No webhook or
AWS deployment exists, and the read-only MAPIT boundary is unchanged. See the
[Phase 5 contract](docs/phase-5-telegram-contracts.md) and
[Phase 5 status](docs/phase-5-status.md).

The local setup GUI is `py scripts/telegram_setup_gui.py`; it writes a single
bounded canonical `telegram-state-v1` envelope (token, nullable pair list, and
one-use challenge) to native Windows Credential Manager and performs no network
call. On startup it recovers any pending one-use pairing challenge into a
readonly selectable command field; `Copiar comando` touches the clipboard only
when explicitly clicked. The GUI shows the exact `/start <challenge>` onboarding
message; it is never printed. The bounded Bot API smoke is
`py scripts/smoke_telegram_live.py`, but it requires both explicit
`--allow-get-updates --allow-send-message` flags and supervisor authorization.

The bounded query E2E seam is `py scripts/run_telegram_once.py`; it requires
`--allow-poll --allow-agent --allow-send`, reuses one poller for at most two
sequential cycles, and emits only safe booleans/categories. The authorized
query E2E completed successfully using only the redacted evidence above.
Future invocations remain supervisor-authorized and are not run by CI.

## Phase 6 — optional local distance history

The approved opt-in SQLite ledger is implemented and independently tested;
the ordinary MCP remains stateless. It stores pseudonymous UTC-day/native
distance facts outside OneDrive with no additional encryption. Explicit local
commands are `mapit-history import-current-month`, `mapit-history summary
--group-by month` and `mapit-history forget --confirm`. Summary output is
private aggregate data; do not copy it into repository/CI logs. No background
sync, coordinates or automatic backups are enabled. See the
[ledger contract](docs/phase-6-ledger-contract.md),
[Phase 6 plan](PHASE_6_PERSISTENCE.md) and [status](docs/phase-6-status.md).
The pure route-input sufficiency analyzer and its tests are offline-only
(`mapit.route_input_analyzer`). The probe
(`scripts/probe_route_input_sufficiency.py`) is live-capable; three bounded
redacted runs were authorized and completed. The third bounded redacted run
populated the current geometry/name structural fields without retaining values.
It may perform public discovery,
Cognito authentication/refresh, and secure refresh-token rotation before
exactly three bounded MAPIT reads. It does not persist route data or probe
output; further runs remain explicitly scoped and authorized.
The analyzer reports only allowlisted gap bands by provenance (LineString
interior, feature boundary, or Point stream); third ordinates remain opaque.
The offline refinement also separates feature-object and coordinate density,
geometry-specific name/label bands and structural name transitions without
exposing values; the third run confirmed those categories safely.

The synthetic local OSRM POC is `scripts/probe_local_osrm_fixture.py`. It is
loopback-only, uses an in-memory synthetic route through `/route` and `/match`,
and emits only a fixed redacted schema; raw responses are discarded. The
deterministic fixture uses two synthetic endpoints and at most 12 equidistant
points, while accepting OSRM's `null` unmatched tracepoints and
`leg.annotation` response shape. The
observed local result was `osrm-local`, `matched`, few matchings, all
tracepoints, medium confidence, with steps/annotations/names present. This
validates the local engine/harness only, not MAPIT or production map matching.

The bounded MAPIT-to-local-OSRM harness is implemented in
`scripts/probe_mapit_osrm.py` and one bounded live run is complete. It reuses the saved
session flow and performs one account-summary read, one route-list read with
`limit=1`, and one current detail read before sending the first real
LineString (without sampling) to a literal loopback matcher. It drops the
third ordinate, requires all points inside the fixed Barcelona research box,
caps input at 500 points, disables proxies/redirects, and emits only OSRM
categories/bands plus a safe stage category. No route data or request details
are persisted or printed. The real selected LineString returned `matched`,
all tracepoints, high confidence, and steps/annotations/names present. This
is promising input-feasibility evidence, not full-route or city-coverage
accuracy; see `docs/phase-6-barcelona-local-probe.md`.
The follow-up `scripts/probe_mapit_osrm_route.py` assessed all bounded source
LineStrings and returned partial point association with low minimum confidence,
mixed inferred flags and excluded Points. It never asserts a complete route;
street percentages and exact full-trip reconstruction remain unproven.
The bounded monthly baseline measurement completed with five successful
repetitions, p50 <1 second and p95 1–5 seconds. This is not a demonstrated
live latency benefit. The distance-ledger/privacy gate was accepted, and the
offline ten-query workload demonstrates fewer repeated API reads. The first
live import stopped before storage on a `complete=false` route flag with
unconfirmed semantics; no private database was created by that attempt.
The subsequent authorized flag investigation found the same sampled routes
and selected facts with omitted/false/true `includeInProgress`; all sampled
routes were false-marked, including coherent old end timestamps. Filtering
on `complete=true` would exclude the entire sample. The user approved revised
admission using identifiers, coherent nonfuture start/end times and distance,
without consulting `complete`. Offline tests and independent review passed.
An earlier import passed validation but failed local permission verification.
The reproduced cause was incompatible PowerShell module paths inherited by
the Python child process. Isolating the Windows PowerShell child environment
fixed verification without relaxing the ACL. After independent review and
renewed explicit authorization, the current-month import and no-op deduplication
check succeeded. Real local day/month/year queries passed with authentication
and MAPIT reads disabled. Phase 6 is complete for the minimal opt-in scope;
private facts remain outside Git/OneDrive, and ordinary MCP reads stay stateless.
See
[flag investigation](docs/phase-6-route-flags-investigation.md).
One separate bounded July 2025 API read confirmed routes before August,
despite the later start reported for the app's visible history. Earliest history
and the cause of that discrepancy remain unknown.

## Phase 7 hardening and offline diagnostics

Default HTTP/WebSocket connections are direct-only: system/environment proxies
are ignored and HTTP redirects are rejected. General MAPIT responses now have
a 2 MiB ceiling even without an explicit caller limit; stricter limits still
apply. Cognito and public discovery inputs are bounded separately. Networks
requiring a corporate proxy need a future explicit compatibility decision.

`python -m mapit.health` reports local package availability without touching
credentials or providers. It is not a live connectivity check. See
[security and operations](docs/security-and-operations.md) and the
[synthetic portfolio demo](docs/portfolio-demo.md).

## CI and environments

Promotion is `feature/* -> develop -> main`; `develop` is dev integration and
`main` is production. CI runs on pull requests and pushes to those two branches
across Linux Python 3.11–3.13 plus Windows Python 3.13, with agent/realtime extras
and a separate known-advisory audit. It has no provider secrets, blocks external application network
access while tests run, and rejects credential variables if injected. Package
installation still uses the normal Python package index. See
`docs/environments-and-ci.md` for the GitHub plan limitation around protection
rules and the distinction between project environments and MAPIT endpoints.

See `docs/phase-0-status.md` and the research notes for current findings and
open questions.

## Future AWS deployment

Phase 8 plans an optional always-available remote MCP on AWS with separate dev
and prod environments. Hosting the MCP does not require hosting a model. A
managed agent and its model/provider evaluation are a separate optional track,
performed only behind an explicit cost gate. See
[`PHASE_8_AWS_REMOTE.md`](PHASE_8_AWS_REMOTE.md).
The approved preparation is documented in
[AWS design, regional cost assumptions and gates](docs/phase-8-aws-preparation.md).
The IaC candidates remain deliberately closed and contain no credentials.
On 2026-10-02 a bounded [closed AWS rehearsal](docs/phase-8-closed-rehearsal.md)
verified scheduled shutdown and scoped deletion; all six application and twelve
control resources were then removed. The regional concurrency quota remains 10.
No remote MCP is currently active. Real OAuth/owner enrollment and synthetic
tool interoperability are still pending; Phase 8 is not complete.

The accepted offline block is a deliberately synthetic local HTTP/auth adapter;
see its [contract and acceptance limits](docs/phase-8-local-http-contract.md).
It constructs fixed fake services rather than loading MAPIT credentials or the
ledger. Separate `.invalid` dev/prod policies and injected public verification
keys test the resource-server boundary without a listener, cloud resources or
inference. This does not establish real Cognito/PKCE or Codex OAuth acceptance,
and does not make the disabled AWS scaffold deploy-ready.

Local Lambda composition is also independently accepted: a synchronous synthetic
handler factory translates strictly bounded API Gateway v2 fixtures to the HTTP
app. See the [Lambda-local contract](docs/phase-8-lambda-local-contract.md) for
lifecycle, remaining-time reserve and acceptance limits. It does not load a
MAPIT session or call AWS; the infrastructure scaffold remains disabled.
Its initial acceptance was 42 focused tests and 754 full offline tests (3 skipped).
Later accepted preparation adds a fixed ARM package, private binding-file input,
conditional artifact publication, and closed OAuth/runtime and cleanup candidates.
See the current AWS preparation record for test checkpoints and remaining gates;
local/schema success does not establish real OAuth interoperability.
