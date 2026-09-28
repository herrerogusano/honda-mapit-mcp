# MAPIT read-only client (Phase 0)

This repository contains the bounded Phase 0 foundation for a standalone,
synchronous Python client. It discovers public runtime configuration, performs
the Cognito authentication flow when explicitly requested, obtains temporary
Identity Pool credentials, signs Core/Geo `GET` requests with AWS SigV4, and
recovers one time from an expired/invalid session.

The reusable client does not implement an MCP server, account/routing writes,
or WebSocket support; the test suite makes no real requests. The explicit local
read-only probe scripts are separate from the client library. The reusable library
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

## CI and environments

Promotion is `feature/* -> develop -> main`; `develop` is dev integration and
`main` is production. CI runs on pull requests and pushes to those two branches
across Python 3.11–3.13. It has no MAPIT secrets, blocks application network
access while tests run, and rejects credential variables if injected. Package
installation still uses the normal Python package index. See
`docs/environments-and-ci.md` for the GitHub plan limitation around protection
rules and the distinction between project environments and MAPIT endpoints.

See `docs/phase-0-status.md` and the research notes for current findings and
open questions.
