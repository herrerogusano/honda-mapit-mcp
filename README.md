# MAPIT read-only client (Phase 0)

This repository contains the bounded Phase 0 foundation for a standalone,
synchronous Python client. It discovers public runtime configuration, performs
the Cognito authentication flow when explicitly requested, obtains temporary
Identity Pool credentials, signs Core/Geo `GET` requests with AWS SigV4, and
recovers one time from an expired/invalid session.

The client does not implement an MCP server, account/routing probes, writes,
WebSocket support, persistence, or real requests in its test suite. Credentials
are read only from the process environment (`MAPIT_EMAIL` and
`MAPIT_PASSWORD`) and are never logged. Cognito identifiers may be supplied as
environment overrides; no real identifiers belong in this repository.
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
