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
persist credentials. See `docs/phase-0-status.md` and the research notes for the
current findings and open questions.
