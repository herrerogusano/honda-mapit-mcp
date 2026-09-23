# Phase 0 Status

## Objective

Understand MAPIT and build a small, independent Python client for authentication,
SigV4-signed read-only requests, endpoint and payload exploration, anonymization,
and manual WebSocket investigation.

## Current State

- Phase 0 started on 2026-09-23.
- Repository began empty with no commits or configured remote.
- Persistent Researcher, Implementer, and Tester roles have been established.
- Initial research into the two reference repositories and the current MAPIT
  frontend is documented.
- MAPIT credentials were entered only into local in-memory GUI probes; they were
  not logged, persisted, committed, or sent through chat.
- Minimal standalone Python scaffold is implemented with typed configuration,
  public runtime discovery, Cognito session handling, SigV4 GET signing, and a
  Core/Geo read-only client. Endpoint overrides/discovery are fail-closed to
  HTTPS MAPIT Core/Geo hosts, unsupported Cognito challenges fail before any
  Identity Pool call, and expired sessions without a refresh callback fail
  closed. Offline tests pass (`38 passed`).
- On 2026-09-23, public frontend discovery was verified without credentials:
  HTML/bundle discovery returned the three Cognito identifiers only as redacted
  `<discovered>` placeholders and the expected Core/Geo hosts.
- CI is documented for `feature/* -> develop -> main`, runs tests with
  application network blocked across Python 3.11-3.13, and has no MAPIT secrets
  or live MAPIT access. GitHub
  `dev`/`prod` are project environments only; the current private plan returned
  HTTP 422 for Environment protection and HTTP 403 for branch protection, so no
  platform enforcement is claimed.
- A manual Windows authentication probe is available with secure prompts and
  redacted categorized output. On 2026-09-23 the owner completed it successfully:
  User Pool authentication, Identity Pool exchange, and temporary credentials
  were confirmed without persisting any secret or account identifier.
- A Tkinter GUI alternative is available for local desktops; its non-UI probe
  logic is tested offline, while the GUI itself is not opened in CI.
- The read-only `account-summary` GUI probe is implemented with immediate
  schema-only conversion and atomic output to
  `samples/anonymized/account-summary.schema.json`. On 2026-09-23 the owner ran
  it successfully; the live SigV4/header contract was accepted and only the
  value-free schema was retained.
- The vehicle-detail GUI probe is implemented but not executed live: it selects
  the first eligible vehicle in memory, URL-encodes one detail path segment,
  persists only a value-free detail schema, and has no fixture until the probe
  is authorized and run.

## Active Constraints

- No MCP server or MCP tool design yet.
- No write operations against MAPIT except required Cognito authentication calls.
- No secrets or real identifiers in source, logs, docs, tests, fixtures, or commits.
- Evidence and documentation precede implementation.
- Live probes are manual and never part of the default test suite.

## Next Steps

1. Compare the confirmed account-summary vehicle schema with the dedicated
   vehicle-detail endpoint.
2. Investigate route-list pagination and filters using evidence-led probes.
3. Investigate route detail and then the current account-level WebSocket.

## Open Questions

- Refresh behavior against the authorized account has not yet been exercised
  near token expiry, although the initial password flow required no challenge.
- Exact live token/subprotocol contract accepted by the WebSocket.
- Current endpoint inventory and route-history pagination/filter behavior.
- Whether other account states trigger Cognito challenges not seen in the
  successful initial login.
- The final persistence policy for refresh tokens; this scaffold keeps session
  state in memory and does not persist secrets.
