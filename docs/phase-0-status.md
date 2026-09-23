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
- No MAPIT credentials have been used and no live account requests have run.
- Minimal standalone Python scaffold is implemented with typed configuration,
  public runtime discovery, Cognito session handling, SigV4 GET signing, and a
  Core/Geo read-only client. Endpoint overrides/discovery are fail-closed to
  HTTPS MAPIT Core/Geo hosts, unsupported Cognito challenges fail before any
  Identity Pool call, and expired sessions without a refresh callback fail
  closed. Offline tests pass (`34 passed`).
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
  `samples/anonymized/account-summary.schema.json`; no live account-summary
  call has been made in this task.

## Active Constraints

- No MCP server or MCP tool design yet.
- No write operations against MAPIT except required Cognito authentication calls.
- No secrets or real identifiers in source, logs, docs, tests, fixtures, or commits.
- Evidence and documentation precede implementation.
- Live probes are manual and never part of the default test suite.

## Next Steps

1. Use an authorized local account to run the first manual authentication and
   `account-summary` probe without persisting raw output.
2. Inventory the anonymized vehicle fields returned by that account.
3. Investigate route-list pagination and filters using evidence-led probes.
4. Investigate route detail and then the current account-level WebSocket.

## Open Questions

- Refresh behavior against the authorized account has not yet been exercised
  near token expiry, although the initial password flow required no challenge.
- Exact live token/header contract accepted by the API and WebSocket.
- Current endpoint inventory and route-history pagination/filter behavior.
- Whether a repository remote and preferred CI provider should be configured.
- The exact Cognito challenge behavior for an authorized test account; the
  scaffold currently covers `USER_PASSWORD_AUTH` and `REFRESH_TOKEN_AUTH` only.
- The final persistence policy for refresh tokens; this scaffold keeps session
  state in memory and does not persist secrets.
