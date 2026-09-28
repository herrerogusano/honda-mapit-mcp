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
- MAPIT passwords were entered only into local in-memory GUI probes; they were
  not logged, persisted, committed, or sent through chat. The only optional
  persistent secret is a Cognito refresh token in the current Windows user's
  native Credential Manager.
- Minimal standalone Python scaffold is implemented with typed configuration,
  public runtime discovery, Cognito session handling, SigV4 GET signing, and a
  Core/Geo read-only client. Endpoint overrides/discovery are fail-closed to
  HTTPS MAPIT Core/Geo hosts, unsupported Cognito challenges fail before any
  Identity Pool call, and expired sessions without a refresh callback fail
  closed. Offline tests pass (`94 passed`). Session and routes GUI failures are
  now exposed only as stable public categories (`discovery_failed`,
  `authentication_rejected`/`authentication_failed`, or
  `credential_store_failed`); keyring size/backend failures remain fail-closed
  without a file fallback.
- The Windows refresh-token store now uses the documented `mapit-refresh-v1`
  manifest plus up to eight UTF-8 chunks, with strict hash/schema validation,
  rollback on write failure, idempotent cleanup, and legacy migration only
  after successful verification. Native WinVault tests on this host confirmed
  save/load, replacement through the alternate staging bank, Unicode handling,
  and cleanup for synthetic tokens longer than 3,000 characters.
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
- The vehicle-detail GUI probe was completed successfully on 2026-09-23. It
  selected the first eligible vehicle in memory, URL-encoded one detail path
  segment, and retained only the value-free schema at
  `samples/anonymized/vehicle-detail.schema.json`. The dedicated response adds
  substantially richer subscription/Stripe and legacy-detail structure than
  `account-summary`; this is structural evidence only, not evidence of write
  capabilities.
- The bounded routes-list GUI probe is implemented but not executed live: it
  performs only `vehicleId` plus `limit=1`, follows no cursor, and persists only
  a value-free schema at `samples/anonymized/routes-list.schema.json`. Its
  final Geo HTTP status, when available, is reduced to an allowlisted category
  (`routes_list_http_400`, `_401`, `_403`, `_404`, `_429`, `_5xx`, or generic)
  without exposing URL, body, headers, or IDs. Transport and invalid-response
  failures are separately reduced to `routes_list_transport_failed` or
  `routes_list_invalid_response` (with `account_summary_` equivalents before
  vehicle selection).
- Session enrollment is now separated into `scripts/session_setup_gui.py`;
  it performs only discovery plus `USER_PASSWORD_AUTH` and persists the refresh
  token. `scripts/check_saved_session.py` validates discovery plus the saved
  refresh/Identity Pool exchange without Core/Geo. The routes GUI no longer
  asks for credentials; without a valid saved session it instructs the user to
  run the setup GUI and makes no data call.
- Refresh-token persistence is implemented as an optional Windows-only,
  fail-closed native keyring backend. The routes GUI attempts a saved refresh
  session first and exposes explicit forget; it does not enroll sessions;
  no vault or live-data call is used by CI.

## Active Constraints

- No MCP server or MCP tool design yet.
- No write operations against MAPIT except required Cognito authentication calls.
- No secrets or real identifiers in source, logs, docs, tests, fixtures, or commits.
- Evidence and documentation precede implementation.
- Live probes are manual and never part of the default test suite.

## Next Steps

1. Investigate route-list pagination and filters using evidence-led probes.
2. Investigate route detail.
3. Investigate the current account-level WebSocket.

## Open Questions

- Refresh behavior against the authorized account has not yet been exercised
  near token expiry, although the initial password flow required no challenge.
- Exact live token/subprotocol contract accepted by the WebSocket.
- Current endpoint inventory and route-history pagination/filter behavior.
- Whether other account states trigger Cognito challenges not seen in the
  successful initial login.
- Live confirmation that the real app client accepts saved-token resumption;
  the password and all short-lived session/AWS credentials remain memory-only.
