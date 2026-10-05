# Phase 1 status

Status: COMPLETE (2026-09-28).

## Implemented

- MCP Python SDK 2.2 server bootstrap over stdio.
- Six Phase 1 tools with structured input/output schemas.
- Thin MCP adapter and reusable `MapitServices` layer.
- Lazy use of the saved Windows Credential Manager session.
- Stable redacted error mapping.
- ISO date validation, 366-day maximum, UTC monthly splitting, route
  normalization, ID deduplication, and deterministic ordering.
- Bounded responses: 2 MiB per route-list window, 1 MiB route detail, and 500
  returned route summaries.
- Fail-closed behavior for pagination cursors and missing distance metrics.
- Explicit unconfirmed-unit and unverified-completeness metadata.
- MCP read-only/idempotent annotations.
- Offline service tests and real in-memory MCP contract tests.

## Validation state

- The complete offline suite was green on Windows at the Phase 1 closure
  snapshot (`191 passed`); later Phase 2 changes have expanded the current
  suite.
- Tests prohibit external network access; the loopback connection used by the
  Windows async event loop is the only socket exception.
- MCP contract tests cover the exact tool list, input/output schemas,
  structured results, nested comparison inputs, annotations, and redacted tool
  errors.
- The bounded, non-persisting live smoke completed successfully through the
  real in-memory MCP client and the saved session. All six tools returned
  success. Its only output contained per-tool booleans; no IDs, dates,
  coordinates, vehicle fields, route data, metrics, tokens, response bodies,
  signed URLs, or exception text were printed or persisted.
- A separate subprocess check started `python -m mapit.mcp_server` over stdio,
  negotiated the server identity `honda-mapit`, and listed exactly six tools.

## Accepted limitations

- First eligible vehicle only; no vehicle selector yet.
- Local stdio only because outputs contain private vehicle/account data.
- MAPIT metric units and route-history completeness remain unconfirmed.
- UTC service windows can differ from the frontend's local-calendar month
  grouping, while still covering the same requested instant interval.
- Upstream date-boundary inclusivity and the effect of `includeStats=true`
  remain unknown.

## Phase 1 gate result

`scripts/smoke_mcp_phase1.py` is the repeatable gate. It uses a 31-day route
window, two adjacent one-day comparison periods, and a route ID derived only in
memory. It cannot report overall success unless all six tools, including route
detail, complete successfully and the MCP client closes cleanly. The successful
2026-09-28 run closes the Phase 1 exit criteria. Accepted limitations above are
inputs to Phase 2 rather than hidden completeness claims.
