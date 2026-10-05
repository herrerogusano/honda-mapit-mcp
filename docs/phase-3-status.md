# Phase 3 status

Status: **COMPLETED** on 2026-09-28.

## Scope delivered

Phase 3 delivers a reusable, in-process `RealtimeClient` and thread-safe
`RealtimeService` for the observed account-level MAPIT WebSocket target. The
implementation validates the fixed `wss://dsw.prod.mapit.me/accounts/{segment}`
endpoint, checks saved-session token freshness before each handshake, uses the
Cognito ID token as the sole subprotocol, sends no application messages, and
keeps only immutable normalized state in a bounded in-memory cache.

It does not add an MCP realtime tool, persistence, notifications, database
storage, or inferred application event semantics/units.

## Evidence

The bounded live gate was run with the saved session and produced only this
allowlisted result:

```json
{"success":true,"started":true,"observed_valid_state":true,"stopped_cleanly":true}
```

The gate waits at most ten seconds for one valid normalized state and always
stops the service. It does not print or persist IDs, frames, coordinates,
timestamps, metrics, URLs, headers, tokens, or exception text. The result is
evidence for the authorized saved-session account and is not a universal MAPIT
realtime contract.

The reusable contract is recorded in
[`phase-3-realtime-contracts.md`](phase-3-realtime-contracts.md), and the gate
is [`scripts/smoke_realtime_phase3.py`](../scripts/smoke_realtime_phase3.py).

## Limitations retained

- MAPIT application event types, alert semantics, and metric units remain
  unconfirmed.
- The service is process-local and memory-only; no durable realtime history or
  cross-account subscription layer is included.
- A third-party token provider or connector that blocks cannot be forcefully
  interrupted; bounded shutdown reports `shutdown_timeout` until it returns.
- No realtime behavior is exposed through MCP in this phase.

## Verification

- Offline suite: `242 passed`.
- `compileall` passed for `src`, `tests`, and `scripts`.
- `git diff --check` passed.
