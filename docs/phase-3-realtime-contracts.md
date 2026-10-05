# Phase 3 realtime contracts

Status: completed after the bounded live gate on 2026-09-28.

## Evidence boundary

The current frontend and the authorized Phase 0 probe support only the
account-level endpoint:

```text
wss://dsw.prod.mapit.me/accounts/{encodedAccountId}
```

The Cognito `IdToken` is the sole WebSocket subprotocol. The client sends no
application message. Only text JSON objects with a non-empty `id` or
`deviceId` are eligible. Phase 3 normalizes the frontend-supported fields:
`status`, `battery`, `lat`, `lng`, `hdop`, and `lastTs` with fallback to
`lastCoordTs`. Numeric strings may become finite numbers; unsupported values
become null. No alert/event types or metric units are inferred.

The legacy `/devicestate/{deviceId}` endpoint remains outside the contract.

## Components

### `RealtimeClient`

- Encapsulates exactly one synchronous account-level WebSocket.
- Builds or validates the fixed `wss://dsw.prod.mapit.me/accounts/` target;
  caller-controlled hosts, ports, queries, fragments, and userinfo are rejected
  before the ID token is supplied to a connector.
- Checks token freshness immediately before each handshake and calls
  `refresh_if_needed()` without arguments, refreshing only when required;
  it never forces a refresh on every reconnect.
- Does not hold the state lock while the token provider, connector, or
  context manager runs. `close()` marks an in-flight handshake cancelled, so
  a connector that honors cancellation can be stopped without waiting for its
  handshake. A third-party token provider or connector that blocks inside its
  call cannot be forcefully interrupted; the service reports a bounded
  `shutdown_timeout` until that call returns, and never hides the still-running
  non-daemon worker.
- Provides connect/receive/close lifecycle only; it has no application `send`.
- Uses a 64 KiB frame bound, queue size 4, one-second receive polling, and
  explicit WebSocket control ping/pong settings. Control frames are transport
  health checks, not MAPIT application events.

### `RealtimeService`

- Owns one non-daemon worker thread and one `RealtimeClient`.
- `start()` and `stop()` are idempotent; context-manager exit stops and joins.
- `stop()` closes the active socket to unblock receive before a bounded join.
- Reconnect delay follows the observed exponential shape exactly: 1, 2, 4,
  8, 16, 30, then 30 seconds, plus injected jitter from 0 to 399 ms.
- A start is bounded to eight reconnects. Exhaustion fails closed instead of
  looping forever. `stop()` cancels backoff immediately and prevents reconnect.
- Token refresh/authentication failure is terminal for that start and does not
  retry a known unusable credential indefinitely.

## State and staleness

Normalized state is immutable and replaces the prior state for that ID. Frames
may be partial, so absent fields become null rather than retaining possibly
stale values. Raw frames are discarded immediately.

The cache:

- is thread-safe and memory-only;
- stores at most 64 IDs;
- never logs or persists IDs, coordinates, timestamps, tokens, URLs, frames, or
  exception text;
- exposes copies/snapshots, never its mutable internals.

Staleness is based only on local monotonic time since connection or the most
recent valid normalized frame. It therefore applies even before the first
valid frame and is not reset by invalid frames or receive timeouts. The default
threshold is 120 seconds, an operational decision rather than a MAPIT semantic
claim. `lastTs` is not used because its unit is unconfirmed.

Lifecycle states are `stopped`, `starting`, `connected`, `backoff`,
`stopping`, and `failed`. Public failures are stable categories only.

## Later-layer boundary

Phase 3 does not add an MCP tool. Later phases may read a process-owned
singleton cache, but must never open a long-lived socket inside a tool call and
must not expose start/stop as model-controlled operations. No database,
notifications, agent, Telegram, remote deployment, or Home Assistant behavior
is authorized here.

## Verification

Offline tests must cover normalization, URL allowlisting before token handoff,
refresh before every handshake, replacement semantics, cache/stale behavior,
bounded reconnect/backoff, dependency/auth failures, callback isolation if
callbacks are provided, concurrent stop during receive, idempotent lifecycle,
and clean shutdown without leaked threads. A bounded live gate may retain only
booleans/categories and must not persist frames or state values.
