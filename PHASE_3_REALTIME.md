# Phase 3 — Realtime State & Event Layer

## Goal
Promote the Phase 0 WebSocket proof into a reusable realtime component.

## Known endpoint
`wss://dsw.prod.mapit.me/accounts/{accountId}`

Authentication uses the Cognito `IdToken` as WebSocket subprotocol.

## Scope
Build a reusable realtime service that can:
- connect safely;
- parse messages;
- normalize state;
- reconnect with controlled backoff;
- detect stale connections;
- expose latest known state;
- avoid sending messages;
- shut down cleanly.

## Architecture
```text
MAPIT WebSocket
      ↓
RealtimeClient
      ↓
RealtimeService
      ↓
MCP / Agent / notifications
```

## Rules
Do not open a fresh long-lived WebSocket inside every MCP tool call.

Only expose event semantics supported by observed payloads.

## Exit criteria
- stable reconnecting realtime service;
- normalized payload model;
- offline tests;
- safe shutdown;
- latest realtime state available to later layers.
