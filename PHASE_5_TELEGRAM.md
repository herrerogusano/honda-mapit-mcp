# Phase 5 — Telegram Interface

## Goal
Use Telegram as a mobile interface without duplicating agent or MAPIT logic.

## Architecture
```text
Telegram
   ↓
Telegram adapter/backend
   ↓
Agent
   ↓
MCP
   ↓
Services
   ↓
MapitClient
   ↓
MAPIT
```

Telegram is an interface, not the reasoning layer.

## Scope
- bot integration;
- authorized-user allowlist;
- incoming message handling;
- agent invocation;
- response formatting;
- timeout/error handling.

## Security
- fail closed for unauthorized users;
- never log MAPIT credentials/tokens;
- avoid exposing internal IDs.

## Exit criteria
The same natural-language queries supported by the agent work from Telegram without duplicated business logic.
