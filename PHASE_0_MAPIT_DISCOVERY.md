# Phase 0 — MAPIT Discovery & Client Foundation

## Status
COMPLETED.

## Goal
Understand MAPIT sufficiently to build later phases from evidence rather than assumptions.

## Completed outcomes
- Cognito User Pool authentication with email/password.
- `REFRESH_TOKEN_AUTH`.
- Cognito Identity Pool exchange.
- Temporary AWS credentials.
- AWS SigV4 signing.
- `X-Id-Token` support.
- Refresh token persistence in Windows Credential Manager.
- Automatic frontend/runtime configuration discovery.
- Reusable read-only Python MAPIT client.
- Core and Geo API clients.
- Safe manual probes.
- Schema-only anonymizer.
- WebSocket probe.
- 168 offline tests.
- CI green on Python 3.11, 3.12 and 3.13.
- Audited schema-only fixtures.

## Confirmed APIs

### Core
- `GET /v1/account-summary`
- `GET /v1/vehicles/{vehicleId}`

### Geo
- `GET /v1/routes`
- `GET /v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true`

### Realtime
- `wss://dsw.prod.mapit.me/accounts/{accountId}`

## Historical data status
Historical access is PARTIAL.

Confirmed:
- frontend queries monthly windows with `from` and `to`;
- monthly reads work;
- daily filtering is local in the frontend;
- no visible cursor/page/offset flow;
- global unfiltered retrieval exceeded the safe 2 MiB limit.

Unknown:
- total route count;
- oldest available route;
- whether a global read is complete;
- exact extra fields added by `includeStats=true`.

## Source of truth
See:
- `docs/phase-0-findings.md`
- `docs/phase-0-status.md`
