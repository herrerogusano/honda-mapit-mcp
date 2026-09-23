# Phase 0 Findings

Status: **IN PROGRESS** as of 2026-09-23. This document is a cumulative summary,
not a declaration that Phase 0 is complete.

## Authentication

Public evidence supports Cognito `USER_PASSWORD_AUTH`, `REFRESH_TOKEN_AUTH`,
Identity Pool `GetId`/`GetCredentialsForIdentity`, and temporary AWS credentials.
The local client implements this flow in memory and fails closed on unsupported
Cognito challenges. Live account validation remains pending.

## Runtime Configuration

The frontend HTML currently advertises hashed JavaScript bundles through module
preloads and dynamic imports. Public discovery now handles those forms and
extracts the region, three Cognito identifiers, and Core/Geo hosts while printing
the identifiers only as `<discovered>`.

## APIs and Endpoints

See `mapit-endpoints-discovered.md`. Core and Geo reads are SigV4-signed for
`execute-api` in `eu-west-1` and include the temporary security token and Cognito
ID token. The client accepts only HTTPS MAPIT Core/Geo hosts and only implements
GET.

## Vehicle Data

Pending an authorized `account-summary` and vehicle-detail read. The inventory
template is in `mapit-data-inventory.md`.

## Routes, Route Detail, and Historical Data

The frontend exposes vehicle route listing with `limit`, calendar/date range, and
in-progress filters, plus a vehicle-scoped detail route with optional statistics.
Actual schemas, limits, pagination, units, oldest recoverable data, and GeoJSON
feature types remain pending. See `mapit-routes-investigation.md`.

## Realtime

The current frontend uses `wss://dsw.prod.mapit.me/accounts/{accountId}`. Older
clients use `/devicestate/{deviceId}`. Compatibility and message schemas require
an authorized manual probe.

## Statistics, Geofences, Alerts, Maintenance, and Appointments

Not yet confirmed. No capability will be claimed until frontend or response
evidence is recorded.

## Other Discoveries

The frontend contains a reverse-geocoding read endpoint and an account-preference
write endpoint. The write endpoint is documented only as evidence and is out of
scope for Phase 0 execution.

## Unknowns

- Cognito challenges for the authorized account.
- Live acceptance of the observed signing/header contract.
- Full account, vehicle, route, route-detail, and realtime schemas.
- Route pagination, history depth, date semantics, and units.
- Read-only endpoints for zones, alerts/events, maintenance, and appointments.

## Potential MCP Capabilities

Preliminary only: current vehicle state/location, vehicle details, route history,
route detail, distance aggregation, period comparison, and realtime state. Tool
schemas and MCP implementation are deliberately deferred.
