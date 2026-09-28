# Phase 0 Findings

Status: **IN PROGRESS** as of 2026-09-23. This document is a cumulative summary,
not a declaration that Phase 0 is complete.

## Authentication

Public evidence supports Cognito `USER_PASSWORD_AUTH`, `REFRESH_TOKEN_AUTH`,
Identity Pool `GetId`/`GetCredentialsForIdentity`, and temporary AWS credentials.
The local client implements this flow in memory and fails closed on unsupported
Cognito challenges. An authorized authentication run accepted
`USER_PASSWORD_AUTH` without an additional challenge; no tokens or credentials
were retained.

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

An authorized read-only `GET /v1/account-summary` completed successfully. The
probe retained only `samples/anonymized/account-summary.schema.json`: field
names, types, and observed nullability, with no values, counts, identifiers, or
raw payload. The response schema confirms account identity/preferences,
payment-method and Stripe structure, regional product catalog, vehicle
capabilities, dealer data, alert settings, and detailed device state. This
confirms response structures only; it does not infer purchase, transfer,
maintenance, alert-delivery, or other write capabilities. Odometer and VIN were
observed as nullable in the sample. See `mapit-data-inventory.md`.

An authorized read of `GET /v1/vehicles/{vehicleId}` also produced only
`samples/anonymized/vehicle-detail.schema.json`. Its top-level object contains
non-null fields for account/dealer/device references, vehicle identity and
registration, branch/model/product plan, usage (`km`), lifecycle timestamps,
legacy detail, two alert-named booleans, products, and a substantially nested
subscription object. The subscription includes account/vehicle references and
a Stripe-shaped object with scalar, nullable, array, and nested object fields;
the fixture records structure and nullability only, never values. The detail
overlaps the account-summary vehicle on identity/device/product/registration/
subscription fields but also has fields absent from that summary, while the
summary has capabilities/dealerData/flags/notificationSettings and lifecycle
fields absent from the detail sample. These differences are schema evidence
only and do not establish any capability or payment/alert operation. See
`mapit-data-inventory.md` for the field-level inventory.

## Routes, Route Detail, and Historical Data

The frontend exposes vehicle route listing with `limit`, calendar/date range, and
in-progress filters, plus the current vehicle-scoped detail route
`/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true`. The current
frontend validator expects a root object with `id`, FeatureCollection GeoJSON,
distance/timing fields, and optional nullable speed fields; it does not
enumerate separate statistics fields. The older `/v1/routes/{routeId}` path is
legacy evidence from the public Python clients and is not the first probe
target. The authorized detail probe then completed exactly one current detail
read with `includeStats=true` and retained only
`samples/anonymized/route-detail.schema.json`. Its root object contains the
route-list fields plus non-null `merged`, while GeoJSON feature properties add
`maxSpeed` and explicitly nullable `avgSpeed`/`distance`. The fixture confirms
structure and sample nullability only; it does not establish units, statistics
semantics, or cross-route stability.
The current dashboard fetches one calendar month at a time using paired
`from`/`to` ISO boundaries, navigates history by changing the month, and
filters selected days locally by `startedAt`. Its route parser permits an
optional `lastEvaluatedKey`, but no route-specific cursor/offset/page/next-token
flow is used. The bounded list fixture likewise contained no pagination
metadata, so server-side pagination and complete historical reach remain open.
An authorized bounded read using the saved session (`session_valid=true`) and
one in-memory vehicle completed with `GET /v1/routes?vehicleId=...&limit=1`.
Only `samples/anonymized/routes-list.schema.json` was retained. It confirms a
non-null root object with a non-null `data` array of route objects. Observed
route fields include string IDs/timestamps/timezone, a numeric legacy ID and
speed/distance metrics, boolean completion/last-known flags, nullable
`continues` and odometer fields, non-null `device.id`/`vehicle.id`, and nested
`geoJSON.features[].geometry`/`properties` structures. The fixture contains no
top-level pagination/count/cursor metadata; this does not establish defaults,
history completeness, units, or cross-account stability. See
`mapit-routes-investigation.md` and `mapit-data-inventory.md`.

## Realtime

The current frontend uses `wss://dsw.prod.mapit.me/accounts/{accountId}`. Older
clients use `/devicestate/{deviceId}`. Compatibility and message schemas require
an authorized manual probe.

## Statistics, Geofences, Alerts, Maintenance, and Appointments

Route-detail response structure was observed after requesting
`includeStats=true`, but the frontend does not enumerate separate statistics
fields and no metric semantics or computation behavior is confirmed. No
statistics capability beyond that structural observation is claimed. Geofences,
alerts, maintenance, and appointments remain unconfirmed.

## Other Discoveries

The frontend contains a reverse-geocoding read endpoint and an account-preference
write endpoint. The write endpoint is documented only as evidence and is out of
scope for Phase 0 execution.

## Unknowns

- Cognito challenges for the authorized account.
- Live acceptance of the observed signing/header contract.
- Full account, vehicle, and realtime schemas; the account, vehicle-detail,
  bounded route-list, and one route-detail probes establish only one-account
  schema-only samples.
- Whether all account-summary substructures and nullable fields are stable
  across accounts; the current account-summary evidence is schema-only for one
  authorized account.
- Semantics and read/write endpoints, if any, behind payment, catalog,
  capability, dealer, notification, and alert-setting structures.
- Route pagination, history depth, date/filter semantics, and units.
- Read-only endpoints for zones, alerts/events, maintenance, and appointments.

## Potential MCP Capabilities

Preliminary only: current vehicle state/location, vehicle details, route history,
route detail, distance aggregation, period comparison, and realtime state. Tool
schemas and MCP implementation are deliberately deferred.
