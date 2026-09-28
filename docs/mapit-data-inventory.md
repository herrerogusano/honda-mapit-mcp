# MAPIT Data Inventory

Status: authorized read-only probes produced schema-only anonymized samples for
`account-summary`, vehicle detail, route listing, and route detail. No values,
counts, raw payloads, headers, tokens, or identifiers were retained. Examples
below are placeholders, not real account data.

| Field | Endpoint/source | Type | Anonymized example | Meaning | Nullable | Historical/current | Status |
|---|---|---:|---|---|---|---|---|
| `account` | `GET /v1/account-summary` | object | `{...}` | Account and preference/payment containers | non-null in schema sample | current | CONFIRMED_SCHEMA_ONLY |
| `vehicles` | `GET /v1/account-summary` | array | `[{...}]` | Vehicle/device/dealer/capability containers | non-null in schema sample | current | CONFIRMED_SCHEMA_ONLY |
| `id` / `deviceId` | current WebSocket bundle | string | `DEVICE_ID_1` | Device identity in a state message | required after normalization | current | FRONTEND_CONTRACT_ONLY |
| `status` | current WebSocket bundle | string or null | `STATE_REDACTED` | State label as consumed by frontend | nullable/absent | current | FRONTEND_CONTRACT_ONLY |
| `battery` | current WebSocket bundle | finite number or null | `<redacted>` | Numeric state field; semantics not confirmed | nullable/absent | current | FRONTEND_CONTRACT_ONLY |
| `lat` / `lng` | current WebSocket bundle | finite number or null | `<redacted>` | Coordinates; highly sensitive | nullable/absent | current | FRONTEND_CONTRACT_ONLY |
| `hdop` | current WebSocket bundle | finite number or null | `<redacted>` | Numeric state field; units not confirmed | nullable/absent | current | FRONTEND_CONTRACT_ONLY |
| `lastTs` | current WebSocket bundle | finite number or null | `<redacted>` | `lastTs`, falling back to `lastCoordTs` | nullable/absent | current | FRONTEND_CONTRACT_ONLY |

## Authorized schema-only result

The file `samples/anonymized/account-summary.schema.json` records field names,
container types, and observed nullability only. It does not record a vehicle
count or any field value. The following structures are therefore
`CONFIRMED_SCHEMA_ONLY` for this authorized account-summary response; they do
not by themselves prove that every account returns the same shape.

### Account

Observed non-null fields include `id`, `email`, `firstName`, `lastName`,
`phone`, `dob`, `document` (`number`, `type`), and `address` (street, number,
locality, region, country, postal code). Also present are `ownedVehicles` (ID
references), `pendingOnboardingMilestones`, `preferences` (`locale`,
`timezone`, `theme`, `marketingConsent`), `review` (`shown`, with `happy` and
`score` observed as null), and `subscriptionBalanceDays`.

Payment-related structure exists but is not evidence of a payment operation:
`paymentMethods` contains an ID, default flag, type, and `info` with card
brand, expiry month/year, funding, and last four digits. The account also
contains `stripeId`, `stripePublishableKey`, and `stripeTenant`. These fields
must never be persisted in a probe sample, even when only their structure is
being inventoried.

### Product catalog

`productCatalog` contains `MapitDevice` and `Subscription`, each with regional
`prices` for `ES`, `PT`, and `US`; each regional entry has `amount` and
`currency`. This confirms catalog-price structure only. No price or currency
value was retained and no purchase/write capability is inferred.

### Vehicle-level structures

Observed vehicle fields include identity and registration (`id`, `name`,
`model`, `registrationNumber`, `vin`, `registrationId`, `legacyId`,
`legacyDealerId`, `firebaseKey`), lifecycle (`pending`, `cancelled`,
`registrationCompletedAt`, `saleDate`, `transferable`), usage (`km`),
`branch`, `product`, `products`, and `subscription` (`id`, `autoRenew`,
`cancelled`, `retryingRenewal`).

Capability flags are present for `deviceTransfer` (dealer/other/private
transfer and `supported`), `finance`, `hondaPlus`, and `maintenance`. These
are capability metadata only; no corresponding action endpoint was called or
confirmed.

`dealerData` includes dealer name, IDs, shop address, contact point, email,
telephone, and opening hours. S3 logo/header keys were observed as null in the
schema sample. Dealer and branch fields are location/business-sensitive and
must be redacted before persistence.

This is embedded dealer metadata only. Neither this structure nor the vehicle
detail's `dealer` object contains a confirmed maintenance history, workshop
visit, appointment, booking slot, or service-order envelope. No such payload
has been observed in the frontend or public reference clients, so no separate
maintenance/appointment inventory is claimed.

`flags` exposes access booleans for accident, fall, hibernation, and ignition-on
alerts. `notificationSettings` contains alert booleans, critical variants,
sound, an ID, and movement-alert schedules (`days`, `startTime`, `endTime`).
The schema specifically includes `geofenceAlertCritical` alongside accident,
fall, ignition and movement settings. These confirm the presence of
alert-setting/entitlement state, not saved geofences, event history, alert
delivery or mutation support. No current frontend bundle or public reference
client consumes a dedicated alert/geofence endpoint.

### Device state

`device` includes `id`, `imei`, `model`, and `deadSim`. Its `state` includes
`battery`, battery-connection status/timestamp, communications-check request
fields, creation/update metadata, `detectedCan`, device/state IDs, `hdop`,
`lastBuzzTs`, `lastCoordTs`, `lastTs`, `lat`, `lng`, `location`, `prevStatus`,
`speed`, `status`, `version`, and `voltage`.

The schema sample observed `data`, communications-check request IDs/timestamps,
`odometer`, and `vin` as null. This records nullability in that sample only;
it does not establish that odometer or VIN are always null. Coordinates,
location encodings, timestamps, IDs, IMEI, VIN, and creator/updater fields are
high-sensitivity data and must be removed or replaced before persistence.

## Statistics and driving-data classification

| Field/group | Evidence | Classification |
|---|---|---|
| `speed` in `account-summary.vehicle.device.state` | Authorized schema-only fixture; public Python clients consume it | Confirmed embedded state shape; current frontend validator does not retain it |
| `battery`, `voltage`, `hdop`, `lat`, `lng`, `status`, `version`, timestamps | Authorized schema-only fixture; current frontend uses a subset | Confirmed embedded state fields; values and units are sensitive/unknown |
| `odometer` | Authorized schema-only fixture, explicit null in sample; public clients expose field | Nullable in this sample only; no universal availability or unit guarantee |
| route `distance`, `avgSpeed`, `maxSpeed`, timestamps | Route-list/detail schema-only fixtures and current UI | Confirmed route metrics; semantics/units and aggregation rules remain open |
| `geoJSON` feature `maxSpeed`, `avgSpeed`, `distance` | Route-detail schema-only fixture; some properties explicitly null | Confirmed property names/types/nullability for one response only |
| `includeStats=true` | Current frontend route-detail request and authorized read | Query accepted; no separate stats envelope or dedicated stats endpoint observed |
| hard braking, acceleration, overspeed events, elevation, tire/oil, firmware telemetry | No match in current bundles or public reference clients | UNCONFIRMED; no endpoint or payload evidence |

The current frontend derives/display-consumes route duration from timestamps and
shows distance, average speed, and maximum speed from the selected route. It
uses `hdop` to render a location-accuracy area. The public reference clients'
speed normalization while `AT_REST` is client behavior, not proof of a server
rule. No separate statistics, driving-event, or extended-telemetry read should
be proposed without a new exact GET contract.

## `account-summary` contract (frontend evidence)

The current public frontend calls exactly:

```text
GET https://core.prod.mapit.me/v1/account-summary
```

It sends no account ID, email query parameter, or request body. The account is
resolved from the authenticated request. The request is SigV4-signed and also
carries the Cognito ID token and temporary AWS security token. The frontend
validates the response with a Zod schema and then filters `vehicles` to entries
whose `id` is a string and whose `device` is non-null. This is response-shape
evidence from the public bundle, not a live account capture.

Expected top-level shape (known fields only):

```text
{
  account: {
    id: string,
    firstName?: string | null,
    lastName?: string | null,
    email: string,
    preferences?: {
      locale?: string | null,
      timezone?: string | null,
      theme?: string | null
    } | null
  },
  vehicles: Vehicle[]
}
```

Known vehicle/device fields in the frontend schema:

| Object | Fields observed | Sensitivity / handling |
|---|---|---|
| `vehicle` | `id`, `pending`, `name`, `model`, `registrationNumber`, `km`, `cancelled`, `subscription`, `device` | IDs, name, registration and model must be redacted; `km` is usage data and should be bucketed or replaced in persisted samples |
| `subscription` | `id`, `autoRenew`, `cancelled`, `retryingRenewal`, `remainingTrialDays` | Subscription ID and trial/billing state are sensitive; replace ID and either redact values or retain only explicitly approved booleans |
| `device` | `id`, `imei`, `state` | Device ID and IMEI must be replaced with placeholders |
| `state` | `battery`, `status`, `lat`, `lng`, `hdop`, `lastTs` | Coordinates and timestamps must be removed/redacted; battery/status/HDOP may be retained only as non-identifying synthetic values |

The schema supplies defaults for some optional subscription booleans
(`autoRenew`, `cancelled`, `retryingRenewal`) and for `pending`/vehicle
`cancelled`; a probe must distinguish fields actually present on the wire from
frontend defaults if that distinction matters. Unknown server fields may exist;
the first probe must not persist them merely because the frontend currently
strips them during validation.

## Current account-level WebSocket inventory (public frontend)

The current frontend constructs
`wss://dsw.prod.mapit.me/accounts/{encodeURIComponent(account.id)}` after a
successful in-memory `account-summary`. It passes the current Cognito ID token
as the only WebSocket subprotocol when present and sends no application frame
on open. This is a frontend contract observation only; no authorized WebSocket
probe or live message was retained.

For a valid text JSON object, the frontend keeps only the normalized fields in
the table above. It accepts `id` or fallback `deviceId`, prefers `lastTs` over
`lastCoordTs`, converts finite numeric strings to numbers, preserves null, and
ignores malformed JSON or objects without an identifier. The raw event may have
more fields. IDs, coordinates, timestamps, and all raw frames are sensitive and
must never be persisted by a probe.

Lifecycle evidence is bounded to the bundle: reconnect after `close` uses
exponential backoff capped at 30 seconds plus 0--399 ms jitter, with no
application heartbeat or explicit `error` handler. The legacy Python clients'
`/devicestate/{deviceId}` path is tracked separately as unverified historical
compatibility. See [mapit-websocket-investigation.md](mapit-websocket-investigation.md)
for the evidence and the 10-second/3-frame schema-only probe design.

## Route-list inventory (authorized schema-only)

The saved-session, bounded Geo read `GET /v1/routes?vehicleId={vehicleId}&limit=1`
completed successfully on 2026-09-28. The retained fixture,
`samples/anonymized/routes-list.schema.json`, contains schema information only:
field names, JSON types, nullability, and nesting. It contains no route values,
counts, identifiers, coordinates, timestamps, headers, or raw response.

The observed response envelope is a non-null object with one non-null `data`
array. Each observed `data` item is a non-null route object with this shape:

| Group | Fields/types observed | Nullability/status |
|---|---|---|
| Identity references | `id`: string; `legacyId`: number; `device.id`: string; `vehicle.id`: string | non-null; `CONFIRMED_SCHEMA_ONLY` |
| Timing/state | `createdAt`, `endedAt`, `startTz`, `startedAt`, `updatedAt`: string; `complete`, `startsAtLastKnown`: boolean | non-null in sample |
| Metrics | `avgSpeed`, `distance`, `maxSpeed`: number | non-null in sample; values/units unknown |
| Optional state | `continues`, `odometerStart`, `odometerEnd`: explicit `null` | nullable in this sample only |
| GeoJSON container | `geoJSON.type`: string; `geoJSON.features`: array | non-null in sample |

Each observed `geoJSON.features` item is a non-null object. It contains
non-null string `type`, a non-null `geometry` object, and a non-null
`properties` object. `geometry.type` is a string and
`geometry.coordinates` is an array whose item type is recorded as `mixed`.
`properties` contains non-null boolean `inferred` and non-null strings `label`
and `name`. This records nesting and types only; it does not establish
GeoJSON geometry semantics, coordinate dimensionality, route naming, or
address meaning.

No top-level cursor, token, offset, count, or `lastEvaluatedKey` field was
observed in this bounded fixture. The route-item field `continues` is not
treated as pagination metadata. This is not evidence that pagination is absent
from other responses, nor that the one-item response represents complete route
history, a default page size, or stable cross-account shape.

Route IDs, legacy/device/vehicle IDs, timestamps, coordinates and location
labels, speed/distance/odometer values, and the raw response are sensitive.
Any future probe must retain schema-only information and discard those values
before persistence.

## Route-detail inventory (authorized schema-only)

The current public frontend constructs route detail as:

```text
GET https://geo.prod.mapit.me/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true
```

This is a `GET` with no body and the same authenticated Core/Geo transport
family used by route listing. The frontend parser expects a root object with:

| Field | Observed frontend shape | Status |
|---|---|---|
| `id` | required string | `FOUND_IN_FRONTEND` |
| `geoJSON` | required FeatureCollection; features are Point or LineString; numeric coordinate arrays have at least two numbers | `FOUND_IN_FRONTEND` |
| `distance` | optional number, defaulted by frontend to `0` | `FOUND_IN_FRONTEND` |
| `startedAt`, `endedAt` | optional strings, frontend-defaulted to empty strings | `FOUND_IN_FRONTEND` |
| `avgSpeed`, `maxSpeed` | optional nullable numbers | `FOUND_IN_FRONTEND` |

The saved-session probe completed the current vehicle-scoped read with
`includeStats=true` after selecting one route ID in memory from the confirmed
`{data: [...]}` list response. The retained fixture,
`samples/anonymized/route-detail.schema.json`, contains schema information
only: field names, JSON types, nullability, and nesting. It contains no route
values, counts, identifiers, coordinates, timestamps, headers, or raw body.

The observed non-null root object has these top-level fields:

| Group | Fields/types observed | Nullability/status |
|---|---|---|
| Metrics | `avgSpeed`, `distance`, `maxSpeed`: number | non-null in sample |
| State | `complete`, `merged`, `startsAtLastKnown`: boolean | non-null in sample |
| Timing | `createdAt`, `endedAt`, `startTz`, `startedAt`, `updatedAt`: string | non-null in sample |
| Identity | `id`: string; `device.id`: string; `vehicle.id`: string | non-null in sample; sensitive |
| Optional state | `continues`, `odometerStart`, `odometerEnd` | explicit `null` in this sample |
| GeoJSON | `geoJSON.type`: string; `geoJSON.features`: array | non-null in sample |

Each observed feature is a non-null object with non-null string `type`,
`geometry`, and `properties`. Geometry has non-null string `type` and a
non-null `coordinates` array whose item type is recorded as `mixed` (array or
number). Properties contain non-null `inferred` (boolean), `label` (string),
`name` (string), and `maxSpeed` (number), with `avgSpeed` and `distance`
explicitly null in this sample. These are observed field types only; no metric
units, GeoJSON semantics, statistics behavior, or universal nullability is
inferred.

Compared with the route-list fixture, detail adds top-level `merged` and
feature-property `avgSpeed`, `distance`, and `maxSpeed`; the broad route,
device/vehicle reference, timing, nullable state, and GeoJSON structure
overlap. The successful read confirms that `includeStats=true` was accepted
for this one authorized route, not what the flag computes or whether it changes
the response for other routes/accounts.

The older public clients also expose `GET /v1/routes/{routeId}` without a
query string and consume a route-shaped object with `geoJSON` and timing fields.
This is legacy evidence only. Route/vehicle IDs, GeoJSON coordinates, timing,
distance/speed values, stats, response body, and signed request material must
be discarded before any persistence.

## Vehicle detail inventory (authorized schema-only)

The public Python clients also issue the following Core read after obtaining a
vehicle from `account-summary`:

```text
GET https://core.prod.mapit.me/v1/vehicles/{vehicleId}
```

| Object | Endpoint/source | Fields/shape observed | Status | Handling |
|---|---|---|---|---|
| `vehicle_detail` | authorized read; schema in `samples/anonymized/vehicle-detail.schema.json` | Non-null JSON object; top-level fields listed below | `CONFIRMED_SCHEMA_ONLY` | Keep only field names, types, nullability and nesting |
| `model` / `vin` | detail schema and d3vv3 consumer | Non-null strings in this schema-only sample | `CONFIRMED_SCHEMA_ONLY` | Always redact values; no semantics inferred |
| `products` | detail schema | Non-null array whose items are non-null strings | `CONFIRMED_SCHEMA_ONLY` | Retain type only |

The authorized schema-only fixture records these non-null top-level fields:
`account` (object), `branch` (string), `canAccessAccidentAlert` (boolean),
`canAccessFallAlert` (boolean), `createdAt` (string), `crmMotoId` (string),
`dealer` (object), `demoBike` (boolean), `device` (object), `firebaseKey`
(string), `id` (string), `km` (number), `legacy` (object), `model` (string),
`productPlanName` (string), `products` (array of strings), `registration`
(object), `registrationNumber` (string), `saleDate` (string), `subscription`
(object), `updatedAt` (string), and `vin` (string).

Nested shape recorded by the fixture:

- `account.id`, `dealer.id`, and `device.id` are non-null strings.
- `registration.id` and `registration.subtype` are non-null strings.
- `legacy.id` is a non-null number; `legacy.detail` contains non-null numeric
  fields `AnyRiskInsurance`, `DemoBike`, `Financing`, `HondaConnect`,
  `HondaPlus`, `HondaPlusGo`, and `Insurance`, plus non-null string fields
  `Model`, `Plate`, `SaleDate`, and `Vin`.
- `subscription` contains non-null `account.id`, `vehicle.id`,
  `vehicle.registrationNumber`, lifecycle/status strings and booleans, and a
  nested `stripeObject`. The latter includes scalar, nullable-null, array, and
  object fields including `automatic_tax`, `billing_mode`,
  `cancellation_details`, `invoice_settings`, `items`, `managed_payments`,
  `metadata`, `payment_settings`, `plan`, and `trial_settings`. The complete
  field/type/nullability enumeration is the JSON fixture; no values are stored.

Compared with the `account-summary` vehicle schema, the observed overlap is
`id`, `branch`, `device`, `firebaseKey`, `km`, `model`, `products`,
`registrationNumber`, `saleDate`, `subscription`, and `vin`. Detail-only
top-level fields include `account`, `dealer`, `createdAt`, `updatedAt`,
`crmMotoId`, `demoBike`, `productPlanName`, `registration`, `legacy`, and the
two `canAccess...Alert` booleans. Summary-only fields include `capabilities`,
`dealerData`, `flags`, `notificationSettings`, `pending`, `cancelled`, `name`,
`product`, `registrationId`, `registrationCompletedAt`, `transferable`,
`dealerId`, `legacyId`, and `legacyDealerId`. The two `subscription` shapes
also differ: summary exposes a small state object, while detail contains
account/vehicle references and the deeper Stripe-shaped object above.

The current public frontend does not call this Core detail path; its current
`/v1/vehicles/` match is the Geo route-detail path. The fixture therefore
confirms structure for one authorized read only, not a universal contract,
semantics, capabilities, units, or stable cross-account nullability.

For the first authorized probe, one read of the first usable
`account-summary.vehicles[*].id` is sufficient for schema discovery. Choose a
non-empty string ID (prefer an entry whose `device` is non-null, matching the
frontend's usable-vehicle filter); do not derive or guess an ID. URL-encode the
path segment, perform no query/body mutation, and stop after that one GET. If no
candidate exists, return a structured no-candidate result instead of calling the
endpoint. Persist only anonymized field names, types, nullability and nesting.
Treat all identities, VIN/IMEI/registration, model/name, dealer/contact/address,
coordinates/timestamps/device state, subscription/payment fields and signed
request material as sensitive.

## Probe requirements (read-only)

The Implementer should add a narrow `account-summary` read after authentication
with these constraints:

1. Issue one `GET` only to the fixed Core host/path above; do not call vehicle,
   route, preference, or websocket endpoints.
2. Use the existing SigV4 client/session and its bounded 401/403 refresh retry.
3. Accept a JSON object with `account` and `vehicles`; validate known types but
   remain forward-compatible with unknown fields.
4. Emit or persist only an anonymized projection. Never save raw JSON, headers,
   signed URLs, tokens, credentials, email, names, registration, IMEI, IDs,
   coordinates, or precise timestamps.
5. Use per-sample placeholders such as `ACCOUNT_1`, `VEHICLE_1`, `DEVICE_1`,
   `SUBSCRIPTION_1` and `<redacted>` values; do not hash PII unless a separate
   key-management policy is approved.

Synthetic fixture shape for offline tests (all identifiers and values are
invented):

```json
{
  "account": {
    "id": "ACCOUNT_1",
    "firstName": "<redacted>",
    "lastName": "<redacted>",
    "email": "<redacted>",
    "preferences": {"locale": "en", "timezone": "<redacted>", "theme": "dark"}
  },
  "vehicles": [{
    "id": "VEHICLE_1",
    "pending": false,
    "name": "<redacted>",
    "model": "<redacted>",
    "registrationNumber": "<redacted>",
    "km": 1234.5,
    "cancelled": false,
    "subscription": {
      "id": "SUBSCRIPTION_1",
      "autoRenew": true,
      "cancelled": false,
      "retryingRenewal": false,
      "remainingTrialDays": 7
    },
    "device": {
      "id": "DEVICE_1",
      "imei": "<redacted>",
      "state": {"battery": 77, "status": "AT_REST", "lat": null, "lng": null, "hdop": null, "lastTs": null}
    }
  }]
}
```

## Rules for live inventory

- Record every returned key, type, nullability, unit, and nesting level.
- Replace account, vehicle, device, route, VIN, registration, and coordinate
  values consistently before saving any sample.
- Also replace account email/name, IMEI, subscription identifiers and precise
  state timestamps; treat subscription state and odometer as sensitive until a
  retention policy is approved.
- Mark a field `CONFIRMED` only after an authorized response establishes its
  presence and shape.
- Do not commit raw responses, headers, tokens, signed URLs, or identifiers.
