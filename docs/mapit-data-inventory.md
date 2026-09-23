# MAPIT Data Inventory

Status: an authorized read-only probe produced a schema-only anonymized sample
for `account-summary`. No values, counts, raw payload, headers, tokens, or
identifiers were retained. Examples below are placeholders, not real account
data.

| Field | Endpoint/source | Type | Anonymized example | Meaning | Nullable | Historical/current | Status |
|---|---|---:|---|---|---|---|---|
| `account` | `GET /v1/account-summary` | object | `{...}` | Account and preference/payment containers | non-null in schema sample | current | CONFIRMED_SCHEMA_ONLY |
| `vehicles` | `GET /v1/account-summary` | array | `[{...}]` | Vehicle/device/dealer/capability containers | non-null in schema sample | current | CONFIRMED_SCHEMA_ONLY |
| `id` / `deviceId` | current WebSocket bundle | string | `DEVICE_ID_1` | Device identity in a state message | unknown | current | FOUND_IN_FRONTEND |
| `status` | current WebSocket bundle | unknown | `STATE_REDACTED` | Device state | unknown | current | FOUND_IN_FRONTEND |
| `battery` | current WebSocket bundle | number | `73` | Suspected tracker battery value | unknown | current | FOUND_IN_FRONTEND |
| `lat` / `lng` | current WebSocket bundle | number | `LAT_REDACTED` / `LNG_REDACTED` | Device coordinates | unknown | current | FOUND_IN_FRONTEND |
| `hdop` | current WebSocket bundle | number | `1.2` | Suspected GPS dilution/accuracy metric | unknown | current | FOUND_IN_FRONTEND |
| `lastTs` / `lastCoordTs` | current WebSocket bundle | unknown | `TIMESTAMP_REDACTED` | State/coordinate timestamps | unknown | current | FOUND_IN_FRONTEND |

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

`flags` exposes access booleans for accident, fall, hibernation, and ignition-on
alerts. `notificationSettings` contains alert booleans, critical variants,
sound, an ID, and movement-alert schedules (`days`, `startTime`, `endTime`).
These confirm the presence of alert-setting state, not alert delivery or
mutation support.

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
