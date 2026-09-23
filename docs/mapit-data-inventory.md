# MAPIT Data Inventory

Status: schema discovery has started from public code; no account payload has
been captured yet. Examples below are placeholders, not real account data.

| Field | Endpoint/source | Type | Anonymized example | Meaning | Nullable | Historical/current | Status |
|---|---|---:|---|---|---|---|---|
| `account` | `GET /v1/account-summary` | object | `{...}` | Account summary container | unknown | current | FOUND_IN_CODE |
| `vehicles` | `GET /v1/account-summary` | array | `[{...}]` | Vehicles associated with the account | unknown | current | FOUND_IN_CODE |
| `id` / `deviceId` | current WebSocket bundle | string | `DEVICE_ID_1` | Device identity in a state message | unknown | current | FOUND_IN_FRONTEND |
| `status` | current WebSocket bundle | unknown | `STATE_REDACTED` | Device state | unknown | current | FOUND_IN_FRONTEND |
| `battery` | current WebSocket bundle | number | `73` | Suspected tracker battery value | unknown | current | FOUND_IN_FRONTEND |
| `lat` / `lng` | current WebSocket bundle | number | `LAT_REDACTED` / `LNG_REDACTED` | Device coordinates | unknown | current | FOUND_IN_FRONTEND |
| `hdop` | current WebSocket bundle | number | `1.2` | Suspected GPS dilution/accuracy metric | unknown | current | FOUND_IN_FRONTEND |
| `lastTs` / `lastCoordTs` | current WebSocket bundle | unknown | `TIMESTAMP_REDACTED` | State/coordinate timestamps | unknown | current | FOUND_IN_FRONTEND |

## Rules for live inventory

- Record every returned key, type, nullability, unit, and nesting level.
- Replace account, vehicle, device, route, VIN, registration, and coordinate
  values consistently before saving any sample.
- Mark a field `CONFIRMED` only after an authorized response establishes its
  presence and shape.
- Do not commit raw responses, headers, tokens, signed URLs, or identifiers.
