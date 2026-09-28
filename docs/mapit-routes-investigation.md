# MAPIT Routes Investigation

Status: public contract discovery plus a bounded local probe implementation.
The saved-session check reported `session_valid=true`; the latest separated
authorized run on 2026-09-28 completed the Core `account-summary` read and the
Geo routes request with `vehicleId` plus `limit=1`. It produced only the
schema-only fixture `samples/anonymized/routes-list.schema.json`; no route
values, counts, identifiers, coordinates, or raw payload were retained.
An earlier attempt had only the generic `routes_list_request_failed` category;
the latest run is the current evidence.

## Current Evidence

The current frontend exposes the following read paths and filters:

```text
GET https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}
GET https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}&limit={limit}&month={month}&day={day}&from={from}&to={to}&includeInProgress={bool}
GET https://geo.prod.mapit.me/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true
```

Older public clients use `GET /v1/routes/{routeId}` for detail. Treat it as a
legacy candidate until an authorized read confirms it still works.

The smallest semantic request has one required query parameter: `vehicleId`.
The ID must be selected in memory from the already-authorized
`account-summary.vehicles` array: choose the first non-empty string `id`,
preferably from an entry whose `device` is non-null, and skip the probe if no
candidate exists. Do not derive, guess, persist, or print the ID. URL-encode the
query value as a query parameter; do not interpolate an unescaped identifier
into a path or log the signed URL.

## Minimum authorized list probe

For the first bounded schema probe, use one read with the public frontend's
observed `limit` parameter:

```text
GET https://geo.prod.mapit.me/v1/routes?vehicleId={url-encoded-vehicle-id}&limit=1
```

`limit=1` is a safety bound, not a confirmed server default and not evidence
that the backend honors exactly one item. A later, separately authorized
unfiltered read (`vehicleId` only) is needed if the default page size matters.
The first probe must not add `month`, `day`, `from`, `to`, or
`includeInProgress`, and must not follow a cursor or call route detail. One
request is sufficient to establish the top-level response shape and any
pagination metadata without attempting route history discovery.

The latest schema-only fixture confirms a non-null object envelope with one
non-null `data` array. Each observed array item is a non-null route object;
the complete field inventory is recorded below. No pagination/cursor/count
metadata field appears in this response, so `lastEvaluatedKey` remains an
unconfirmed hypothesis rather than an observed contract. Absence in one
bounded response does not prove that all pages or accounts lack pagination.
Treat all values as discarded and do not assume that one bounded response
represents complete history.

Observed optional filters and their current evidence level:

| Query parameter | Evidence | First-probe policy |
|---|---|---|
| `limit` | Frontend query construction; accepted by latest authorized probe | Use only `limit=1` as a bounded probe; default/maximum unknown |
| `month`, `day` | Frontend query construction | Defer; calendar semantics and required combinations unknown |
| `from`, `to` | Frontend query construction | Defer; timezone, format, inclusivity, and pairing unknown |
| `includeInProgress` | Frontend query construction | Defer; boolean encoding and behavior unknown |

These observations establish parameter names only. They do not establish route
history completeness, units, ordering, pagination, date semantics, or the
meaning of any returned route field.

## Latest schema-only route-list result

The authorized `vehicleId` + `limit=1` read produced a root object with this
observed structure:

```text
{
  data: Route[]
}
```

The root `data` is a non-null array; each observed item is a non-null object
with these fields and types:

| Field | Type/nullability in fixture |
|---|---|
| `avgSpeed`, `distance`, `maxSpeed` | non-null number |
| `complete`, `startsAtLastKnown` | non-null boolean |
| `createdAt`, `endedAt`, `startTz`, `startedAt`, `updatedAt` | non-null string |
| `id` | non-null string |
| `legacyId` | non-null number |
| `odometerStart`, `odometerEnd`, `continues` | nullable `null` in this sample |
| `device`, `vehicle` | non-null object containing non-null string `id` |
| `geoJSON` | non-null object; `type` is a non-null string and `features` is a non-null array |

Each observed `geoJSON.features` item is a non-null object with non-null string
`type`, a `geometry` object, and a `properties` object. `geometry.type` is a
non-null string and `geometry.coordinates` is a non-null array whose item type
is recorded as `mixed`; `properties` contains non-null boolean `inferred` and
non-null string `label` and `name`. This is only a structural description:
there are no retained geometry values, coordinate dimensionality, route IDs,
timestamps, metric values, or counts, and no geometry semantics are inferred.

The fixture contains no top-level cursor, token, offset, count, or
`lastEvaluatedKey` field. The observed `continues` field is part of each route
item and is explicitly `null` in this schema sample; it is not treated as
pagination metadata. Pagination behavior, ordering, units, date semantics and
whether additional fields appear on another page remain open.

The probe's persisted artifact, if any, must be schema-only: field names, JSON
types, nullability, and nesting. It must contain no route/vehicle IDs, item
counts, timestamps, coordinates, addresses, GeoJSON coordinates, speed,
distance, duration, route names, raw response, headers, signed URL, token, or
temporary credentials. A non-JSON response or HTTP error should be recorded as
sanitized status/category metadata only, without body text.

## Geo transport contract and discrepancy hypotheses

The exact Geo contract supported by the public clients is:

```text
Host: geo.prod.mapit.me
Method/path: GET /v1/routes
Query: vehicleId=<value>
Body: none
```

Both public Home Assistant clients call the route list with **only**
`vehicleId`; neither adds `limit=1` in its route method. The current frontend
bundle exposes `limit`, `month`, `day`, `from`, `to`, and `includeInProgress` as
query construction options, but their acceptance and semantics are not
confirmed by a response. The local bounded probe adds `limit=1`, so removing
that optional parameter is the smallest contract-isolating retry after this
failure.

The public clients use the same API authentication family for Core and Geo:
temporary Identity Pool credentials, SigV4 service `execute-api` in
`eu-west-1`, `X-Amz-Security-Token`, and Cognito `X-Id-Token`. Their signed
header set is `accept;host;x-amz-date`; the transmitted headers additionally
include `Origin: https://app.mapit.me/`, `Referer: https://app.mapit.me/`,
`X-Amz-Security-Token`, and `X-Id-Token`. The local signer currently signs all
headers it constructs (including the security and ID tokens) and does not add
Origin/Referer. Core `account-summary` succeeded with the local contract, so
this is not proof that Geo accepts the same header/canonicalization combination.
No separate Geo token, AWS service, region, or credential exchange is
supported by public evidence.

The current request URL construction percent-encodes query keys/values and the
SigV4 canonical query is generated from that URL. Public clients instead pass a
parameter map to the HTTP library and sign the equivalent canonical query. A
vehicle ID containing reserved characters must therefore be compared only by
the resulting canonical query, never by logging the ID or URL.

Current hypotheses, ordered by the evidence available without another call:

| Hypothesis | Why it is plausible | Safe discriminator |
|---|---|---|
| `limit=1` is rejected or differs from the historical contract | Both public route clients omit `limit`, but the latest authorized run accepted `limit=1` and returned a schema | Keep default/maximum semantics open; no extra live call required for this question |
| Geo requires browser-origin headers or a different signed-header subset | Public clients transmit Origin/Referer and sign only `accept;host;x-amz-date`; local client omits Origin/Referer and signs more headers | Latest success shows the local shape works for this account/run; cross-account/variant behavior remains unconfirmed |
| Account/vehicle has no route permission or route service rejects the selected vehicle | `account-summary` success alone would not establish route entitlement, but the latest route schema proves this selected run was accepted | Do not generalize beyond this authorized account/vehicle |
| Geo returned non-JSON or a transport error | Current probe collapses JSON/transport/write failures into one category | Sanitized category `invalid_json`, `timeout`, `dns`, `tls`, or `http_4xx/5xx` |

The latest schema-only success removes the earlier `limit` failure hypothesis
for this run and demonstrates that the local Geo host/path/query/signing
contract can return JSON for the selected account/vehicle. It does not prove
default limits, route history completeness, cross-account behavior, or that
Origin/Referer are universally unnecessary.

## Minimal live diagnostic (completed; safe result policy)

The latest diagnostic used the already-valid saved session and one eligible
in-memory vehicle. It issued one bounded request with `vehicleId` and
`limit=1`, with the existing bounded 401/403 retry, then stopped. It did not
try another vehicle, add date filters, follow a cursor, call route detail, or
retry across header variants.

The only permitted result is sanitized metadata, for example:

```text
success=false, stage=geo_routes, category=http_4xx, status=403
```

The current client already performs at most one forced refresh/retry for a
401/403; report only the final status/category after that bounded behavior, not
the first response or any refresh details.

or a transport category such as `timeout`, `dns`, `tls`, or `invalid_json`.
For a local `MapitHTTPError`, read only its numeric `status`; never render
`str(exc)` or its stored URL because that would expose the query/vehicle ID.
Never emit the URL, query string, vehicle ID, response body, response headers,
signature, token, credential, exception text, or counts. If HTTP 200 is
returned, immediately convert the body to schema-only and retain only field
names, types, nullability, and nesting; do not print top-level values or item
counts. The successful schema-only result confirms the bounded probe contract
for this run. A future unfiltered (`vehicleId` only) request would be needed
only to study default page size; it must not retain counts or values.

## Questions to Answer with Authorized Reads

| Question | Evidence required | Status |
|---|---|---|
| Default number of routes | Count and response metadata from an unfiltered request | PENDING |
| Oldest/newest recoverable route | Repeated evidenced page/filter reads | PENDING |
| List envelope and pagination metadata | Root response keys in the bounded schema-only fixture | `CONFIRMED_SCHEMA_ONLY` for `{data: Route[]}`; pagination behavior remains PENDING |
| Date boundary semantics | Controlled `from`/`to`, `month`, and `day` reads | PENDING |
| Units for distance/speed/duration | Payload plus frontend formatting code | PENDING |
| In-progress routes | `includeInProgress` comparison when safely observable | PENDING |
| Detail GeoJSON shapes | Inventory of every feature geometry/properties type | `PARTIAL_SCHEMA_ONLY` for list-item GeoJSON nesting; detail shapes PENDING |
| Statistics source | `includeStats=true` response versus derivable route values | PENDING |

## Probe Discipline

- Use only documented/frontend-evidenced query parameters.
- Make read-only requests and keep retries bounded.
- For the first probe, retain only field names, types, nulls, and nesting; do
  not retain counts, values, identifiers, or boundary examples.
- Do not infer that one response contains complete history without proving the
  pagination and filter contract.

## Local bounded probe implementation

`scripts/routes_list_prompt_gui.py` reuses the secure local GUI pattern. It
authenticates, reads `account-summary` in memory, prefers the first vehicle
with a non-null `device` (falling back to the first valid non-empty string ID),
and makes exactly one `GET /v1/routes` with `vehicleId` and `limit=1`. It does
not follow cursors or request route detail. The response is converted
immediately with `schema_only` and atomically written only to
`samples/anonymized/routes-list.schema.json`; UI/error output is categorized
and value-free. The 2026-09-28 authorized run reached the Geo request with
`vehicleId` and `limit=1` and produced that schema-only fixture. An earlier
attempt returned only the sanitized category `routes_list_request_failed`; the
latest result is authoritative for the bounded schema contract. A
`MapitHTTPError` from the Geo request now exposes only one of
`routes_list_http_400`, `_401`, `_403`, `_404`, `_429`, `_5xx`, or the generic
`routes_list_http_error`; transport and invalid-JSON failures are exposed as
`routes_list_transport_failed` and `routes_list_invalid_response`. Before a
vehicle is selected, the equivalent categories use the `account_summary_`
prefix. Local-write and other unexpected failures retain the generic
`routes_list_request_failed` category; schema conversion and atomic persistence
have their own `routes_list_schema_failed` and `routes_list_persist_failed`
categories. No exception text, URL, body, headers, or vehicle ID is returned.

## Evidence references

- [d3vv3 `api.py`, route method at commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/api.py) — Geo host/path, `vehicleId`-only query, `data` extraction, and shared SigV4/header construction.
- [citylife4 `api.py`, route method at commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/custom_components/mapit_tracker/api.py) — same Geo route contract and shared Core/Geo transport.
- Local `src/mapit/client.py` and `src/mapit/signing.py` — allowlisted Geo host, query encoding, SigV4 service/region, bounded 401/403 recovery, and current header/signing differences described above.
