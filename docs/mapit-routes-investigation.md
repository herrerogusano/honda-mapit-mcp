# MAPIT Routes Investigation

Status: public contract discovery plus a bounded local probe implementation.
The probe has not been run against MAPIT; no route values, counts, identifiers,
coordinates, or raw payloads are retained.

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

The existing evidence indicates a collection named `data` in the route-list
response, but does not establish whether the complete envelope is an object,
which metadata keys are present, or whether pagination uses a cursor, token,
offset, or no pagination. `lastEvaluatedKey` is an open hypothesis from the
broader API inventory, not a confirmed route response field. Treat the response
as an unknown JSON object: inventory object/array/scalar/null types and nesting,
including `data` if present, while ignoring all values. Do not assume that one
bounded response represents complete history.

Observed optional filters and their current evidence level:

| Query parameter | Evidence | First-probe policy |
|---|---|---|
| `limit` | Frontend query construction | Use only `limit=1` as a bounded probe; default/maximum unknown |
| `month`, `day` | Frontend query construction | Defer; calendar semantics and required combinations unknown |
| `from`, `to` | Frontend query construction | Defer; timezone, format, inclusivity, and pairing unknown |
| `includeInProgress` | Frontend query construction | Defer; boolean encoding and behavior unknown |

These observations establish parameter names only. They do not establish route
history completeness, units, ordering, pagination, date semantics, or the
meaning of any returned route field.

The probe's persisted artifact, if any, must be schema-only: field names, JSON
types, nullability, and nesting. It must contain no route/vehicle IDs, item
counts, timestamps, coordinates, addresses, GeoJSON coordinates, speed,
distance, duration, route names, raw response, headers, signed URL, token, or
temporary credentials. A non-JSON response or HTTP error should be recorded as
sanitized status/category metadata only, without body text.

## Questions to Answer with Authorized Reads

| Question | Evidence required | Status |
|---|---|---|
| Default number of routes | Count and response metadata from an unfiltered request | PENDING |
| Oldest/newest recoverable route | Repeated evidenced page/filter reads | PENDING |
| Pagination contract | Response keys and frontend use of cursor/token/offset | PENDING |
| Date boundary semantics | Controlled `from`/`to`, `month`, and `day` reads | PENDING |
| Units for distance/speed/duration | Payload plus frontend formatting code | PENDING |
| In-progress routes | `includeInProgress` comparison when safely observable | PENDING |
| Detail GeoJSON shapes | Inventory of every feature geometry/properties type | PENDING |
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
and value-free. No live request or schema fixture has been made for this
probe yet.
