# MAPIT Routes Investigation

## Current Evidence

The current frontend exposes the following read paths and filters:

```text
GET /v1/routes?vehicleId={vehicleId}
GET /v1/routes?vehicleId={vehicleId}&limit={limit}&month={month}&day={day}&from={from}&to={to}&includeInProgress={bool}
GET /v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true
```

Older public clients use `GET /v1/routes/{routeId}` for detail. Treat it as a
legacy candidate until an authorized read confirms it still works.

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
- Record counts, field names, types, nulls, and boundary behavior; anonymize
  identifiers and coordinates before persistence.
- Do not infer that one response contains complete history without proving the
  pagination and filter contract.
