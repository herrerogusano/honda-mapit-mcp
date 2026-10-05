# Geographic route summaries — bounded first increment

User approval: 2026-10-03, two-hour work window starting about 13:42 UTC
(15:42 Europe/Madrid). Keep display/system awake temporarily, restore ordinary
behaviour before handoff. This increment is geographic queries, not Telegram,
multiuser, street coverage, automatic collection or persistent geometry.

## Reused evidence and patterns

The canonical AI Engineering index, MCP/OAuth guide, agent operation and
delegation guides were consulted. Reuse injected services, explicit bounds,
independent review, model-free checks, categorical diagnostics and the existing
owner/MFA. The older guide's temporary synthetic deployment limits do not
replace this project's subsequently approved permanent production contract.

The existing schema-only MAPIT list evidence includes embedded FeatureCollection
geometry. `MapitServices._normalize_route` discards it after deriving inference
flags. A geographic path can inspect it in memory without route-detail fan-out
or any geometry persistence. Availability in old samples does not guarantee
availability or semantics for every route. No new probe has been consumed yet.

## Required first result

- Named area with a frozen public Polygon/MultiPolygon, source, version and
  attribution; never silently substitute a bounding box for an island/city.
- General explicit interval and a summer convenience path, so the user need not
  know their travel dates. Summer means June 1 inclusive through September 1
  exclusive, local Europe/Madrid calendar convention, with explicit year.
- Inspect source LineStrings, not labels or start/end points alone. Classify
  observed geometry as inside, outside, crossing or unknown; boundary contact
  and unsupported/malformed data must have explicit conservative treatment.
- Sum the whole MAPIT native route distances only for admitted inside geometry;
  present additive kilometre companions with the existing conversion basis.
  Do not infer native distance within the polygon from clipped GPS length.
- Return all category counts and inference/missing-data limitations. No claim of
  complete history, physically exact route, streets visited or missing-distance
  reconstruction. No route identifiers or private coordinates in the summary.
- Validate input before upstream reads; retain existing response/period/auth
  bounds. Add aggregate geometry and segment/edge work limits, duplicate conflict
  checks, and explicit start-in-interval admission on the new path. Legacy ten
  tools must not change their output or network behaviour.
- No automatic per-route detail calls, geocoder requests with private positions,
  new database, IAM expansion, quota increase or paid model call.

GeoJSON WGS84/longitude-latitude semantics follow
[RFC 7946](https://www.rfc-editor.org/rfc/rfc7946), but MAPIT's universal adherence
remains an evidence limitation, not established by the standard alone.
The Madrid summer helper can explicitly bind the contemporary CEST convention
for the supported years; it must not pretend to implement arbitrary historical
time zones. Current EU clock-change rules are documented by the
[European Commission](https://transport.ec.europa.eu/transport-themes/summertime_en)
and the [2027–2031 calendar](https://www.boe.es/buscar/doc.php?id=DOUE-Z-2026-70018).

## Sequencing and acceptance

Researcher selects public boundary provenance. Implementer builds the pure
classifier and bounded service path with synthetic tests. Tester independently
reviews topology, work limits, missing/inferred data and network-call boundaries.
Supervisor accepts before MCP registration, packaging and any production update.
Keep source/client credentials and private operator journals outside Git/vault.
Do not reuse the consumed prior production smoke allowance. Any real geography
check needs its own documented finite interval/read budget before execution.
Deploying a changed runtime must preserve owner/MFA, exact bindings, independent
stop controls, quota 10 and the existing USD 1/month target, not a hard cap.
