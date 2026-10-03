# Geographic query research (public boundary only)

Status: source discovery and offline design note; no MAPIT geometry was read,
retained, or transmitted for this research. This does not approve adding
geographic route queries or a geometry dependency.

## Bounded Menorca boundary source

The selected operational boundary is the union of the eight Menorca
municipality polygons, not an asserted coastline/island polygon. The official
IGN WFS `Unidades administrativas de España` declares the feature type
`au:AdministrativeUnit`, INSPIRE national administrative hierarchy, and
`CC BY 4.0 ign.es` access constraints in GetCapabilities:

- WFS endpoint: <https://www.ign.es/wfs-inspire/unidades-administrativas?>
- Capabilities: <https://www.ign.es/wfs-inspire/unidades-administrativas?service=WFS&request=GetCapabilities>
- Feature schema: <https://www.ign.es/wfs-inspire/appschemas/AdministrativeUnits.xsd>
- CNIG product/licence/provenance: <https://centrodedescargas.cnig.es/CentroDescargas/limites-municipales-provinciales-autonomicos>
- CNIG GML file record: <https://centrodedescargas.cnig.es/CentroDescargas/detalleArchivo?sec=12408588>

The bounded WFS GetFeature request used `version=2.0.0`,
`typeNames=au:AdministrativeUnit`, `count=20`, and an FES 2.0 `Or` of eight
`PropertyIsEqualTo` filters on `nationalCode` (listed below). It returned
exactly eight administrative units, with source response timestamp
`2026-10-03T13:48:56Z` and HTTP body size 597,902 bytes. The WFS GML declares
EPSG:4258. The response envelope's first ordinate is in the latitude range
39.799–40.095 and second in longitude range 3.791–4.328, consistent with the
CRS axis order; no full coordinates are reproduced here.

| Municipality | WFS nationalCode | GML rings | 2D vertices |
|---|---:|---:|---:|
| Alaior | `34040707002` | 1 | 3,108 |
| Ciutadella de Menorca | `34040707015` | 11 | 4,974 |
| Es Castell | `34040707064` | 1 | 728 |
| Es Mercadal | `34040707037` | 38 | 5,666 |
| Es Migjorn Gran | `34040707902` | 2 | 1,408 |
| Ferreries | `34040707023` | 3 | 1,111 |
| Maó | `34040707032` | 45 | 5,902 |
| Sant Lluís | `34040707052` | 10 | 1,853 |
| **Total** | **8 features** | **111** | **24,750** |

The public response was saved unchanged for reproducibility at
`C:\Users\herre\AppData\Local\Temp\honda-menorca-ign-wfs-20261003.gml`
(597,902 bytes). It is a temporary source extract, not a repository asset and
contains public administrative boundaries only. The exact filter semantics
are reproducible with this FES body, URL-encoded as the WFS `filter` query
parameter:

```xml
<fes:Filter xmlns:fes="http://www.opengis.net/fes/2.0">
  <fes:Or>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707002</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707015</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707064</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707037</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707902</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707023</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707032</fes:Literal></fes:PropertyIsEqualTo>
    <fes:PropertyIsEqualTo><fes:ValueReference>nationalCode</fes:ValueReference><fes:Literal>34040707052</fes:Literal></fes:PropertyIsEqualTo>
  </fes:Or>
</fes:Filter>
```

CNIG lists the current national GML as 63.18 MB, at 1:25,000, and describes
Balearic data as ETRS89 compatible with WGS84; its reuse terms are compatible
with CC-BY 4.0 and require attribution to the source/property. Suggested
attribution to retain with any derived boundary asset: “Instituto Geográfico
Nacional (IGN) / Centro Nacional de Información Geográfica (CNIG), Unidades
administrativas de España, retrieved 2026-10-03; CC BY 4.0 (Order
FOM/2807/2015 terms).” Recheck the source licence/version when republishing.

The offline conversion prototype is
[inspect_ign_menorca_boundary.py](../scripts/inspect_ign_menorca_boundary.py).
It uses a hardened XML parser, exact source/code/count/CRS checks, PyProj 3.7.2
and Shapely 2.1.2 in the isolated local audit environment. It converted
EPSG:4258 to EPSG:4326 with authority axis order (`always_xy=False`, no
ballpark operation, best operation required); pyproj selected `ETRS89 to WGS
84 (1)` with reported 1.0 m accuracy. It then emitted RFC 7946
longitude/latitude positions. See [PROJ's axis-order guidance](https://proj.org/en/stable/faq.html),
[pyproj Transformer docs](https://pyproj4.github.io/pyproj/stable/api/transformer.html),
and the [EPSG:1149 operation record](https://epsg.org/transformation_1149/ETRS89-to-WGS-84-1.html).
This is suitable for a boundary at the documented accuracy, not survey-grade
positioning.

Converted public GeoJSON was saved outside the repository at
`C:\Users\herre\AppData\Local\Temp\honda-menorca-ign-review-20261003.geojson`
(515,890 bytes). The union is a valid `MultiPolygon` comprising 111 polygon
parts/rings. The 24,750 listed vertices include one closing coordinate per
ring; therefore the number of unique ring edges is 24,639, not 49,500.
Measured locally: parse+transform 220.128 ms, union 96.607 ms, preparation
0.080 ms, and 1,000 repeated prepared `covers` checks 6.519 ms. The benchmark
tests the same synthetic point derived from the public boundary and is only a
local geometry-engine sanity check—not a route-classification benchmark,
Lambda SLO, or deployment acceptance.

## Safe ingestion and classification contract

- Treat the WFS source as EPSG:4258 GML, not GeoJSON. Parse GML ring structure
  (exterior and interior rings, multipolygons) with a hardened XML parser:
  DTD/entity expansion disabled, bounded response bytes, element/depth and
  coordinate-count ceilings, exact expected feature count and codes, CRS and
  valid polygon checks. Fail closed if any check disagrees. Preserve holes;
  do not flatten polygon parts or infer a boundary from a bbox.
- Interpret GML positions using the declared EPSG:4258 axis order, transform
  through a CRS-aware library to WGS84, then explicitly emit GeoJSON positions
  as `[longitude, latitude]` per [RFC 7946](https://www.rfc-editor.org/rfc/rfc7946).
  The CNIG bulk-file page separately documents geographic coordinates as
  longitude/latitude. Do not “fix” axis order by range heuristics alone.
- This establishes only the boundary dataset's CRS/axis handling. It does not
  establish that MAPIT's `geoJSON` obeys RFC 7946 or that its ordinates have
  the expected axis/dimension. MAPIT's source geometry ordering/semantics must
  remain an explicit validation gate; otherwise geographic status is unknown.
- Current [services.py](../src/mapit/services.py) normalizes the list-row
  GeoJSON to the source inference indicator and drops the geometry; calling
  route detail per item would add N+1 upstream reads. A future opt-in analyzer
  can process only embedded list geometry in memory, within response/route/
  coordinate caps, without persistence or geocoding.
- Classify whole routes only: a valid, usable `LineString` fully covered by
  the selected municipal union may contribute its existing route-level
  `distance_km` and one route count. A crossing route is reported separately
  and never prorated; a missing/malformed/unsupported geometry is unknown, not
  outside the boundary. Define whether boundary-touching counts as covered.
  Keep native distance and unverified units; the km value remains only the
  accepted UI-correlated conversion. Preserve source `inferred` as
  true/false/unknown metadata, not GPS accuracy. Do not infer street paths,
  route completeness, or total history coverage.
- The polygon has 24,750 listed vertices / 24,639 unique ring edges, beyond the current
  small-geometry guard. A naive every-route-edge-by-every-boundary-edge scan
  can scale as `route_edges × 24,639` per route; it is not acceptable as an
  unbounded request-time loop. Prefer exact topology with a prepared polygon /
  spatially indexed geometry engine (for example Shapely's prepared `covers`
  predicate, which indexes polygon segments), plus route/vertex/deadline caps.
  See [Shapely prepare](https://shapely.readthedocs.io/en/stable/reference/shapely.prepare.html)
  and [Shapely covers](https://shapely.readthedocs.io/en/stable/reference/shapely.covers.html).
  This is a candidate, not a benchmark or dependency decision. Do not simplify
  the official boundary unless a later acceptance defines a conservative
  error corridor and tests no false-inside classifications; near-boundary
  routes should otherwise remain unknown.
- Counts/distances describe only returned, classifiable routes in the
  requested window. Existing limits, truncation and unverified pagination /
  history completeness must remain visible in the result.

## MAPIT GeoJSON axis-order evidence and limits

The current public frontend entry page (`https://app.mapit.me/`) referenced
the following public modules on 2026-10-03. They were fetched directly without
authentication, and only their hashes/selected code structure were inspected:

| Public module | Bytes | SHA-256 | Relevant evidence |
|---|---:|---|---|
| [`main-Dug8aeN1.js`](https://app.mapit.me/assets/main-Dug8aeN1.js) | 1,080,699 | `AD383023DF93873130894E23B94F451FF45BEA464D4552FC8E872ECB39AAB0FF` | Current route validators include FeatureCollection/coordinate structure; the selected route source uses detail `geoJSON` with list-row `geoJSON` fallback. |
| [`index-D-ZY9Bmv.js`](https://app.mapit.me/assets/index-D-ZY9Bmv.js) | 137,436 | `9E6B48945DAA065217DFE06F005B82B98A586900D51C3A88AFAF6ECCFA642322` | Passes selected `geoJSON` as `selectedRouteGeoJson` to the map view; this assignment has no visible coordinate-axis swap. The same bundle uses Mapbox GL GeoJSON sources (`type: "geojson"`, `data: ...`) for map layers. |

This is useful UI evidence that route geometry is expected to be map-ready
GeoJSON: there is no visible normalization at the route data-selection/prop
seam. Static evidence inspected here does not independently prove that the
final renderer's route layer is the same source path, nor validate coordinate
values or establish a server-wide axis contract.

Mapbox's [GeoJSONSource API](https://docs.mapbox.com/mapbox-gl-js/api/sources/)
accepts a GeoJSON object as `data`; its [geography API](https://docs.mapbox.com/mapbox-gl-js/api/geography/)
states GeoJSON position pairs use longitude, latitude order. RFC 7946 likewise
requires longitude then latitude. These sources describe the consumer-side
convention, not MAPIT's server guarantees. The frontend schema accepts numeric
coordinate arrays of at least two numbers and does not validate axis order.

There is one prior per-sample plausibility signal: the already documented,
bounded Barcelona LineString probe interpreted positions longitude-first,
kept them inside the predeclared Barcelona bounds, and the local OSRM check
returned all tracepoints associated with high confidence. No coordinates or
IDs were retained. This supports the lon/lat interpretation for that sample
only; it is not ground truth, a universal backend guarantee, or proof of
physical route accuracy. See [route reconstruction research](phase-6-route-reconstruction-research.md)
and [the bounded Barcelona probe](phase-6-barcelona-local-probe.md).

Operational rule remains: classify route geography as unknown unless its
positions are structurally valid and plausible under longitude/latitude for
that route; retain an explicit unknown category when they are not. Do not
infer global compliance from RFC 7946, Mapbox use, or one matched sample, and
do not swap axes solely by numeric range.
