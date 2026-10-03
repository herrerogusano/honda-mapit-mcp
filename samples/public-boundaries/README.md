# Public boundary source — no MAPIT route data

`menorca-ign-20261003.gml` is an unchanged 597,902-byte public IGN WFS extract
of the eight municipalities listed in `docs/geographic-query-research.md`.
SHA-256: `90689fddc0bdbdd98627532cbd083094485ef6f45fd0c7ba03d127edc4b65ad3`.
The WFS response timestamp is 2026-10-03T13:48:56Z. Its coordinates are
EPSG:4258 latitude/longitude, not RFC 7946 GeoJSON longitude/latitude.

Attribution: Instituto Geográfico Nacional (IGN) / Centro Nacional de Información
Geográfica (CNIG), Unidades administrativas de España, retrieved 2026-10-03;
CC BY 4.0 (Order FOM/2807/2015 terms).

Source: https://www.ign.es/wfs-inspire/unidades-administrativas
Licence/product: https://centrodedescargas.cnig.es/CentroDescargas/limites-municipales-provinciales-autonomicos

This is a reproducible public administrative boundary source, not a coastline
claim, a private location record, or an accepted production runtime asset.
Do not load it as GeoJSON or infer MAPIT coordinate semantics from it.

The independently checked derived asset is
`src/mapit/data/menorca-ign-20261003.geojson` (515,890 bytes), SHA-256
`1e75a0c988fe13c2917487bf6b9834bd6aa4f48af5117b6ed216901be09b33cd`.
It preserves all eight municipality features and polygon parts, converting
EPSG:4258 to EPSG:4326 and explicitly writing longitude/latitude GeoJSON.
PyProj 3.7.2 selected ETRS89 to WGS 84 (1), reported accuracy 1 metre, with
networking disabled. No simplification or topology repair was performed.
The same IGN/CNIG attribution and CC BY 4.0 terms apply to this derivative.
Prototype independent acceptance is not production deployment acceptance.

## Barcelona metropolitan municipalities

`amb-ign-20261003.gml` is the unchanged public IGN extract for all 36 AMB
municipalities: 838,790 bytes, source timestamp 2026-10-03T16:04:04Z, SHA-256
`5249ea12f55825213590ec9da298f12852535bfa036e00a0c3c76e637f86b5ca`.
Membership and the exact Idescat/IGN crosswalk are documented in
[`geographic-spain-research.md`](../../docs/geographic-spain-research.md).
The same attribution, CC BY 4.0 licence and EPSG:4258 axis rules above apply.

The derived `src/mapit/data/amb-ign-20261003.geojson` has 36 features,
38 rings and 32,299 listed positions, without simplification or repair:
676,078 bytes, SHA-256
`13a14638f0dbe45b4c34a2b5bdea9923da4bb2a174e79697d65ae157b7caed3a`.
It was converted to EPSG:4326 longitude/latitude with the same pinned offline
transform. A named municipality selects only its polygon; AMB selects the
complete official union, not a radius or a generic Barcelona bounding box.
Neither polygon selection establishes MAPIT GPS accuracy or history completeness.
