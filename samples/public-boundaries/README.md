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
