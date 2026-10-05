# Spain and Barcelona-area boundary research

Status: public-source feasibility and a bounded public AMB WFS extract.
No authenticated MAPIT calls, route geometry, AWS calls, code changes, or
runtime-boundary asset were created for this note. Geographic classification
remains a separate acceptance gate.

## Recommendation

Start with the named **Àrea Metropolitana de Barcelona (AMB), 36 municipalities**,
not all Spain and not a guessed radius/bbox. The AMB is an official, discrete
administrative coverage set with a maintained municipality list and codes. Its
union can answer a narrowly worded “fully inside the AMB” query while keeping
crossing/outside/unknown distinct. It does not mean “Barcelona surroundings” in
every colloquial sense; users should see the exact AMB label.

Nationwide boundaries are technically possible as a later static-data build,
but not the lowest-risk increment in the current window. CNIG's current
whole-Spain GML archive is 63.18 MB compressed and includes distinct reference
systems for the Canary Islands versus the mainland/Balearics. There is no
measured filtered asset size, total vertex count, Lambda memory use, or cold
start cost for a national polygon set. AWS Lambda permits 250 MB total unzipped
deployment package (including layers); the 63.18 MB compressed source archive
is not an acceptable proxy for the size of a processed runtime asset. A
national build would need per-feature CRS/axis checks, municipality identity
crosswalk, resource measurements, and geometry regression tests before it
could be called feasible for this service.

## Exact AMB target

Idescat identifies the metro area as `AM01` and currently lists 36 municipality
codes. Preserve these official identifiers as the membership allowlist; do
not match fuzzy names or treat the codes as IGN `nationalCode` values without
an authoritative crosswalk.

| Idescat code | IGN WFS `nationalCode` | Municipality |
|---|---|---|
| `080155` | `34090808015` | Badalona |
| `089045` | `34090808904` | Badia del Vallès |
| `082520` | `34090808252` | Barberà del Vallès |
| `080193` | `34090808019` | Barcelona |
| `080207` | `34090808020` | Begues |
| `080543` | `34090808054` | Castellbisbal |
| `080569` | `34090808056` | Castelldefels |
| `082665` | `34090808266` | Cerdanyola del Vallès |
| `080689` | `34090808068` | Cervelló |
| `080728` | `34090808072` | Corbera de Llobregat |
| `080734` | `34090808073` | Cornellà de Llobregat |
| `080771` | `34090808077` | Esplugues de Llobregat |
| `080898` | `34090808089` | Gavà |
| `081017` | `34090808101` | l'Hospitalet de Llobregat |
| `081234` | `34090808123` | Molins de Rei |
| `081252` | `34090808125` | Montcada i Reixac |
| `081265` | `34090808126` | Montgat |
| `081574` | `34090808157` | Pallejà |
| `081580` | `34090808158` | el Papiol |
| `081691` | `34090808169` | el Prat de Llobregat |
| `081803` | `34090808180` | Ripollet |
| `081944` | `34090808194` | Sant Adrià de Besòs |
| `081960` | `34090808196` | Sant Andreu de la Barca |
| `082009` | `34090808200` | Sant Boi de Llobregat |
| `082042` | `34090808204` | Sant Climent de Llobregat |
| `082055` | `34090808205` | Sant Cugat del Vallès |
| `082114` | `34090808211` | Sant Feliu de Llobregat |
| `082172` | `34090808217` | Sant Joan Despí |
| `082212` | `34090808221` | Sant Just Desvern |
| `082444` | `34090808244` | Santa Coloma de Cervelló |
| `082457` | `34090808245` | Santa Coloma de Gramenet |
| `082634` | `34090808263` | Sant Vicenç dels Horts |
| `082824` | `34090808282` | Tiana |
| `082896` | `34090808289` | Torrelles de Llobregat |
| `083015` | `34090808301` | Viladecans |
| `089058` | `34090808905` | la Palma de Cervelló |

Source: [Idescat, territorial and entity codes—metropolitan areas](https://www.idescat.cat/codis/?id=50&n=76&var=1), which identifies `AM01` and enumerates these 36 municipality codes. The IGN `nationalCode` values were then verified in the exact-filter WFS response below; do not generalize the Catalonia prefix to other autonomous communities. Verify that the list is still current at asset-generation time.

## Boundary source and bounded extraction plan

Preferred polygon source: the official IGN/CNIG INSPIRE administrative-units
WFS, feature type `au:AdministrativeUnit`, with EPSG:4258 GML and CC BY 4.0
terms in its service capabilities. The previous bounded Menorca extraction
used the same service, explicit `nationalCode` filters, and produced eight
municipal units in 597,902 bytes (24,750 listed ring vertices / 24,639 unique
edges). This is a useful small-set baseline, not an estimate for AMB.

An exact public WFS query using one FES `Or` of the 36 `nationalCode` values
returned `numberMatched=36`, `numberReturned=36`, and 36 unique IDs, exactly
matching the allowlist. A prior query using the Balearic prefix returned zero;
the query was corrected after a direct exact Barcelona-name/code lookup
verified the Catalonia-specific values. That failed query is why the extraction
must compare the complete returned ID set and fail closed on zero/partial
matches. The successful response timestamp was `2026-10-03T16:04:04Z`, body
size 838,790 bytes, with 38 `posList` rings and 32,299 listed coordinate
vertices (before any geometry/topology validation). The raw public GML is
outside the repository at
`C:\Users\herre\AppData\Local\Temp\honda-amb-ign-wfs-20261003.gml`; its
SHA-256 is `5249EA12F55825213590EC9DA298F12852535BFA036E00A0C3C76E637F86B5CA`.

For reproducible future retrieval, use the exact `nationalCode` column above
in one FES `Or` filter, `typeNames=au:AdministrativeUnit`, WFS 2.0.0, a
bounded count of 40, an 8 MiB body cap and short timeout. Require exactly 36
unique codes and expected names, CRS, 2D coordinate structure, closed rings,
preserved holes and valid individual polygons/union before producing a derived
asset. The current measured body size is below 1 MiB; it is evidence for this
one timestamp, not a permanent service-size guarantee. Record timestamp, exact
code set, raw/derived hashes and byte sizes with the generated asset. No runtime
geocoding, WFS lookup, or arbitrary-region selector is needed.

Official references:

- [IGN administrative-units WFS](https://www.ign.es/wfs-inspire/unidades-administrativas?)
- [WFS GetCapabilities](https://www.ign.es/wfs-inspire/unidades-administrativas?service=WFS&request=GetCapabilities)
- [INSPIRE Administrative Units schema](https://www.ign.es/wfs-inspire/appschemas/AdministrativeUnits.xsd)
- [CNIG current boundaries product](https://centrodedescargas.cnig.es/CentroDescargas/limites-municipales-provinciales-autonomicos)
- [CNIG current GML archive record](https://centrodedescargas.cnig.es/CentroDescargas/detalleArchivo?sec=12408588)

The CNIG whole-Spain archive currently identifies `LINEAS_LIMITE_GML.ZIP`,
date 2026-08-10, 1:25,000, 63.18 MB, GML, download unit “Toda España.” It
documents ETRS89 for mainland, Balearics, Ceuta and Melilla, REGCAN95 for
Canarias, and states geographic coordinates as longitude/latitude. The reuse
terms are compatible with CC BY 4.0 and require attribution. Suggested derived
asset attribution: “Obra derivada de BDLJE CC-BY 4.0 ign.es.” The service GML
and CNIG bulk archive must not be assumed to serialize axes identically just
because both describe Spanish administrative geography; validate each file's
own CRS/axis metadata.

If the WFS extract is unsuitable, CNIG's national archive is an official
**offline reference**: download once, verify TLS and archive length, compute
SHA-256, inspect ZIP paths and expansion totals before extracting, and inspect
the actual GML geometry types before treating anything as a polygon. “Líneas
límite” may provide linework rather than the area features needed for whole-
route coverage; do not assume it can be polygonized without a validated
topology step. Do not bundle the full source archive in the Lambda package.
Preserve raw and derived hashes plus source date/license; do not silently fall
back to a bbox.
The successful AMB raw GML extract is 838,790 bytes. The derived union/GeoJSON
size and topology validity remain unmeasured. A prior reviewed public Menorca
GeoJSON is 515,890 bytes, which only shows that a small multi-municipality
union can be compact.

## National feasibility and runtime implications

The national source is not “free to process” merely because it is public. It
contains 63.18 MB compressed at 1:25k; complete decompressed GML, polygonized
or converted national GeoJSON, and spatial-index memory have not been measured.
The national set also spans ETRS89 and REGCAN95, so an asset builder must use
feature-level CRS-aware transforms with network grids disabled and fail closed
on missing/ballpark transformations. Lambda's 250 MB unzipped limit applies
to code, dependencies, data and layers together; [AWS Lambda quotas](https://docs.aws.amazon.com/lambda/latest/dg/gettingstarted-limits.html)
confirm that limit. Therefore whole-Spain coverage is not rejected as
impossible, but is not yet justified for the existing constrained runtime.
First benchmark the filtered static asset, parser/union peak memory, prepared
geometry load time and classification latency on the actual ARM image. Do not
assume in-memory spatial indexing is negligible from the Menorca microbenchmark.

The resulting route-query semantics should remain conservative:

- Use the dissolved exact administrative polygon set, not a bbox or centroid.
- Count a route only if its entire valid supported LineString is covered; keep
  crossing, outside, inferred-source-segment, malformed and missing geometry
  categories separate. Never prorate a crossing route's distance.
- For an AMB query, say “entire route contained in AMB,” not “Barcelona” unless
  separately using Barcelona municipality code `080193`.
- Keep route distances as existing route-level values; do not reconstruct
  roads, infer GPS accuracy, persist geometry, fetch one detail per route, or
  imply complete history/pagination.
- Resolve edge policy explicitly (a line on the municipality boundary), and
  keep the existing native-distance/unit caveat and `inferred` true/false/
  unknown metadata.

## Safest increment in this window

1. Validate the already saved exact 36-unit GML and generate a public GeoJSON
   review artifact outside runtime code, preserving
   polygon parts/holes and recording source timestamp, licence, raw/derived
   SHA-256, byte sizes, exact municipality codes, CRS transform and validation
   counts. Do not commit the 63 MB source archive.
2. Measure AMB extraction/union and target ARM memory/latency. Then add one
   fixed named-area query behind an explicit unknown result for invalid or
   implausible geometry. Keep all-Spain support as a later measured decision.

The crosswalk and raw extract are now established, but polygon topology/CRS
validation and the derived asset are not. If those cannot be independently
reviewed within this window, stop at the public GML snapshot; do not substitute
the historic Menorca boundary or silently return zero.
