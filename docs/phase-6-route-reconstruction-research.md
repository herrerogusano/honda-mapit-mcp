# Phase 6: investigación de reconstrucción de rutas y cobertura urbana

Estado: **investigación acotada; tres probes live redacted completados, sin
pagos ni writes MAPIT** (2026-09-29).

Este documento responde primero a qué datos entrega MAPIT y si esos datos son
suficientes para map matching. OSRM, Valhalla, GraphHopper y Amazon Location
se comparan solo como opciones posteriores; no se selecciona una arquitectura
ni se abre un gate de persistencia.

## Conclusión ejecutiva

MAPIT sí expone una ruta de detalle GeoJSON y la interfaz pública valida
`Point`/`LineString` con coordenadas numéricas. Eso hace técnicamente plausible
un intento posterior de map matching. El probe redacted autorizado confirmó
una entrada candidata (features `Point` y `LineString`, dimensión 3, forma
anidada y pair-like, rango WGS84 válido y densidad `many`), pero no retuvo
coordenadas ni valores. No se puede afirmar que se puedan reconstruir calles
exactas, giros o la última ruta, ni calcular cobertura de una ciudad.

La principal carencia ya no es demostrar que existe una geometría candidata,
sino su semántica: el orden de cada secuencia, el significado de la tercera
ordenada y qué representan los gaps. El tercer run confirmó densidad
`LineString=many` y `Point=few`, nombres `few` en ambas clases, labels
`none`/`few`, transiciones de nombre y cobertura `inferred` parcial/all;
también confirmó gaps `medium` internos y `long` entre features/Points. Estas
señales siguen sin demostrar segmentación vial o nombres canónicos. No hay
timestamps, precisión, heading ni velocidad por punto.

## 1. Inventario MAPIT confirmado

La fuente primaria local es la auditoría del bundle público vigente y los
fixtures schema-only autorizados:
[`mapit-routes-investigation.md`](mapit-routes-investigation.md),
[`mapit-data-inventory.md`](mapit-data-inventory.md),
[`routes-list.schema.json`](../samples/anonymized/routes-list.schema.json) y
[`route-detail.schema.json`](../samples/anonymized/route-detail.schema.json).

| Fuente | Confirmado | No confirmado / límite |
|---|---|---|
| `GET https://geo.prod.mapit.me/v1/routes?vehicleId=...` | Respuesta observada como objeto `{data: [...]}`. Cada ruta observada tiene `id`, referencias `device`/`vehicle`, timestamps de ruta, métricas numéricas, flags, y `geoJSON` con `type` y `features`. | No hay valores retenidos; no se conoce orden del servidor, tamaño por defecto, completitud, paginación universal ni unidades. La lectura global autorizada superó 2 MiB y quedó en `PARTIAL`. |
| `GET .../v1/routes?...&limit=&month=&day=&from=&to=&includeInProgress=` | El builder del frontend serializa esas claves; el dashboard usa ventanas mensuales `from`/`to`. Dos ventanas acotadas con `limit=1` fueron aceptadas. | Semántica, inclusividad, timezone, combinaciones y máximo de cada filtro son desconocidos. `lastEvaluatedKey` no apareció en esas respuestas, pero no se puede generalizar. |
| `GET https://geo.prod.mapit.me/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true` | El bundle valida un objeto raíz con `id`, `geoJSON`, `distance`, tiempos y velocidades opcionales/nullables. La lectura autorizada produjo el mismo tipo de objeto, además de `complete`, `merged`, referencias y estado nullable. | `includeStats` fue aceptado, pero su cálculo y efecto no están demostrados. Solo se conservó el esquema de una ruta. |
| `geoJSON` de lista/detalle | La interfaz valida `FeatureCollection`; el resultado redacted confirmó features `Point` y `LineString`, forma `nested` y `pair-like`, dimensión `3`, densidad `many` y rango WGS84 válido. Propiedades observadas: `inferred`, `label`, `name` y, en detalle, `avgSpeed`, `distance`, `maxSpeed`. | No se retuvieron coordenadas ni valores; no se conoce el orden semántico, muestreo, continuidad ni el significado de la tercera ordenada. `name`/`label` no son evidencia de nombres OSM ni de un identificador vial estable. No hay `way_id`, segmento, rumbo, precisión ni giro. |
| Tiempos y métricas | `startedAt`, `endedAt`, `createdAt`, `updatedAt`, `startTz`, `distance`, `avgSpeed`, `maxSpeed` aparecen a nivel de ruta; algunas propiedades de feature son nullable en el fixture de detalle. El resultado redacted clasifica el gap interno de `LineString` como `medium`, los gaps entre features y de `Point` como `long`, y la fuente agregada como `multiple`. | No hay timestamps por punto, heading, precisión GPS, velocidad por punto ni unidades confirmadas. Las bandas de gap no prueban segmentación vial ni continuidad semántica. `hdop` de estado del dispositivo no equivale a precisión de cada punto histórico. |
| `GET https://core.prod.mapit.me/v1/reverse-geocoding/{lat}/{lng}?lang=...` | Path de lectura encontrado en el bundle vigente. | No se probó y no es un sustituto de map matching: produciría etiquetas/direcciones para coordenadas individuales, no secuencia vial ni cobertura completa. |

La ruta de detalle histórica `/v1/routes/{routeId}` de los clientes públicos
queda como compatibilidad legacy, no como contrato actual para esta
investigación. El selector existente de `limit=1` tampoco demuestra que el
elemento sea el más reciente: el orden del backend no está confirmado.

## 2. Suficiencia de entrada para map matching

| Entrada que necesitaría un matcher | Evidencia MAPIT actual | Evaluación |
|---|---|---|
| Secuencia de posiciones `(lon, lat)` | El analizador redacted confirmó coordenadas presentes, rango WGS84 válido y dimensión `3`; los valores se descartaron. | **Candidata**. Hay entrada horizontal plausible, pero no se puede clasificar la tercera ordenada ni afirmar el orden de ejes solo con esta salida. |
| Orden de la secuencia | Hay features `LineString`, pero no se retuvo ninguna secuencia ni relación temporal. | **Parcial**. Se debe verificar que el orden de coordenadas representa el trayecto y que no se trata solo de una geometría de visualización. |
| Geometría y densidad | El resultado redacted confirmó `Point` y `LineString`, formas `nested`/`pair-like` y densidad `many` (sin conteos). | **Candidata**. La mezcla de features requiere conservar fronteras de feature al analizar gaps y no asumir que todos los Points son muestras del mismo stream. |
| Tercera ordenada | Se observó dimensión `3` y el rango WGS84 horizontal fue válido. | **Opaca**. No se puede llamarla altitud, timestamp, precisión ni otra unidad sin valores/contrato MAPIT. |
| Tiempo por posición | Solo hay tiempos a nivel de ruta. | **Ausente en evidencia**. OSRM puede trabajar sin ellos, pero no se pueden detectar gaps ni velocidad temporal con rigor. |
| Precisión/radio GPS | No aparece en el esquema de ruta. `hdop` pertenece al estado actual del dispositivo. | **Ausente**. El matcher tendrá que usar un radio conservador/configurable y reportar menor confianza. |
| Heading y velocidad instantánea | Solo hay métricas agregadas y propiedades agregadas/nullable. | **Ausente**. Ambigüedad en paralelas, cruces y sentidos no puede resolverse siempre. |
| Nombres/labels | `properties.name` y `properties.label` son strings no vacíos en la muestra. | **Disponible como texto**, no como identidad vial; semántica y fuente desconocidas. |
| Gaps, discontinuidades y segmentos | El tercer run confirmó `medium` interno, `long` entre features y `long` en Point-stream, con fuente `multiple`, bajo la semántica vigente. No hay tiempos por punto ni campo de segmento; `continues` es estado de ruta nullable, no paginación. | **Desconocido en MAPIT**. Las bandas y la fuente agregada no demuestran segmentación vial ni que los Points sean auxiliares. |
| Última ruta/histórico | Histórico global quedó `PARTIAL` por el límite de 2 MiB; no hay orden/paginación universal. | **No disponible** como afirmación de “última ruta”. |

Implicación: un resultado futuro debe llamarse “secuencia mejor estimada
ajustada a una versión de red” y no “calles exactas”. GeoJSON estándar suele
usar `[longitud, latitud]`, pero esa convención externa no demuestra que MAPIT
la cumpla en todos sus features; debe verificarse de forma controlada antes de
calcular distancias o pasar puntos a un matcher.

## 3. Probe acotado implementado y resultado live redacted

`src/mapit/route_input_analyzer.py` contiene el analizador puro y
`scripts/probe_route_input_sufficiency.py` contiene el flujo no interactivo.
El analizador puro y sus pruebas sintéticas no hacen llamadas de red. El
script live se ejecutó tres veces con autorización separada y produjo
únicamente categorías redacted; no se conservaron cuerpos, coordenadas, IDs ni
valores. Al iniciar con una sesión
guardada, su preparación puede hacer discovery público, autenticación/refresh
Cognito y rotar atómicamente el refresh token seguro existente; eso no guarda
datos de ruta ni la salida del probe.
El probe reutiliza el flujo aprobado: `account-summary`, una selección de
vehículo solo en memoria, un listado `limit=1` y un único detalle actual con
`includeStats=true`. Cada operación es una lectura lógica y solo puede usar la
recuperación 401/403 ya existente del cliente. No sigue cursores, no prueba el
endpoint legacy, no llama al reverse geocoder y no envía datos a OSRM,
Valhalla, GraphHopper o AWS. La ejecución live no invocó ningún matcher,
geocoder ni servicio externo.

El detalle se inspeccionaría en memoria y se descartaría inmediatamente. La
salida permitida es el esquema fijo implementado, con valores allowlisted:

- `geometry_classes`: conjunto (`Point`, `LineString`);
- `coordinate_shape_classes`: conjunto (`pair-like`, `nested`);
- `coordinate_dimension_classes`: conjunto (`2`, `3`);
- `point_density_band`: banda gruesa (`none`, `few`, `many`), nunca el conteo;
- `max_gap_within_linestring_band`, `max_gap_between_features_band` y
  `max_gap_point_stream_band`: bandas (`none`, `short`, `medium`, `long`,
  `unknown`);
- `max_consecutive_gap_source`: `none`, `inside_linestring`,
  `between_features`, `point_stream`, `multiple` o `unknown`;
- `feature_count_band_by_geometry`: bandas `none`/`few`/`many` de objetos
  `Point` y `LineString`;
- `coordinate_density_band_by_geometry`: bandas `none`/`few`/`many` de puntos
  aportados por cada clase de geometría, sin conteos;
- presencia/distinción de `name`/`label` por geometría, sin texto ni hashes;
- `inferred_coverage_class_by_geometry` y `feature_order_name_pattern`;
- `linestring_gap_distribution_band`: `none`, `short`, `medium`, `long`,
  `mixed` o `unknown`;
- `per_point_time/accuracy/heading/speed`: booleanos;
- `distinct_name_band`/`distinct_label_band`: bandas, nunca los valores;
- `inferred_coverage_class`: `all`, `partial`, `none`, `unknown`;
- `input_sufficiency`: `insufficient`, `candidate`, `candidate_with_time`.

No se mostrarían ni guardarían valores, coordenadas, route/vehicle IDs,
timestamps exactos, nombres, labels, distancias, velocidades, headers,
tokens, URLs firmadas, cuerpos o conteos exactos. El probe tampoco decidiría
qué ciudad es ni produciría una métrica de cobertura.

La salida fija incluye clases de geometría, forma/dimensión de coordenadas,
validez de rango WGS84, bandas de densidad y de gaps por procedencia, bandas
de nombres/labels distintos, clase de cobertura `inferred`, presencia de
metadatos por punto e `input_sufficiency`. El stream observado conserva el
orden de features y, dentro de cada feature, el orden de coordenadas; los
gaps entre features también se clasifican sin revelar sus valores. Solo usa
enums, bandas y booleanos; no contiene IDs, coordenadas, timestamps, nombres,
labels, métricas, conteos, URLs, cuerpos ni excepciones.
Los límites entre dos features `Point` se reportan únicamente en la banda
`point_stream`; los límites `Point↔LineString` y `LineString↔LineString` van en
`between_features`. Si las máximas numéricas de fuentes distintas empatan, la
fuente agregada es `multiple`.
Una tercera ordenada solo se clasifica como dimensión `3` y
`present_opaque` (o `absent`/`unknown` ante fallo): nunca se infiere como
elevación, timestamp, precisión o velocidad.

### Resultados redacted de los tres runs autorizados

El primer run fue `success`, con `geometry_classes={Point, LineString}`,
`coordinate_shape_classes={nested, pair-like}`, dimensión `3`, rango WGS84
válido, densidad `many`, nombres en banda `many`, labels en banda `few`,
`inferred_coverage_class=partial`, sin timestamp/accuracy/heading/speed por
punto e `input_sufficiency=candidate`; solo informó un gap máximo global en
banda `long`, sin provenance.

El segundo run fue `success`, con la misma política redacted. Su gap máximo
interno de `LineString` quedó en banda `medium` (100 m–1 km), mientras que el
máximo entre features quedó en `long` y el del stream de `Point` también en
`long`. La fuente agregada del mayor gap fue `multiple`.

El tercer run fue `success` y pobló el refinamiento estructural vigente:
`LineString` tuvo densidad de coordenadas `many` y `Point` `few`; ambas clases
tuvieron banda de features `few`. La presencia de nombres fue `few` por clase
y la de labels `none` en `LineString` y `few` en `Point`; la diversidad de
nombres fue `few` por clase y la de labels `none`/`few`, respectivamente. El
patrón de nombres fue `transitions_present`; `inferred` fue `partial` para
`LineString` y `all` para `Point`. También confirmó las bandas de gap
`medium`/`long`/`long`, `multiple`, dimensión `3` opaca, WGS84 válido,
`candidate` y ausencia de metadata por punto.

Estos hechos elevan la entrada desde “desconocida” a “candidata”, pero no
demuestran map matching correcto. La diferencia de densidad y la ausencia de
labels en `LineString` son señales estructurales, no prueba de que MAPIT
segmente calles; la presencia de nombres en ambas clases tampoco demuestra que
sean nombres viales canónicos. `transitions_present` solo indica cambios en
clases de igualdad, no expone el texto ni su semántica. El gap interno `medium`
puede ser una discontinuidad o una separación normal de muestreo; los gaps
`long` entre features y de Points no permiten concluir que los Points sean
muestras del mismo recorrido.

El analizador refinado conserva la política de no valores, no coordenadas, no
conteos exactos y no persistencia de la geometría, y ahora emite las bandas separadas
`max_gap_within_linestring_band`, `max_gap_between_features_band` y
`max_gap_point_stream_band`, junto con `max_consecutive_gap_source` y
`third_ordinate_class=present_opaque`. El tercer run confirmó esos campos y
los refinamientos de densidad/nombre actuales como categorías redacted de
MAPIT; no añadió valores, nombres, coordenadas ni semántica vial.

### Refinamiento estructural implementado offline (sin matcher)

El analizador ya emite, sobre entradas inyectadas o fixtures sintéticos,
únicamente estas categorías por clase de feature:

- `feature_count_band_by_geometry`: `Point` y `LineString` por separado,
  con `none`/`few`/`many`, nunca conteos;
- `coordinate_density_band_by_geometry`: densidad de coordenadas aportadas por
  cada clase, también solo `none`/`few`/`many`;
- `name_presence_band_by_geometry` y `label_presence_band_by_geometry`, más
  `distinct_name_band_by_geometry` y `distinct_label_band_by_geometry`, sin
  valores ni hashes de nombres;
- `inferred_coverage_class_by_geometry`, para no mezclar Points auxiliares
  con segmentos de línea;
- `feature_order_name_pattern`: solo `stable`, `repeating`,
  `transitions_present` o `unknown`, calculado sobre clases de igualdad y no
  sobre el texto del nombre;
- `linestring_gap_distribution_band`: `none`, `short`, `medium`, `long`,
  `mixed` o `unknown`, exclusivamente dentro de cada LineString;
- `feature_boundary_gap_band` y `point_stream_gap_band`, manteniendo la
  distinción entre límites y continuidad interna.

Estas señales sirven para decidir si la respuesta parece segmentada por
carretera o contiene geometrías auxiliares; no prueban semántica vial. La
tercera ordenada sigue siendo `present_opaque`, y cualquier origen de gap que
no pueda clasificarse debe ser `unknown`/fail-closed.

### Siguiente experimento local/offline (sin implementación en este hito)

Construir únicamente en memoria un fixture GeoJSON sintético, sin coordenadas
reales ni nombres reales, que represente: una `LineString` densa con gap
`medium`, varios `Point` escasos con gap `long`, labels ausentes en líneas,
nombres/labels presentes en Points, cambios de nombre estructurales y tercera
ordenada opaca. Ejecutar el analizador puro y comparar sus enums/bandas con la
clasificación conocida del fixture. El criterio de éxito sería que distinga
densidad, presencia/diversidad por geometría, transición de nombres y origen
de gaps sin imprimir ni persistir valores.

Este experimento valida el analizador, no la semántica MAPIT ni las calles. No
requiere red, extracto OSM, matcher, reverse geocoder ni servicio de pago; un
matcher sigue siendo necesario más adelante para asociar una geometría real a
segmentos/giros de una red vial.

Si el objetivo específico es “última ruta”, hará falta además una ventana
acotada cuyo orden temporal pueda inspeccionarse efímeramente; el primer item
de `limit=1` no basta. Incluso una comparación mensual positiva no prueba
completitud universal mientras el backend no exponga un contrato de total o
paginación verificable.

## 4. Feasibility tiers

| Objetivo | Estado actual | Condición mínima para subir de nivel |
|---|---|---|
| Última ruta y sus calles | **NO FEASIBLE como afirmación exacta**. No hay orden global ni valores de geometría retenidos; histórico es `PARTIAL`. | Una política de selección temporal acotada y una lectura de detalle con geometría real; aun así “última” queda limitada a la ventana comprobada. |
| Secuencia de calles de una ruta | **CANDIDATO condicionado**. El run redacted confirma geometría mixta y densidad `many`, pero no orden verificado, semántica de la tercera ordenada, precisión ni continuidad; los gaps internos/entre features tienen bandas distintas y fuente agregada `multiple`. | Separar señales por geometría y transiciones estructurales; después comparar un matcher local contra un snapshot OSM, con confidence y segmentos no asignados explícitos. |
| Orden de giros/turns | **CANDIDATO DE BAJA CONFIANZA**. La topología OSM puede derivar giros después del matching, pero MAPIT no entrega heading, tiempos por punto ni turn events; los gaps `medium`/`long` pueden romper continuidad. | Verificar continuidad o reglas de gap por clase de feature y usar una red con restricciones de giro y reporte de ambigüedad. Nunca prometer exactitud en cruces/parallel roads. |
| Porcentaje de calles cubiertas por ciudad | **NO FEASIBLE actualmente**. Faltan histórico completo, geometrías/segmentos y definición de ciudad/denominador. | Matchear múltiples rutas a IDs/segmentos OSM, congelar boundary y snapshot, y publicar denominador/inclusiones junto a la métrica. |

## 5. Definición de cobertura y riesgos de interpretación

Una métrica defendible debe fijar, por ejecución:

1. el polígono de ciudad (administrativo, área urbana o límite de usuario) y
   la fecha/snapshot de la red;
2. el perfil (`motor_vehicle`, moto/scooter u otro) y qué valores de
   `highway=*` entran; `highway` cubre carreteras, calles, caminos y otras
   instalaciones, no solo calles transitables;
3. si el denominador son segmentos OSM dirigidos, segmentos no dirigidos,
   longitud recortada al boundary o nombres únicos;
4. tratamiento de `service`, `track`, `path`, zonas privadas, accesos,
   carriles paralelos, rotondas, ramps y sentidos de una vía;
5. reglas para geometría fuera de la ciudad, GPS que cruza el boundary,
   tramos no asignados, duplicados y cambios de versión OSM.

Se deben reportar por separado al menos:

- cobertura ponderada por longitud de segmentos elegibles;
- cobertura por segmentos/way IDs únicos;
- opcionalmente, nombres únicos normalizados, claramente etiquetados como
  aproximación y no como cobertura vial.

Contar nombres `name` mezcla calles divididas, homónimos y calles sin nombre;
contar ways sin su dirección puede duplicar o ocultar calzadas. OSM modela
nodes, ordered ways y relations, y sus tags son libres; por ello un “way” o un
nombre no es automáticamente una calle humana única. Los cierres de mapas,
GPS noise, rutas inferidas, mapas cambiantes y carreteras privadas hacen que
la cifra sea una estimación dependiente de políticas.

## 6. Opciones downstream (sin decisión)

La red de referencia tendría que venir de OSM o un extracto compatible. OSM
define nodes, ordered ways y relations, y `highway=*` clasifica carreteras y
otros elementos; Overpass es útil para consultas espaciales acotadas, pero no
debe tratarse como un exportador ilimitado de una ciudad. Para un denominador
urbano reproducible será preferible un extracto regional versionado y un
importador local.

| Opción | Evidencia primaria | Utilidad potencial | Límite para este proyecto |
|---|---|---|---|
| OSRM Match | La API documenta coordenadas ordenadas, `timestamps`, `radiuses`, `gaps`, `tidy`, `tracepoints`, `matchings` y `confidence`; también advierte splits/outliers y saltos temporales grandes. | Prototipo local claro para probar si un GeoJSON de MAPIT basta. | Requiere decidir perfil/red; la API pública no es un supuesto de producción ni de privacidad. |
| Valhalla Meili | Documenta matching de trayectorias GPS ruidosas con candidatos, costes de emisión/transición, alternativas y segmentos/edges. | Control fino sobre ambigüedad y resultado por edge en despliegue local. | Mayor coste operativo de importar/mantener el grafo; no elimina datos ausentes de MAPIT. |
| GraphHopper Map Matching | La documentación oficial expone la capacidad de map matching y su distribución open-source documenta ejecución con datos preparados localmente. | Candidato adicional para benchmark offline. | Debe compararse con fixtures sintéticos y políticas de licencia/recursos antes de decidir. |
| Amazon Location SnapToRoads | AWS documenta `SnapToRoads` para alinear GPS traces con la red vial. | Posible opción administrada posterior, también con otros servicios de rutas. | Introduce llamadas/coste, dependencia externa y retención/configuración AWS; queda fuera del gate actual. |

Estas opciones no son intercambiables en significado: un matcher devuelve una
hipótesis sobre una red concreta, no prueba la calle real. Para el primer
experimento no se necesita ningún servicio de pago: bastan un fixture GeoJSON
sintético, un extracto OSM pequeño versionado y un proceso local. Los
resultados deben incluir versión de red y atribución/licencia OSM.

### POC OSRM local sintético (implementado y observado)

El arnés reproducible `scripts/probe_local_osrm_fixture.py` usa solo stdlib,
acepta exclusivamente un endpoint loopback, genera una ruta sintética en
memoria mediante `/route`, muestrea un número acotado de puntos y llama a
`/match`. El transporte es inyectable para tests; no usa MAPIT, credenciales,
servicios externos ni persistencia de respuestas raw. El clasificador puro
`mapit.osrm` devuelve un schema fijo redacted y falla cerrado ante JSON,
profundidad o tamaños inválidos.

El fixture determinista usa los extremos sintéticos `(7.4165,43.7304)` y
`(7.4320,43.7420)` y como máximo 12 puntos equidistantes. Sigue el esquema
real de Match: un `tracepoint` `null` es un punto no emparejado y produce
`partial`; los tracepoints objeto deben llevar `matchings_index`, los nombres
de step vacíos son válidos pero no cuentan como nombre presente, y
`annotations` se detecta solo desde `leg.annotation` (objeto o `null`).

La reproducción local observada usó la imagen oficial OSRM `v26.9.0` con
digest `sha256:c29a50d67b9be17d10773fa2b52bb045ee3fbb8f42e5f9d1c671ce0d9bb21f37`
y el PBF de Monaco de Geofabrik con SHA-256
`30A84C07C16E7525E255FEEB0D26BD2BE9C79EF772C2B91C958AA2417C253A23` y tamaño
691480 bytes; no se registra ninguna ruta local del archivo. Docker Desktop
quedó reparado y operativo para este POC. El contenedor se trató como
loopback/log-none/read-only.

El resultado sintético redacted fue `engine=osrm-local`,
`category=matched`, `matching_count_band=few`,
`tracepoint_coverage_band=all`, `confidence_band=medium`,
`steps_present=true`, `annotations_present=true`, `names_present=true` y
`raw_discarded=true`. Esto valida el engine y el arnés local, no MAPIT ni la
calidad de un matching de rutas MAPIT.

### Probe MAPIT → OSRM local de Barcelona (ejecutado una vez)

`scripts/probe_mapit_osrm.py` reutiliza el flujo de sesión guardada y limita
la preparación a tres lecturas MAPIT: `account-summary`, `/v1/routes` con
`limit=1` y un detalle actual `includeStats=true`. Selecciona la primera
`LineString` estructural en orden de features, conserva sus 2–500 puntos sin
muestrear y descarta la tercera ordenada. Cada punto debe caer en el rectángulo
público fijo `1.8,41.2,2.45,41.65`; un fallo de forma, rango o tamaño termina
sin intentar otra ruta. Solo se hace una petición local `/match`, con timeout
de 5 segundos, respuesta máxima de 2 MiB, `tidy=false`, opener sin proxies ni
redirects y URL limitada a 16 KiB. La salida añade solo una categoría de etapa
allowlisted al schema redacted de `mapit.osrm`; no imprime ni persiste IDs,
coordenadas, cuerpos, URLs, nombres, métricas o excepciones. La implementación
y sus dobles offline no constituyen evidencia de precisión MAPIT.

Tras aceptación independiente y 450 tests offline correctos se realizó una
única ejecución autorizada con una LineString real. Resultado redacted:
`matched`, todos los tracepoints asociados, confianza `high`, pocos matchings
y steps/annotations/names presentes. No se retuvieron coordenadas, nombres,
IDs ni respuestas. El contenedor temporal se detuvo y eliminó. Es evidencia
favorable de viabilidad para esa línea; no demuestra exactitud real, continuidad
de todo el recorrido ni porcentaje de calles. Protocolo, snapshot público y
límites en [prueba Barcelona](phase-6-barcelona-local-probe.md).

Una prueba posterior de todas las LineStrings seleccionadas (no se garantiza
la misma ruta/snapshot) obtuvo `partial_lines`: todas las líneas evaluadas,
asociación parcial de puntos, confianza mínima baja, flags `inferred` mixtos,
Point excluidos, gap interno medio y frontera entre features larga. No se
estableció continuidad ni exactitud de calles/giros. Estas separaciones son
estructurales; no prueban huecos temporales GPS. El éxito de una línea no
generaliza al conjunto. La cobertura vial urbana sigue **no demostrada**.

## 7. Privacidad y gate posterior

Coordenadas, timestamps, nombres/labels y IDs de ruta son datos de movilidad.
Un `way_id` o una secuencia de segmentos también puede revelar hábitos cuando
se vincula a tiempo o vehículo; no es automáticamente anónimo. El reverse
geocoder puede convertir una coordenada en una dirección más identificable y
no debe usarse por defecto.

La línea base sigue siendo sin persistencia. Si un gate posterior lo aprueba,
la opción menos invasiva sería procesar la geometría efímeramente y retener
solo métricas agregadas con snapshot de red, política de inclusión, confianza
y fecha truncada; la retención de coordenadas o secuencias OSM requeriría una
decisión independiente. En AWS futuro, la misma separación local podría
empaquetarse, pero no se deben crear tracker, bucket, base de datos ni IAM de
proyecto antes de una decisión de producto y privacidad.

## Fuentes primarias consultadas

- [MAPIT route investigation](mapit-routes-investigation.md) y [MAPIT data inventory](mapit-data-inventory.md) (evidencia local del bundle y fixtures).
- [OpenStreetMap Elements](https://wiki.openstreetmap.org/wiki/Elements) y [Key:highway](https://wiki.openstreetmap.org/wiki/Key:highway) (modelo de nodes/ways/relations, tags y clasificación vial).
- [Overpass spatial selection](https://dev.overpass-api.de/overpass-doc/en/full_data/index.html) y [area queries](https://dev.overpass-api.de/overpass-doc/en/full_data/area.html) (consultas espaciales y límites de escala).
- [OSRM HTTP API, Match service](https://project-osrm.org/docs/v5.15.2/api/) (timestamps, radiuses, gaps, tracepoints, matchings y confidence).
- [Valhalla Meili](https://valhalla.github.io/valhalla/contributing/architecture/meili/) (HMM/candidates, transición, `MatchResult`, edge segments y discontinuidades).
- [GraphHopper OpenAPI](https://docs.graphhopper.com/openapi) y [GraphHopper map-matching README](https://github.com/graphhopper/graphhopper/tree/master/map-matching) (capacidad y opción local).
- [Amazon Location API Reference](https://docs.aws.amazon.com/location/latest/APIReference/) y [Routes guide](https://docs.aws.amazon.com/location/latest/developerguide/routes.html) (Routes V2/SnapToRoads).
- [Amazon Location trackers](https://docs.aws.amazon.com/location/latest/developerguide/trackers.html) (histórico, filtrado, precisión, coste y sensibilidad de almacenar posiciones).
