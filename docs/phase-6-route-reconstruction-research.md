# Phase 6: investigación de reconstrucción de rutas y cobertura urbana

Estado: **investigación acotada; analizador/probe offline implementado, sin
llamadas MAPIT live ni pagos** (2026-09-29).

Este documento responde primero a qué datos entrega MAPIT y si esos datos son
suficientes para map matching. OSRM, Valhalla, GraphHopper y Amazon Location
se comparan solo como opciones posteriores; no se selecciona una arquitectura
ni se abre un gate de persistencia.

## Conclusión ejecutiva

MAPIT sí expone una ruta de detalle GeoJSON y la interfaz pública valida
`Point`/`LineString` con coordenadas numéricas. Eso hace técnicamente plausible
un intento posterior de map matching, pero la evidencia conservada es
schema-only: no contiene coordenadas, su orden, densidad ni valores temporales.
Por tanto, hoy no se puede afirmar que se puedan reconstruir calles exactas,
giros o la última ruta, ni calcular cobertura de una ciudad.

La principal carencia no es todavía el motor de mapas: es verificar, con una
única lectura autorizada y efímera, que el detalle contiene una secuencia de
coordenadas utilizable. El primer probe debe medir solo propiedades redacted
(por ejemplo, presencia y clases de geometría, profundidad/tamaño en bandas y
presencia de metadatos por punto), sin guardar coordenadas, IDs, timestamps,
conteos exactos ni llamar a un geocoder o matcher externo.

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
| `geoJSON` de lista/detalle | La interfaz valida `FeatureCollection`; sus features pueden ser `Point` o `LineString` y sus arrays de coordenadas son numéricos con al menos dos componentes. El fixture registra `geometry.type` string y `coordinates` como array de elementos `mixed` (`array` o `number`); propiedades observadas: `inferred`, `label`, `name` y, en detalle, `avgSpeed`, `distance`, `maxSpeed`. | No se ha observado el valor de ninguna coordenada ni su dimensionalidad real, secuencia, muestreo o continuidad. `name`/`label` no son evidencia de nombres OSM ni de un identificador vial estable. No hay `way_id`, segmento, rumbo, precisión ni giro. |
| Tiempos y métricas | `startedAt`, `endedAt`, `createdAt`, `updatedAt`, `startTz`, `distance`, `avgSpeed`, `maxSpeed` aparecen a nivel de ruta; algunas propiedades de feature son nullable en el fixture de detalle. | No hay timestamps por punto, heading, precisión GPS, velocidad por punto, gaps ni unidades confirmadas. `hdop` de estado del dispositivo no equivale a precisión de cada punto histórico. |
| `GET https://core.prod.mapit.me/v1/reverse-geocoding/{lat}/{lng}?lang=...` | Path de lectura encontrado en el bundle vigente. | No se probó y no es un sustituto de map matching: produciría etiquetas/direcciones para coordenadas individuales, no secuencia vial ni cobertura completa. |

La ruta de detalle histórica `/v1/routes/{routeId}` de los clientes públicos
queda como compatibilidad legacy, no como contrato actual para esta
investigación. El selector existente de `limit=1` tampoco demuestra que el
elemento sea el más reciente: el orden del backend no está confirmado.

## 2. Suficiencia de entrada para map matching

| Entrada que necesitaría un matcher | Evidencia MAPIT actual | Evaluación |
|---|---|---|
| Secuencia de posiciones `(lon, lat)` | El parser acepta arrays numéricos y el nombre `geoJSON`; el fixture solo conserva tipos. | **Desconocida** hasta inspeccionar valores efímeros. Sin ella no hay matching. |
| Orden de la secuencia | `LineString` es el único indicio estructural; no se conservó ninguna secuencia. | **Parcial**. Se debe verificar que el orden de coordenadas representa el trayecto y que no se trata solo de una geometría de visualización. |
| Geometría y densidad | El frontend acepta `Point`/`LineString`; el fixture permite arrays anidados o numéricos, sin conteo. | **Parcial**. Hace falta saber si existe una `LineString` suficientemente densa o solo puntos/resúmenes. |
| Tiempo por posición | Solo hay tiempos a nivel de ruta. | **Ausente en evidencia**. OSRM puede trabajar sin ellos, pero no se pueden detectar gaps ni velocidad temporal con rigor. |
| Precisión/radio GPS | No aparece en el esquema de ruta. `hdop` pertenece al estado actual del dispositivo. | **Ausente**. El matcher tendrá que usar un radio conservador/configurable y reportar menor confianza. |
| Heading y velocidad instantánea | Solo hay métricas agregadas y propiedades agregadas/nullable. | **Ausente**. Ambigüedad en paralelas, cruces y sentidos no puede resolverse siempre. |
| Nombres/labels | `properties.name` y `properties.label` son strings no vacíos en la muestra. | **Disponible como texto**, no como identidad vial; semántica y fuente desconocidas. |
| Gaps, discontinuidades y segmentos | No hay tiempos por punto ni campo de segmento; `continues` es estado de ruta nullable, no paginación. | **Desconocido**. No se debe convertir en recorrido continuo sin validación. |
| Última ruta/histórico | Histórico global quedó `PARTIAL` por el límite de 2 MiB; no hay orden/paginación universal. | **No disponible** como afirmación de “última ruta”. |

Implicación: un resultado futuro debe llamarse “secuencia mejor estimada
ajustada a una versión de red” y no “calles exactas”. GeoJSON estándar suele
usar `[longitud, latitud]`, pero esa convención externa no demuestra que MAPIT
la cumpla en todos sus features; debe verificarse de forma controlada antes de
calcular distancias o pasar puntos a un matcher.

## 3. Probe acotado implementado, no ejecutado live

`src/mapit/route_input_analyzer.py` contiene el analizador puro y
`scripts/probe_route_input_sufficiency.py` contiene el flujo no interactivo.
El analizador puro y sus pruebas sintéticas no hacen llamadas de red. El
script es capaz de ejecutarse live, pero no se ha ejecutado y requiere
autorización explícita. Al iniciar con una sesión guardada, su preparación
puede hacer discovery público, autenticación/refresh Cognito y rotar
atómicamente el refresh token seguro existente; eso no guarda datos de ruta ni
la salida del probe.
El probe reutiliza el flujo aprobado: `account-summary`, una selección de
vehículo solo en memoria, un listado `limit=1` y un único detalle actual con
`includeStats=true`. Cada operación es una lectura lógica y solo puede usar la
recuperación 401/403 ya existente del cliente. No sigue cursores, no prueba el
endpoint legacy, no llama al reverse geocoder y no envía datos a OSRM,
Valhalla, GraphHopper o AWS. No se ha ejecutado con sesión, credenciales ni
red live.

El detalle se inspeccionaría en memoria y se descartaría inmediatamente. La
salida permitida es el esquema fijo implementado, con valores allowlisted:

- `geometry_classes`: conjunto (`Point`, `LineString`);
- `coordinate_shape_classes`: conjunto (`pair-like`, `nested`);
- `coordinate_dimension_classes`: conjunto (`2`, `3`);
- `point_density_band`: banda gruesa (`none`, `few`, `many`), nunca el conteo;
- `per_point_time/accuracy/heading/speed`: booleanos;
- `distinct_name_band`/`distinct_label_band`: bandas, nunca los valores;
- `inferred_coverage_class`: `all`, `partial`, `none`, `unknown`;
- `input_sufficiency`: `insufficient`, `candidate`, `candidate_with_time`.

No se mostrarían ni guardarían valores, coordenadas, route/vehicle IDs,
timestamps exactos, nombres, labels, distancias, velocidades, headers,
tokens, URLs firmadas, cuerpos o conteos exactos. El probe tampoco decidiría
qué ciudad es ni produciría una métrica de cobertura.

La salida fija incluye clases de geometría, forma/dimensión de coordenadas,
validez de rango WGS84, bandas de densidad y de mayor gap consecutivo, bandas
de nombres/labels distintos, clase de cobertura `inferred`, presencia de
metadatos por punto e `input_sufficiency`. Solo usa enums, bandas y booleanos;
no contiene IDs, coordenadas, timestamps, nombres, labels, métricas, conteos,
URLs, cuerpos ni excepciones.
Una tercera ordenada solo se clasifica como dimensión `3`: se trata como
ordenada opaca candidata a elevación/desconocida y nunca como timestamp.

Si el objetivo específico es “última ruta”, hará falta además una ventana
acotada cuyo orden temporal pueda inspeccionarse efímeramente; el primer item
de `limit=1` no basta. Incluso una comparación mensual positiva no prueba
completitud universal mientras el backend no exponga un contrato de total o
paginación verificable.

## 4. Feasibility tiers

| Objetivo | Estado actual | Condición mínima para subir de nivel |
|---|---|---|
| Última ruta y sus calles | **NO FEASIBLE como afirmación exacta**. No hay orden global ni valores de geometría retenidos; histórico es `PARTIAL`. | Una política de selección temporal acotada y una lectura de detalle con geometría real; aun así “última” queda limitada a la ventana comprobada. |
| Secuencia de calles de una ruta | **CANDIDATO, no demostrado**. `LineString` validada por frontend podría ser una entrada, pero faltan coordenadas reales, orden verificado, densidad y precisión. | Probe schema-plus seguro; luego matcher local contra un snapshot OSM, con confidence y segmentos no asignados explícitos. |
| Orden de giros/turns | **CANDIDATO DE BAJA CONFIANZA**. La topología OSM puede derivar giros después del matching, pero MAPIT no entrega heading, tiempos por punto ni turn events. | Secuencia suficientemente densa, continuidad temporal o reglas de gap, red con restricciones de giro y reporte de ambigüedad. Nunca prometer exactitud en cruces/parallel roads. |
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
