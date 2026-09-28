# Mapit: endpoints descubiertos

Estado de investigación: 2026-09-28. Los contratos se descubrieron en código
público; los probes autorizados de lectura conservaron solo schemas anónimos y
no se invocó ninguna operación de escritura.

## Hosts

| Rol | Host observado | Evidencia / confianza |
|---|---|---|
| Frontend | `https://app.mapit.me/` | HTML público; alta |
| Core API | `https://core.prod.mapit.me` | bundle actual y ambos clientes Python; alta |
| Geo API | `https://geo.prod.mapit.me` | bundle actual y ambos clientes Python; alta |
| Device-state websocket (actual) | `wss://dsw.prod.mapit.me/accounts/{accountId}` | bundle `useDashboardSummary` actual + probe autorizado; alta |
| Device-state websocket (fallback legado) | `wss://dsw.prod.mapit.me/devicestate/{deviceId}` | ambos clientes Python; media, pendiente de compatibilidad |
| Cognito User Pool | `https://cognito-idp.eu-west-1.amazonaws.com/` | bundle/config y clientes; alta |
| Cognito Identity Pool | `https://cognito-identity.eu-west-1.amazonaws.com/` | bundle/config y clientes; alta |

Los valores entre llaves son identificadores del usuario/tenant y se mantienen como placeholders. No se copian IDs reales en este repositorio.

## Endpoints de lectura observados

| Método | Endpoint | Fuente | Estado |
|---|---|---|---|
| `GET` | `https://core.prod.mapit.me/v1/account-summary` | bundle actual (`bG`), d3vv3, citylife4; authorized schema-only probe | **CONFIRMED**: HTTP 200 read completed; only anonymized schema retained |
| `GET` | `https://core.prod.mapit.me/v1/vehicles/{vehicleId}` | d3vv3 y citylife4; probe autorizado schema-only | **CONFIRMED_SCHEMA_ONLY**: lectura autorizada completada; no se retuvieron valores |
| `GET` | `https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}` | bundle actual y clientes públicos; bounded probe autorizado | **CONFIRMED_SCHEMA_ONLY**: el host/path y la lectura con `vehicleId` más `limit=1` fueron aceptados; solo se retuvo el esquema de la respuesta |
| `GET` | `https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}&limit={limit}&month={month}&day={day}&from={from}&to={to}&includeInProgress={bool}` | bundle actual; `limit=1` también en el probe acotado | **PARTIAL_FRONTEND_CONTRACT**: el builder serializa estas claves; el dashboard actual solo envía `from`/`to` mensuales |
| `GET` | `https://geo.prod.mapit.me/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true` | bundle actual vigente; probe autorizado schema-only | **CONFIRMED_SCHEMA_ONLY**: lectura actual completada; `includeStats=true` aceptado y solo se retuvo la forma de la respuesta |
| `GET` | `https://geo.prod.mapit.me/v1/routes/{routeId}` | d3vv3 y citylife4 | **LEGACY_PUBLIC_CONTRACT**: ruta de detalle histórica sin query; no asumir que sustituye a la actual |
| `GET` | `https://geo.prod.mapit.me/v1/reverse-geocoding/{lat}/{lng}?lang={language}` | bundle actual | geocodificación inversa |

La lectura autorizada de `account-summary` confirmó una respuesta con `account`,
`vehicles` y estructuras adicionales de pagos/catálogo, capacidades, dealer,
alert settings y estado detallado del dispositivo. Solo se retuvo el schema
anónimo (`samples/anonymized/account-summary.schema.json`), sin valores,
conteos ni identificadores. El probe autorizado acotado de rutas reutilizó un
vehículo seleccionado en memoria y ejecutó una sola lectura Geo con
`vehicleId` y `limit=1`; produjo `samples/anonymized/routes-list.schema.json`.
La respuesta observada es un objeto `{data: Route[]}` con objetos de ruta,
referencias `device`/`vehicle`, métricas, marcas temporales y un `geoJSON`
anidado. No se observaron metadatos de paginación en ese fixture; el tamaño
por defecto, cursores, completitud histórica y semántica de campos siguen
pendientes. No se retuvieron valores, conteos, IDs ni geometrías.

El detalle de ruta actual usa el host Geo, método `GET`, sin body y el único
query parameter `includeStats=true`. El bundle valida un objeto raíz con `id`,
`geoJSON` (FeatureCollection con features `Point`/`LineString`), distancia,
marcas temporales y velocidades opcionales/nullables; no enumera campos de
estadísticas separados. El probe autorizado produjo
`samples/anonymized/route-detail.schema.json`, con un objeto raíz no nulo,
campos adicionales `complete`/`merged`, referencias `device`/`vehicle`,
odómetros y `continues` nullables, y propiedades GeoJSON con `inferred`,
`label`, `name`, `maxSpeed` y `avgSpeed`/`distance` observados como null.
Esto confirma estructura y nullabilidad de una sola lectura, no semántica,
unidades ni universalidad. En el dashboard, `routesMonth` genera ventanas
mensuales mediante `from`/`to`, mientras que `routeDay` filtra localmente por
`startedAt`; no se observó carga incremental por cursor. El parser permite
`lastEvaluatedKey`, pero el frontend no lo consume ni lo reenvía. La ruta histórica `/v1/routes/{routeId}` aparece
solo en los clientes Python públicos y sus consumidores esperan un objeto de
ruta con `geoJSON`; se conserva como compatibilidad pendiente, no como primera
opción de probe.

El probe histórico autorizado aceptó exactamente dos ventanas mensuales
acotadas con `from`/`to`, `vehicleId` y `limit=1`. Ninguna expuso
`lastEvaluatedKey` y no se persistió ningún resultado; esto confirma solo esas
dos lecturas y no la ausencia universal de paginación ni la cobertura completa
del histórico.

## Zonas, geofences y alertas/eventos

No se encontró un endpoint público actual de lectura para zonas, geofences,
alertas o eventos. En los bundles vigentes, las únicas rutas MAPIT literales
observadas son `GET /v1/account-summary`, `GET /v1/routes`, el detalle Geo de
ruta, `GET /v1/reverse-geocoding/{lat}/{lng}` y el `PUT` de preferencias; no
aparecen rutas `/v1/geofences`, `/v1/zones`, `/v1/alerts` o `/v1/events`.
Tampoco se encontró consumo de esos recursos en los clientes públicos d3vv3 o
citylife4.

El schema ya conservado de `account-summary` sí contiene configuración de
alertas dentro de cada vehículo: `notificationSettings.geofenceAlertCritical`,
los flags de acceso a alertas y ajustes de accidentes, caída, ignición y
movimiento. Esto es estructura de configuración/entitlement únicamente; no
demuestra una lectura de eventos, zonas guardadas, entrega de notificaciones ni
una operación de escritura. El bundle actual no valida ni consume esos campos
en una pantalla o llamada separada.

El repositorio citylife4 menciona geofencing y eventos como posibles mejoras
futuras, no como contrato implementado. Por tanto no hay un path, host,
parámetros, body o envelope de respuesta que pueda documentarse honestamente
para un probe dedicado. No se deben adivinar rutas ni probar POST/PUT/PATCH/
DELETE. Si documentación primaria futura revela una ruta GET, el primer probe
debe ser una sola lectura acotada, con cualquier identificador obtenido en
memoria, sin filtros inventados y con retención schema-only.

## Mantenimiento, revisiones, dealer y citas Honda

El frontend vigente no contiene paths, métodos o consumidores específicos para
mantenimiento, revisiones/taller, citas o servicios de dealer. Los clientes
públicos d3vv3 y citylife4 solo leen `account-summary`, detalle de vehículo,
rutas y detalle de ruta para este conjunto de datos; no añaden un GET de
service history, booking, appointment o workshop.

El schema-only de `account-summary` sí contiene `dealerData` embebido en el
vehículo (nombre, IDs, dirección de tienda, contacto, email, teléfono y
horario), y el detalle Core de vehículo contiene un objeto `dealer`. Es
metadata de dealer observada dentro de lecturas ya conocidas, no un historial
de mantenimiento ni una API de citas. El mismo detalle contiene además
`branch`, `productPlanName` y estructura de suscripción; ninguno prueba
revisiones, órdenes de trabajo o disponibilidad de agenda.

El único write relevante encontrado en el bundle actual sigue siendo el
`PUT /v1/accounts/{accountId}/preferences` para preferencias de cuenta; no se
ejecutó y no se relaciona con dealer, taller o citas. No hay un path GET exacto
con evidencia primaria para proponer un probe de mantenimiento/appointment.
No se deben adivinar rutas ni ejecutar writes. Si el backend documenta después
un GET concreto, el primer probe debe limitarse a una lectura, un vehículo o
cuenta en memoria y schema-only sin valores de contacto, IDs, fechas de cita o
historial.

## Estadísticas, conducción y telemetría adicional

La única ruta actual con una opción explícita de estadísticas es el detalle Geo
de una ruta:

```text
GET https://geo.prod.mapit.me/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true
```

El bundle vigente la consume y valida un objeto de ruta con `distance`,
`startedAt`, `endedAt`, `avgSpeed`, `maxSpeed` y `geoJSON`; no valida un bloque
de estadísticas separado. La lectura autorizada schema-only confirmó esa
forma y que `includeStats=true` fue aceptado, pero no estableció semántica,
unidades ni qué cambia al omitir el parámetro. No se observó un endpoint
dedicado `/stats`, `/telemetry` o equivalente.

El schema de `account-summary` contiene telemetría de estado embebida en
`vehicle.device.state`: `speed`, `battery`, `voltage`, `hdop`, `lat`, `lng`,
`odometer` (null en la muestra), `status`, `prevStatus`, `version`,
`detectedCan`, `location` y marcas de estado/coordenadas. El frontend vigente
valida/usa solo un subconjunto (`battery`, `status`, `lat`, `lng`, `hdop`,
`lastTs`); `hdop` se usa para dibujar un área de precisión. Los clientes
Python públicos exponen además velocidad, odómetro y HDOP, pero su
normalización de velocidad en `AT_REST` es lógica del cliente, no semántica
confirmada del backend.

No hay evidencia primaria actual o histórica en los repos de hard braking,
acceleration, overspeed como evento MAPIT, elevation, tire/oil state,
firmware-update API o un flujo de telemetría distinto del estado y rutas.
`speed`/`avgSpeed`/`maxSpeed` y distancia sí están observados; no se debe
derivar de ellos capacidades de conducción avanzada ni crear endpoints de
estadísticas. No hay un probe adicional justificado: cualquier trabajo futuro
debe reutilizar el detalle de ruta exacto anterior y conservar solo schema,
sin valores ni geometrías.

## Detalle de vehículo: contrato público y primer probe

Los dos clientes Home Assistant públicos construyen la lectura de detalle como:

```text
GET https://core.prod.mapit.me/v1/vehicles/{vehicleId}
```

No se observa query string ni body. El valor de `vehicleId` procede del campo
`id` de cada elemento de `vehicles` devuelto por `GET /v1/account-summary`;
ningún cliente público deriva el identificador desde el VIN, la matrícula, el
dispositivo o un identificador legado. El cliente d3vv3 usa `vehicle["id"]` y
el cliente citylife4 omite entradas sin un `id` utilizable. Para una primera
lectura debe seleccionarse el primer `id` no vacío de tipo string (y,
preferiblemente, de una entrada con `device` no nulo, como hace el filtro del
frontend actual). No se debe adivinar ni fabricar un identificador cuando la
colección no contiene un candidato.

El bundle frontend público vigente no llama a este endpoint Core: usa el objeto
de vehículo ya obtenido en `account-summary` para la vista principal. Su único
match de `/v1/vehicles/` corresponde a la ruta Geo
`/v1/vehicles/{vehicleId}/routes/{routeId}`. Por tanto, el detalle Core está
respaldado por clientes públicos históricos/alternativos, no por una captura del
frontend actual.

El probe autorizado produjo `samples/anonymized/vehicle-detail.schema.json`:
un objeto no nulo con campos `account`, `branch`,
`canAccessAccidentAlert`, `canAccessFallAlert`, `createdAt`, `crmMotoId`,
`dealer`, `demoBike`, `device`, `firebaseKey`, `id`, `km`, `legacy`, `model`,
`productPlanName`, `products`, `registration`, `registrationNumber`,
`saleDate`, `subscription`, `updatedAt` y `vin`. En el fixture todos esos
campos son no nulos; `products` es un array no nulo de strings. Las estructuras
anidadas mínimas son `account.id`, `dealer.id`, `device.id` y
`registration.{id,subtype}`, todos strings no nulos; `legacy` contiene `id`
number y `detail` con campos numéricos y string legacy; y `subscription` tiene
campos de cuenta, ciclo/estado, identificadores y un `stripeObject` anidado.

El detalle se solapa con el vehículo de `account-summary` en `id`, `branch`,
`device`, `firebaseKey`, `km`, `model`, `products`, `registrationNumber`,
`saleDate`, `subscription` y `vin`, pero no debe asumirse equivalencia de
forma. El detalle añade `account`, `dealer`, `createdAt`, `updatedAt`,
`crmMotoId`, `demoBike`, `productPlanName`, `registration`, `legacy` y dos
campos booleanos denominados `canAccess...Alert`; el resumen contiene en su
lugar (o además) `capabilities`, `dealerData`, `flags`,
`notificationSettings`, `pending`, `cancelled`, `name`, `product`,
`registrationId`, `registrationCompletedAt`, `transferable` e identificadores
legacy separados. Estos nombres y tipos no demuestran ninguna capacidad de
acción o entrega de alertas.

La estructura de `subscription` del detalle es más profunda en el fixture:
incluye `account`, `vehicle`, fechas, estado, identificadores CRM/Stripe y
`stripeObject`, que a su vez contiene objetos de facturación, `items`,
`metadata`, `plan`, `payment_settings` y `trial_settings`, además de campos
escalares, arrays y campos explícitamente nulos. Es estructura observada
únicamente; no se infieren operaciones de pago. El fixture no conserva valores,
por lo que tampoco establece semántica, unidades o estabilidad entre cuentas.

Para el primer probe de descubrimiento basta una sola lectura del primer
vehículo válido. El probe debe detenerse después de esa lectura, no recorrer
todos los vehículos y no encadenar rutas ni WebSocket. Debe reutilizar el GET
SigV4 existente, URL-encodear el segmento de path, aceptar campos desconocidos
y registrar solo nombres, tipos, nullabilidad y nesting. IDs de cuenta, vehículo,
dispositivo, legado, Firebase y dealer, VIN, IMEI, matrícula, nombre/modelo,
contactos/direcciones, coordenadas, timestamps, estado de dispositivo,
suscripción/pagos y cualquier cabecera o URL firmada se consideran sensibles y
deben eliminarse o sustituirse antes de persistir.

Este estado no confirma que el endpoint siga habilitado para todos los tenants,
ni su respuesta HTTP para vehículos pendientes/cancelados o sin dispositivo:
no se realizó una llamada protegida. Tampoco se ha confirmado si el backend
requiere algún escape adicional del identificador más allá de la codificación
normal del segmento URL.

## Operación de escritura descubierta (no ejecutada)

El bundle actual contiene una llamada:

```text
PUT https://core.prod.mapit.me/v1/accounts/{accountId}/preferences
```

El body representa preferencias de cuenta (el frontend valida al menos la zona horaria). Se documenta solo para evitar perder la evidencia; está fuera de la investigación de lectura y nunca se invocó.

## Websocket y divergencia de contrato

El frontend actual abre:

```text
wss://dsw.prod.mapit.me/accounts/{accountId}
```

El bundle vigente obtiene `accountId` de `account.id` del `account-summary`
que ya tiene en memoria y aplica `encodeURIComponent` al segmento. Obtiene el
token de su contexto de autenticación y, si no está vacío, lo pasa como el
único subprotocolo (`new WebSocket(url, [token])`); no lo coloca en query ni en
`Authorization`. El bundle principal público muestra que el getter devuelve
`fetchAuthSession().tokens?.idToken?.toString()`, por lo que el subprotocolo es
el Cognito `IdToken`; el probe autorizado confirmó conexión y aceptación del
subprotocolo para una sesión/cuenta, sin demostrar universalidad.

No envía mensaje inicial. Solo procesa frames de texto JSON y descarta JSON
inválido u objetos sin `id`/`deviceId` string. Normaliza `id` (preferido) o
`deviceId`, `status`, `battery`, `lat`, `lng`, `hdop` y `lastTs` (fallback a
`lastCoordTs`); los números finitos se convierten desde string cuando procede.
No se ha demostrado que estos sean todos los campos del servidor ni se han
establecido unidades.

El bundle implementa reconexión indefinida tras `close`, con backoff de
`min(30 s, 1 s * 2^attempts)` más jitter de 0--399 ms; `open` reinicia los
intentos. No contiene heartbeat/ping de aplicación ni handler explícito de
`error`. Al desmontar, deshabilitar o cambiar de cuenta cierra el socket y
limpia el temporizador. El detalle, el probe acotado y las restricciones de
retención están en [mapit-websocket-investigation.md](mapit-websocket-investigation.md).

El probe schema-only autorizado conectó, observó al menos un frame de texto con
forma válida y escribió únicamente
`samples/anonymized/websocket-message.schema.json`. Terminó por el timeout local
de diez segundos tras la conexión; esa finalización era esperada y no implicó
reconexión ni mensaje enviado. El schema conserva solo nombres, tipos y
nullabilidad de una captura, no valores ni semántica.

Los dos clientes Home Assistant públicos abren en cambio una URL derivada/fallback de la forma:

```text
wss://dsw.prod.mapit.me/devicestate/{deviceId}
```

también con el `IdToken` como subprotocolo y heartbeat del cliente. Esto puede
ser compatibilidad retroactiva o un contrato cambiado. Para la Fase 0 se debe
tomar el websocket account-level del bundle actual como hipótesis primaria y no
eliminar el fallback hasta una prueba autorizada.

## Autenticación de API

Los endpoints Core/Geo no se llaman con bearer token. Los clientes obtienen credenciales temporales del Identity Pool y calculan SigV4 con servicio `execute-api`, región `eu-west-1`, incluyendo `X-Id-Token` y `X-Amz-Security-Token`. La descripción completa está en [mapit-authentication.md](mapit-authentication.md).

## Runtime discovery

### Discovery vigente y corrección incorporada

La observación inicial del 2026-09-23 mostró que el HTML no tenía
`script[src]`: exponía `modulepreload` e import dinámico inline, y la versión
anterior de `bundle_urls()` devolvía `[]`, por lo que el diagnóstico imprimía
los identificadores Cognito como `null`. Esa descripción es histórica, no el
estado actual del código.

`src/mapit/config.py` ya recoge `script[src]`,
`link[rel="modulepreload"]`, `link[rel="preload"][as="script"]` e imports
dinámicos inline `.js`; normaliza con `urljoin`, deduplica, prioriza bundles
`main*`/`index*` y filtra por HTTPS y host del frontend. Los tests sintéticos
de `tests/test_config.py` cubren preloads, imports inline, deduplicación y
rechazo de hosts externos.

El discovery público actual fue verificado después de esa corrección: devuelve
la región `eu-west-1`, los tres campos Cognito y los hosts Core/Geo, mientras
que `scripts/discover_frontend.py` imprime solo `<discovered>` para los
identificadores. No se usan credenciales ni se hacen llamadas a API de datos.

Queda como riesgo normal el cambio futuro de bundler o de nombres de campos;
la mitigación vigente es el fallback configurable, validación estricta de
hosts y fixtures offline, no una nueva ampliación especulativa.

## Evidencia y referencias

- [Frontend público](https://app.mapit.me/) — HTML y entry assets observados el 2026-09-23.
- [Bundle público `useDashboardSummary`](https://app.mapit.me/assets/useDashboardSummary-Bt9fZxl2.js) — URL account-level, subprotocolo, parsing y reconexión observados el 2026-09-28.
- [d3vv3/hass-honda-mapit, `api.py`, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/api.py) — endpoints, firma, websocket y discovery.
- [d3vv3/hass-honda-mapit, README, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/README.md) — alcance funcional público.
- [citylife4/Honda-Mapit-HA, `api.py`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/custom_components/mapit_tracker/api.py) — revisión posterior con `account-summary`, persistencia y discovery.
- [citylife4/Honda-Mapit-HA, `mapit.py`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/mapit.py) — cliente standalone y paths históricos.
- [citylife4/Honda-Mapit-HA, `INTEGRATION_SUMMARY.md`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/docs/INTEGRATION_SUMMARY.md) — geofencing/eventos aparecen como mejoras futuras, no endpoints implementados.

## Preguntas abiertas para el supervisor

- ¿Debe el cliente inicial implementar solo lecturas actuales o conservar compatibilidad con `/v1/routes/{routeId}`?
- ¿El websocket account-level funciona para todos los tenants/dispositivos o solo para el frontend actual?
- ¿Hay paginación obligatoria (`lastEvaluatedKey`) o límites regionales para `/v1/routes`?
- ¿Qué estados HTTP y challenges Cognito deben mapearse en la UX sin filtrar detalles sensibles?
