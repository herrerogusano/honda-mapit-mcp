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
| Device-state websocket (actual) | `wss://dsw.prod.mapit.me/accounts/{accountId}` | bundle `useDashboardSummary` actual; alta |
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
| `GET` | `https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}&limit={limit}&month={month}&day={day}&from={from}&to={to}&includeInProgress={bool}` | bundle actual; `limit=1` también en el probe acotado | filtros opcionales observados; aceptación/semántica del resto pendiente |
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
unidades ni universalidad. La ruta histórica `/v1/routes/{routeId}` aparece
solo en los clientes Python públicos y sus consumidores esperan un objeto de
ruta con `geoJSON`; se conserva como compatibilidad pendiente, no como primera
opción de probe.

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

Si hay token, lo pasa como subprotocolo WebSocket; recibe JSON y extrae un identificador `id` o `deviceId` junto con campos de estado como `status`, `battery`, `lat`, `lng`, `hdop` y `lastTs`/`lastCoordTs`. El bundle implementa reconexión con backoff.

Los dos clientes Home Assistant públicos abren en cambio una URL derivada/fallback de la forma:

```text
wss://dsw.prod.mapit.me/devicestate/{deviceId}
```

también con el `IdToken` como subprotocolo. Esto puede ser compatibilidad retroactiva o un contrato cambiado. Para la Fase 0 se debe tomar el websocket account-level del bundle actual como hipótesis primaria y no eliminar el fallback hasta una prueba autorizada.

## Autenticación de API

Los endpoints Core/Geo no se llaman con bearer token. Los clientes obtienen credenciales temporales del Identity Pool y calculan SigV4 con servicio `execute-api`, región `eu-west-1`, incluyendo `X-Id-Token` y `X-Amz-Security-Token`. La descripción completa está en [mapit-authentication.md](mapit-authentication.md).

## Runtime discovery

### Fallo reproducido en el discovery actual

El comando público de diagnóstico (`PYTHONPATH=src; py scripts/discover_frontend.py`) devuelve la región y los hosts fallback, pero deja `user_pool_id`, `user_pool_client_id` e `identity_pool_id` a `null`.

La causa está aislada en la extracción de URLs, no en las expresiones de configuración:

- `bundle_urls()` solo recoge etiquetas `<script src="...">`.
- El HTML vigente de `https://app.mapit.me/` contiene cero scripts externos con `src`.
- En su lugar contiene seis `<link rel="modulepreload" href="/assets/<hash>.js">`, incluyendo el entry `main-<hash>.js`, y un `<script type="module">` inline que ejecuta `import("/assets/main-<hash>.js")`.
- Por tanto, `bundle_urls(html)` devuelve `[]`, no se descarga ningún bundle y `extract_runtime_config()` recibe texto vacío.

Evidencia de control: al descargar directamente el entry bundle público vigente (764020 bytes en la observación del 2026-09-23) y pasarlo a `extract_runtime_config()`, se obtienen correctamente la región `eu-west-1`, los tres campos Cognito y ambos hosts API. Esto demuestra que los patrones actuales para `userPoolId`, `userPoolClientId`, `identityPoolId`, `https://core.*` y `https://geo.*` sí alcanzan el formato actual.

### Propuesta mínima (pendiente de implementación)

Ampliar `bundle_urls()` para recoger, además de `script[src]`:

1. `<link rel="modulepreload" href="...js">`.
2. `<link rel="preload" as="script" href="...js">` si aparece en otra variante del bundler.
3. Como fallback, imports dinámicos inline `import("...js")`.

Reutilizar la misma normalización `urljoin`, deduplicación, orden `main*`/`index*` y validación HTTPS/host que ya usa `fetch_public_runtime_config()`. El fixture sintético mínimo (sin IDs reales) debería ser:

```html
<link rel="modulepreload" href="/assets/main-test.js">
<link rel="modulepreload" href="/assets/index-test.js">
<script type="module">import("/assets/main-test.js")</script>
```

El test debe comprobar que `bundle_urls()` devuelve `main-test.js` primero, que deduplica la importación inline y que `discover_runtime_config()` extrae valores de un bundle sintético con campos Cognito y hosts `core.prod.mapit.me`/`geo.prod.mapit.me`. Debe conservarse el test fail-closed para hosts externos/maliciosos.

### Flujo esperado tras el arreglo

Las implementaciones públicas:

1. descargan el HTML;
2. extraen rutas `/assets/*.js` y priorizan nombres `main*`/`index*`;
3. buscan `userPoolId`, `userPoolClientId`, `identityPoolId`, endpoints `https://core.*` y `https://geo.*`;
4. derivan región desde Cognito si no hay un campo `region`;
5. derivan el websocket reemplazando `core.` por `dsw.` y añadiendo `/devicestate` como fallback.

El método es frágil frente a cambios de bundler o nombres de campos; debe incluir fallback configurable y tests con HTML/bundles congelados.

## Evidencia y referencias

- [Frontend público](https://app.mapit.me/) — HTML y entry assets observados el 2026-09-23.
- [d3vv3/hass-honda-mapit, `api.py`, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/api.py) — endpoints, firma, websocket y discovery.
- [d3vv3/hass-honda-mapit, README, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/README.md) — alcance funcional público.
- [citylife4/Honda-Mapit-HA, `api.py`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/custom_components/mapit_tracker/api.py) — revisión posterior con `account-summary`, persistencia y discovery.
- [citylife4/Honda-Mapit-HA, `mapit.py`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/mapit.py) — cliente standalone y paths históricos.

## Preguntas abiertas para el supervisor

- ¿Debe el cliente inicial implementar solo lecturas actuales o conservar compatibilidad con `/v1/routes/{routeId}`?
- ¿El websocket account-level funciona para todos los tenants/dispositivos o solo para el frontend actual?
- ¿Hay paginación obligatoria (`lastEvaluatedKey`) o límites regionales para `/v1/routes`?
- ¿Qué estados HTTP y challenges Cognito deben mapearse en la UX sin filtrar detalles sensibles?
