# Mapit: endpoints descubiertos

Estado de investigación: 2026-09-23. Todos los endpoints de datos de esta nota son descubrimientos de código público; no se probaron con credenciales y no se invocó ninguna operación de escritura.

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
| `GET` | `https://core.prod.mapit.me/v1/account-summary` | bundle actual (`bG`), d3vv3, citylife4 | principal actual |
| `GET` | `https://core.prod.mapit.me/v1/vehicles/{vehicleId}` | d3vv3 y citylife4 | observado en clientes; no aparece en el fragmento principal actual |
| `GET` | `https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}` | d3vv3/citylife4; el frontend además admite filtros | principal para listado |
| `GET` | `https://geo.prod.mapit.me/v1/routes?vehicleId={vehicleId}&limit={limit}&month={month}&day={day}&from={from}&to={to}&includeInProgress={bool}` | bundle actual | filtros opcionales observados; confirmar combinaciones |
| `GET` | `https://geo.prod.mapit.me/v1/vehicles/{vehicleId}/routes/{routeId}?includeStats=true` | bundle actual | detalle actual del frontend |
| `GET` | `https://geo.prod.mapit.me/v1/routes/{routeId}` | d3vv3 y citylife4 | ruta de detalle legado; no asumir que sustituye a la actual |
| `GET` | `https://geo.prod.mapit.me/v1/reverse-geocoding/{lat}/{lng}?lang={language}` | bundle actual | geocodificación inversa |

Las respuestas observadas por los clientes Python se interpretan de forma general: `account-summary` devuelve un objeto con `account` y `vehicles`; el listado de rutas usa una colección `data`; los detalles de rutas contienen `geoJSON`, marcas temporales y métricas. Los esquemas completos deben validarse con fixtures autorizados antes de congelarlos.

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
