# MAPIT WebSocket investigation

Estado: investigación pública y diseño de probe, 2026-09-28. No se abrió una
conexión autenticada en esta investigación y no se conservaron mensajes.

## Contrato observado en el frontend vigente

El bundle público `useDashboardSummary-Bt9fZxl2.js` usa como base exacta
`wss://dsw.prod.mapit.me` y construye:

```text
wss://dsw.prod.mapit.me/accounts/{encodeURIComponent(accountId)}
```

`accountId` es `account.id` del resultado en memoria de la consulta de
`account-summary`; el hook se habilita solamente cuando esa consulta termina
con éxito. El valor se recorta (`trim`) antes de construir la ruta. No se
deriva del VIN, del vehículo ni del dispositivo.

Antes de abrir el socket, el frontend obtiene el token vigente de su contexto
de autenticación. En el bundle principal público, el getter usado por este
chunk devuelve `fetchAuthSession().tokens?.idToken?.toString()`. Si existe,
llama al constructor equivalente a
`new WebSocket(url, [token])`: el token se envía como el único subprotocolo
WebSocket, no como `Authorization` ni como query parameter. Por tanto es el
Cognito `IdToken`; la aceptación live del subprotocolo queda pendiente. Si el
getter no devuelve token, el
frontend abre el socket sin lista de subprotocolos.

No se envía ningún mensaje de aplicación al abrir. El frontend acepta solo
frames de texto JSON. Ignora JSON inválido y objetos sin un `id` o `deviceId`
string. Para los demás objetos normaliza, sin conservar el resto del payload:

```text
{
  id: string,
  status: string | null,
  battery: finite number | null | absent,
  lat: finite number | null | absent,
  lng: finite number | null | absent,
  hdop: finite number | null | absent,
  lastTs: finite number | null | absent
}
```

`id` toma primero `id` y después `deviceId`; `lastTs` toma primero `lastTs` y
después `lastCoordTs`. Los strings numéricos finitos se convierten a número;
los valores no numéricos se omiten. Esta es una forma de consumo del frontend,
no una afirmación de que el backend solo envíe esos campos ni de que los
nombres tengan unidades conocidas.

## Ciclo de vida

- `onopen` reinicia el contador de reintentos y cancela el temporizador.
- `onclose` vuelve a conectar sin límite explícito. El retardo es
  `min(30 s, 1 s * 2^attempts) + jitter` entero de 0--399 ms.
- No se observó heartbeat, ping de aplicación ni mensaje periódico enviado por
  este bundle.
- No hay handler explícito `onerror`; el código sí reacciona a `close`.
- Al desmontar, deshabilitar el hook o cambiar de cuenta, cancela el temporizador
  y cierra un socket `OPEN` o `CONNECTING`.

## Diferencia con el contrato legado

Los clientes públicos d3vv3 y citylife4 construyen el fallback:

```text
wss://dsw.prod.mapit.me/devicestate/{deviceId}
```

y pasan el `IdToken` como subprotocolo, además de configurar heartbeat en su
cliente WebSocket. Esa ruta es evidencia de compatibilidad histórica, no una
confirmación de que el frontend actual la use. No se debe probar o eliminar el
fallback hasta que el contrato account-level haya sido verificado y el
supervisor autorice una comparación.

## Probe manual mínimo recomendado

Cuando el supervisor autorice una conexión autenticada, limitarla a una sola
sesión y a un solo `accountId` obtenido en memoria:

1. Reutilizar la sesión guardada; ejecutar `account-summary` únicamente para
   obtener `account.id` en memoria. No imprimirlo ni escribirlo.
2. Abrir la URL account-level con el `IdToken` como único subprotocolo. No
   enviar mensaje inicial y desactivar la reconexión automática del probe.
3. Esperar como máximo 10 segundos o hasta 3 frames. Registrar únicamente
   categorías booleanas (`connected`, `valid_shape_observed`, `closed`) y
   nombres de campos con tipos/nullabilidad; no guardar valores, conteos,
   identificadores, coordenadas, timestamps ni frames sin filtrar.
4. Cerrar localmente al alcanzar el límite. Reducir close/error a una categoría
   estable sin URL, razón, cabeceras o cuerpo. No abrir el endpoint legado en
   el mismo probe.

Este probe puede confirmar transporte, subprotocolo aceptado y si aparece un
frame con la forma consumida por el frontend; no puede establecer semántica de
estado, unidades, frecuencia, cobertura de todos los dispositivos ni ausencia
de heartbeat del servidor.

## Implementación local

`scripts/probe_websocket.py` implementa este alcance con la dependencia
opcional `.[realtime]` (`websockets>=17.1,<18`) importada de forma perezosa.
Usa `websockets.sync.client.connect`, no envía mensajes, no reconecta y cierra
localmente al llegar a tres frames o al límite total de diez segundos. El
conector recibe `max_size=64 KiB` y `max_queue=4`. Solo los frames de texto JSON
objeto que contienen `id` o `deviceId` como cadena no vacía se convierten
inmediatamente con `schema_only`; sus esquemas se fusionan sin conservar
valores. El archivo `samples/anonymized/websocket-message.schema.json` solo se
escribe tras observar una forma válida. Sin frame válido el resultado puede
confirmar transporte (`connected`) pero no crea fixture. Handshake HTTP,
timeout, cierre, transporte y dependencia ausente se reducen a categorías
seguras, sin URL, subprotocolo, razón, headers, IDs ni payload.

## Evidencia pública

- [Bundle actual `useDashboardSummary`](https://app.mapit.me/assets/useDashboardSummary-Bt9fZxl2.js) — URL, extracción de `account.id`, subprotocolo, parsing y reconexión.
- [d3vv3/hass-honda-mapit, `api.py`](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/api.py) — ruta legacy y subprotocolo del cliente histórico.
- [citylife4/Honda-Mapit-HA, `api.py`](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/custom_components/mapit_tracker/api.py) — revisión pública del cliente legacy.

## Preguntas abiertas

- ¿El gateway acepta siempre `IdToken` como subprotocolo para la ruta
  account-level, o requiere otra condición de sesión?
- ¿Cuál es el frame inicial real y qué eventos adicionales puede emitir el
  servidor?
- ¿El servidor usa ping/pong WebSocket estándar aunque el frontend no tenga un
  heartbeat de aplicación?
- ¿Sigue disponible `/devicestate/{deviceId}` para todos los dispositivos?
