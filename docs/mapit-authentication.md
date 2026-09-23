# Mapit: autenticación y configuración runtime descubiertas

Estado de investigación: 2026-09-23. Esta nota documenta evidencia pública y
probes autorizados de lectura; no se retuvieron credenciales, tokens, datos de
cuenta ni se ejecutaron escrituras.

## Resumen ejecutivo

El patrón observado es Cognito User Pool + Cognito Identity Pool + AWS Signature V4 frente a API Gateway:

1. El frontend público `https://app.mapit.me/` carga un bundle JavaScript con una configuración Amplify Cognito embebida.
2. La pantalla web solicita email y contraseña. Las dos implementaciones públicas revisadas realizan `InitiateAuth` con `USER_PASSWORD_AUTH` y el app client del User Pool.
3. La respuesta de autenticación contiene tokens Cognito (`IdToken`, `AccessToken` y, normalmente, `RefreshToken`).
4. El `IdToken` se intercambia mediante `GetId` y `GetCredentialsForIdentity` por credenciales AWS temporales del Identity Pool.
5. Las llamadas Mapit se firman con SigV4 para el servicio `execute-api` en `eu-west-1` y añaden `X-Id-Token` y `X-Amz-Security-Token`.

Los identificadores de User Pool, app client, Identity Pool, cuenta, vehículo, dispositivo, ruta, tokens y credenciales se omiten o redactan deliberadamente aquí.

## Configuración runtime observada

El HTML de `app.mapit.me` obtenido el 2026-09-23 referencia un entry bundle con nombre hashado (`/assets/main-<hash>.js`). En ese bundle se observó una llamada equivalente a:

```text
Amplify.configure({
  Auth: { Cognito: {
    userPoolId: "eu-west-1_<redacted>",
    userPoolClientId: "<redacted>",
    identityPoolId: "eu-west-1:<redacted>",
    allowGuestAccess: true
  }}
})
```

La región puede derivarse del prefijo de los identificadores Cognito. El bundle actual no expone una URL de User Pool distinta del endpoint regional estándar. `allowGuestAccess: true` es una configuración de identidad, no evidencia de que la API de datos permita acceso anónimo: las llamadas de datos observadas están protegidas por middleware de sesión y SigV4.

Las dos integraciones públicas incorporan el mismo fallback de producción (los valores sensibles están redactados):

```text
region: eu-west-1
core API: https://core.prod.mapit.me
geo API: https://geo.prod.mapit.me
device-state WS: wss://dsw.prod.mapit.me/devicestate  # fallback legado
```

Ambas también intentan descubrir la configuración desde los bundles públicos antes de usar el fallback. Los patrones soportados son tanto constantes `VITE_*` antiguas como campos Amplify actuales (`userPoolId`, `userPoolClientId`, `identityPoolId` y `endpoint`).

## Secuencia Cognito reproducible (sin credenciales)

Los clientes públicos hacen las siguientes peticiones JSON 1.1 a endpoints regionales estándar:

### User Pool

```text
POST https://cognito-idp.eu-west-1.amazonaws.com/
Content-Type: application/x-amz-json-1.1
X-Amz-Target: AWSCognitoIdentityProviderService.InitiateAuth
```

Login inicial (forma observada en ambos repositorios):

```json
{
  "AuthFlow": "USER_PASSWORD_AUTH",
  "ClientId": "<redacted>",
  "AuthParameters": {
    "USERNAME": "<user-supplied-email>",
    "PASSWORD": "<user-supplied-password>"
  },
  "ClientMetadata": {}
}
```

Renovación (sin volver a enviar contraseña):

```json
{
  "AuthFlow": "REFRESH_TOKEN_AUTH",
  "ClientId": "<redacted>",
  "AuthParameters": {"REFRESH_TOKEN": "<refresh-token>"},
  "ClientMetadata": {}
}
```

El cliente conserva `IdToken` para la federación y calcula su expiración a partir de `exp` del JWT o `ExpiresIn`.

### Identity Pool

```text
POST https://cognito-identity.eu-west-1.amazonaws.com/
Content-Type: application/x-amz-json-1.1
X-Amz-Target: AWSCognitoIdentityService.GetId
```

```json
{
  "IdentityPoolId": "eu-west-1:<redacted>",
  "Logins": {
    "cognito-idp.eu-west-1.amazonaws.com/<user-pool-id>": "<id-token>"
  }
}
```

Después:

```text
X-Amz-Target: AWSCognitoIdentityService.GetCredentialsForIdentity
```

```json
{
  "IdentityId": "eu-west-1:<redacted>",
  "Logins": {
    "cognito-idp.eu-west-1.amazonaws.com/<user-pool-id>": "<id-token>"
  }
}
```

La respuesta entrega credenciales temporales (`AccessKeyId`, `SecretKey`, `SessionToken`, `Expiration`). La forma y la semántica coinciden con la documentación primaria de AWS para [InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) y [GetCredentialsForIdentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html).

## Firma de llamadas Mapit

El frontend y las dos implementaciones construyen una firma AWS4 para `execute-api` con:

- método, path y query canónicos;
- `Accept: application/json`, `x-amz-date` y `Authorization: AWS4-HMAC-SHA256 ...`;
- `X-Amz-Security-Token` con la credencial temporal;
- `X-Id-Token` con el ID token Cognito;
- origen/referer `https://app.mapit.me` en los clientes Python.

No se observó un header `Authorization: Bearer` para la API Mapit. Un cliente nuevo debe tratar todos los tokens, secretos y credenciales temporales como secretos efímeros y nunca persistirlos en logs.

## Diferencias de persistencia entre implementaciones

- `d3vv3/hass-honda-mapit`: mantiene tokens/credenciales en memoria y redescubre runtime con fallback.
- `citylife4/Honda-Mapit-HA`: persiste únicamente piezas de sesión para reanudar tras reinicio (refresh token, identity id y account id), y admite overrides de Cognito para entradas antiguas.

Para este proyecto, la opción segura es persistir solo refresh token cifrado/gestionado por el runtime elegido; no persistir contraseñas, access keys, secret keys ni tokens completos en texto plano.

## Decisión implementada para probes locales Windows

La dependencia de producción actual sigue deliberadamente vacía. Para los
probes locales Windows se añade como extra opcional `keyring` fijado a una
versión revisada y se exige su backend nativo **Windows Credential Locker /
Credential Manager**. La documentación de `keyring` enumera Windows Credential
Locker entre los backends de sistema soportados. Microsoft recomienda para
nuevo desarrollo usar Windows Credential Manager antes que almacenamiento
casero, y deja DPAPI como alternativa para secretos locales:
[Handling Passwords](https://learn.microsoft.com/en-us/windows/win32/secbp/handling-passwords),
[Kinds of Credentials](https://learn.microsoft.com/en-us/windows/win32/secauthn/kinds-of-credentials)
y [keyring: supported backends](https://keyring.readthedocs.io/en/stable/).

La decisión es **Credential Manager a través de `keyring`, sin fallback a
backend de archivo**. No se usará `keyrings.cryptfile`, un `.env`, JSON,
registro propio ni DPAPI envuelto manualmente como almacenamiento primario.
DPAPI sigue siendo una alternativa válida solo si una implementación futura
decide llamar directamente a `CryptProtectData` con asociación al usuario
(nunca `CRYPTPROTECT_LOCAL_MACHINE`); Microsoft documenta que esa función cifra
y verifica integridad, normalmente solo para el mismo usuario y equipo:
[CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata).
El uso directo de DPAPI exigiría además gestionar un blob, ACLs, borrado y
compatibilidad de perfil, por lo que no se recomienda duplicar la protección
que ya ofrece el almacén de credenciales.

### Único secreto persistente y alcance

- Guardar únicamente el `RefreshToken` de Cognito en una entrada Generic
  Credential del usuario Windows actual. El nombre de servicio/cuenta será
  constante y no incluirá email, account ID, tenant, vehículo ni otros datos
  personales; el diseño soporta un único perfil MAPIT activo por usuario
  Windows y exige borrar/reautenticar al cambiar de cuenta.
- No guardar contraseña, email, `IdToken`, `AccessToken`, `IdentityId`,
  `AccessKeyId`, `SecretKey`, `SessionToken`, account/vehicle IDs, headers,
  payloads ni URLs firmadas. Tokens y credenciales temporales solo viven en
  memoria del proceso.
- No aceptar como mecanismo de persistencia variables de entorno, archivos,
  argumentos de línea de comandos, stdout/stderr, excepciones, dumps ni
  fixtures. `MAPIT_PASSWORD` puede permanecer solo como compatibilidad de
  pruebas/manual explícita hasta una decisión de implementación; los probes
  interactivos deben preferir GUI/entrada segura y nunca copiar esa contraseña
  al almacén.
- El proceso debe verificar que el backend efectivo de `keyring` es el vault
  Windows esperado. Backend nulo, `fail` o de archivo implica *fail-closed* y
  fallback a GUI; nunca se debe degradar silenciosamente a texto plano.

La implementación actual ofrece `.[windows-auth]` con `keyring>=25.6,<26`
únicamente bajo `sys_platform == "win32"`. El import es lazy, por lo que CI
Linux no instala ni importa `keyring`. `WindowsKeyringRefreshTokenStore`
acepta exclusivamente el backend `keyring.backends.Windows.WinVaultKeyring`,
usa servicio/cuenta constantes (`mapit-client`/`refresh-token`) y hace
`save`/`load`/`delete` idempotentes sin fallback a archivos.

### Lifecycle implementado

1. **Load:** al iniciar, leer solo el refresh token desde Credential Manager.
   Si falta, el vault falla, el backend no es el esperado o el token no puede
   recuperarse, no se intenta una llamada protegida: abrir el flujo GUI.
2. **Refresh:** usar `REFRESH_TOKEN_AUTH` con el app client configurado, sin
   volver a enviar contraseña. Cognito documenta que `InitiateAuth` acepta
   `REFRESH_TOKEN_AUTH` y que devuelve tokens nuevos; el token de refresh puede
   expirar o revocarse ([InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html),
   [refresh tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html)).
   Si llega un refresh token nuevo, reemplazar el anterior en el vault solo
   después de validar una respuesta completa y hacerlo como actualización
   atómica. Nunca imprimir el token ni el body de error.
3. **Identity credentials:** con el `IdToken` renovado, repetir en memoria
   `GetId`/`GetCredentialsForIdentity`. Las credenciales AWS temporales se
   conservan solo en `MapitSession`, se renuevan antes de `Expiration` y no se
   escriben en Credential Manager; AWS documenta su naturaleza temporal y el
   campo `Expiration` ([identity-pool flow](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html),
   [GetCredentialsForIdentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html)).
4. **Missing/expired/revoked:** ante refresh ausente se vuelve a GUI. Un rechazo
   HTTP 4xx explícito de Cognito elimina el token almacenado sin registrar el
   motivo sensible. Los fallos transitorios de discovery/red y las respuestas
   no clasificadas fallan cerrados, pero no destruyen un token potencialmente
   válido. Un challenge no soportado también termina *fail-closed* y pasa a GUI,
   sin exponer `Session` ni parámetros.
5. **Save:** tras un login GUI exitoso, guardar únicamente el refresh token
   devuelto, si el usuario ha habilitado persistencia local. Si no hay refresh
   token, no guardar nada. La contraseña se descarta inmediatamente después de
   `USER_PASSWORD_AUTH`.
6. **Delete:** exponer borrado explícito/logout y ejecutarlo también al detectar
   revocación o cambio de cuenta. El borrado debe ser idempotente y no revelar
   si existía una entrada.

`REFRESH_TOKEN_AUTH` no funciona en app clients con refresh-token rotation
habilitada; AWS indica que esos clientes deben usar el mecanismo de refresh
correspondiente a rotation. Por ello el cliente debe detectar ese caso sin
reintentos infinitos y caer en GUI hasta que se implemente el flujo compatible.

### Amenazas y límites

Credential Manager protege el secreto en reposo para el usuario Windows, pero
no protege frente a malware, inyección, depuración o código arbitrario que se
ejecute con la misma sesión/usuario mientras el probe está activo. DPAPI tiene
además límites de perfil/equipo y `CRYPTPROTECT_LOCAL_MACHINE` ampliaría el
acceso a otros usuarios del equipo; por eso se prohíbe esa opción. La revocación
remota, expiración, rotación y cambio de app client siguen requiriendo
fallback a GUI. Ningún mecanismo local elimina la necesidad de minimizar el
tiempo de vida en memoria y de redactar errores.

### Criterios de aceptación cubiertos

- En una máquina Windows, `save/load/delete` usa exclusivamente Credential
  Manager del usuario actual; no crea archivos de secretos ni claves de
  registro propias.
- La contraseña nunca aparece en configuración persistida, logs, errores,
  `repr`, salida de probes, trazas, tests o artefactos; tampoco aparecen
  refresh/ID/access tokens ni credenciales AWS.
- Ausencia, backend incorrecto, expiración, revocación, challenge o error de
  vault producen una salida categorizada y fallback GUI, sin llamada de datos
  cuando no existe sesión válida.
- `USER_PASSWORD_AUTH` solo se usa con entrada interactiva segura; el camino
  de reanudación usa únicamente `REFRESH_TOKEN_AUTH` y actualiza de forma
  segura un refresh token rotado.
- Las credenciales temporales del Identity Pool se mantienen en memoria,
  respetan `Expiration` y se descartan al terminar o invalidar la sesión.
- Los tests usan transportes/keyrings falsos y secretos sintéticos; CI no
  requiere credenciales, acceso al vault del desarrollador ni red MAPIT.

## Probe manual seguro

El repositorio incluye `scripts/run_auth_probe.ps1` para una prueba interactiva
autorizada en Windows. Solicita email y contraseña con `Read-Host
-AsSecureString`, convierte cada valor únicamente en memoria para el proceso
hijo `scripts/probe_auth.py`, y libera ambos BSTR en `finally`. También restaura
los valores previos de `MAPIT_EMAIL`, `MAPIT_PASSWORD` y `PYTHONPATH` si
existían.

El probe ejecuta discovery público y el flujo Cognito documentado, pero nunca
realiza probes de cuenta ni llamadas de datos. Su salida es un JSON reducido
con `success`, región, expiraciones ISO y booleanos de disponibilidad. No
imprime email, identificadores, tokens, credenciales AWS, headers ni payloads
de excepciones. Los errores se convierten en categorías seguras y producen un
código de salida distinto de cero; un challenge Cognito no soportado se
categoriza sin exponer su `Session`.

Como alternativa local, `scripts/auth_prompt_gui.py` ofrece una ventana
Tkinter sin autocomplete: tanto email como contraseña se muestran enmascarados,
se limpian al iniciar y nunca se escriben en `.env` ni en archivos. La red y
la autenticación se ejecutan en un hilo daemon; la cola y `after` reservan las
actualizaciones de widgets para el hilo principal. El resultado visible usa el
mismo resumen redactado y el cierre de la ventana no persiste los valores.

## Probe `account-summary` schema-only

La GUI `scripts/account_summary_prompt_gui.py` reutiliza discovery y Cognito,
y después hace exactamente un `GET /v1/account-summary` mediante el cliente
read-only (salvo el único recovery controlado de 401/403). Convierte la
respuesta inmediatamente a un esquema recursivo que conserva únicamente
nombres de campos, tipos, nullabilidad y forma; descarta valores, longitudes,
conteos y ejemplos. Las claves dinámicas que parecen email, UUID, token o ID
largo se sustituyen por marcadores neutros.

El esquema se guarda atómicamente en
`samples/anonymized/account-summary.schema.json`. La UI solo muestra éxito o
error categorizado, claves top-level ya seguras y la ruta. Este probe no
ejecuta escrituras ni otros endpoints; se ejecutó manualmente con éxito el
2026-09-23 y nunca forma parte de la suite/CI.

## Probe de detalle de vehículo

`scripts/vehicle_detail_prompt_gui.py` es el siguiente paso read-only. Tras
discovery y Cognito, solicita `GET /v1/account-summary` y selecciona solamente
en memoria el primer elemento de `vehicles` cuyo `id` sea una cadena no vacía y
cuyo `device` no sea nulo. El ID se codifica estrictamente como un único
segmento URL y se realiza exactamente un `GET /v1/vehicles/{encodedId}`; si no
hay vehículo válido, no se llama al endpoint de detalle.

La respuesta de detalle se convierte inmediatamente con el mismo
`schema_only`, y solo se escribe atómicamente
`samples/anonymized/vehicle-detail.schema.json`. No se guarda el schema del
account-summary, payload crudo, ID ni conteo. La interfaz muestra únicamente
estado, claves top-level seguras y ruta. Se ejecutó manualmente con éxito el
2026-09-23; el fixture resultante contiene únicamente estructura y tipos.

La GUI de rutas intenta primero `REFRESH_TOKEN_AUTH` con el token guardado. Si
falta, el backend no es nativo o la reanudación falla, muestra el formulario sin
hacer llamadas de datos. Solo un rechazo HTTP 4xx explícito de Cognito borra la
entrada; fallos transitorios o no clasificados la conservan.
El login manual guarda únicamente el refresh token tras una respuesta completa;
si Cognito rota el token, la entrada se actualiza. El botón `Forget saved
session` ejecuta un borrado explícito e idempotente. Sin sesión válida no se
realiza ninguna llamada de datos.

## Evidencia pública

- [d3vv3/hass-honda-mapit, `api.py`, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/api.py) — flujo Cognito, SigV4, descubrimiento del bundle y fallback.
- [d3vv3/hass-honda-mapit, `const.py`, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/const.py) — hosts y nombres de fallback; los IDs no se reproducen aquí.
- [citylife4/Honda-Mapit-HA, `api.py`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/custom_components/mapit_tracker/api.py) — misma secuencia, persistencia y overrides.
- [app.mapit.me](https://app.mapit.me/) y su bundle actual — configuración Amplify pública y cliente SigV4; los nombres hashados de assets son efímeros.
- [AWS Cognito: InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) y [AWS Cognito Identity: GetCredentialsForIdentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html).
- [AWS Cognito: refresh tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html) — expiración, revocación, rotation y compatibilidad de `REFRESH_TOKEN_AUTH`.
- [AWS Cognito: identity-pool authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html) — `GetId`, credenciales temporales y expiración.
- [Microsoft: Handling Passwords](https://learn.microsoft.com/en-us/windows/win32/secbp/handling-passwords), [Generic Credentials](https://learn.microsoft.com/en-us/windows/win32/secauthn/kinds-of-credentials) y [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) — orden recomendado Credential Manager/DPAPI y límites de protección.
- [Python keyring](https://keyring.readthedocs.io/en/stable/) — interfaz y backends de almacén del sistema, incluido Windows Credential Locker.

## Preguntas abiertas

- El 2026-09-23, el propietario completó el probe local autorizado con resultado
  `Complete`: el flujo `USER_PASSWORD_AUTH` observado fue aceptado, el Identity
  Pool entregó credenciales temporales y no apareció un challenge adicional.
  No se conservaron tokens, credenciales, identificadores ni datos de cuenta.
- Validar el backend nativo Credential Manager en una máquina Windows con el
  extra opcional instalado; CI solo cubre stores/transports falsos.
- Confirmar si el app client real tiene refresh-token rotation habilitada antes de
  depender de `REFRESH_TOKEN_AUTH` para reanudación automática.
- Resolver la divergencia del websocket actual frente al fallback legado; está documentada en `docs/mapit-endpoints-discovered.md`.
