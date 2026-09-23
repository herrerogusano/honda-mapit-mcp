# Mapit: autenticación y configuración runtime descubiertas

Estado de investigación: 2026-09-23. Esta nota documenta únicamente evidencia pública; no se utilizaron credenciales, no se intentó iniciar sesión y no se ejecutaron escrituras.

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
ejecuta escrituras ni otros endpoints y no se ha ejecutado contra MAPIT en la
suite/CI.

## Evidencia pública

- [d3vv3/hass-honda-mapit, `api.py`, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/api.py) — flujo Cognito, SigV4, descubrimiento del bundle y fallback.
- [d3vv3/hass-honda-mapit, `const.py`, commit 034a467](https://github.com/d3vv3/hass-honda-mapit/blob/034a467b75e3e59003a3bd82a8ea46953772b2cf/custom_components/honda_mapit/const.py) — hosts y nombres de fallback; los IDs no se reproducen aquí.
- [citylife4/Honda-Mapit-HA, `api.py`, commit 4bc092b](https://github.com/citylife4/Honda-Mapit-HA/blob/4bc092bab6125d0f7cb8e59780d04fe8ee90dda9/custom_components/mapit_tracker/api.py) — misma secuencia, persistencia y overrides.
- [app.mapit.me](https://app.mapit.me/) y su bundle actual — configuración Amplify pública y cliente SigV4; los nombres hashados de assets son efímeros.
- [AWS Cognito: InitiateAuth](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_InitiateAuth.html) y [AWS Cognito Identity: GetCredentialsForIdentity](https://docs.aws.amazon.com/cognitoidentity/latest/APIReference/API_GetCredentialsForIdentity.html).

## Preguntas abiertas

- El 2026-09-23, el propietario completó el probe local autorizado con resultado
  `Complete`: el flujo `USER_PASSWORD_AUTH` observado fue aceptado, el Identity
  Pool entregó credenciales temporales y no apareció un challenge adicional.
  No se conservaron tokens, credenciales, identificadores ni datos de cuenta.
- Definir almacenamiento de refresh token para el cliente del proyecto sin exponer secretos.
- Resolver la divergencia del websocket actual frente al fallback legado; está documentada en `docs/mapit-endpoints-discovered.md`.
