# Phase 0 Status

## Objective

Understand MAPIT and build a small, independent Python client for authentication,
SigV4-signed read-only requests, endpoint and payload exploration, anonymization,
and manual WebSocket investigation.

## Current State

- Phase 0 is **COMPLETE** as of 2026-09-28 at the documented evidence level;
  the closure table below preserves partial areas and explicit unknowns.
- Phase 0 started on 2026-09-23.
- Repository began empty with no commits or configured remote.
- Persistent Researcher, Implementer, and Tester roles have been established.
- Initial research into the two reference repositories and the current MAPIT
  frontend is documented.
- MAPIT passwords were entered only into local in-memory GUI probes; they were
  not logged, persisted, committed, or sent through chat. The only optional
  persistent secret is a Cognito refresh token in the current Windows user's
  native Credential Manager.
- Minimal standalone Python scaffold is implemented with typed configuration,
  public runtime discovery, Cognito session handling, SigV4 GET signing, and a
  Core/Geo read-only client. Endpoint overrides/discovery are fail-closed to
  HTTPS MAPIT Core/Geo hosts, unsupported Cognito challenges fail before any
  Identity Pool call, and expired sessions without a refresh callback fail
  closed. Offline tests pass (`168 passed` on the 2026-09-28 audit). Session and routes GUI failures are
  now exposed only as stable public categories (`discovery_failed`,
  `authentication_rejected`/`authentication_failed`, or
  `credential_store_failed`); keyring size/backend failures remain fail-closed
  without a file fallback.
- The Windows refresh-token store now uses the documented `mapit-refresh-v1`
  manifest plus up to eight UTF-8 chunks, with strict hash/schema validation,
  rollback on write failure, idempotent cleanup, and legacy migration only
  after successful verification. Native WinVault tests on this host confirmed
  save/load, replacement through the alternate staging bank, Unicode handling,
  and cleanup for synthetic tokens longer than 3,000 characters.
- On 2026-09-23, public frontend discovery was verified without credentials:
  HTML/bundle discovery returned the three Cognito identifiers only as redacted
  `<discovered>` placeholders and the expected Core/Geo hosts.
- CI is documented for `feature/* -> develop -> main`, runs tests with
  application network blocked across Python 3.11-3.13, and has no MAPIT secrets
  or live MAPIT access. GitHub
  `dev`/`prod` are project environments only; the current private plan returned
  HTTP 422 for Environment protection and HTTP 403 for branch protection, so no
  platform enforcement is claimed.
- A manual Windows authentication probe is available with secure prompts and
  redacted categorized output. On 2026-09-23 the owner completed it successfully:
  User Pool authentication, Identity Pool exchange, and temporary credentials
  were confirmed without persisting any secret or account identifier.
- A Tkinter GUI alternative is available for local desktops; its non-UI probe
  logic is tested offline, while the GUI itself is not opened in CI.
- The read-only `account-summary` GUI probe is implemented with immediate
  schema-only conversion and atomic output to
  `samples/anonymized/account-summary.schema.json`. On 2026-09-23 the owner ran
  it successfully; the live SigV4/header contract was accepted and only the
  value-free schema was retained.
- The value-free anonymizer now merges heterogeneous array objects safely,
  retaining only one-sided fields, nullability, and mixed primitive types;
  source values, counts, and examples remain excluded.
- The vehicle-detail GUI probe was completed successfully on 2026-09-23. It
  selected the first eligible vehicle in memory, URL-encoded one detail path
  segment, and retained only the value-free schema at
  `samples/anonymized/vehicle-detail.schema.json`. The dedicated response adds
  substantially richer subscription/Stripe and legacy-detail structure than
  `account-summary`; this is structural evidence only, not evidence of write
  capabilities.
- The bounded routes-list GUI probe completed an authorized run with the saved
  session (`session_valid=true`), after account-summary success. It performed
  exactly one Geo read with an in-memory `vehicleId` plus `limit=1`, followed no
  cursor, and persisted only the value-free schema at
  `samples/anonymized/routes-list.schema.json`. The fixture confirms a root
  `data` array and nested route/GeoJSON structure, but no top-level pagination
  metadata; defaults, history completeness, and units remain open. Its final
  Geo HTTP status, when available, is reduced to an allowlisted category
  (`routes_list_http_400`, `_401`, `_403`, `_404`, `_429`, `_5xx`, or generic)
  without exposing URL, body, headers, or IDs. Transport and invalid-response
  failures are separately reduced to `routes_list_transport_failed` or
  `routes_list_invalid_response` (with `account_summary_` equivalents before
  vehicle selection); schema and persistence failures are categorized as
  `routes_list_schema_failed` and `routes_list_persist_failed`.
- Session enrollment is now separated into `scripts/session_setup_gui.py`;
  it performs only discovery plus `USER_PASSWORD_AUTH` and persists the refresh
  token. `scripts/check_saved_session.py` validates discovery plus the saved
  refresh/Identity Pool exchange without Core/Geo. The routes GUI no longer
  asks for credentials; without a valid saved session it instructs the user to
  run the setup GUI and makes no data call.
- Refresh-token persistence is implemented as an optional Windows-only,
  fail-closed native keyring backend. The routes GUI attempts a saved refresh
  session first and exposes explicit forget; it does not enroll sessions;
  no vault or live-data call is used by CI.
- A non-interactive saved-session route-detail probe is implemented in
  `scripts/probe_route_detail.py`. It is bounded to account-summary, one
  routes-list request (`vehicleId` + `limit=1`), and one current detail GET
  (`includeStats=true`), with strict segment encoding and immediate
  schema-only atomic persistence. The authorized live run completed and
  retained only `samples/anonymized/route-detail.schema.json`; no route values,
  counts, IDs, coordinates, headers, tokens, or raw payload were retained.
  The fixture confirms the root route-detail shape and sample nullability, but
  not statistics semantics, units, or cross-account stability.
- A non-interactive `scripts/probe_route_history_filters.py` is implemented
  and its authorized live run completed exactly two monthly `from`/`to` Geo
  reads with `vehicleId` and `limit=1`. Both were accepted; neither response
  exposed `lastEvaluatedKey`. It validated only root/data shape, persisted
  nothing, and retained no counts, dates, IDs, route values, coordinates, or
  raw responses. This does not establish universal absence of pagination or
  complete historical reach.
- La investigación pública del WebSocket account-level quedó documentada en
  `docs/mapit-websocket-investigation.md`: el frontend vigente usa
  `/accounts/{encodeURIComponent(account.id)}`, pasa el `IdToken` como único
  subprotocolo cuando está disponible, no envía mensaje inicial y reconecta
  tras `close` con backoff. El probe live fue aceptado, observó forma válida,
  terminó por el timeout local esperado tras la conexión y retuvo únicamente
  `samples/anonymized/websocket-message.schema.json`, sin valores, IDs ni raw
  frames.
- El probe account-level `scripts/probe_websocket.py` ya está implementado con
  `websockets` opcional y lazy. Queda limitado a una lectura de cuenta, una
  conexión, tres frames de texto y diez segundos; no envía mensajes ni
  reconecta. Solo un frame válido con `id`/`deviceId` produce el schema-only
  fusionado. El fixture schema-only fue creado por la ejecución live
  autorizada; handshake, close, timeout y demás diagnósticos siguen reducidos
  a categorías seguras.
- El gate histórico `scripts/probe_route_history_coverage.py` fue ejecutado con
  la sesión autorizada: la primera lectura sin filtros superó el límite de 2
  MiB y terminó fail-closed como `response_too_large`, antes de decodificar
  JSON. No hubo controles mensuales, inspección de conteo/fechas/paginación ni
  persistencia. El supervisor acepta no aumentar bytes ni barrer meses; el
  histórico queda `PARTIAL`.
- La investigación pública de zonas/geofences y alertas/eventos no encontró
  rutas GET dedicadas en los bundles vigentes ni en d3vv3/citylife4. El schema
  de `account-summary` sí contiene `geofenceAlertCritical` y flags de acceso,
  pero solo como configuración/entitlement; no hay evidencia de eventos,
  geofences guardadas o delivery. No se diseñará un probe hasta descubrir un
  path GET primario y exacto.
- La investigación pública de mantenimiento, revisiones/taller, dealer y
  citas no encontró GETs dedicados en el frontend vigente ni en d3vv3/citylife4.
  Solo están confirmados metadata `dealerData`/`dealer` embebida y estructura
  de suscripción; no historial de servicio, órdenes de trabajo ni agenda. El
  único write relacionado es preferencias de cuenta, documentado pero no
  ejecutado. No se propone probe hasta descubrir un path GET primario.
- La revisión de estadísticas y telemetría no encontró un endpoint dedicado.
  Quedan confirmados solo los campos embebidos de estado (`speed`, `battery`,
  `voltage`, `hdop`, `odometer` nullable, `version`, etc.) y las métricas de
  ruta (`distance`, `avgSpeed`, `maxSpeed`); `includeStats=true` fue aceptado
  en el detalle de ruta, sin envelope de estadísticas separado. Hard braking,
  acceleration, overspeed events, elevation, tire/oil y firmware telemetry no
  tienen evidencia primaria y no requieren probe adicional ahora.
- El gate de cobertura histórica queda documentado como lectura segura
  acotada: un GET sin filtros y hasta dos ventanas mensuales de control, límite
  duro de respuesta, máximo tres GET Geo y sin persistir conteos/fechas/IDs.
  El run live falló antes de los controles por `response_too_large`; solo puede
  producir `COMPLETE_FOR_RETURNED_RESPONSE`, `PARTIAL` o `UNKNOWN`, y la
  completitud universal sigue siendo imposible sin contrato explícito.

## Active Constraints

- No MCP server or MCP tool design yet.
- No write operations against MAPIT except required Cognito authentication calls.
- No secrets or real identifiers in source, logs, docs, tests, fixtures, or commits.
- Evidence and documentation precede implementation.
- Live probes are manual and never part of the default test suite.

## Criterio de cierre de Fase 0 (auditoría 2026-09-28)

| Área | Estado | Evidencia y límite restante |
|---|---|---|
| Autenticación Cognito + Identity Pool + SigV4 | COMPLETO para baseline; lifecycle PARCIAL | Flujo inicial y sesión guardada confirmados, con tests offline y almacenamiento fail-closed. Expiración/revocación natural y challenges de otras cuentas siguen abiertos. |
| Vehículos | COMPLETO como descubrimiento schema-only | `account-summary` y un detalle de vehículo confirmados; solo una cuenta/probe, sin afirmar estabilidad cross-account ni capacidades de pago/alertas. |
| Rutas e histórico | PARCIAL | Listado, dos ventanas mensuales y ausencia de cursor en esas respuestas confirmados. El gate live falló cerrado como `response_too_large` (>2 MiB) antes de decodificar la lectura sin filtros; no hubo controles ni conteo/extremos. El supervisor acepta no aumentar el límite ni barrer meses. Paginación universal, filtros completos, orden, unidades y profundidad histórica siguen abiertos. |
| Detalle de ruta | COMPLETO como contrato estructural | Ruta actual con `includeStats=true` y GeoJSON confirmada; semántica/unidades de métricas no confirmadas. |
| Frontend/runtime/endpoints | COMPLETO para los endpoints públicos observados | Discovery modulepreload/preload/import inline corregido y verificado; capacidades secundarias sin path primario permanecen fuera de contrato. |
| Realtime | PARCIAL pero transporte confirmado | WebSocket account-level aceptado para una cuenta y schema-only fixture retenido; cobertura de eventos, ping/pong, cross-account y fallback legacy siguen abiertos. |
| Capacidades adicionales | UNKNOWN/PARCIAL | Dealer metadata, alert settings y telemetría embebida confirmadas como estructura; geofences, eventos, mantenimiento, citas, conducción avanzada y endpoints dedicados no están evidenciados. |

## Decisión de cierre (2026-09-28)

El supervisor acepta los límites parciales, el resultado fail-closed del gate y
la decisión de no aumentar bytes ni barrer meses. No queda trabajo
imprescindible basado en la evidencia para el alcance de Fase 0: contratos,
probes autorizados, fixtures schema-only y documentación están reconciliados a
su nivel de confianza. Fase 0 queda **COMPLETE**. Esto no convierte en conocidas
las capacidades secundarias ni garantiza completitud histórica; los unknowns
siguen explícitos y cualquier lectura adicional, compatibilidad legacy o diseño
de la siguiente fase requiere decisión separada.

## Next Steps

1. No quedan probes obligatorios de Fase 0; conservar el resultado histórico
   como `PARTIAL` bajo el límite aceptado.
2. Reservar para una fase posterior cualquier compatibilidad legacy, lectura
   adicional o decisión de producto; no se diseñan tools aquí.

## Open Questions

- Refresh behavior against the authorized account has not yet been exercised
  near token expiry, although the initial password flow required no challenge.
- Cobertura de frames/eventos WebSocket adicionales, ping/pong del servidor y
  compatibilidad legacy `/devicestate/{deviceId}`.
- Unfiltered route-history coverage for this account could not be assessed under
  the accepted 2 MiB safety cap; pagination/filter semantics remain partial.
- Whether other account states trigger Cognito challenges not seen in the
  successful initial login.
- Saved-token resumption is live-confirmed; expiry/revocation fallback remains
  to be observed naturally. The password and all short-lived session/AWS
  credentials remain memory-only.
