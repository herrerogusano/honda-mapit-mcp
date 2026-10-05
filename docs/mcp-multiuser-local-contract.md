# Local invitation-scoped MCP composition

Status (2026-10-05): independently accepted offline, not deployed. Twelve new
tests cover actual SDK/ASGI protocol dispatch plus independent negative cases;
the focused regression passed 69 tests. The full suite passed 2,014 tests with
five Windows fixture skips, compilation passed and the model-free evaluator
passed 12/12. Tests use signed synthetic JWTs and injected fake services with
external networking blocked; this is not evidence of real tenant onboarding,
MAPIT account ownership, durable revocation or multi-user Lambda operation.

`mapit.invited_mcp.create_invited_mcp_app` is an opt-in composition seam for
offline/local validation of the already accepted invitation authority and
tenant router. It requires the same `InvitedTenantAuthority` instance as the
`TenantServicesRouter`, and checks their common Cognito issuer, resource,
client and scope against one explicit `CognitoProdPolicy`. The public keys are
already pinned inside that authority; the factory does not fetch keys or build
credentials, sessions, providers, or storage.

The SDK verifier validates a bearer through the finite invited authority and
places a short-lived sealed grant on a private `AccessToken` subtype. Bearer,
grant and dispatch proof are excluded from repr and model serialization. Each
synchronous tool call reads the current SDK auth context again, validates the
sealed grant, and opens `router.bind(grant)` only around that operation. It does
not retain a grant in a provider proxy or use a process-global tenant. The MCP
SDK's authenticated ASGI context is propagated to synchronous handlers through
AnyIO; protocol tests exercise this exact path with concurrent synthetic
tenants.

This is not a deployment entrypoint and is not connected to the Lambda runtime,
Codex configuration, Telegram, or a credential store. The HTTP factory has no
arbitrary provider argument: callers must supply the invitation-scoped router.
No live MAPIT, AWS, Telegram or model operation is part of its acceptance.
