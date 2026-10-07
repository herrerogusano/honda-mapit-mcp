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

This is not a deployment entrypoint and is not connected to the deployed Lambda runtime,
Codex configuration, Telegram, or a credential store. The HTTP factory has no
arbitrary provider argument: callers must supply the invitation-scoped router.
No live MAPIT, AWS, Telegram or model operation is part of its acceptance.

## Opt-in Cognito identity proof

Status (2026-10-06): offline implementation only; not deployed. The optional
`MapitIdentityVerifier` accepts a fixed `MapitConfig`, an injected bounded set
of pinned RSA keys and an injected HMAC seal key. It verifies RS256, `kid`, the
exact Cognito issuer derived from the configured region/pool, exact client
audience, `token_use=id`, canonical UUID subject and bounded Cognito time
claims. It performs no key discovery, SDK call, network request or default
credential lookup.

`MapitIdentityProof` is frozen and redacted: it retains issuer plus an HMAC
subject digest and seal, never the subject or raw claims. When injected into
`CognitoAuthenticator`, the ID token is verified before `GetId` or temporary
credential exchange. Refresh requires a valid existing proof and continuity
of issuer/subject digest before the identity-pool calls or session mutation.
This proves a signed Cognito pool identity only; it does not prove MAPIT
vehicle/account ownership and remains opt-in. The legacy authenticator path is
unchanged when no verifier is supplied.

## Opt-in cloud MAPIT identity continuity

The cloud provider accepts an explicitly supplied `MapitIdentityVerifier` and
`expected_identity_proof` together, or neither. The verifier must belong to the
same configuration object and must validate the proof before any secret read.
The initial refreshed ID token must match that proof before Identity Pool ID or
credential exchange. Refresh checks the original provider-bound proof before
and after authentication; a different signed MAPIT subject cannot rebind it.
Failures do not publish a replacement session or disclose tokens.

This is an offline composition seam, not real-user onboarding or deployment.
The caller must obtain the expected proof through a trusted enrollment flow;
deriving it from the same untrusted refresh being checked would be circular.
Live proof objects are verifier-instance-bound and attest a signed Cognito
identity, not vehicle ownership. The later offline onboarding increment adds
explicit context-sealed export/restore envelopes and a local durable registry;
see [its contract](multiuser-onboarding.md). Key discovery, shared cloud binding,
real enrollment and per-user hosted session publication remain separate work.
The default provider calls and deployed single-owner entrypoints are unchanged.

## Offline durable authorization increment

Status (2026-10-06): implemented and tested offline only; not deployed. The
opt-in `mapit.durable_tenants` module stores only an opaque tenant key, an
`active`/`revoked` status and a positive revision. `SQLiteTenantStore` accepts
an explicitly supplied SQLite connection and an explicitly initialized schema;
it has no default path, autoload, migration, Telegram pair, MAPIT session,
secret, claim or history field. Records are bounded to 16 and revoked rows are
terminal tombstones. Compare-and-set is transactional and is exercised across
two connections for reopen and race behavior.

`DurableTenantGuard` binds the store to the exact existing invitation
authority, seals the key/revision snapshot, and re-reads authorization before
provider creation, before each business lookup and after the lookup. Store
errors fail closed; an in-flight provider call is not forcibly cancelled and
its result is discarded if the post-check fails. `TenantServicesRouter` keeps
the guard optional and disabled by default, so the existing invitation-only
composition is unchanged. This is a local MCP authorization seam, not a
hosted Lambda backend, distributed lease, onboarding flow or durable delivery
claim.

Independent synthetic ASGI/MCP tests exercise two separately signed users,
revocation during a tool call (no result disclosure), and reopening the same
authorization database with a fresh authority/router. The existing no-guard
Lambda deadline behavior is preserved; only the durable opt-in path resamples
after storage latency. SQLite lock contention fails closed immediately, without
automatic retries. This local database is not a shared Lambda storage solution.

Acceptance checkpoint: independent review accepted the corrected opt-in seam;
the integrated offline suite passed 3,079 tests with 12 environment skips,
compilation passed, and the model-free evaluator passed 12/12. No private
account credentials or live MAPIT requests were required.

## Offline Lambda payload-v2 composition

Status (2026-10-05): independently accepted offline. The full suite passed
2,038 tests with five Windows fixture skips; compilation and the model-free
evaluator passed (12/12). The focused implementation suite passed 80 tests,
and independent regressions plus Lambda/router tests passed 49. No production
package, entrypoint, infrastructure or real invitation/session was changed.

`mapit.invited_lambda.create_invited_lambda_runtime` is a separate opt-in
payload-v2 composition. Its fixed invited policies and public keys are copied
into one authority; every invocation gets a fresh HTTP/MCP app. A shared router
uses request-local `ContextVar` scopes and atomically claims provider instances,
while every tool operation still resolves and validates the current SDK token.
No provider is created for `initialize` or `tools/list`; an authenticated
operation's factory receives only an opaque tenant key and a deadline capped by
both the Lambda budget and token expiry.

The handler samples monotonic time before the single original Lambda-context
getter, subtracts getter and later processing latency, passes only a bounded
snapshot context to the existing payload-v2 adapter, and rejects results after
the fixed deadline. This is cooperative deadline enforcement, not a hard kill
of a running thread. Tests use an in-memory API Gateway v2 event and an ASGI/
HTTPX transport adapter; there is no AWS SDK, network, credential lookup,
entrypoint, builder, or deployed runtime integration.

The Lambda composition now has an optional offline-only `authorization_store`
seam. When an explicitly initialized SQLite store is supplied, the invocation
router builds the same authority-bound durable guard used by local MCP and
revalidates the tenant revision before and after business work. The default is
`None`, so existing payload-v2 behavior and production constructors remain
unchanged. This is not a hosted Lambda storage decision or cloud acceptance.

Primary protocol references checked during preparation:
[Lambda context remaining-time method](https://docs.aws.amazon.com/lambda/latest/dg/python-context.html)
and [API Gateway HTTP API payload-v2 format](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html).
They describe the transport/context contract, not successful cloud acceptance.
