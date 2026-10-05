# Telegram multi-user expansion: offline design contract

## Current product decision (2026-10-05)

The user selected **multi-user MCP access and owner-only Telegram**. Existing
offline invitation/tenant libraries remain reusable, but Telegram enrollment for
other people is deferred until incremental cost is known and separately approved.
The two-person Telegram hosting proposal is not the current deployment target.
Continue local MCP request-isolation preparation without enabling hosted signup,
new identity/storage/IAM resources, account reads or live provider calls. The
previous two-hour external-operation window has expired; no new window was granted.
Owner-only Telegram still needs reviewed application-session renewal, durable
receipt behavior and transport/cost acceptance before permanent activation.

The next local MCP integration is accepted separately in
[`mcp-multiuser-local-contract.md`](mcp-multiuser-local-contract.md): actual
SDK/ASGI dispatch with synthetic A/B tenants and per-operation authenticated
context. Full offline checkpoint: 2,014 passed, five Windows fixture skips;
compilation and the model-free evaluator passed. Production remains single-owner.

Status: **offline library accepted; hosted linking/deployment pending**. This document records existing seams and a
bounded direction for a later implementation. It does not authorize account
creation, public signup, deployment, credential collection, new paid services,
live MAPIT/Telegram calls, or model inference. The existing production endpoint
remains single-owner. A separate geography scope for Barcelona/Spain must not
be inferred from this multi-user design; the separately accepted geography
bundle is deployed for Menorca and Barcelona/AMB, as recorded in
`geographic-query-status.md`.

## Accepted offline invitation boundary

`tenant_router.py` verifies fixed-policy RS256 access tokens against at most
sixteen explicit invitations and issues tamper-evident, expiring request grants.
Opaque HMAC-derived tenant keys select injected, request-local providers; no
legacy-owner fallback or credential store is constructed. Each proxied service
call rechecks authorization/context/deadline before and after execution.
Concurrent tenant requests, revocation, provider reuse, escaped proxies/copied
contexts, forged/expired claims and safe failures passed 28 tests including an
independent review. Existing production and Telegram entrypoints are unchanged.
This library does not establish account linking, real secret-reader isolation,
multiuser deployment or durable Telegram delivery.

## Deterministic Telegram command increment

The separate offline dispatcher is independently accepted for `/ayuda`,
`/verano <zona> [año]` and `/kms <zona> | <desde ISO> | <hasta ISO>`.
It takes an already-verified tenant grant, not identity claims from text or a
Telegram username. It calls only bounded geographic service methods and returns
typed, reconciled counts/km with canonical timestamps and source-geometry caveats.
It does not send messages, poll Telegram, invoke models or modify the existing
adapter. Nineteen focused tests include two-tenant output separation and exact
result area/period binding. A new invitation-link challenge core and a bounded,
injected local delivery adapter are independently accepted offline; the
old bot-token onboarding challenge is not an OAuth/MAPIT account-link proof.

The delivery increment is limited to one process and at most 64 distinct
updates: no eviction, background worker, webhook or durable delivery claim.
It requires fresh verified OAuth authorization plus the exact linked private
pair before dispatch and rechecks both immediately before one sender attempt.
Unknown/unlinked/swapped identities never touch a MAPIT provider; ambiguous
sends retain the local receipt and are not automatically retried. No real
Telegram method or MAPIT call has been made for this increment.

The link registry caps pending links/bindings at sixteen, expires challenges
after five monotonic minutes and retains bounded digest/expiry tombstones to
reject consumed-code reissue during that lifetime. It never stores plaintext
challenges; pair identifiers are held only in RAM with redacted repr. Binding,
lookup and unlink require a fresh authority-validated grant; lookup returns an
opaque key, never new authorization. Independent tests cover replay, revocation
after business output but before send, concurrent duplicates and cancellation.
Durable storage, human OAuth/MAPIT linking, application-session renewal and a
hosted Telegram transport remain separate work, not implied by this acceptance.

## Accepted offline tenant session reader

`AwsTenantSessionReader` reuses the existing fixed reader through a strict
namespace bridge rather than changing the production reader. A fresh validated
grant selects `/honda-mapit-mcp/prod/tenants/<opaque-key>/mapit-refresh-token`.
Exactly one injected read attempt is permitted per reader, including ambiguous
failures; the bridge verifies the original tenant name/account ARN before
normalizing a new response copy for the established version/type/value/deadline
checks. Authorization is checked after method lookup, immediately before the
read and after the result. There is no legacy-owner fallback, SDK construction,
list/scan, parameter publication or IAM change.

Independent synthetic integration covers Router → tenant reader →
CloudServicesProvider: A/B select distinct exact SSM names, refresh with their
own tokens and return disjoint synthetic status. Wrong namespace metadata fails
before Cognito and prior revocation prevents provider/SSM work. The 82 focused
tests do **not** prove that arbitrary token content belongs to the advertised
MAPIT account: stable provider identity verification at real onboarding remains
mandatory. The existing production package still contains only the fixed
single-owner reader, not this opt-in library.

Final local checkpoint: 2,002 tests passed, five Windows fixture skips;
compilation and the twelve-case model-free evaluator passed. The optional
geometry tests run in the pinned geometry-enabled CI job; the base matrix keeps
geometry optional without skipping identity/linking/privacy checks.

## Next concrete hosted gate

Do not switch the deployed single-owner runtime to these libraries implicitly.
Before a real invited user can use Telegram, accept the complete application
composition: authenticated Bot API delivery; protected first-party OAuth/PKCE
linking and initial human MFA; separate MAPIT identity/session proof; exact
tenant-scoped secret publication/IAM; durable revocation/link/update receipts;
and reviewed request/cost/shutdown controls. No paid conversational model is
needed for the implemented commands.

The authorization-renewal decision is still open. The current core deliberately
requires a fresh verified OAuth grant for every command. A Telegram message
does not supply that token. A persistent bot must use a reviewed application
session renewal/delegation flow (not a Codex login/subscription credential or an
unchecked tenant lookup), so normal use does not require interactive MFA for
each message. Each new person still needs one explicit initial application and
MAPIT login/link. Public signup remains excluded.

A webhook and a new durable AWS state store would expand the Phase 5 transport
and hosted-storage contract; the only live Telegram write previously accepted
was bounded `sendMessage`. Present the exact resources, regional cost estimate,
authorization/retention policy and bounded first-user test before enabling that
permanent transport. No new live historical query is authorized by this gate.

## What exists today

- `src/mapit/telegram_bot.py` is a synchronous, one-update long-polling client.
  It loads one bot token and a set of numeric `(user_id, chat_id)` allowlisted
  pairs from the Windows Credential Manager envelope. The offset and bounded
  duplicate cache are in memory. `TelegramAdapter` is sequential and permits
  only a fixed read-only tool-name set; its output filter is a conservative
  lexical guard, not a proof of semantic privacy.
- `src/mapit/telegram_adapter.py` accepts only private chats and the exact
  configured numeric pair. Those Telegram IDs are authorization inputs for
  this local prototype; they are not a Honda account identity and do not
  establish a MAPIT session.
- There is no `src/mapit/telegram_agent.py`; the conversational adapter is
  `src/mapit/agent.py`, and the Telegram backend currently uses
  `CodexCliBackend`. That backend requires a local Codex CLI ChatGPT login and
  starts a local subprocess. It is not a remote Lambda backend or a per-user
  model entitlement mechanism.
- The production HTTP/MCP verifier pins one Cognito issuer, resource, client,
  scope, and `owner_subject`. `aws_prod_runtime` closes over that single policy.
  The verified subject is not passed to the provider builder. The production
  entrypoint uses one fixed Parameter Store name/version and one fixed MAPIT
  configuration; it therefore cannot select a different user's MAPIT token.
- `CloudServicesProvider` is a useful request-local seam: it lazily reads one
  refresh token, authenticates once, and creates a client/services object for
  its instance, with a deadline. The current fixed `AwsSessionReader` is
  deliberately single-parameter and does not implement tenant lookup.
- The optional SQLite distance ledger and its active scope are designed for a
  single local owner. They are not a shared multi-user database or tenant
  isolation boundary.

## Required identity and account-linking boundary

Treat the Telegram bot as one service identity and each linked human as a
separate tenant. Resolve a tenant only from an authenticated principal that
the server has verified, using the exact `(issuer, subject)` pair. Never accept
`tenant_id`, Cognito `sub`, MAPIT account identifiers, or account selection from
a Telegram message, tool argument, URL parameter, unsigned claim, or client
header. Telegram's numeric user/chat IDs prove only which bot conversation is
being handled; they must not stand in for the IdP subject.

Linking is a separate, explicit flow with two independent proofs:

1. A one-use, expiring link challenge binds a private Telegram conversation to
   a successful OAuth authorization for the fixed application. State, PKCE,
   exact issuer/client/resource/scope/redirect validation, replay protection,
   and authenticated subject validation are required. Consume the challenge
   atomically; do not expose authorization URLs, codes, verifiers, or tokens in
   chat, logs, or durable diagnostics.
2. The same user explicitly links their Honda/MAPIT account through its
   supported authentication flow. Store only the minimum refresh/session
   material needed to resume that user's MAPIT session. Do not store the
   account password. Verify the MAPIT identity through a trustworthy provider
   identity claim before binding it to the application subject; email equality
   or a Telegram display name is insufficient. Cognito authentication to the
   MCP alone does not authenticate the user's MAPIT account.

The mapping is one-to-one by policy unless a separately reviewed account
sharing feature is approved. Unlink/revocation must atomically disable the
binding, stop future session reads, and make tenant-owned history inaccessible.
Never fall back to the permanent single-owner MAPIT session when a tenant
binding is missing, malformed, expired, or unauthorized.

## Request isolation requirements

- Authenticate and validate the caller before resolving a tenant or touching a
  MAPIT secret. Pass the verified `(issuer, subject)` as trusted server-side
  request context; do not re-parse an unverified JWT in a tool/service layer.
- Resolve only that principal's linked MAPIT credential. Use an opaque,
  collision-resistant tenant key derived server-side from issuer+subject (for
  example a keyed HMAC); do not place raw subjects, email addresses, Telegram
  IDs, VINs, route IDs, or coordinates in secret names, database keys, logs, or
  metrics.
- Construct a fresh provider/session/client per authenticated request, or use
  a rigorously tenant-keyed cache with bounded lifetime and explicit eviction.
  Never share a `MapitSession`, refresh callback, authorization headers, or
  `CloudServicesProvider` across tenants. Clear references after the request;
  ensure a refresh cannot replace or leak another tenant's token.
- Apply tenant authorization to every resource lookup, tool invocation,
  background job, idempotency key, and response. A route ID supplied by one
  tenant must never retrieve another tenant's route. MAPIT remains GET-only;
  no cross-tenant search, unbounded history scan, or detail-per-route loop.
- No history persistence by default. If separately approved, extend the ledger
  with an explicit tenant namespace/key boundary and per-tenant retention and
  deletion semantics. A single global `active_scope` or the current one-owner
  ledger is not acceptable for a shared service. Do not persist route geometry.
- Keep request, error, and audit output category-only. Never log Telegram
  message text, OAuth material, tokens, headers, raw MAPIT bodies, IDs,
  coordinates, vehicle details, or exception strings. Per-tenant quotas and
  rate limits must prevent one user exhausting shared capacity.

## Telegram and response behavior

Keep private-chat-only handling, strict message/update bounds, sequential or
durably idempotent update processing, and no blind retry of an ambiguous
`sendMessage`. A multi-instance deployment cannot rely on the current
in-memory update offset or dedupe map: it needs a durable, atomic per-bot
delivery cursor/idempotency record and a single-owner lease or webhook replay
protection. Do not add group chats by default.

The current lexical output filter is not sufficient as a multi-tenant privacy
boundary. Prefer fixed, typed command intents and deterministic, templated
answers that call only existing read-only tools. Return only the minimum
requested facts for the authenticated, linked tenant. A conversational model
is not part of this design: do not automatically invoke a paid model, treat a
local Codex subscription as a remote service entitlement, or move local Codex
credentials to a server. Any later model option requires a distinct explicit
choice, privacy review, budget controls, and a supported per-user billing or
entitlement model.

## Implementation and acceptance gates

The concrete invitation-only hosted proposal, durable delivery semantics,
separate app-session renewal, and incomplete incremental cost illustration are
in [`telegram-hosted-gate.md`](telegram-hosted-gate.md). It is design evidence,
not deployment acceptance or an authorization expansion.

Before code changes, decide whether Telegram is only a transport for an
already-authenticated MCP caller or a separate login/linking client. Do not
combine the trust models implicitly. A bounded implementation should proceed
in separately reviewed steps:

1. Pure tenant-identity/binding model and tests: issuer+subject canonicalization,
   one-time linking, concurrent/replay handling, unlink and account-switch
   behavior. No network or secrets in tests.
2. Injected per-tenant secret reader and provider factory: exact opaque tenant
   lookup, one read, no fallback, strict deadline, one request-local session;
   fake transports must prove no cross-tenant cache or token reuse.
3. Authenticated request-context propagation into tool dispatch and, if
   approved, Telegram delivery. Tests mix two synthetic tenants concurrently,
   swap Telegram pairs and route IDs, inject expired/missing bindings, and
   assert no cross-tenant output, secret reads, or sends.
4. Durable update/idempotency design and tenant-scoped retention/deletion only
   if a persistent multi-instance Telegram service is actually selected.
5. Separate operator/user gates for public signup, pricing, production
   deployment, privacy notice/consent, account recovery, abuse handling,
geographic regions, and any paid model. Offline tests or this document do
   not satisfy those gates.

Required invariant tests include: verified subject A can read only A's fake
MAPIT data; subject B and an unlinked subject cannot; forged claims, wrong
issuer/client/scope, replayed link challenges, mismatched Telegram pair, and
missing MAPIT binding perform zero secret reads and zero sends; cached or
concurrent requests cannot cross tenants; malformed upstream data and
exceptions produce fixed safe categories; revocation blocks the next request;
and no test output contains synthetic tokens, IDs, coordinates, or message
content.
