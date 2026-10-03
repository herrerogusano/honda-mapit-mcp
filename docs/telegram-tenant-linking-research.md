# Telegram tenant linking and durable delivery research

Status: offline design only. No Telegram/MAPIT/cloud calls, credentials, code,
or account bindings were created. This note does not authorize a Telegram
deployment, user onboarding, or paid model inference.

## Decision and smallest next implementation

Reuse the accepted identity and dispatch seams, but give account linking its
own pure challenge registry. Do not reuse
`WindowsKeyringTelegramCredentialStore`'s setup challenge: that challenge
proves possession during local bot-token onboarding, has no expiry, lives in a
single WinVault envelope, and is not bound to an OAuth principal. The existing
store is not a tenant directory.

The next bounded offline block can be implemented with two synthetic principals
and no real accounts: a `TenantLinkChallengeRegistry` accepts a private exact
Telegram `(user_id, chat_id)` pair and a still-valid
`AuthenticatedTenant` issued by `InvitedTenantAuthority`, then binds the pair
to that grant's opaque `tenant_key`. Proposed challenge lifetime is five
minutes, measured with a monotonic clock; store only a challenge digest
(the bounded offline core uses SHA-256 of a 256-bit cryptographic random token),
serialize mutations with an async lock, and consume/bind in one critical
section. Cap active bindings at the existing 16-tenant policy. Require unique
pair and tenant key, reject account switching/rebinding, and make expiry,
replay, duplicate-pair, revoked-principal and malformed-input behavior
explicit. `resolve_pair()` may return an opaque tenant key only; it must not
mint or imply a fresh OAuth authorization grant.

This primitive proves that an already authenticated application principal
claimed a particular private Telegram pair. It does not solve durable login or
future per-message authentication. The accepted Cognito runtime is explicitly
single-owner, and Telegram updates do not carry that user's Cognito access
token. A separate authenticated Telegram authorization model must be accepted
before any Telegram update can reach a MAPIT provider.

## Existing code seams and limits

- [`telegram_credentials.py`](../src/mapit/telegram_credentials.py) enforces a
  strict, redacted, single-envelope WinVault store for the local bot token,
  challenge and numeric pairs. `save_token()` creates a strong challenge;
  `delete_challenge()` consumes it by constant-time comparison. There is no
  expiration, tenant identity, database transaction, or multi-host semantics.
- [`telegram_adapter.py`](../src/mapit/telegram_adapter.py) projects bounded
  updates, accepts private chats only, checks the exact configured numeric
  pair, processes sequentially, and keeps at most 64 duplicate reservations in
  memory. It retains a `send_started` reservation after ambiguous sender failure
  so an in-process retry does not duplicate a possible message; process restart
  loses that protection.
- [`telegram_bot.py`](../src/mapit/telegram_bot.py) performs one bounded
  `getUpdates` cycle and stores `_next_offset` only in memory. It advances the
  offset to the batch maximum plus one before dispatching that batch; a durable
  worker must instead couple cursor advancement to a durable terminal update
  receipt, or a restart/failure can acknowledge work that was not completed.
- [`tenant_router.py`](../src/mapit/tenant_router.py) supplies
  `tenant_key(key, issuer, subject)`, finite explicit invitations, strict
  fixed-policy RS256 validation, short-lived/tamper-evident request grants,
  revocation, request-local providers and a 14-second deadline. Its
  `InvitedTenantAuthority` is in-memory and policy-specific. The accepted
  production verifier pins one `owner_subject`; it is not a dynamic identity
  directory.
- [`aws_prod_runtime.py`](../src/mapit/aws_prod_runtime.py) composes a fresh
  `CloudServicesProvider` per authenticated request, but only for the current
  single-owner policy. [`aws_session_reader.py`](../src/mapit/aws_session_reader.py)
  reads one fixed, pinned Parameter Store token version. Neither is a
  tenant-indexed MAPIT session reader. The provider factory is the right seam
  for a later fake per-tenant credential reader, but the single-owner secret
  path must not be a fallback.
- [`telegram-multiuser-expansion-contract.md`](telegram-multiuser-expansion-contract.md)
  already sets the core separation rules: exact `(issuer, subject)`, no trust
  in Telegram usernames or client-provided tenant IDs, independent MAPIT
  authentication, request-local providers, no history by default, and no
  Codex CLI/local subscription on a hosted server. This note narrows the next
  linking and delivery-store contract; it does not supersede those rules.

## Invitation-only linking lifecycle

The smallest explicit flow has three independent proofs and no public signup:

1. **Operator invitation.** Create a cryptographically random, one-use
   invitation with a short expiry (recommended: 24 hours to claim). Store only
   a keyed digest, purpose, expiry and state. It grants eligibility to link; it
   is not an identity or MAPIT credential.
2. **Telegram possession.** Accept only a non-bot message in a private chat,
   with strictly typed positive numeric user and chat IDs. Bind both values as
   a server-side HMAC tag over a canonical, domain-separated encoding. Never
   use username, display name, group ID, or user-supplied account selection.
   The challenge itself is single-use and expires after five minutes.
3. **Application identity and MAPIT session.** Complete a separate fixed
   OAuth authorization-code + PKCE flow on a first-party HTTPS login surface.
   Validate exact issuer, client, audience/resource, required scope, redirect,
   state, PKCE and token signature before deriving the tenant key from the
   verified `(issuer, subject)`. The provider's map of a Telegram pair to this
   verified principal must be completed only after both proofs match the same
   pending link record. Then require a separate supported MAPIT authentication
   flow, and verify a stable MAPIT identity claim before storing the user's
   refresh/session material under a server-derived tenant secret reference.
   Never store a password or infer a match from email/display name.

OAuth access/refresh tokens, authorization codes, PKCE verifiers and MAPIT
secrets do not belong in Telegram messages, durable link rows, logs, fixtures,
or diagnostics. Link state may store only digests and opaque tenant references;
if an OAuth verifier must survive a serverless callback boundary, keep it in a
short-lived, encrypted server-side state record or a protected browser session,
not a plaintext URL/query field. On any failed step, expire or consume the
relevant challenge and leave the tenant unbound. There is no fallback to the
retained single-owner MAPIT session.

The exact human/browser UX and how the first-party flow returns the second
proof to the Telegram pair remain a separate product decision. A Telegram
update cannot itself attest that a Cognito login occurred, and Cognito login
does not authenticate the user's MAPIT account.

## Revocation and immutable ownership

Treat the link as an immutable one-to-one association unless account sharing
is separately approved. A new tenant cannot claim an occupied Telegram pair;
an existing principal cannot silently replace its pair or MAPIT account. An
account switch is explicit unlink, verification, then a new invitation/link.

On unlink, atomically mark the binding revoked/increment its version first.
Every subsequent Telegram update must resolve an active binding before any
MAPIT secret read, and the request provider must recheck the version at service
boundaries. Then revoke/retire the tenant's MAPIT secret reference and make
its optional tenant history inaccessible. A crash after marking revoked may
leave an orphan secret, but that secret must be unreachable; cleanup can retry
by exact reference. Never delete the definitive Cognito user/MFA as part of
Telegram unlink. Pending OAuth/link state is consumed or invalidated so replay
cannot recreate the association. An unexpired JWT alone must not override a
revoked binding.

## Minimal durable store before an always-on bot

The pure registry above should first use in-memory fakes. Before persistent
private polling, add an injected transactional state-store interface and a
single-host private SQLite implementation (outside Git/OneDrive with restrictive
OS ACLs), not the existing one-owner route ledger. This proposed operational
scope is one active host/worker (not a general claim that SQLite cannot support
multiple local processes); it must not be shared on a network folder or
treated as a multi-instance Lambda coordination mechanism.

Minimum durable records, with no messages, route IDs, MAPIT payloads, raw
Telegram IDs, or secrets:

| Record | Key/state | Purpose |
|---|---|---|
| `link_intent` | challenge digest; pair HMAC; tenant key; state; `expires_at`; consumed/revoked time | Atomic one-use linking, expiry and replay prevention |
| `tenant_binding` | tenant key; principal HMAC; pair HMAC; opaque MAPIT secret reference; active/revoked; version | Unique one-to-one binding and immediate revoke checks |
| `bot_cursor` | fixed bot namespace; `next_offset`; lease/fencing version | Durable long-poll cursor and single-poller ownership |
| `update_receipt` | `(bot_namespace, update_id)` unique; received/processing/send-started/sent/ambiguous/terminal; timestamps; safe category | Atomic duplicate suppression and recovery without retaining message content |

Keep the Telegram bot token and each tenant MAPIT refresh token in a separate
secret store; the state DB contains only opaque secret references. Keep HMAC
keys outside the database and version them for planned rotation. Whether the
principal HMAC is enough for lookup depends on the token verifier: today's
`InvitedTenantAuthority` constructs owner-specific policies and holds raw
subjects in memory. A dynamic durable identity index needs a reviewed verified-
claims seam; do not let an unsigned `sub` select a secret/provider. The existing
accepted single-owner `FixedRS256TokenVerifier` must not be weakened or reused
as a dynamic verifier by omission.

For each update, atomically claim its unique receipt before dispatch. Retrying
`received`/expired `processing` may be allowed only before any sender call and
under a bounded lease. Persist `send_started` before calling Telegram; after
that state, a timeout/crash is ambiguous and must not automatically resend.
On success, store only `sent`; on a permanent safe rejection, store a bounded
category. Do not promise exactly-once delivery: Telegram `sendMessage` has no
idempotency key in the current transport, so the privacy-preserving recovery
choice is at-most-one send attempt, accepting that a reply can be lost if the
process stops after marking `send_started`.

The Telegram Bot API documents `update_id` as unique and useful for ignoring
repeated/out-of-order webhook updates; `getUpdates` confirms updates when the
next request uses a greater offset, and pending updates are not kept over 24
hours. Retain terminal update receipts for at least 48 hours as a minimal
replay margin, then delete them; keep the compact high-water cursor. See the
[official Telegram Bot API](https://core.telegram.org/bots/api#update) and
[getUpdates](https://core.telegram.org/bots/api#getupdates) documentation.
For webhooks, validate the configured `X-Telegram-Bot-Api-Secret-Token`, commit
the receipt before acknowledging with 2xx, and expect Telegram retries. For
long polling, keep a single active poller; persist terminal receipt and cursor
before issuing a higher offset. If the process is stopped beyond Telegram's
24-hour update retention, report a gap instead of claiming complete processing.

For multi-instance/always-on operation, replace local SQLite coordination with
a shared store that supports conditional writes/transactions plus an explicit
single-poller lease or webhook receipt idempotency. Never place one SQLite file
on a shared filesystem and call that tenant isolation. Tenant history remains
off by default; the existing [`ledger.py`](../src/mapit/ledger.py) has one-owner
scope and is not suitable to share across tenants.

## Offline acceptance without two real accounts

Create synthetic issuer/client/scope/subject pairs A and B, two fake MAPIT
secret references, two fake services and a fake private Telegram transport.
Prove:

- a fresh verified grant A links only its exact synthetic pair, and B cannot
  claim A's pair;
- expired, malformed, wrong-issuer/client/resource/scope, revoked, forged or
  replayed grants perform zero binding changes, secret reads, service calls or
  sends;
- duplicate challenges, expired invitations, concurrent pair claims,
  account-switch attempts and unlink races fail closed;
- `resolve_pair` returns only an opaque tenant key and never creates a grant;
- a request always requires a fresh authorization grant before
  `TenantServicesRouter.bind`, and the factory reads exactly that tenant's
  fake session once, producing no cross-tenant provider/cache reuse;
- duplicate update IDs, worker restart, lease expiry, cursor ordering,
  `send_started` crash and ambiguous send never cause an automatic duplicate
  send; no receipt stores input text, reply text or business data;
- output is deterministic and templated through existing read-only tools; no
  `CodexCliBackend`, `Agent`, hosted paid-model API, real secrets, or network is
  configured.

These pure tests can prove the finite-state contract with two fake principals;
two genuine Cognito/MAPIT accounts are not a prerequisite for this offline
design or its tests. Real OAuth/MAPIT linking, durable secret isolation,
privacy/consent, retention, user recovery, abuse controls, hosted persistence,
pricing, and any external Telegram operation are later separate gates.
