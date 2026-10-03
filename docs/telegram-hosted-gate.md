# Hosted Telegram multi-user gate (design only)

Status: proposal for review; **no webhook, new table, secret, or hosted multi-user path is deployed or authorized here**. The retained production MCP remains the accepted single-owner service. This proposal adds no model or conversational inference and does not extend the prior bounded Telegram `sendMessage` authorization to `setWebhook` or persistent processing.

## Bounded target

Private, invitation-only bot access for at most two initial tenants in `eu-west-1`, with a reviewed path to the existing offline limit of sixteen invitations. Use the current API Gateway HTTP API/Lambda pattern for a fixed webhook route and one on-demand DynamoDB table for durable link state and update receipts. Keep the Telegram webhook and MCP OAuth endpoints distinct: Telegram presents a per-bot secret header, while the web linking flow uses an app-specific Cognito public OAuth client with authorization code + PKCE. Do not share the permanent Codex client, callback, tokens, or browser session.

No public Cognito self-signup, group chats, user-supplied tenant/account selectors, data history, route geometry, or model calls. Only the existing fixed deterministic read-only commands are candidates; each may read only the bound user's MAPIT account. Retain private-chat-only behavior and the accepted areas/period limits. MAPIT remains GET-only.

## Link and identity proof

1. Operator explicitly invites one person and creates one short-lived, one-use link challenge. The bot accepts the challenge only in a private Telegram conversation. Store only a challenge digest, expiry, attempt/state, and HMAC of the exact numeric `(user_id, chat_id)` pair; never persist plaintext challenge, message, display name, or pair identifiers. Consume atomically and reject replay, expiry, public/group chat, pair change, and duplicate active binding.
2. The user completes a browser OAuth flow against the separate Cognito app client: exact issuer, audience/resource, client, redirect, and required scope; state and PKCE; initial human password + TOTP MFA. The callback binds the verified issuer+subject to that exact challenge/pair. MFA enrollment is human interactive, never bypassed by the webhook. No identity or tenant choice comes from Telegram message text.
3. In a distinct, explicit step the user authenticates to MAPIT. Verify a stable provider-side account identity before binding; a Telegram name, email match, or Cognito subject is not MAPIT proof. Store no MAPIT password. If the provider cannot provide a trustworthy identity signal or token renewal behavior is uncertain, do not link/activate that tenant.
4. Derive an opaque server-side tenant key from the verified issuer+subject using a secret HMAC key. A durable binding record contains the opaque key, identity digest/reference, Telegram pair HMAC, status/revocation epoch and token-parameter names+versions, not raw identifiers or secrets. `resolve` only selects the binding; authorization still requires fresh, validated app claims. Missing, revoked, ambiguous, or malformed binding fails closed. There is no fallback to the permanent owner's MAPIT session.

The current accepted `TenantLinkChallengeRegistry` and `InvitedTenantAuthority` are in-memory/offline libraries. The hosted implementation needs a DynamoDB conditional transaction equivalent; passing those unit tests is not durable storage acceptance. Use one table with explicit partition/sort keys for invitation/link records and update receipts, point lookup only (no Scan), and conditions for one-use challenge consumption, one active tenant↔pair binding, revocation, and update state transitions. Do not store raw Telegram update bodies or command text. Retention, user deletion, backup/PITR policy, and receipt retention need explicit user approval; default history remains off.

## Webhook/update semantics

The one webhook endpoint is a fixed HTTPS POST path, separate from `/mcp`. Validate the exact Telegram secret header in constant time, cap body size, accept only the expected Bot API update shape/private-message subset, and redact all request bodies/headers from logs. Store only a keyed digest of `update_id`, tenant key, receipt state and timestamps/category. Telegram documents that it retries webhook deliveries after non-2xx responses and that `update_id` supports duplicate/out-of-order detection; use a conditional durable claim before any MAPIT read or send.

Prefer conservative at-most-once delivery: persist `processing` before business work and persist `send_attempted` before one `sendMessage` call. A duplicate of a completed or ambiguous receipt is acknowledged without repeating the read/send. If the process dies in an in-progress/ambiguous state, mark for bounded operator review rather than blindly replaying. Exactly-once behavior across DynamoDB and Telegram's external send cannot be promised. Do not acknowledge an update before its durable claim exists. Define and test a short lease/recovery rule for pre-send failures; never let lease expiry repeat an ambiguous send. The current 64-entry in-memory cache/offset is not adequate for multiple Lambda invocations.

The endpoint must not call `getUpdates`; Telegram specifies long polling and webhooks are mutually exclusive. `setWebhook` and `deleteWebhook` are operator-controlled external writes and require a separate explicit approval, exact URL/secret handling, preflight, and rollback plan. The webhook secret and bot API token are separate secrets, stored as exact SSM SecureString parameters; neither goes in URL paths, code, environment values, receipts, logs, or Git. Do not activate a webhook in this design task.

## Cognito and MAPIT session renewal are separate

Initial linking uses a dedicated Cognito client with required TOTP and a verified human MFA setup. A background Telegram update carries no Cognito bearer token, so the service needs a separately reviewed application session strategy that maps only an existing verified tenant binding to that tenant's app-specific Cognito refresh token, then validates the resulting access token against the same exact policy before issuing the short-lived `AuthenticatedTenant` grant. This must not reuse Codex CLI login/token/subscription state. The refresh credential is not itself an authorization grant.

Store the app Cognito refresh token and MAPIT refresh token as two distinct exact tenant-scoped SSM SecureString paths, for example:

`/honda-mapit-mcp/prod/tenants/<opaque-tenant-key>/cognito-refresh-token`

`/honda-mapit-mcp/prod/tenants/<opaque-tenant-key>/mapit-refresh-token`

Use Standard only after verifying each UTF-8 value fits 4 KiB; otherwise stop for explicit Advanced-tier/cost approval (8 KiB ceiling). Pin expected account/region/name/ARN/type/version and reject mismatched reads. The accepted tenant SSM reader covers only the MAPIT-token path and must not be treated as proof that Cognito refresh renewal or two-secret binding is implemented. Do not write rotated tokens from request Lambdas: Parameter Store has no expected-version compare-and-swap; concurrent refresh can lose a newer token. First establish Cognito rotation configuration and MAPIT refresh rotation behavior. Either keep app refresh non-rotating if the supported flow allows it, or design and test an atomic version-pointer/rotation protocol before activation. No automatic MAPIT SSM write is accepted today.

## IAM boundary (proposed, not yet policy-validated)

- Webhook Lambda execution role: `dynamodb:GetItem`, `PutItem`, `UpdateItem`, and only if proven necessary `TransactWriteItems` on this one table ARN; no `Scan`, table administration, or index wildcard. `ssm:GetParameter` only for the bot token and an explicit finite list of active tenant Cognito/MAPIT parameter ARNs. If using a broader tenant prefix for invitations, scope it to this product path and keep the application-side opaque-key allowlist authoritative; prefer exact ARNs for the two initial tenants. Add `kms:Decrypt` only as required by SecureString, constrained to the region's SSM service and exact parameter encryption context where AWS policy semantics permit. No Cognito admin, SSM write, S3, or CloudFormation permissions.
- API Gateway invoke permission: only the fixed webhook Lambda/route/stage source ARN. Webhook route is not protected by the MCP Cognito JWT authorizer; its independent secret-header check is mandatory. `/mcp` keeps its existing Cognito resource/scope/subject policy and has no Telegram bypass.
- Operator-only enrollment/publisher role: create/revoke explicit tenant parameters and update allowlist/bindings under a reviewed workflow; never grant this to the webhook runtime. Initial user creation/MFA support must be a separately scoped human/operator action, not runtime admin credentials.
- No cross-tenant session cache. Build a fresh request-local MAPIT provider from the selected tenant token, enforce the existing bounded deadline, and clear it after one update. Per-tenant rate limiting is required before more than the initial two tenants; it must not depend on global capacity alone.

## Cost illustration; not a quote or cap

Incremental-only example for 1,000 accepted webhook updates/month and two additional monthly active Cognito users; existing single-owner Lambda/API/monitoring baseline is excluded. Assume each update triggers one 256 MiB Lambda invocation lasting one second, one HTTP API request, roughly 2 KiB of sanitized logs, and a compact DynamoDB receipt lifecycle with two ordinary ≤1 KiB writes and two ≤4 KiB reads per update. This is a workload assumption, not an observed rate. Use no free tier, credits, reserved discounts, or paid model.

- HTTP API: 1,000 × the existing eu-west-1 first-tier rate of $1.11/million ≈ **$0.00111**.
- Lambda: 250 GB-seconds × $0.0000133334/GB-second + 1,000 × $0.20/million requests ≈ **$0.00353**.
- Cognito Essentials: two additional direct MAUs × $0.015 ≈ **$0.03**.
- Logs: 2 MiB ingestion × the existing eu-west-1 $0.57/GB rate ≈ **$0.0012**, excluding retained storage. Telegram API calls themselves are outside this AWS estimate.
- SSM Standard storage/request charges are $0 under the documented Standard tier if values fit 4 KiB and high-throughput mode is not enabled; Advanced adds $0.05/parameter-month and $0.05/10,000 interactions. For four tenant refresh parameters, that would add $0.20/month plus reads if all require Advanced.
- DynamoDB uses on-demand request and storage billing, but this proposal has not verified the current eu-west-1 unit rates. The total is **not fully priced** here; DynamoDB requests/storage, conditional/transactional write multipliers, retries, KMS encryption/decryption requests and key charges where applicable, egress, retained logs, Cognito token-refresh MAU interpretation, alarms/metrics and tax also remain to verify. SSM Standard's zero parameter/API charge does not imply free KMS operations; no KMS free-tier eligibility is assumed.

The priced subtotal is approximately **$0.036/month before DynamoDB, storage and the listed omissions**, or approximately $0.236 with four Advanced SSM parameters before their interactions and those omissions; neither figure is an upper bound. The assumed one-second execution duration is unmeasured. At the existing fourteen-second provider deadline, the same 1,000 invocations would cost approximately $0.04687 for Lambda and bring the priced subtotal to approximately $0.079 before Advanced parameters and all other omissions. This sensitivity illustration is not a complete end-to-end execution bound. Neither scenario establishes that the service stays below the user's $1 gross monthly target. A CloudWatch alarm, optional custom metric, table backups/PITR, and retained Cognito active users can have fixed or usage-based costs even when the bot is quiet. A budget notification is not a billing hard cap; cost-allocation tag activation is not assumed. Obtain current regional price-list rates and approve actual resource/retention choices before a hosted implementation or webhook write.

## Acceptance gates before any implementation/deployment

1. User approves the new Telegram external-write set (`setWebhook`, `deleteWebhook`, bounded `sendMessage`), retention, public/private ingress and two-person operational support expectations.
2. Independently review the durable one-use/idempotency schema and deletion semantics; fake tests prove concurrency, replay, crash-before/after-send, revocation, cross-tenant isolation, no body/secret logging, and no ambiguous automatic send retry.
3. Verify app Cognito session-renewal behavior and MAPIT account identity/refresh behavior without assuming either refresh token can rotate safely. Require initial human TOTP enrollment for each tenant.
4. Review exact principal/parameter/table/API ARNs and KMS conditions; test least-privilege negative cases. No admin/SSM writes in the handler.
5. Verify exact eu-west-1 DynamoDB and SSM costs, log retention, alarm/metric residuals and spending alert availability. Preserve the $1 goal as a target, never a hard cap.
6. Only after separate approval, deploy disabled/closed, verify exact readbacks, arm independent shutdown/abuse controls, then separately authorize webhook registration and a tiny synthetic-to-real-user E2E. Provide rollback (`deleteWebhook` + disable endpoint) and verify closure. No MCP, MAPIT, Telegram or user-resource production test is implied by this design document.

## Evidence

Project seams: [`telegram-multiuser-expansion-contract.md`](telegram-multiuser-expansion-contract.md), [`phase-8-aws-preparation.md`](phase-8-aws-preparation.md), `src/mapit/tenant_router.py`, `src/mapit/aws_tenant_session_reader.py`, `src/mapit/telegram_bot.py`, `src/mapit/telegram_adapter.py`.

Primary sources:

- [Telegram Bot API](https://core.telegram.org/bots/api) — webhook setup/secret header, `update_id`, webhook retry and mutual exclusion with `getUpdates`.
- [Cognito TOTP MFA](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html) and [Managed Login](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-managed-login.html) — human setup and MFA behavior.
- [SSM Parameter Store pricing](https://aws.amazon.com/systems-manager/pricing/) and [PutParameter limits](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html) — Standard/Advanced charging and 4/8 KiB ceilings.
- [DynamoDB pricing](https://aws.amazon.com/dynamodb/pricing/) — on-demand read/write-unit billing, item-size rounding, storage/backup costs; regional request rates still need verification.
- [Lambda pricing](https://aws.amazon.com/lambda/pricing/) and [API Gateway pricing](https://aws.amazon.com/api-gateway/pricing/) — usage dimensions; the eu-west-1 rates used above are from the already-reviewed project Price List snapshot, not a fresh account read.
