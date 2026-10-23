# Invitation-only multiuser MCP (design)

Status: design accepted by the owner on 2026-10-23 (vault decisions D-049 to
D-052). This document is the implementation contract. It supersedes the
operator-assisted loopback enrollment for guests; historical DEV/prod stacks,
journals and the owner identity pool stay untouched and are not reused.

## Goal and limits

- Invited friends (at most 10 users per environment) use the hosted MCP from
  Claude (claude.ai / Desktop custom connector) and Codex. ChatGPT comes later.
- Users sign in **only with their Honda MAPIT email and password**.
- MAPIT stays read-only. We store only each user's MAPIT refresh token, encrypted
  in SSM Parameter Store. MAPIT passwords are never written by our code.
- Cost target about USD 5/month gross with an AWS Budget alert (not a hard cap).
  Regional Lambda concurrency stays 10; no reserved concurrency is used.
- Everyone, including the owner, is an ordinary user. The owner can enable
  optional TOTP.

Explainable summary: *"Users sign in with their Honda account. An Amazon
Cognito user pool with a user-migration Lambda trigger validates the
credentials against MAPIT on first sign-in and stores only the MAPIT session,
encrypted in SSM. A pre-token-generation trigger puts an opaque tenant id in
the access token, and the MCP Lambda reads that tenant's session per request."*

## Accepted risks

- Cognito keeps its own hash of the MAPIT password after the first sign-in.
  If the user later changes the MAPIT password, the old one keeps opening the
  MCP until the MAPIT session stops working or the user/owner relinks.
- `ALLOW_USER_PASSWORD_AUTH` may be needed on the app clients for the migration
  trigger; verify in DEV.
- The migration trigger has a fixed 5-second limit and may be retried by
  Cognito, so it is idempotent (overwrite the same parameter, same tenant id).

## Resources (one CloudFormation stack per environment)

Stack `honda-mapit-mcp-{env}-multiuser`, `env` in `dev|prod`, region eu-west-1.
A separate small stack `honda-mapit-mcp-{env}-multiuser-artifacts` holds the
private, versioned, encrypted S3 bucket for Lambda ZIPs.

| Logical resource | Key settings |
|---|---|
| `UserPool` `honda-mapit-mcp-{env}-users` | Email as username, case-insensitive; admin-create-only (no self sign-up); tier ESSENTIALS; MFA OPTIONAL (TOTP); custom attribute `tenant_id` (string, immutable); account recovery admin only; deletion protection ACTIVE in prod; triggers: UserMigration and PreTokenGeneration V2_0 -> identity Lambda |
| `UserPoolDomain` | Prefix from private config; ManagedLoginVersion 2 |
| `ResourceServer` | Identifier = MCP URL `https://{ApiId}.execute-api.eu-west-1.amazonaws.com/mcp`; scope `use` |
| `ClaudeClient`, `CodexClient` | Public (no secret), code flow + PKCE, scopes `openid` and `{MCP URL}/use`, callbacks `https://claude.ai/api/mcp/auth_callback` and the private exact Codex loopback URL; refresh-token and (if needed) user-password auth flows; access/ID tokens 60 min, refresh 30 days; token revocation and user-existence-error prevention on; clients cannot write `custom:tenant_id` |
| `ManagedLoginBranding` per client | `UseCognitoProvidedValues: true` (required for `aud` = resource) |
| `InvitationsTable` `honda-mapit-mcp-{env}-invitations` | PK `email` (S), on-demand, deletion protection in prod |
| `HttpApi` + `$default` stage | Throttling rate 10 rps, burst 20; access logs off |
| JWT authorizer | Issuer = pool issuer, audience = MCP URL |
| Routes | `POST /mcp` (JWT, scope `{MCP URL}/use`) and `GET /.well-known/oauth-protected-resource/mcp` (NONE) -> MCP Lambda; `GET /invitacion`, `POST /invitacion`, `GET /privacidad` (NONE) -> identity Lambda |
| `McpFunction` `honda-mapit-mcp-{env}-mcp` | python3.13 arm64, 512 MB, timeout 20 s, handler `mapit.multiuser_entrypoint.handler` |
| `IdentityFunction` `honda-mapit-mcp-{env}-identity` | same ZIP, handler `mapit.multiuser_identity.handler`, 512 MB, timeout 5 s |
| Log groups | 14-day retention |
| `Budget` (prod only) | USD 5 monthly; email at 80% actual and 100% forecast |

Both functions use the same ZIP (pinned ARM wheels + source modules).

### IAM (least privilege)

- Identity role: `dynamodb:GetItem/UpdateItem` on the invitations table;
  `ssm:PutParameter` on `/honda-mapit-mcp/{env}/users/*`; `kms:Encrypt` only via
  SSM on `alias/aws/ssm` (default key, granted through SSM); logs.
- MCP role: `ssm:GetParameter` (with decryption) and `ssm:DeleteParameter` on
  `/honda-mapit-mcp/{env}/users/*`; `dynamodb:UpdateItem/DeleteItem` on the
  invitations table; `cognito-idp:AdminDeleteUser` on the pool; logs.

## Data

### Invitation item

| Attribute | Meaning |
|---|---|
| `email` | Normalized (trimmed, lowercase) email; partition key |
| `tenant_id` | 32 lowercase hex chars (uuid4 hex), created at invitation |
| `status` | `invited` -> `accepted` (consent given) -> `active` (MAPIT linked) |
| `invite_token_sha256` | SHA-256 hex of the random invitation token (token never stored) |
| `invite_expires_at` | Epoch seconds; invitation link validity (default 14 days) |
| `consent_at`, `consent_version` | Epoch seconds and privacy-text version accepted |
| `failed_logins`, `locked_until` | Lock 15 minutes after 5 consecutive MAPIT failures |
| `created_at`, `updated_at`, `last_login_at` | Epoch seconds |

### MAPIT session

SecureString `/honda-mapit-mcp/{env}/users/{tenant_id}/mapit-refresh-token`,
Standard tier, default `alias/aws/ssm` key, written with `Overwrite=True`.
This prefix is new and disjoint from every historical `/tenants/` path.

### MAPIT configuration

The public MAPIT Cognito/API identifiers (`MapitConfig` fields) come from a
private deployment config and are passed as one Lambda environment variable
`MAPIT_CONFIG_JSON` with `discovery_enabled=false`. They are not committed.

## Flows

### Invite (owner)

`python -m scripts.mcp_users --env dev invite friend@example.com` creates the
item (`status=invited`, new `tenant_id`, token hash, expiry) with a conditional
put (no overwrite) and prints the personal link
`{ApiBase}/invitacion?email=<urlencoded>&token=<token>`. Also `list`, `revoke
EMAIL` (delete user, parameter and item), `relink EMAIL` (delete Cognito user
and parameter, set `status=accepted`).

### Accept (guest, identity Lambda)

`GET /invitacion` shows what the service does, the privacy notice summary with a
link to `/privacidad`, and a consent checkbox; it reveals nothing about whether
the email exists. `POST /invitacion` (form-encoded `email`, `token`, `consent`)
checks the token hash in constant time, expiry and status `invited|accepted`,
sets `status=accepted`, `consent_at`, `consent_version`, and shows connection
instructions: MCP URL, Claude client id, Codex command. Errors render one
generic message. Pages: no scripts, inline CSS only, CSP `default-src 'none';
style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none';
base-uri 'none'`, `cache-control: no-store`, `referrer-policy: no-referrer`.

### Sign in (Cognito managed login -> identity Lambda)

`UserMigration_Authentication`: normalize the user name as email; strongly
consistent read of the item; require `status in {accepted, active}` and not
locked; authenticate against MAPIT with `USER_PASSWORD_AUTH` (existing
`CognitoAuthenticator`, pinned config, bounded timeouts, total budget about
3.5 s); on success put the refresh token, update the item to `active` (reset
failures, `last_login_at`) and return `userAttributes = {email,
email_verified: "true", custom:tenant_id}`, `finalUserStatus=CONFIRMED`,
`messageAction=SUPPRESS`. On MAPIT rejection increment failures and fail with
a user-safe Spanish message. Not invited: generic message. Never log the event.

`UserMigration_ForgotPassword`: fail with a message to sign in with the current
MAPIT password (users never reset passwords in our pool).

`TokenGeneration_*` (V2): add access-token claim `mapit_tenant` =
`custom:tenant_id`; fail if missing or malformed.

### MCP request (MCP Lambda)

API Gateway validates issuer, audience and scope. The Lambda re-verifies the
JWT against the pool JWKS (fetched over HTTPS at cold start, cached, refetched
at most every 5 minutes for an unknown `kid`): RS256, `iss`, `aud` = MCP URL,
`token_use=access`, `client_id` in the stack's client set, scope contains
`{MCP URL}/use`, `exp/iat`, `mapit_tenant` = 32 lowercase hex, `username`
present. A per-request lazy provider reads that tenant's parameter and builds
the existing `CloudServicesProvider`/`CloudDirectTransport`.

- Parameter missing: tool error "Tu cuenta no está vinculada o se ha dado de
  baja. Abre de nuevo tu enlace de invitación o pide uno nuevo."
- MAPIT refresh rejected (NotAuthorized): relink automatically - delete the
  parameter, `AdminDeleteUser(username)`, set `status=accepted` - and return
  "Tu sesión de MAPIT ha caducado. Desconecta y vuelve a conectar el conector
  e inicia sesión con tu contraseña actual de MAPIT."
- New tool `borrar_mis_datos(confirmar: bool)`: when `confirmar` is true,
  delete the parameter, the invitation item and the Cognito user; returns a
  confirmation. With `false` it explains what would be deleted.

The ten existing read-only tools (and geography tools when enabled) are
unchanged.

## Privacy and consent

`/privacidad` (Spanish) states: controller (the owner, contact email from
private config), purpose (answer the user's own questions about their
motorbike through MCP clients), data (email, opaque id, encrypted MAPIT
session, consent and login timestamps; MAPIT data is read on demand and not
stored by us; the AI client the user chooses processes answers under its own
terms), legal basis (consent), retention (until deletion or 12 months
without use), rights (delete instantly with `borrar_mis_datos` or by asking
the owner), processors (AWS eu-west-1), no sale or sharing, not affiliated
with Honda. `consent_version` starts at `2026-10-23`.

## Delivery

`python -m scripts.deploy_multiuser --env dev --private-config PATH` builds
the ZIP, uploads it to the artifacts bucket (content-addressed key), creates a
CloudFormation change set, prints its summary and, only with `--execute`,
executes it and waits. DEV first; prod only after the DEV acceptance below.
Historical stacks and the current single-owner prod service keep running until
the cutover, when the owner moves his Codex connection to the new URL.

## Acceptance (DEV, then prod)

1. Owner invites himself, accepts, connects Codex and Claude, signs in with
   MAPIT, and gets vehicle status and current-month distance.
2. A second invited account cannot see the first account's data (or, without
   a second MAPIT account, a token for a non-invited email is rejected and a
   forged/missing `mapit_tenant` is rejected offline).
3. `borrar_mis_datos` removes parameter, item and user; the next request fails.
4. Before inviting any third party in prod, stop and notify the owner.
