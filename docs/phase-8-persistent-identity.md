# Persistent owner identity — 2026-10-02

The user approved preserving a definitive Cognito owner/MFA identity rather than
enrolling a disposable dev user. This supersedes temporary deletion only for the
new, separate identity stack. The existing closed dev app, control stack and
artifact bucket remain disposable and must still be cleaned up; their schedules
must not be redirected, disabled or extended to preserve identity.

## Boundary

- Fixed stack `honda-mapit-mcp-identity`, `eu-west-1`, four Cognito resources only.
- Essentials pool, administrator-only creation, email-form login, required TOTP.
- Pool deletion protection; Retain/UpdateReplacePolicy Retain on all four
  resources and CloudFormation termination protection at creation.
- Managed Login v2, provided branding, public authorization-code client,
  five-minute access/ID tokens, one-day refresh token, revocation enabled.
- The enrollment client has only `openid`, no MCP scope, administrative scope,
  client secret or SDK password/SRP flow. It cannot authorize dev/prod MCP tools.
- The dedicated local callback is `http://127.0.0.1:8785/callback`, for the
  actual one-session PKCE enrollment helper, not a claimed Codex callback.
- Future dev/prod clients will require their own exact resource/audience/scope
  bindings and separate compute/access review. No production service, MAPIT
  credentials/data, Telegram or paid model inference is approved by identity
  creation. This is not completion of Phase 8.

The owner enters their own password into the local form; the operator sends one
suppressed admin creation and sets that chosen permanent password, without email
or SMS. Managed Login handles QR/TOTP enrollment. The operator verifies the
confirmed user and software-token MFA, and matches authenticated UserInfo subject
to the owner. Secrets/tokens remain in process memory, not Git/vault/journal.
Only private identity bindings and safe progress flags are journaled outside
Git/OneDrive with operator/SYSTEM ACLs.

## Cost and recovery

Public Cognito pricing has no minimum fee and includes 10,000 direct/social
monthly active users in Lite/Essentials, shared across the account/organization.
One direct owner is expected to fit the allowance, but eligibility/shared usage
and the actual bill are not verified; no universal zero-cost claim. No SMS,
machine-to-machine tokens, custom domain, Lambda, API, database or IAM role is
part of this identity stack. Review usage before broader use.

The same retained pool/user can later serve production without transferring its
TOTP enrollment. Retention is not backup or disaster recovery. Lost authenticator
recovery needs a trusted AWS administrator and an explicit identity-verification
procedure; no automatic MFA reset is implemented. Removing protection and
deleting the permanent identity requires separate user direction.

Primary sources: [Cognito pricing](https://aws.amazon.com/cognito/pricing/),
[TOTP enrollment](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html),
[Cognito pool CloudFormation contract](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html).

## Evidence

The pure four-resource template passed pinned eu-west-1 schema validation with
Python networking blocked, zero findings, and focused tests. Actual creation,
readback and human MFA results are recorded separately after execution.

### Live progress (bounded session)

The separate persistent identity stack was created and independently read back
against the fixed template: four expected resources, required TOTP only, protected
pool, protected stack, and exact enrollment-client configuration. The owner user
was created through the human-operated enrollment form. No credentials or tokens
were persisted in the repository.

The first OAuth callback failed. A subsequent administrative read showed a
confirmed user but no reported software-token MFA setting; therefore enrollment
and login were not accepted at that point. The callback helper now reports only a fixed
failure-stage category, error kind, and HTTP status (never exception text, bodies,
codes, tokens, email or password). A fresh human login is needed to isolate the
failure; no user deletion, password change or MFA reset was performed.

The human confirmed scanning the QR and submitting an authenticator code. The
callback diagnostic localized the rejection to user-level MFA readback, after a
successful token exchange. A separate factor read also provided no active-factor
evidence. After primary-document review and independent operator-helper review,
one journaled `AdminSetUserMFAPreference` enabled and preferred the existing TOTP.
AWS accepted it, and a fresh `AdminGetUser` confirmed both the active software
token and its preference. No association, reset, new QR or credential change was
performed. The helper now uses `prompt=login` to avoid accepting only a cached
Managed Login session. The subsequent fresh human login completed successfully:
authorization-code/PKCE exchange, confirmed active software-token MFA, and
authenticated UserInfo subject matching the intended owner. Safe portal status
reported `login_complete=true`, `mfa_confirmed=true`, and `failed=false`.
The owner/MFA identity is retained for future production clients. This verifies
identity enrollment/login, not a completed MCP E2E or production deployment.

The separate temporary ten-resource OAuth setup was deleted and absence of its
pool/domain/client verified. Control-stack removal and all 21 final absence
checks passed. The empty,
owned temporary artifact stack reached DELETE_COMPLETE. These cleanup operations
did not target the persistent identity.

### Shared-identity synthetic runtime rehearsal

The renewed two-hour authority retained the existing synthetic-dev limits,
regional quota 10 and USD 1 gross envelope. The user/MFA remained in the
separate protected identity stack. A new owned dev stack was staged as five
closed bootstrap resources, then eight OAuth setup resources, then fourteen
runtime resources. The effective Codex callback was obtained from the actual
temporary connection before registering the dev client. Other MCP settings were
preserved. No authentication URL, state, token or private binding is in Git.

The shared setup passed eleven bounded readbacks. CloudFormation's observed
branding physical identifier was `<pool>|<branding UUID>`, although its `Ref`
documentation describes the UUID alone. The checker now accepts only the bare
canonical nonzero UUID or that exact pool-bound composite; malformed, foreign
pool and fuzzy matches fail closed.

The real runtime ZIP was built from hash-locked ARM wheels and the retained
pool's public keys, imported in the pinned official ARM image with networking
disabled, conditionally uploaded to a verified owned/private/unversioned bucket,
and verified by checksum/size readback. Ten runtime readbacks confirmed the
closed fourteen-resource deployment, exact routes/authorizer/integration,
Lambda ZIP hash/environment and invocation grants. Twelve control resources
were updated for exact API-child cleanup without any Cognito permission.
All five control roles' exact trust and inline policies, shutdown ASL and both
schedules were verified.

Preparation consumed the arming lead for the immutable execution window.
The endpoint was never enabled and no Lambda tool or model was invoked; this
is not a successful MCP E2E. The owned compute stack was deleted with its scoped
no-Cognito deletion role. Its three retained dev-only Cognito children were then
retired by exact observed identifiers, and their absence verified. A fresh owner
read matched the retained subject and confirmed preferred/active TOTP. The exact
runtime object was retired and bucket emptiness verified; the artifact and
control stacks reached deletion completion, with all twenty-one final rehearsal
absence checks passing. The temporary Codex connection was logged out/removed,
and full parsed configuration preservation outside that entry was verified.

The installed CLI's model-free app-server smoke helper now uses the actual
initialize/status schemas, an explicitly ephemeral thread response, discovery
and two fixed synthetic calls only. It never sends `turn/start`, binds its URL
to the exact configured temporary server, disables other configured MCPs/plugins
with process-local settings, bounds output/deadline and suppresses raw results.
Its offline acceptance does not prove actual OAuth/MCP interoperability or a
broader persistence guarantee. Separate loopback-only probes confirmed that
`mcp login --no-browser` opens its callback listener and handles HTTP redirects
without requiring a pasted callback URL; no real login/token exchange occurred
in those probes.

The injected-client activation core and the private operator/portal wiring received
independent offline acceptance. Activation checks the exact tripwire before and
after enabling it, records write intent, bounds the immutable execution window,
and always attempts the checked shutdown path. The portal accepts only the eight
expected PKCE query keys, including rejection of blank or sensitive extra keys.
The frozen source passed 1,549 offline tests (five skipped) and compilation.
This acceptance does not replace the pending human OAuth login and synthetic
Codex-to-cloud tool-call test. No second rehearsal was provisioned while human
availability remained unconfirmed.
