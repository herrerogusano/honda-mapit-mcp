# Retained-dev multi-user hosted candidate

Status: hosted DEV scope authorized on 2026-10-06; implementation and
independent offline validation in progress. Not yet deployed or activated.

`scripts/build_aws_retained_dev_multiuser.py` deep-copies the closed
five-resource retained-dev scaffold and adds a separate, opt-in development
composition. It performs no AWS SDK calls, credential lookup, user creation,
password handling, or network operation.

## Fixed inventory

The candidate retains the existing API, stage, ARM Lambda, execution role and
log group, and adds:

- an administrator-created-only Cognito user pool with MFA disabled, managed
  login v2 domain, resource server with only the `use` scope, public PKCE
  client, and Cognito-provided managed-login branding;
- a JWT authorizer, one `POST /mcp` JWT route, and two unauthenticated metadata
  GET routes (`oauth-protected-resource/mcp` and
  `oauth-authorization-server`) targeting the existing Lambda integration;
- exact API Gateway invoke permissions for those three routes; and
- `honda-mapit-mcp-dev-tenants`, an on-demand DynamoDB table matching the
  existing reader's single string `key` primary key and `status`/`revision`
  item shape. The table uses AWS-owned default encryption and has no PITR,
  TTL, streams, indexes, backups, or customer-managed KMS key. New resources
  use explicit retain policies and require owner-directed deletion.

The table ceiling is ten read units/second and one write unit/second. Each
business operation deliberately rechecks authorization several times, so one
read unit/second would throttle the safety checks themselves. This is not a
Lambda quota increase; its regional ceiling remains ten concurrent executions.
The table charges requests, not this configured capacity. A five-minute test
at ten read units/second would be about USD 0.000425 of reads at the verified
regional rate, before burst behavior; this is not a billing hard cap.

The Lambda remains ARM64, 256 MiB, 20 seconds, reserved concurrency zero, and
uses an addressable `runtime/<sha256>.zip` object. Its proposed handler is
`mapit.aws_dev_multiuser_entrypoint.handler`, now separately implemented and
independently tested offline. Its role keeps the existing log writes and adds
only `dynamodb:GetItem` on the exact table ARN with the two supplied opaque
leading-key values. There is no scan, list, write, SSM, Secrets Manager, KMS,
network, MAPIT, or token permission.

The builder requires a lowercase observed API ID, content-addressed artifact
and source/JWKS/manifest digests, an exact loopback callback, an expected
12-digit account binding, and a positive execution window of at most 300
seconds. It also requires exactly two distinct canonical Cognito UUID subjects
and `tenant-<sha256>` keys. Here the synthetic DEV subject contract is a
lowercase hexadecimal UUID-shaped identifier, not an RFC version/variant
restriction or a claim about every possible Cognito subject. The Lambda environment is fixed to `MAPIT_MCP_ENV=dev`
and synthetic mode, and binds the manifest digest, account, and window. User
passwords, tokens, and MAPIT credentials are not placed in
CloudFormation. The generated real-bound template/manifest is private; technical
subject identifiers are private bindings, not portfolio examples. The resource identifier, pool, client, and callback values
are constrained parameters rather than guessed generated IDs.

The manifest contract is schema 1 and records the builder name, `dev`/
`synthetic` mode, source/API/pool/client/JWKS/table bindings, and exactly two
labelled tenant entries containing canonical UUID subjects and opaque keys.
Pool, client, and table identifiers are
CloudFormation references in the draft and require actual readback before an
operator can materialize or use a manifest.

## Gates still required

The owner accepted preserving the isolated pool/table and two technical users,
MFA off only in that pool, quota 10, no real MAPIT data or paid inference, and
bounded DEV opening. Before any account write, implementation must pass a
fresh V2 preflight/readback, dev-only IAM role and permission review, closed CD
and recovery design, artifact provenance, and the real Lambda entrypoint. At
most two technical users would be created in a journaled private operator step;
CloudFormation creates no users or passwords. This draft does not prove pool,
API, callback, Cognito, DynamoDB, or runtime interoperability and does not
change the production stack, quota, owner identity, Telegram, or MAPIT paths.

The first closed setup adds only six resources to the original five and leaves
all runtime properties unchanged. This obtains actual Cognito identifiers
before the private runtime artifact can be built. The second closed phase has
nineteen resources, with the endpoint disabled and Lambda reservation zero.
Opening and shutdown acceptance are separate from these closed updates.

## Private acceptance operator

The opt-in hosted acceptance operator composes the closed setup, exact V2
infrastructure readbacks, two administrator-created technical users, managed
login/PKCE, pinned public JWKS, private ARM artifact, recurrent IAM narrowing,
and bounded HTTP MCP checks. Passwords and tokens remain in memory. It checks
tenant-specific synthetic results, foreign-route denial, anonymous denial,
terminal revocation of A, and continued access for B. The fixed existing remote
stop waits five minutes only for a bounded probe; tripwire shutdown stays
immediate. Both local stop primitives must be read back before handoff.

Multi-user journals use a separate strict durable envelope over the existing
atomic file/lock mechanics. Historical rehearsal journals and expired write
intents are not migrated, extended, or replayed. SDK template readback accepts
JSON text and observed mapping responses while retaining exact source hashes.

These operators are preparation until an actual hosted receipt succeeds.
Neither offline tests nor resource creation alone establish functional DEV,
real MAPIT multi-user onboarding, production readiness, or completed DEV CD.

## IAM size compatibility

The first closed V2 role update rolled back when AWS rejected its managed
boundary size. The original role pair subsequently passed exact readback;
that acknowledged intent is consumed, not a retry candidate. Equivalent
compaction removes non-authorizing `Sid` labels and unions actions only when
every other authorization field matches. The materialized boundary must fit
IAM's [6,144-character managed-policy limit](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_iam-quotas.html)
before any update intent. Customer-managed key creation is outside this scope.
The separately approved existing AWS-managed Lambda-key recovery retains the
attached boundary and its exact wrong-key/service/context denies, and places
the equivalent explicit deny for all unlisted actions in the CFN role's sole
inline policy. That inline policy must fit its separate 10,240-byte aggregate
limit; the managed boundary must fit 6,144. Independent review must verify the
combined effective authorization, including resource/session grants, not just
document sizes. The executor and historical/prod role factories are unchanged.

## Hosted DEV checkpoint

The compacted V2 role update, closed eleven-resource setup, and timed controls
were accepted in AWS on develop `4d1db49`, after all eight source checks passed.
Exact role, Cognito, table and closed-runtime readbacks passed. The first hosted
acceptance stopped during its read-only infrastructure preflight, before user
creation, artifact publication, runtime delivery or endpoint opening. S3 returned
the same AES256 configuration with the already-supported optional disabled
bucket-key and exact SSE-C-blocking fields, and the exact tags in another order.
Compatibility uses the prior artifact verifier's semantics, not relaxed security
or an AWS configuration change. Functional multi-user acceptance remains pending.

The next credential-free login smoke exposed a local parser bug: the exact
owned POST `/login` form had non-empty CSRF, username/password and an empty
hidden `cognitoAsfData` field. Only that known auxiliary field may be empty;
it is forwarded unchanged, never synthesized. CSRF stays unique/non-empty,
unknown hidden fields are rejected, and PKCE/token validation is unchanged.
This field is observed HTML, not a documented stable Cognito API. Before user
writes, the pool must read back as ESSENTIALS with threat-protection add-ons
absent or exactly OFF. A successful form smoke is not a successful user login.

On develop `6bf4ce8`, all eight source checks and the actual infrastructure,
pool and login-form smokes passed. One initial local attempt stopped before
user writes because a nested directory exceeded Windows path limits; a shorter
independently verified private root resolved that without ACL relaxation.
The subsequent attempt created technical A but stopped before assigning any
password: Cognito's observed subject matched the existing builder's hexadecimal
shape, but not the user operator's unjustified RFC version/variant restriction.
A read-only lookup confirmed A enabled and `FORCE_CHANGE_PASSWORD`; B creation,
artifact publication, runtime update and endpoint opening did not occur.
The acknowledged A creation intent is consumed. Recovery must keep that account,
preserve the original journal/window and use fresh separately bound provenance,
readback and first-password/B-creation intents. It must never replay A creation.
AWS documents `sub` as the stable identity within a user pool, not a validation
requirement for RFC UUID version/variant:
[Cognito user attributes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html).

On develop `86e58bf`, all eight source checks passed. The separate recovery
read back the existing A and absent B, preserved the original creation journal,
and assigned A's first permanent password exactly once. The managed-login
callback then failed; the private recovery journal confirms A's password write
and B still pending. The password was discarded rather than persisted. No
artifact publication, runtime delivery, table authorization write or endpoint
opening followed. This is not functional multi-user acceptance.

A bounded read of existing Cognito audit events matched one `login_POST` and
two `OAuth2_Authorize_GET` events for that attempt, without a logged error;
no `Token_POST` event matched. Only categorical projections were emitted, not
raw audit payloads. This narrows the observed failure to before token exchange,
but does not identify its cause or prove successful authentication. Event names
follow [Cognito CloudTrail logging](https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html).
The generic callback failure needs allowlisted stage/category diagnostics.
The first-password recovery is consumed and no longer applicable to confirmed
A. Another password assignment/login requires a separately authorized bounded
reset, exact same-user readback and fresh provenance; never replay either
historical creation or password intent, or create a replacement third user.

The owner subsequently authorized one fresh same-A password reset/login,
followed only on success by B and hosted DEV acceptance. The separate reset
operator must retain A's confirmed standard journal status, use a new reset
operation/token bound to both historical journals and the new source/window,
and stop on an ambiguous write or failed login. Offline review and fresh CI
are prerequisites, not evidence that this new live allowance has been used.

The diagnostic, bounded standards-based cookie compatibility, and separate
one-shot reset recovery passed independent offline review. The integrated
checkpoint is 3,347 passing tests, twelve environment skips, compilation and
model-free evaluation 12/12. CLI reset opt-in requires both historical journals;
every consumed reset phase is terminal for re-entry because credentials/tokens
are memory-only. This checkpoint is preparation, not another live login or a
hosted acceptance receipt. See docs/dev-multiuser-cookie-clear-hypothesis.md.

The newly authorized reset was consumed on develop `064e231`, after all eight
source checks and fresh protection checks passed. The same A reset was
acknowledged and its confirmed identity read back; login then stopped at
`login_post` with `cookie_invalid`. This establishes a local cookie-processing
failure, not which cookie attribute failed or successful authentication. B
remained pending; publication, runtime, tenant writes and opening did not run.
The final immutable reset journal is terminal (`login_failed`). Four bounded
read-only identity/app/API/Lambda checks confirmed eleven setup resources,
API disabled and reservation zero. Do not repeat this reset. A standards-based
cookie correction may be reviewed offline; another live reset requires a new
explicit allowance, not an extension of either consumed journal/window.
The owner subsequently granted one such new attempt, after standards-based
cookie repair, independent review and fresh CI. Its latest-confirmed input must
be the consumed `064e231` attempt's standard user journal; all earlier reset
journals remain immutable and terminal. This new allowance is not yet consumed.

The standards-based cookie increment passed independent offline review and
37 focused tests. It uses a memory-only native cookie jar with exact HTTPS
host/port fencing, domain/path/secure/expiry rules, 32-cookie/header limits,
4 KiB per header/value and 16 KiB outgoing header cap. Foreign cookies are
ignored rather than stored/sent; control characters and malformed/oversized
inputs fail with a fixed category. This does not loosen PKCE, CSRF, redirect,
JWT or user bindings and does not establish a successful live login.

The subsequent source attempt `545b` reached the token endpoint and stopped at
`token_post` with the safe `token_invalid` category; no raw response was
retained. Cognito's documented token response examples do not require a
`scope` member ([token endpoint documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html)).
The client therefore accepts an omitted scope as unknown, but rejects an
explicit null/wrong-type scope or a present scope missing the required value.
The independently verified JWT remains the authority for issuer, audience,
subject, resource and scope; the client never invents or decodes an unverified
grant. Token failures expose only fixed allowlisted subfield reasons.

On develop `545b7fd`, eight source checks, fresh protections and native-cookie
review passed. The same-A reset was consumed; login progressed to token POST
and failed with `token_invalid`. B remained pending and no publication/runtime/
table/opening step followed. That terminal reset journal must not be replayed.
The local full checkpoint is 3,358 passed and twelve environment skips; an earlier
run had two packaging-fixture read failures which passed isolated and on the full
rerun, without relaxing source checks. The token parser's mandatory response-body
scope is incompatible with official Cognito token response examples; this is not
proof of which field failed live. The owner approved one new bounded attempt
after repairing that documented incompatibility, independent review and fresh CI.
Missing body scope must not invent a grant or weaken signed JWT scope validation.

The corrected token-body parser passed the integrated offline checkpoint of
3,374 tests with twelve environment skips, compilation and model-free evaluation
12/12. Omitted scope remains unknown; explicit invalid or insufficient scope
fails closed. Only fixed validation reasons may leave the operator. This is
preparation for the newly authorized attempt, not hosted acceptance. Independent
review accepted the increment, including real RSA/JWKS tests for absent/wrong
JWT scope, valid scope and a foreign signature, plus diagnostic redaction.

The newly authorized attempt was consumed on develop `a7bbd0a`, after eight
green checks and fresh protections. A and B authenticated and their signed
JWTs were verified. The pinned ARM package, private artifact publication and
recurrent IAM narrowing passed. Runtime update was acknowledged but rolled
back; bounded existing stack-event projections identify `kms:Encrypt` denied
explicitly by the permissions boundary for `McpHandler`. They do not establish
the exact KMS key binding. Read-only checks confirmed `UPDATE_ROLLBACK_COMPLETE`,
eleven resources, API disabled and Lambda reservation zero. No endpoint opening,
tenant authorization publication or HTTP E2E occurred. The same-A reset is
terminal `complete`; both users are confirmed. Do not replay those writes or
the acknowledged runtime update. Any exact-key permission repair, subsequent
deployment and fresh authentication must use a separately reviewed recovery
and new authorization, not the earlier partial-A/B-pending reset path.

Offline diagnosis confirms the V2 role factory currently rejects an environment
key binding and its boundary denies unlisted KMS actions. The existing exact-key
variant must not simply be activated: its V2 boundary is approximately 7,034
bytes, exceeding IAM's 6,144-byte limit (the no-key variant is approximately
5,073). Recovery must independently accept semantically equivalent compaction
and exact key/account/Lambda-service/function-context fencing before any role
update. Never remove the boundary or substitute wildcard KMS permissions. A
fresh two-confirmed-user login recovery is also required; the previous
A-confirmed/B-absent recovery is no longer applicable. The existing private
artifact has an expired immutable execution window and is evidence only, not
a package to reopen implicitly.

The owner approved the exact-key recovery and one fresh reset/login of each
same confirmed technical user, followed by bounded DEV E2E only on success.
Read-only alias metadata verified the existing AWS-managed enabled regional key;
one exact failed handler event names that same key. The matching rollback root
event uses the consumed runtime intent's exact request token. Audit event
request parameters were absent, so they do not independently prove encryption
context. The proposed grant nevertheless fails closed on any context other than
the exact DEV Lambda function ARN, and on a different key/account/service.
No key creation, quota change, production update, owner MFA or MAPIT access is
authorized. Fresh closed IAM intents/source CI and two-confirmed-user recovery
replace, rather than replay, the prior operation. Live acceptance remains pending.

The recovery CLI is `scripts/run_dev_multiuser_kms_repair.py`: fresh source/CI,
private authorization, exact closed app and recurrent role readbacks precede
one new role-stack update intent. Accepted IAM readback creates a new private
fourteen-field binding; it never replaces the original thirteen-field input.
The executor role/boundary remain byte-identical. The new confirmed-pair path
resets each existing technical user at most once, with A login required before B.
HTTP acceptance uses monotonic pacing, ten planned RPCs, a twelve-attempt ceiling
and a 120-second budget, within the independently closed five-minute endpoint.

The exact environment-encryption context remains unconfirmed: the bounded
historical setup-window lookup returned no Encrypt events, and the failed
event has no request parameters. AWS's FunctionArn examples for
[ZIP packages](https://docs.aws.amazon.com/lambda/latest/dg/encrypt-zip-package.html)
and [filter criteria](https://docs.aws.amazon.com/lambda/latest/dg/security-encryption-at-rest.html)
are not proof of the environment-variable context. The approved FunctionArn
condition stays fail-closed; a mismatch must stop the one live attempt, not
silently remove the condition or broaden permissions. No new key or KMS
encryption/decryption probe was executed.

### Subsequent live checkpoint (2026-10-06 UTC)

The owner subsequently approved the exact unused-authorizer deletion and one
new bounded pair-reset/login/deployment attempt (2026-10-07 Europe/Madrid).
Preparation must preserve terminal pair-reset lineage and the first B-creation
window. Cleanup consumes a fresh write intent before its single DeleteAuthorizer,
with closed DEV and exact old creation/delete-skipped lineage, then verifies
absence. No 404-as-success, implicit retries, IAM expansion or KMS-context
relaxation follows. This new allowance is pending execution, not a replay of
the earlier writes. AWS documents successful deletion as HTTP 204 without body:
[DeleteAuthorizer](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/apis-apiid-authorizers-authorizerid.html).

The cleanup runner is `scripts/run_dev_multiuser_orphan_cleanup.py`.
Its private `--lineage-runtime` input must be the earlier authorizer-creation
receipt, not the later failed-runtime receipt used by hosted recovery. Exact
physical-ID/create/delete-skipped event checks fence incorrect lineage before
deletion. Two CLI reads plus at most thirteen core attempts are permitted;
only one attempt can be destructive. Missing collection members remain a
fail-closed outcome. Actual bounded DEV reads confirmed explicit empty lists
for routes/integrations and no ApiId member on the authorizer item.

Recurring hosted recovery is separately opt-in via
`--allow-recurring-confirmed-pair-password-resets` and
`--pair-creation-user-journal`: original A creation, first confirmed pair/B
creation and latest terminal pair-reset journals remain distinct. Only a
complete revision-six initial pair reset is admitted; subsequent recurrence
is intentionally not accepted. Offline preparation passed 3,464 tests with
twelve environment skips, compilation and model-free evaluation 12/12.
This is preparation, not yet a successful delete/deployment/E2E.

PR #61 passed all eight checks and merged normally to develop at `9f2c5d9`.
The develop CI then failed only an existing SQLite race test on Python 3.13;
all other seven checks passed. No cleanup/reset/deployment followed. The unused
private source envelope remains immutable evidence, not an allowance to bypass
failed CI. Independent review confirmed that immediate SQLite lock rejection
does not guarantee a winner; the test now requires exactly two outcomes, at
most one winner and no persisted row if both operations fail closed. A held-lock
regression also verifies rejection and a later explicit operation after release.
Runtime behavior, retries and authorization remain unchanged. Ten focused tests
passed. See [SQLite locking](https://www.sqlite.org/lockingv3.html).

PR #60 merged normally to develop at `5b6c379` after eight green checks;
all eight develop checks also passed. The separately journaled exact-key role
repair was acknowledged and independently read back. Executor permissions stayed
byte-identical; only the CloudFormation role/boundary gained the reviewed grant.
This accepts role configuration, not Lambda environment-encryption compatibility.

The fresh confirmed-pair recovery completed one reset/login per existing A/B
account and signed-token validation for both. Its pair-reset journal is terminal
and consumed. The pinned ARM package passed verification and was published
privately. The new runtime update was acknowledged, then rolled back completely:
the JWT authorizer creation failed with `AlreadyExists`. No endpoint opening,
tenant publication or hosted HTTP E2E occurred. Dev remains disabled with Lambda
reserved concurrency zero and the original eleven-resource stack.

Bounded read-only evidence matched the sole named JWT authorizer to the prior
attempt's exact creation and `DELETE_SKIPPED` events. Its audience/issuer matched
and no route referenced it. The template's retention policy explains why it
survived rollback outside the stack's resource list. Do not infer an empty API
from the rolled-back template: the new offline preflight checks authorizers,
routes and integrations before login or password changes.

Deleting that exact orphan and another bounded pair-reset/deployment attempt
require a fresh owner decision. No deletion is implemented or executed here.
The prior reset/runtime/role write intents must never be replayed. Further pair
recovery must validate the terminal pair-reset journal and retain the original
B-creation window provenance, rather than reuse the older A-only reset validator.
Production, owner MFA, MAPIT and quota ten remain unchanged. DEV multiuser is
not yet accepted as functional; the strict KMS context remains untested.

The independent API-child helper/order tests passed (18 cases). Final integrated
offline verification passed 3,442 tests with twelve environment skips, compilation
and model-free evaluation 12/12. An earlier run hit an unrelated restart-fixture
failure that passed in isolation and in the final full run; no unrelated repair
was made. This checkpoint does not accept another live attempt. The owned
temporary wakefulness process was stopped before handoff; the original power
scheme was read back unchanged and no persistent display setting was modified.
