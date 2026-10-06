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
before any update intent. The optional customer-managed environment KMS-key
variant exceeds that limit and remains fail-closed; it is not used in the
approved standard DEV scope. This does not change historical role factories,
executor permissions, or production policies.

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

The diagnostic, narrow explicit cookie-deletion compatibility, and separate
one-shot reset recovery passed independent offline review. The integrated
checkpoint is 3,347 passing tests, twelve environment skips, compilation and
model-free evaluation 12/12. CLI reset opt-in requires both historical journals;
every consumed reset phase is terminal for re-entry because credentials/tokens
are memory-only. This checkpoint is preparation, not another live login or a
hosted acceptance receipt. See docs/dev-multiuser-cookie-clear-hypothesis.md.
