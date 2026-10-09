# Invitation-only MAPIT onboarding preparation

The initial increment prepared and tested the enrollment composition offline.
The subsequent cloud storage proof below uses real SDK calls with synthetic
identities and business data. Neither registers real users, publishes real
sessions, changes deployed handlers, or promotes production. The previously
accepted hosted DEV E2E used technical
identities and synthetic business data; that evidence remains separate.

## Assisted user experience when a guest is available

### Real-account DEV continuation — 2026-10-09

The owner requested completing preparation/integration up to a consenting second
real MAPIT account, and authorized a **separate real-config DEV namespace** with
its own keys/secrets and minimum read permissions, within the existing gross
USD 1/month DEV target (not a billing cap). Exact changes and costs must be
reviewed before applying them. Production, definitive owner MFA, consumed
synthetic journals/keys, Telegram and regional Lambda quota ten are preserved.

The accepted synthetic key document pins a fictitious MAPIT pool/client and
identity pool in its configuration digest. It must not be rebound, rewritten,
rotated or reused as authorization for real accounts. The new explicit `mapit`
namespace uses table `honda-mapit-mcp-dev-mapit-identity-bindings` and config
`/honda-mapit-mcp/dev/mapit-identity-binding-config`, with a separate schema-two
key envelope. The legacy default preserves its schema-one bytes and fixed paths.
New invitations/session paths must use keys disjoint from historical keys.

The new DEV-only contextual provider receives the **existing verified grant**,
the exact durable authorization snapshot and a request-liveness check. It never
constructs an invitation from an email, free tenant argument, or unsigned claim.
The readonly enrolled factory reconstructs a binding and MAPIT proof per tool
operation; it supplies no writer to the shared registry. The opt-in entrypoint
pins a private manifest, separate invitation/MAPIT public JWKS and a fixed
maximum five-minute window. Only authenticated, durably authorized tools may
load private key material/session values. Latest config version one and its
accepted publication window are checked before the pinned decrypt read.
The paired same-credential STS verifier runs before the first authorization
table read, and independently before key metadata/decryption reads.

The separate pure four-resource bootstrap uses AWS-owned DynamoDB encryption
from creation, one exact-operator role/boundary and a read-only handler policy.
Operator and boundary retain identical exact KMS parameter-context conditions;
runtime gets decrypt only, never publication. The factory accepts at most eight
explicitly permitted tenant paths to stay below the managed-policy size limit.
This is an initial IAM subset, not a two-user product limit: registry capacity
remains sixteen, and more allowed paths require a separately reviewed change.
No wildcard tenant path, new customer-managed KMS key, or historical key rewrite
is introduced. These drafts do not grant the existing CD role new permissions.

These are new source components, **not a deployment or real-login receipt**.
The deterministic new archive is separate from the historical synthetic archive.
Offline payload-v2 tests traverse the actual MCP router, signed MAPIT identity
verifier, shared registry, pinned SSM adapter and business provider. They cover
A/B isolation, crossed sessions and in-call revocation using synthetic transports.
Actual Lambda-role decrypt permission still needs separate live readback/proof;
an enroller-role success does not establish handler-role permission.

Incremental storage cost model checked 2026-10-09 (not the full DEV bill):
the public AWS Ireland DynamoDB offer lists USD 0.1415/million on-demand read
units, USD 0.705/million write units and USD 0.283/GB-month Standard storage.
An illustrative 10,000 read units, 1,000 write units and 0.01 GB, plus 10,000
symmetric KMS requests at USD 0.03/10,000, totals approximately USD 0.035/month
before tax, ignoring free allowances and credits. Units are not API-call counts:
strong reads and document sizes determine consumed units. IAM has no standalone
resource fee; Standard Parameter Store/default throughput has no additional SSM
charge, while KMS requests remain separate. No new customer-managed key fee is
introduced. This excludes existing/new runtime invocations, API, logs, artifacts,
data transfer and any Cognito usage; complete scope/cost review still precedes
live provisioning and the USD 1/month target is not a guaranteed billing cap.
Sources: [Ireland DynamoDB public offer](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonDynamoDB/current/eu-west-1/index.json),
[Parameter Store pricing](https://aws.amazon.com/systems-manager/pricing/),
[KMS pricing](https://aws.amazon.com/kms/pricing/).

Remaining execution sequence:

1. Independent review, source CI, exact cost/IAM/template diff and fresh private
   authority for the new namespace; no replay of accepted synthetic operations.
2. Read back/provision only approved real-DEV resources and create-only keys.
   Preserve the original tables, rows, key versions and complete old receipts.
3. Pin the real MAPIT configuration/JWKS and explicit DEV invitation. A dedicated
   DEV OAuth client for the existing owner identity was separately approved;
   no MFA change, new user, password reset or identity-pool migration is implied.
4. Deliver the new closed runtime through reviewed artifact/CD gates, then arm
   independent closure before a bounded test. No endpoint opening from imports.
5. Connect the owner's session through the private assisted channel with consent,
   verify real identity/refresh continuity and readonly status/distance access.
   No password/session token in chat, source, archives, environment or vault.
6. Stop for the second consenting real MAPIT user; test cross-account isolation
   and revocation with two real accounts before any production promotion.

No self-service public registration, hosted password portal, paid model or
Telegram multiuser expansion is included. A guest is not required for offline
integration, but synthetic acceptance cannot substitute for the final real-user
test. Retention and exact reconciliation remain mandatory after ambiguous writes.

### Approved isolated owner OAuth client — 2026-10-09

**Actual cloud checkpoint:** PR #81 merged normally to develop `2118d9b` after
eight green PR checks (CI 37922442130) and eight integrated checks (CI
37922805228). Frozen suite: 3,968 passed/twelve skips; 73 focused checks,
compilation, deterministic evaluation 12/12 and 49 network-denied schemas pass.
Fresh preparation/preflight/create/readback completed with 16/18/33/23 calls.
Only one `CreateStack` was dispatched; its intent is consumed. The new retained
stack has exactly three complete resources, and the old pool/domain/MFA/clients
and closed nineteen-resource application match the pinned pre-create context.
Independent receipt review and 22 bounded metadata reads accepted that unchanged
context, the three owned resources and the exact candidate readback digest.
No real login or MAPIT session operation followed. The registered assisted
callback is not yet a listener or a Codex callback registration. Do not replay
this operation, reset users or confuse infrastructure acceptance with onboarding.

The remaining real-account deployment is not a replay of the synthetic E2E.
The MAPIT factory/schema-two namespace and runtime/archive source exist, but
their exact bootstrap/key-publication, private manifest and closed-runtime
delivery operators are not ready. A fresh owner invitation also needs its own
exact authorization-table grant and runtime read permission: the old technical
A/B keys/grants are immutable and cannot authorize a new real identity. The
assisted PKCE listener/token exchange is another explicit missing integration;
registering a callback is not evidence of a working login. Do not ask for guest
credentials or substitute historical users while these seams remain unverified.

The owner approved a DEV-exclusive public OAuth client in the existing permanent
identity pool, reusing the same user and enrolled MFA. The separate stack owns
only a DEV resource server, code/PKCE client and Cognito-provided managed-login
branding. It does not update the identity stack, its clients, pool, domain,
users or MFA; it does not open DEV or touch MAPIT. The DEV resource URI and
scope cannot authorize production. Callback registration must use the exact
assisted listener URL from fresh private authority, not a guessed Codex callback.

The injected coordinator requires source CI/protection checks, a pinned readonly
security-context digest and a durable one-shot create intent. Existing client
configurations, pool MFA, identity/app templates, closed API and zero Lambda
reservation must read back unchanged, excluding only the newly created client.
Any unacknowledged write is fenced, not retried. Offline tests/schema validation
are not a deployed-client or real-login receipt. Fresh reviewed source and
immutable private authority precede the single allowed create operation.

For these three OAuth resources, the published Cognito price model has no
minimum/upfront resource fee; direct user authentication is MAU-based. Essentials
lists USD 0.015/MAU above the shared 10,000-MAU account/organization allowance.
This client uses authorization code, not paid machine-to-machine client-credentials
grants; existing user/pool/tier remain unchanged. For one owner's direct login,
the illustrative authentication amount before allowances is USD 0.015/month,
not the whole DEV bill or a guaranteed incremental charge. MFA remains existing
TOTP (no SMS); no email/reset operation is included. Reviewed 2026-10-09 against
[Cognito pricing](https://aws.amazon.com/cognito/pricing/). Runtime, storage and
logs remain governed by the separate DEV estimate above.

### Actual DEV storage checkpoint — 2026-10-07

**Superseding accepted recovery:** PR #78 merged to develop `4169fa4` after eight
green checks; all eight integrated checks passed (CI 37646210883). Local tests:
3,842 passed, twelve skips; compilation, model-free evaluation 12/12 and 47
actual pinned network-denied schema checks passed. A new immutable private
authority and separate journals performed one table-only update: preflight 46
calls, update acknowledged 47, exact transition readback accepted 47. The table's
identity, four resources, IAM and original config keys were preserved; only its
SSE flag changed to AWS-owned default encryption.

The new real SDK exercise passed (132 calls): both synthetic tenants enrolled,
results isolated, A terminally revoked and B unaffected. Final readback passed
(58 calls), including durable statuses and latest version-one tenant parameters.
Independent local receipt review accepted historical digests and separate update/
proof states. Nine independent final AWS reads verified closure, nineteen app
resources, completed binding stack, same TableId, owned encryption, config version
one and regional Lambda quota ten. No endpoint opening, historical user reset,
real MAPIT operation, paid model or production change occurred. Both new intents
are consumed: do not replay them or regenerate the retained keys.

This is cloud **storage/onboarding-component** acceptance with synthetic data,
not a new hosted guest-MAPIT login or production multiuser deployment. Connecting
that component to a reviewed hosted manifest/runtime and testing a real guest
remain separate work. The paragraphs below preserve the earlier consumed failure
and its approved recovery context, not a current storage blocker.

The dedicated four-resource stack was created once and accepted with 47 exact
readbacks on develop `d375e4e` (eight integrated checks, CI 37637055555). The
original nineteen-resource app stays closed; its code/template and regional
quota are unchanged. The added read-only policy belongs to the separate stack.

The first real SDK proof passed preflight and create-only publication plus
decrypted readback of config keys at version one. It then stopped with
`storage_exercise_unverified`: this is NOT A/B storage or onboarding acceptance.
Its durable intent is consumed. Read-only reconciliation found no binding item
and neither synthetic tenant parameter; config keys remain accepted and private.

Actual assumed-role GetItem returned a dependent KMS Decrypt denial. The table
uses the existing AWS-managed DynamoDB key, while the enroller explicitly allows
only the exact SSM key. A DynamoDB-only IAM simulation was allowed, but did not
model that dependent call. The table factory's `SSEEnabled: true` selects the
AWS-managed key, not the AWS-owned default.

The owner subsequently approved a separate one-attempt recovery: update only
this still-empty table to `SSEEnabled: false`, preserving encryption with the AWS-owned key and
avoiding any new KMS permission. Never delete/recreate the table, relax denies,
overwrite config keys or replay consumed intents. Independently review exact
old/new template and resource binding, closure, retained key provenance, fresh
CI/protections, one update intent/readback and a separate new probe envelope.
CloudFormation's table property documents possible interruptions; DEV remains
closed during any approved change. No production, MAPIT, owner MFA, historical
technical-user reset or quota change is included.

The new recovery operator must bind the immutable prior bootstrap, stopped
probe and accepted-key journals, and preserve the table's TableId and creation
time. Its update receipt and new proof receipt are separate: testing must not
rewrite acceptance of the encryption transition. Existing config keys remain
version one and are loaded only into memory; no key publication is replayed.
Source CI and independent operator review precede execution. Authorization
alone does not establish that this transition or the new storage proof passed.

Sources: [CloudFormation SSESpecification semantics](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-dynamodb-table-ssespecification.html),
[DynamoDB table update behavior](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html),
[changing existing table encryption](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/encryption.tutorial.html).

### Newly authorized isolated DEV storage block

The owner approved a dedicated DEV binding table and minimum operator/runtime
permissions. This does not authorize production promotion, historical technical
account resets, owner MFA changes, real MAPIT sessions, or a Lambda quota change.
The new bootstrap is separate from the accepted nineteen-resource closed app.
Its enrollment role is trusted only to the privately pinned, independently
verified operator IAM user; CD and read-only proof roles receive no enrollment
powers. Runtime access is read-only. Two fresh synthetic tenant paths must not
reuse either historical technical tenant key.

The operator and runtime also require stable independent binding-MAC and
identity-proof keys. Their explicit handoff is one additional Standard
SecureString at `/honda-mapit-mcp/dev/identity-binding-config`, version one,
using `alias/aws/ssm`. Keys are generated in memory and never belong in source,
CloudFormation, ZIPs, Lambda environment values, journals or the vault. The
canonical bounded payload binds account, table, environment and MAPIT config.
Create-only publication and exact decrypted readback precede any enrollment;
an uncertain write is consumed, not retried. No implicit key rotation exists.

Standard SecureString also requires KMS Encrypt/Decrypt. Only the new enrollment
role/boundary allow those two actions on the independently resolved existing
AWS-managed SSM key ARN, with exact SSM ViaService, caller account and the three
parameter encryption contexts. Separate explicit denies reject other or missing
contexts and keys. The key policy and original Lambda permissions are unchanged.
Read-only IAM simulation accepted the intended context and explicitly denied
wrong service/path; the boundary is below the managed-policy size limit.

Cost planning uses the public AWS Ireland Price List published 2026-09-11:
Standard on-demand reads USD 0.1415/million units, writes USD 0.705/million,
and storage USD 0.283/GB-month without assuming free allowances. At the entire
document's maximum 96 KiB, 100 strong reads plus 100 writes consume 2,400 RRU
and 9,600 WRU, approximately USD 0.00711. There is one document covering all
sixteen tenants, not sixteen 96 KiB documents. Idle document storage is about
USD 0.000026/month plus item overhead. Each repeated test multiplies request
charges. Standard Parameter Store/default throughput has no additional storage
or API charge; AWS-managed keys have no monthly key rental, but underlying KMS
request charges remain part of the budget assessment. No Advanced tier, paid
model, new Lambda or customer-managed key is planned. The existing DEV target
of USD 1/month remains a target, not a guaranteed billing cap; throughput limits
are not monthly spending limits.

Sources: [Ireland DynamoDB Price List](https://pricing.us-east-1.amazonaws.com/offers/v1.0/aws/AmazonDynamoDB/current/eu-west-1/index.json),
[DynamoDB billing units](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/bp-understanding-billing.html),
[Systems Manager pricing](https://aws.amazon.com/systems-manager/pricing/),
[KMS pricing](https://aws.amazon.com/kms/pricing/).

These are implementation and cost contracts, not a live deployment receipt.
SDK storage composition is not hosted MCP HTTP acceptance. Fresh source CI,
independent review, immutable private authorization, exact existing closure and
new-stack readbacks remain mandatory before declaring a live phase accepted.

1. The owner explicitly invites the guest's MCP identity. No public signup or
   freely chosen tenant identifier is accepted. Existing policies support up to
   sixteen identities, not just the two technical test accounts.
2. The guest signs in to the MCP identity provider and sets its required MFA.
   Their MCP identity and MAPIT identity are different identities.
3. The guest connects MAPIT through a trusted, private enrollment channel.
   Passwords, tokens and OAuth callback codes never go in chat, Git or the vault.
   The local private form accepts a signed MCP access token and a MAPIT refresh
   token in a POST body. It is an operator-assisted session connection, not a
   password login or a claim that MAPIT exposes third-party delegated OAuth.
   Acquiring those sessions must use the respective supported login flow; this
   channel does not reset passwords, configure MFA, or capture browser sessions.
4. Backend enrollment reserves a durable one-shot pending intent before
   authentication, then authenticates that refresh token and verifies its signed
   MAPIT ID token. This establishes the account the guest chose to connect; it
   does not establish ownership of a particular vehicle.
5. The verified binding is sealed before the narrowly scoped publisher may
   create that tenant's secret. Exact readback and fresh authorization checks
   are required before the binding becomes active.
6. Every subsequent provider restores the independently established identity
   binding before reading the session. Another account's valid token is rejected
   before the Identity Pool credential exchange or business access.

## Implemented opt-in building blocks

| Component | Responsibility |
|---|---|
| `InvitedTenantAuthority` and `DurableTenantGuard` | Signed MCP identity, explicit invitation, authorization revision and revocation |
| `MapitIdentityVerifier.export_proof/restore_proof` | Persistent, context-sealed pseudonymous MAPIT identity; no raw subject or JWT |
| `SQLiteIdentityBindingRegistry` | Explicit local database, one-shot enrollment lifecycle and terminal tombstones |
| `DynamoDBIdentityBindingRegistry` | Shared strongly consistent document and conditional revision updates; dedicated table, maximum sixteen records |
| `AwsIdentityBindingPublisher` | Injected create-only Standard SecureString adapter and exact decrypted readback |
| `create_enrollment_clients` | Explicit temporary credentials; exact-client fresh STS verification before DDB/SSM mutations |
| `PrivateEnrollmentChannel` / `serve_private_enrollment` | Single-use loopback form, signed invitation, consent, exact Host/Origin and CSRF; no logging or external assets |
| `CloudEnrollmentFactory` | Lazy DEV-only channel composition; the fourteen-second cloud lease starts after form submission |
| `build_dev_identity_binding_table` / policy draft | Pure retained dedicated-table and exact-resource permission drafts; no deployment or existing role change |
| Explicit-environment `AwsTenantSessionReader` | Pinned version from the grant's own dev/prod namespace |
| `EnrolledCloudServicesProvider` | Restored expected identity, binding checks around secret and business access |

No component constructs a default SDK client, loads a default owner session,
discovers credentials or automatically deploys. Existing default behavior and
single-owner production entrypoints are unchanged.

## Durable data and keys

The identity registry is separate from the authorization registry. It stores
opaque tenant keys, environment, a pseudonymous account tag, a sealed identity
envelope, fixed secret path/version, lifecycle status and revision. It stores
no password, refresh/access/ID token, raw account subject, routes or coordinates.
These pseudonymous records are still private operational metadata, not public
portfolio fixtures. Repr and errors are redacted; do not dump database rows.

Both stable HMAC keys must be supplied privately. A fresh verifier can restore a
binding only with matching key, configuration and tenant/environment context.
Losing or changing keys invalidates existing bindings; rotating keys, refreshing
sessions, reconnecting a revoked tenant and migrating records require separate
reviewed procedures. There is no automatic fallback or key generation on reopen.
Pinned verification keys must also be managed before any real onboarding.

The registry has an explicit initialized schema and capacity sixteen, including
terminal tombstones. An existing row blocks another enrollment attempt before
authentication. Duplicate MAPIT identities within the environment are rejected,
including retained tombstones. No implicit schema migration or eviction occurs.

## Publication and interruption contract

The only new-secret path is
`/honda-mapit-mcp/{environment}/tenants/{opaque-tenant-key}/mapit-refresh-token`.
Initial publication is version one, `Overwrite=False`, `SecureString`,
`Tier=Standard`, `DataType=text`, with `alias/aws/ssm`. The Standard 4-KiB limit
is enforced before publication. The adapter performs at most one PUT and one
GET; it requires an explicitly configured client with total attempts one and
bounded timeouts. See AWS [PutParameter](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html)
and [SecureString encryption](https://docs.aws.amazon.com/systems-manager/latest/userguide/secure-string-parameter-kms-encryption.html).

The caller must inject a trusted account verifier that checks fresh STS identity
against the exact expected account using the same credential/client
configuration. The adapter passes its exact client to that verifier and requires
literal `True` before any SSM write. Merely supplying an account number, a
previous receipt, or a verifier that always returns true is NOT live account
verification. Synthetic tests deliberately substitute a fake verifier.

The explicit factory now provides that verifier: SSM, STS and optional DynamoDB
clients are constructed with the same supplied temporary credentials, bounded
timeouts, canonical eu-west-1 endpoints and one total SDK attempt. Its separate
one-shot verifiers accept only their exact SSM/DynamoDB client and perform fresh
GetCallerIdentity before each store's first mutation. No ambient credential
chain or credential file is used. The backend also requires pinned table ARN,
account/environment, client metadata and a short monotonic deadline. These
checks are tested with SDK Stubber; they have not been exercised live here.

## Shared backend and local channel

The cloud registry uses a dedicated `honda-mapit-mcp-dev-identity-bindings`
table, never the existing authorization table. Its string partition key is
`key`; the only authorized item is `identity-bindings-v1`. A canonical document
of at most sixteen bindings, including pending/revoked tombstones, is protected
by record and document MACs. Its 96-KiB payload ceiling is below DynamoDB's
[400-KiB item limit](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/WorkingWithItems.html).
Strong GetItem plus conditional PutItem on the document revision makes capacity
and account uniqueness atomic within that document. Conflicts are not retried.
This deliberately small registry serializes enrollment writes across tenants;
it is not an unlimited-user/scalable-per-tenant partition design.

Runtime construction passes `writer=None`; business providers can read bindings
but cannot enroll/revoke. Mutation is a separate operator capability. The pure
DEV table draft uses on-demand billing, maximum read/write throughput 100 units,
retention and deletion protection, with no TTL, stream, index, customer KMS key,
user pool or new Lambda. Throughput bounds are not a guaranteed billing cap;
96-KiB document reads/writes consume multiple request units. Exact regional
pricing and the complete IAM/boundary recovery require a new live plan before
resource creation. The permission draft is not an attached role or complete
deployed permissions boundary. It limits the table's LeadingKeys and enumerates
exact tenant secret ARNs; operator publication denies overwrite, following
[SSM's documented condition](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policy-conditions.html).

The assisted server binds only `127.0.0.1` on an explicit port, with a maximum
ten-minute form window, exact Host/Origin, no CORS, no query credentials, bounded
body/header timeouts, CSRF, signed MCP invitation and consent. It closes after
one submitted authentication attempt or expiry. Responses and representations
never contain submitted credentials; no access/body logging exists. The page
uses local fonts, no scripts, assets, analytics or external requests. Local HTTP
is acceptable only for this same-computer loopback channel: do not expose it
through a proxy, LAN bind, tunnel or public ingress. It is not a hosted guest
portal. The static form was visually checked in a background local browser.

An operator supplies `CloudEnrollmentFactory` as the channel's
`enrollment_factory`, together with the exact invitation authority/guard,
privately supplied stable keys, pinned MAPIT verifier/config/transport and a
temporary-credential supplier returning `EnrollmentCredentials`. No client or
credential is constructed/read until a signed form is submitted. Do not build
a fourteen-second DynamoDB registry before the user reads the page: the lazy
factory creates it inside that short post-submission lease. Existing production
and hosted synthetic entrypoints are unchanged, so importing these components
does not deploy or activate enrollment.
The expected account/role must come from independently verified private DEV
operator authority, never a form field or caller-selected account. DEV and prod
may share an AWS account; fixed DEV names alone do not prove credential/account
identity. No production account identifier is hardcoded in the public source.
Browser password managers/extensions are outside the server's control; the
form disables autocomplete and warns the user not to save its token fields.

Publication receipts are strict typed path/version/create acknowledgements,
not a substitute for cloud evidence. The real adapter issues its receipt only
after comparing the exact ARN, path, type, version and value in memory and
rechecking authorization. No secret is returned in a receipt.

Neither SQLite nor DynamoDB and Parameter Store are one atomic transaction. A crash, timeout,
unknown PUT outcome, failed readback or revocation before activation can leave a
pending row and possibly a retained secret. Revocation immediately after
activation can leave an active binding behind revoked authorization; access is
still denied. There is no cross-store atomicity claim. Such an intent is consumed and
must not be replayed, auto-reset, overwritten or automatically deleted. A
separate exact, read-only reconciliation must first establish what exists.
An unknown DynamoDB write also fences further mutations on that registry
instance. A fresh instance or an absent read is not authorization to repeat an
unknown request: delayed completion must be reconciled against fresh immutable
operator intent, exact item revision/MAC and exact secret version/ARN. No
automatic retry, deletion, reset, tombstone eviction or key regeneration follows.
Revocation denies cached services and discards in-flight results; it neither
cancels an already started request nor deletes credentials.

## Evidence and gates before real hosting

Local tests must cover two independently signed MCP callers and MAPIT accounts,
durable reopen with a new verifier, swapped sessions, malformed context/keys,
duplicate accounts, pending/revoked records, ambiguous publication, replay,
cached revocation and revocation during a call. The SSM adapter is also tested
with real SDK models and Stubber, without network calls. These are offline
composition tests, not live MAPIT or AWS onboarding acceptance.

The backend, assisted channel, explicit credential/account factory and DEV
resource/permission drafts are now implemented and tested offline. Before
deploying this path, separately approve and prepare the live integration:

- Creation/readback of the dedicated table and exact reviewed operator/runtime
  permissions, without treating existing authorization-table grants as sufficient.
- Invitation administration, supported session acquisition, MFA policy and
  private persistent MAPIT/HMAC key lifecycle. The local channel is assisted,
  not a production-ready hosted password/OAuth onboarding portal.
- Exact per-tenant secret IAM, durable backend schema/retention, migration and
  recovery/credential rotation contracts. Do not expand the legacy owner IAM.
- A reviewed manifest/entrypoint/artifact, cost estimate, source CI, immutable
  deployment authority and bounded synthetic DEV window with verified closure.
- A separately authorized owner MAPIT test, followed eventually by a consenting
  second real account, and a separate production promotion decision.

No real guest is needed to complete the offline preparation. Without those
future integrations, do not describe this library as deployed self-service
onboarding or two-real-account production acceptance. Telegram remains
owner-only, production MFA remains intact, Lambda quota remains ten, and no
paid model is involved.

## Reproducing the offline checks

With the project's test dependencies installed, run:

```powershell
python -m pytest -q tests/test_identity_binding.py tests/test_identity_binding_independent.py tests/test_enrolled_provider.py tests/test_aws_identity_binding_publisher.py tests/test_aws_identity_binding.py tests/test_cloud_enrollment.py tests/test_private_enrollment.py tests/test_private_enrollment_independent.py tests/test_aws_enrollment_clients.py tests/test_aws_identity_binding_infra.py tests/test_mapit_identity.py tests/test_aws_tenant_session_reader.py
python -m compileall -q src tests
python scripts/evaluate_agent_dataset.py
```

For the SSM SDK-model test, the caller's isolated test environment must also
provide boto3/botocore; Stubber receives explicit synthetic credentials and
performs no cloud operation. These commands do not ask for guest credentials.
Independent review accepted the registry, adapter and composition, plus eight
holdouts for token validation, capacity and concurrent enrollment. The earlier
local-registry suite passed 3,593 tests with twelve Windows-specific skips.
The shared-backend/channel increment was independently reviewed with three
additional full composition holdouts; its final full suite passed 3,653 tests
with twelve environment skips. Compilation and model-free evaluation passed
(12/12); all 45 fixed CloudFormation drafts passed pinned network-denied schema
lint. This is offline evidence, not a hosted onboarding acceptance receipt.
