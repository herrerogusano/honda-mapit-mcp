# Invitation-only MAPIT onboarding preparation

This increment prepares and tests the enrollment composition offline. It does
not register real users, publish real sessions, change deployed handlers, or
promote production. The previously accepted hosted DEV E2E used technical
identities and synthetic business data; that evidence remains separate.

## Assisted user experience when a guest is available

### Actual DEV storage checkpoint — 2026-10-07

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

The proposed recovery needs a new owner decision: update only this still-empty
table to `SSEEnabled: false`, preserving encryption with the AWS-owned key and
avoiding any new KMS permission. Never delete/recreate the table, relax denies,
overwrite config keys or replay consumed intents. Independently review exact
old/new template and resource binding, closure, retained key provenance, fresh
CI/protections, one update intent/readback and a separate new probe envelope.
CloudFormation's table property documents possible interruptions; DEV remains
closed during any approved change. No production, MAPIT, owner MFA, historical
technical-user reset or quota change is included.

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
