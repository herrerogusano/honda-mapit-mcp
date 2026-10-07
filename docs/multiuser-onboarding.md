# Invitation-only MAPIT onboarding preparation

This increment prepares and tests the enrollment composition offline. It does
not register real users, publish real sessions, change deployed handlers, or
promote production. The previously accepted hosted DEV E2E used technical
identities and synthetic business data; that evidence remains separate.

## Assisted user experience when a guest is available

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
