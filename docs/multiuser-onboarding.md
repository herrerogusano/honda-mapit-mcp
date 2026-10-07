# Invitation-only MAPIT onboarding preparation

This increment prepares and tests the enrollment composition offline. It does
not register real users, publish real sessions, change deployed handlers, or
promote production. The previously accepted hosted DEV E2E used technical
identities and synthetic business data; that evidence remains separate.

## User experience to provide when a guest is available

1. The owner explicitly invites the guest's MCP identity. No public signup or
   freely chosen tenant identifier is accepted. Existing policies support up to
   sixteen identities, not just the two technical test accounts.
2. The guest signs in to the MCP identity provider and sets its required MFA.
   Their MCP identity and MAPIT identity are different identities.
3. The guest connects MAPIT through a trusted, private enrollment channel.
   Passwords, tokens and OAuth callback codes never go in chat, Git or the vault.
   The library accepts a refresh token in memory; it is not a login UI and does
   not assume that MAPIT exposes third-party delegated OAuth.
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
| `AwsIdentityBindingPublisher` | Injected create-only Standard SecureString adapter and exact decrypted readback |
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

Publication receipts are strict typed path/version/create acknowledgements,
not a substitute for cloud evidence. The real adapter issues its receipt only
after comparing the exact ARN, path, type, version and value in memory and
rechecking authorization. No secret is returned in a receipt.

SQLite and Parameter Store are not one atomic transaction. A crash, timeout,
unknown PUT outcome, failed readback or revocation before activation can leave a
pending row and possibly a retained secret. Revocation immediately after
activation can leave an active binding behind revoked authorization; access is
still denied. There is no cross-store atomicity claim. Such an intent is consumed and
must not be replayed, auto-reset, overwritten or automatically deleted. A
separate exact, read-only reconciliation must first establish what exists.
Revocation denies cached services and discards in-flight results; it neither
cancels an already started request nor deletes credentials.

## Evidence and gates before real hosting

Local tests must cover two independently signed MCP callers and MAPIT accounts,
durable reopen with a new verifier, swapped sessions, malformed context/keys,
duplicate accounts, pending/revoked records, ambiguous publication, replay,
cached revocation and revocation during a call. The SSM adapter is also tested
with real SDK models and Stubber, without network calls. These are offline
composition tests, not live MAPIT or AWS onboarding acceptance.

Before deploying this path, separately prepare:

- A shared cloud identity-binding backend with the same conditional lifecycle;
  local SQLite is not a Lambda shared database.
- A private user enrollment channel, consent, trusted account verifier,
  invitation administration, MFA policy and pinned MAPIT key lifecycle.
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
python -m pytest -q tests/test_identity_binding.py tests/test_identity_binding_independent.py tests/test_enrolled_provider.py tests/test_aws_identity_binding_publisher.py tests/test_mapit_identity.py tests/test_aws_tenant_session_reader.py
python -m compileall -q src tests
python scripts/evaluate_agent_dataset.py
```

For the SSM SDK-model test, the caller's isolated test environment must also
provide boto3/botocore; Stubber receives explicit synthetic credentials and
performs no cloud operation. These commands do not ask for guest credentials.
Independent review accepted the registry, adapter and composition, plus eight
holdouts for token validation, capacity and concurrent enrollment. The frozen
full offline suite passed 3,593 tests with twelve Windows-specific
environment skips; compilation and model-free evaluation passed (12/12).
