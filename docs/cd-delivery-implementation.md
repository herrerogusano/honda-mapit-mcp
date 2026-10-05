# Operational CD — IN PROGRESS

The owner explicitly required complete CD on October 5. Successful dev/prod
identity proofs alone do not satisfy that goal. Completion requires a protected
release workflow, reproducible private publication, actual CloudFormation update
and readbacks, and independently checked recovery. No deployment is claimed here.

## Implemented and independently reviewed offline

- `ProdDeliveryAuthorization` opts into a fresh positive UTC interval of at most
  one hour, source SHA and fixed account-owned CFN role. Historical operators
  retain their expired windows. CD journal kind/source/role are distinct and
  bound to the existing artifact/template/ownership/window facts. Old journals
  cannot be reused. Owned-stack readback requires the exact role; UpdateStack
  passes it explicitly. A separately approved first-attachment opt-in accepts
  an absent role only on the exact old template; updated-template readbacks
  always require the fixed role. The boolean is immutable in the journal.
  Caller role/session is checked exactly. This is an
  operational binding, not AWS cryptographic attestation of a commit: the runner
  must still verify claims, checkout, latest release head and same-source CI.
- `build_cd_delivery_roles` produces two new prod roles and scoped boundaries,
  leaving identity roles unchanged. The executor has no Lambda code/config
  writes or IAM management. Its S3 rights are scoped to conditional runtime
  publication, journals, exact-bucket metadata and terminal tagging, without
  listing/deletion or MAPIT-secret access. The CFN role is scoped to the exact
  handler, supplied runtime prefix and existing execution-role dependencies;
  passing the execution role is an explicit decision. API management uses the
  exact HTTP API ARN, with no invented property condition. The template guard,
  not IAM, constrains changed properties. The draft is NOT_DEPLOY_READY until
  effective policy/readbacks and the real provider path are accepted.
- `S3DeliveryJournal` is injected: no clients, resources or retention mutation.
  It binds `journals/<GitHub run ID>.json`, account and source; allows only CD
  metadata, canonical JSON/checksum/SSE-S3, 64 KiB and 128 revisions. Initial
  writes use If-None-Match; later writes use the observed ETag via If-Match.
  Exact readback precedes cloud actions. Intents cannot be removed/changed or
  true receipts cleared. Conflict/timeout/uncertain write fences that instance;
  a new reader reconciles without replay. Local locking is not distributed;
  CAS is the optimistic fence. Previous-body hash is structural metadata, not
  independently retained history or an authenticated audit chain.

Synthetic delivery-role fixtures are included in the network-denied schema
checker. Components are not a workflow, deployed roles, private-bucket ownership
receipt or completed CD. Integration remains under independent review.

Offline checkpoint: 2,356 tests passed with ten environment skips, compilation
passed and model-free evaluator passed 12/12. The actual pinned schema-lint run
was unavailable in the local interpreter; focused checker tests passed, while
the two new synthetic fixtures still require the real CI schema job. No account
reads, resource writes, session migration or business invocation occurred.

## Remaining work and live gates

1. The owner approved permanent CFN role association and private journal
   storage in the existing bucket. Only verified terminal receipts receive
   `cd-terminal=true` and 30-day expiry; pending records and runtime packages
   do not expire. Preserve owner/MFA,
   quota 10, MAPIT sessions, single-owner production and the USD 1/month target.
2. Accept exact publisher/journal permissions, private bindings, fresh bootstrap/
   association procedure and recovery. Review/preserve existing lifecycle rules
   before adding journal expiry; this adapter does not delete records itself.
3. Implement the release workflow/runner: quality gates before OIDC, explicit
   temporary credentials only, reproducible private ARM candidate, serialization,
   durable journal handoff and separate protected reopening approval. No private
   packages, bindings, credentials or journals in logs/public workflow artifacts.
   A manually prepared package alone does not prove automatic CD.
4. Present exact candidate and retained previous package before updating prod.
   Close → verify → single update → exact readback → approved reopen. Reconcile
   ambiguity without replay; rollback uses a fresh journal and prior package.
   No incidental business invocation, MAPIT/Telegram or paid model smoke.
5. Record an actual successful release-branch deployment and recovery evidence.
   The deleted dev rehearsal is not permanent dev; recreating it needs a scoped
   cost/lifetime/shutdown/isolation decision.

Until these conditions hold, CD is IN PROGRESS, not complete.

A fresh read-only inventory confirmed the exact production stack, ZIP/Lambda
code hash, manifest/public JWKS and open API, without business requests or
credential retrieval. No service role is attached yet. The observed bucket is
a CloudFormation-generated abbreviated name; its bounded namespace is accepted
only with an exact owned-stack proof. Role bootstrap and terminal-only lifecycle
operators use separate one-attempt intents, immutable one-hour windows, an exact
operator identity and nondecreasing observed time. These are preparation facts,
not completed live-delivery evidence.

The operational release workflow now verifies all eight same-source CI checks
and latest main before OIDC, runs a synthetic network-disabled ARM probe,
builds the private source-bound candidate, and tests that exact ZIP in the pinned
ARM image before acquiring AWS credentials. Explicit short-lived credentials
remain in memory. Conditional publication and CAS journal handoff precede the
closed update; reopening is a separate protected job. Bucket checks bind the
complete privately recorded CFN tag fingerprint, exact TLS-only policy, owner,
region, encryption and unversioned state. The provider role additionally has
exact-function tag maintenance/read actions required by CloudFormation; the
template guard still permits only ZIP key and manifest hash changes.

The manual retained-artifact recovery workflow uses current-main CI, a fresh
journal/window and explicit prior ZIP/manifest digests. It validates bounded
SSE/checksum/body, current public bindings and semantic JWKS equivalence before
the same closed-update/readback/reopen sequence. It never republishes a package
or replays an old update. Its target can also be the newly retained package to
return forward after a rollback test. Live deployment/recovery remains pending.

Local checkpoint: 2,426 passing tests, ten environment skips and model-free
evaluation 12/12; 94 latest focused operator/workflow tests pass. Local Docker is
not running, so real ARM execution is required in GitHub's native ARM runner;
offline unit acceptance does not claim that image execution already happened.
The `ubuntu-24.04-arm` label is a supported standard public-repository runner,
verified against the [official runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
