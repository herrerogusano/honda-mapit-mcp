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

## Operational preparation checkpoint — 2026-10-05

The two scoped deployment roles/boundaries now have exact live IAM and stack
readbacks. Terminal-only 30-day journal retention is installed and verified;
runtime packages and incomplete journals do not expire. The private production
binding is configured without passwords, session transfer or business facts.
These preparations did not update the production handler or attach its service
role. PRs 17–20 passed protected promotion; the first two automatic CD attempts
stopped at the credential-free source gate, with all AWS jobs skipped.

The source gate now resolves the exact upstream REST run by webhook ID and SHA,
retains the fixed CI workflow/repository/latest-main/eight-check bindings, and
provides fixed-stage diagnostics. At most five same-source check reads allow
valid pending checks to finish; negative or mismatched responses stop immediately.

An explicit retained-recovery mode permits an exactly owned stable rollback
state and either a fully open/unreserved or fully closed/reserve-zero service.
Mixed states and incomplete/failed rollbacks remain rejected. If the validated
retained ZIP and manifest are already current, recovery records a skip rather
than calling UpdateStack, then rechecks closure, code, capacity and tripwire
before a separately approved reopen. Every recovery uses a new journal/window;
historical writes and expired cutoffs are never replayed or widened.

Independent offline review accepted 100 focused tests; the full suite passed
2,457 tests with ten environment skips. Actual deployment and recovery remain
pending. CD is still IN PROGRESS, not operationally complete.

The subsequent source-gate diagnosis confirmed that the expression-based event
path was empty in Actions. The gate now uses the standard `GITHUB_EVENT_PATH`
runtime variable and BOM-tolerant JSON loading; its real source gate passed on
`89e31f3`. That run then stopped before OIDC at locked-wheel download: requesting
only manylinux2014 selected a different cryptography wheel than the existing
hash lock. Official PyPI metadata and independent actual downloads verified all
30 unchanged locks with the explicit ARM platform sequence manylinux 2.34,
2.28 and 2014. The workflow retains CPython 3.13, binary-only/no-dependency
downloads, exact hashes and pinned-image import acceptance. No AWS application
write occurred in either failure; actual release and recovery remain pending.

Run `37383378294` passed the synthetic ARM probe and all nine exact-candidate
ARM checks, but stopped at initial journal preflight. A read-only exact-key
check confirmed no journal had been created. The executor deliberately lacks
ListBucket; [S3 documents](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html)
that a missing-key GET then returns 403 rather than 404. Fresh release/recovery
records now use explicit create-only initialization: the initial absence value
is provisional, and `IfNoneMatch=*` is the atomic freshness authority before
any shutdown/update action. Creation mode is consumed before the first PUT;
all readbacks and subsequent reads are real, checksum/ETag-bound GETs. Collision,
ambiguous write or failed readback fences the instance; no 403 is interpreted as
absence. Default/reopening readers remain unchanged. No IAM expansion is added.

The next run created and read back its initial journal, but still stopped before
shutdown/publication. CloudTrail identified a service-mediated KMS Decrypt denial
while reading the Lambda environment. The generated boundary explicitly denies
unlisted actions, including KMS, even though the AWS-managed default key normally
supplies access. Three successful corresponding reads independently bound the
existing `alias/aws/lambda` key and `aws:lambda:FunctionArn` context to this exact
handler. No customer key is configured.

The opt-in correction adds executor Decrypt and CloudFormation
Decrypt/Encrypt/GenerateDataKey only for that verified key, caller account,
regional Lambda service and exact function context. The original no-key factory
remains unchanged. No key policy, CreateGrant, DescribeKey, re-encryption, SSM or
other-project capability is granted. A separate fresh, reviewed delivery-role
stack update is required before the next release; production is still unchanged.
Core preflight diagnostics expose only a fixed category and bounded call count.
Three separate explicit boundary denies fence other keys, missing/wrong service
mediation and missing/wrong function context, including resource-policy grants
to role sessions. The verified real-input boundary documents are 5,876 and
2,578 characters, below the 6,144-character limit. The IAM-only operator retains
both exact templates, records a fresh immutable one-hour window and persists its
one-shot intent before updating the existing four resources. Ambiguous outcomes
permit readback reconciliation, never a repeated write. Independent offline
checks cover drift, identity, clock reversal and post-write boundary mismatch.
See [Lambda encryption permissions](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html)
and [service/context restrictions](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html).

## First real release and recovery polling observation

The fresh four-resource delivery-role correction was read back successfully.
[Release 37387644931](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37387644931)
passed source/CI, the synthetic ARM probe and all nine exact-candidate ARM checks.
Its twelve-read core preflight, independent close, actual CloudFormation update
and separate protected reopening succeeded. Parent readbacks confirmed the exact
new code/template, attached service role, open API, unreserved function and
terminal journal tag. The first-association opt-in was then disabled for future
deliveries with a fresh secret-update intent; no application credentials changed.

[Recovery 37388126973](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37388126973)
restored the previous package, but its polling job stopped during the brief
`UPDATE_COMPLETE_CLEANUP_IN_PROGRESS` transition. CloudFormation events place
cleanup at 23:24:48.811 UTC and completion at 23:24:49.443 UTC, overlapping the
failed step at 23:24:49. The service remained closed. The proposed narrow fix
treats this owned intermediate state as pending only during update polling;
identity/ownership checks still run first and final acceptance still requires
`UPDATE_COMPLETE` plus exact template/resource/function/control readbacks.
Stable preflight, failed rollback states and opening remain fail-closed. A fresh
same-artifact recovery, not a replay of the failed intent, is being used for
restoration. Operational recovery acceptance is not yet complete.
