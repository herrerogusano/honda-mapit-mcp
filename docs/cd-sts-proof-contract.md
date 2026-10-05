# Bounded GitHub-to-AWS identity proof

This is preparation for a separate dev/prod identity verification, not a
deployment. The previously approved two claim-discovery runs are consumed;
approving new protected-environment runs requires the owner's separate answer.

Prerequisites are exact source CI, protected target branches/environments,
actual closed-role/boundary/provider readbacks, and a private role binding.
The role ARN is provided through a target-environment secret; neither a real
account binding nor temporary credentials belong in source, logs or artifacts.

Each target may request one runner OIDC token, make one unsigned STS
`AssumeRoleWithWebIdentity` request with a 900-second duration, then one
`GetCallerIdentity` request using only the returned credentials in memory.
Use the canonical HTTPS STS endpoint in eu-west-1, no proxy or redirects,
single-attempt SDK configuration and bounded timeouts. No default credential
lookup, environment credential export, token files, retries or polling.

Before exchange, reuse the bounded claim validator against the exact target,
source SHA/ref and default runner repository/owner IDs. AWS, not that local
inspection, verifies the token signature. Check returned issuer, audience,
subject, exact role/session ARN and credential expiration; then verify the
caller's exact account, ARN and session identity. Failure emits only fixed
categories. Success emits only target/source SHA and verified status.

Use a manually dispatched exact-checkout workflow with target-environment
approval, minimal contents-read/id-token-write permissions and pinned public
SDK dependencies. Do not expose the ARN through explicit step setup output or
use an action that exports AWS credentials into later steps. Offline fake-client
and real SDK Stubber tests must exercise mismatch, ambiguous/failing calls,
credential-chain denial, and output redaction before a live run.

These roles explicitly deny all actions except caller-identity inspection.
Successful exchange therefore proves identity trust only. It grants no Lambda,
CloudFormation, S3, IAM or MAPIT operation and does not complete deployment CD.
Production updates require a separately reviewed executor, permissions upgrade,
exact artifact/change presentation and recovery procedure.

Primary references: [STS web-identity API](https://docs.aws.amazon.com/boto3/latest/reference/services/sts/client/assume_role_with_web_identity.html),
[caller identity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html),
and [explicit SDK credentials](https://docs.aws.amazon.com/boto3/latest/guide/credentials.html).

## Offline implementation accepted

The pure injected proof core and separate runner/workflow are independently
accepted offline. The runner rejects all ambient `AWS_*` variables except its
exact role-ARN secret, rejects profile/config files and debug sources, and
constructs direct regional single-attempt SDK clients with TLS verification.
The web-identity request is unsigned; the second client uses only the returned
credential trio. Both are closed without credential export or persistence.
The workflow invokes the module from the exact checked-out source, installs
the pinned public SDK lock and retains environment approval. Tests include
real SDK Stubber/configuration/no-chain checks, a clean subprocess import and
transport redirect denial. The dedicated SDK CI job runs these tests with
pinned dependencies. No actual token request, STS proof, environment-secret
binding or workflow dispatch follows from this offline acceptance.

The actual verified dev/prod role ARNs were subsequently submitted once as
target-environment metadata secrets after fresh GitHub controls/owner binding
checks and private write intents. Both writes were acknowledged and their
metadata presence read back. GitHub does not return plaintext secret values,
so this is a submission/metadata receipt, not a readable-value attestation.
No AWS credentials or tokens were uploaded. Do not overwrite/replay these
bindings; the actual protected STS runs and their approvals remain pending.

## First authorized live proof — 2026-10-05

The owner separately authorized exactly two identity-only runs. Fresh GitHub
source CI, branch/environment protections, disabled administrator bypass and
secret metadata checks passed. A separate read-only probe verified the exact
four-resource identity stack, both closed roles/boundaries and existing OIDC
provider with sixteen reads; it did not alter the original creation journal
or extend its immutable window.

- [Dev run](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37338161383):
  source `726929c505ca11c21446ecf9a35c6d689773f027`, failed.
- [Prod run](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37338166318):
  source `6be4b6738ab100bae8b0944717c04e97a82e57d3`, failed.

Both received normal protected-environment approval and emitted only the fixed
`proof_failed` category. That category does not identify whether failure occurred
at token acquisition, claims validation, STS exchange or response verification.
Neither run establishes successful AWS identity interoperability. No deployment
or MAPIT operation occurred. The two-run allowance is consumed: do not rerun,
relax trust/verification or broaden role permissions automatically. Investigate
offline and add reviewed, non-sensitive failure-stage diagnostics before seeking
a new bounded proof allowance.

## Offline diagnostic increment

The next increment preserves the successful output and all exact trust,
response, credential, timeout and single-attempt checks. Failure output may
contain only an allowlisted stage and category. Stages distinguish runner-token
acquisition, claim validation, unsigned client creation, web-identity exchange,
exchange-response verification, credential verification, signed client creation,
caller-identity exchange and caller-response verification. Unknown exceptions
must produce fixed fallback codes, never exception text or provider payloads.
Error metadata must be sanitized again at serialization, not trusted merely
because its constructor originally validated it. Clients still close on every
exit and diagnostics must not trigger additional requests.

Neither the `Provider` expectation nor the IAM trust is relaxed: the official
[STS response contract](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html)
describes the OIDC provider as the token issuer. No evidence from the two generic
failures identifies that field as the cause. This increment is offline only;
another real proof requires separate, bounded authorization after acceptance.

Implementation preserves the legacy pre-context failure output and successful
proof projection. Known token-acquisition categories survive translation;
unexpected token errors retain a fixed acquisition stage. All other proof
errors carry sanitized stage/category pairs, with a fixed internal fallback.
The full offline checkpoint passed 2,256 tests with ten environment skips;
compilation passed. Workflow, dependencies, IAM and deployed resources are
unchanged. Independent diagnostic review and source CI are recorded separately
once complete; this checkpoint itself permits no live retry.

Independent offline review accepted the change; the supervisor's combined
focused run passed 46 tests, including
all nine failure stages, bounded call counts, client closure and canary-safe
main serialization. The source increment is prepared in PR #9. No live proof
was repeated and the original two-run allowance remains consumed.

## One separately authorized dev diagnostic attempt

The diagnostic PR #9 merged normally into develop at
`bae697e9fd47a1687fab980314430024ce24621a`; all eight source CI checks passed
in run 37340654012. Fresh branch/environment/owner/secret metadata checks and a
separate sixteen-read exact closed-stack/IAM/provider probe passed.

The owner then authorized one dev-only attempt, normally approved in the
protected environment: [run 37341041504](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37341041504).
It failed with `identity_mismatch` at `assume_role_response_validation`.
This establishes that token acquisition, local claim validation and the AWS
web-identity exchange returned successfully with HTTP 200, but an exact returned
identity-field check failed. It does not identify the field or establish a
successful end-to-end identity proof. The signed caller-identity request was not
reached. No deployment, MAPIT call, role-permission change or prod attempt occurred.

The one-attempt allowance is consumed. Do not guess a Provider-format repair,
relax identity checks, replay this run or request another token automatically.
The next diagnostic choice is a separately bounded read of the existing AWS
audit event, filtering in memory to this exact role/session/time and emitting
only field-match booleans; this is proposed, not authorized or performed.

## Authorized existing-event audit read

The owner subsequently authorized the bounded audit investigation. One regional
STS account-identity read and two single-attempt CloudTrail lookups inspected the
same narrow job-time interval in eu-west-1, at most ten events each with no
pagination. Each query matched exactly the requested role/session event; neither
was truncated. Responses remained in process memory and only comparison
booleans were emitted. No new web-identity exchange was requested.

The successful event's audience, subject digest, assumed-role ARN and session-ID
suffix matched; a credentials object was present. Its `provider` matched exactly
the privately verified owned OIDC-provider ARN, not the issuer URL or bare host.
This is concrete audit evidence of the representation mismatch. The primary
[CloudTrail STS documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html)
states that these events contain response elements except the secret access key,
and its OIDC example represents `provider` as an IAM OIDC-provider ARN. The STS
API reference's issuer wording differs. Do not expose raw audit data, which can
include temporary session tokens; the actual SDK response was not retained.

Proposed correction: accept only the exact configured issuer URL or the exact
owned IAM OIDC-provider ARN derived from the already validated expected account
and fixed GitHub issuer. Retain exact token issuer/audience/subject and all
role/session/caller checks; reject other accounts/providers and malformed forms.
This read-only authorization did not approve that implementation or another
proof. Independent offline acceptance and a new dev-only attempt allowance
remain separate before verifying actual SDK interoperability.

## Strict provider compatibility authorization

The owner approved the proposed implementation, offline validation and exactly
one new dev-only proof. Accept only a string exactly equal to the fixed issuer
URL or the exact IAM OIDC-provider ARN constructed from the already validated
expected account and fixed issuer host. Do not normalize paths/schemes, accept
the bare host, other accounts/providers or change token/role/session/caller
checks. No environment/IAM/workflow/dependency mutation or prod proof is included.
Require independent offline acceptance, eight exact source CI checks, fresh
closed IAM/provider and GitHub-protection readbacks, then normal dev approval.
The earlier proof and audit allowances remain consumed.

The compatibility increment passed independent offline acceptance; the combined
focused regression passed 75 tests, including dev/prod synthetic positives and
cross-account/path/scheme/non-string/missing-provider negatives before caller
access. Compilation and diff checks passed. No other proof check, workflow,
dependency or IAM setting changed. Live acceptance remains pending until exact
source CI and the separately authorized one-attempt dev proof complete.

## Successful dev compatibility proof

PR #10 merged normally to develop at
`7a6dbe41f0960ccd61db0126bfa8270e6cb5be34`; all eight exact source CI checks
passed. Fresh GitHub protection/owner/secret metadata checks and a separate
sixteen-read closed IAM/provider verification passed before normal approval.
[Dev run 37343136563](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37343136563)
succeeded, emitting `aws_identity_verified`, `account_verified=true` and
`role_verified=true` for that exact source. This verifies the bounded token,
web-identity exchange and signed caller-identity pipeline; it does not deploy.
Only a safe allowlisted result projection was retained. The single dev allowance
is consumed; no automatic retry or permission expansion follows.

During the owner's renewed one-hour window, 16:40:52–17:40:52 UTC on October 5,
the supervisor continued identity-only promotion/prod verification and offline
delivery design, explicitly without deployment, IAM expansion or new spending.
PR #12 synchronized main ancestry into develop without a tree change; PR #11
then promoted normally to main at `02449071162755c015692bf8d44736b14502e223`.
All eight integrated main CI checks subsequently passed in run 37344681117.
Fresh GitHub controls and a separate sixteen-read exact closed IAM/provider
verification passed. [Prod run 37344958197](https://github.com/herrerogusano/honda-mapit-mcp/actions/runs/37344958197)
received normal environment approval and succeeded on that exact main source,
with `aws_identity_verified`, `account_verified=true` and `role_verified=true`.
Its safe result projection passed the high-signal log check. This one-attempt
prod allowance is consumed, not authority for automatic re-execution.
The existing roles remain caller-identity-only; actual delivery prerequisites
are detailed in [the next production gate](cd-production-next-gate.md).
