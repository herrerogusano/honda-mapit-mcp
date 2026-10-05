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
