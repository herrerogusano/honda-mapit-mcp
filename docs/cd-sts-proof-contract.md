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
