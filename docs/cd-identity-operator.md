# Closed CD identity bootstrap operator core

`mapit.aws_cd_identity_bootstrap.CdIdentityBootstrapCoordinator` is an
injected, one-step coordinator, not a deployment command. A caller must supply
single-attempt `sts`, `iam`, and `cloudformation` clients plus the private
journal; importing the module constructs no SDK clients and makes no requests.
The accepted steps are `preflight`, `create`, `check-create`, and
`final-readback`. Each invocation is capped at 30 seconds and 24 AWS calls.

Preflight checks a non-root caller in the expected account, the exact existing
GitHub OIDC provider URL and audience, absence of the fixed stack, and absence
of both exact roles and boundaries. It derives the fixed dev/prod subjects
from the separately observed legacy/immutable formats and verifies their
subject digests. Only after every check passes does it save the immutable
account/provider/subject/source/window/template bindings and a fresh UUID.

`create` saves the unique run tag, exact template digest and
`ClientRequestToken` intent before its one `CreateStack` call. It sets named-IAM
capability and termination protection, and attaches no CloudFormation service
role. An ambiguous write is never replayed. A later `check-create` can only
reconcile through the exact stack name plus the unique run tag and matching
CloudFormation event token; it never adopts by name alone. Readback must match
the complete template, four resource types/identities, termination protection,
both exact role trust/policy configurations, and both exact boundary policy
versions. `final-readback` repeats those read-only checks.

Output is limited to step/category/call-count booleans and contains no account,
provider, subject, stack, role, or policy identifiers. This core does not
exchange a GitHub token for AWS credentials, update any existing stack, grant
deployment permissions, or prove an AWS trust exchange. The boundary and inline
policy permit only `sts:GetCallerIdentity`; later deployment permissions
require a separate, reviewed permissions upgrade. Effective AWS permission
evaluation is also subject to other applicable policies; see the
[IAM boundary and policy-evaluation documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html).

Tests use synthetic IDs and fake clients only. No AWS deployment, token
exchange, or live identity read was performed by this module's test suite.

## Offline acceptance — 2026-10-05

Independent review accepted the fixed CloudFormation role-name readback,
exact missing-stack error, crash-after-intent read-only reconciliation,
pagination denial and final existing-provider recheck. The focused core and
independent suite passed 32 tests. A local pinned Botocore model check confirmed
the boundary-type field belongs to the role attachment, not the managed policy.
The existing SDK CI job now runs both files with pinned SDK dependencies.
These are offline acceptance facts, not evidence of role creation or AWS trust.
