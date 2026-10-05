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

## Initial cloud receipt and bounded compatibility repair

After all eight source checks passed, one new private-journal preflight passed
the exact account/provider/name checks. One `CreateStack` was acknowledged;
it must never be replayed. The first readback verified the exact four-resource
template and ownership, then failed closed on boundary type `Policy`.
Bounded signed diagnostics on both roles confirmed exact boundary ARN, policy
name/path, default version and the complete expected explicit-deny document.
This is not yet full coordinator acceptance or a successful STS exchange.

AWS's [GetRole reference](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/get_role.html)
is inconsistent: response syntax/model use `PermissionsBoundaryPolicy`, while
the field description uses `Policy`. Accept only these two string literals,
never a missing/unknown value, and retain every exact ARN/policy/inline/trust
readback. This changes no AWS permission or template. A repaired read-only
verification records its own reviewed source SHA separately; the original
creation source, template digest, request token and window remain unchanged.
An alternate verification source is forbidden for preflight/create steps.

## Final cloud readback accepted — 2026-10-05

After all eight checks passed on
`3df301af48aa1c2e8c0397cadd9b9c7e99e7877d`, the repaired read-only checker
passed its complete 16-read verification and a second complete 16-read final
verification. Exact template/resources/ownership, both role trusts, empty
attached-policy lists, exact sole inline policies, boundary default versions
and explicit-deny documents, termination protection and the unchanged existing
provider URL/audience all passed. The private journal retains its original
creation source `c044f257128bb60b2a62dc6db990b5dd65cbbc49`, template digest,
window, run ID and consumed write token; the verifier source is recorded
separately. No write was replayed or window extended. These are closed-role
configuration receipts, not successful STS exchange or deployment receipts.
