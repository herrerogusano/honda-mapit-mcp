# Retained-dev read-only proof increment

Status: separate offline factory and bounded private bootstrap. This document does not change the accepted four-resource
role factory, its boundary, AWS, or any production workflow. It is the minimum
capability map needed to obtain a fresh owner proof for the future delivery
preflight.

An offline two-resource draft now exists in
[`build_cd_retained_dev_proof_role.py`](../scripts/build_cd_retained_dev_proof_role.py):
`honda-mapit-mcp-dev-retained-readonly-proof` plus its exact boundary. It binds
only the immutable dev subject, owner/repository IDs, provider and private
app/artifact/controls/API/Lambda/IAM bindings, plus the fixed shutdown,
tripwire and alarm ARNs. It also reads its own role/boundary and the existing
executor role/boundary for fresh drift proof. The Lambda execution role is
read without inventing a boundary ARN because the retained scaffold has no
such boundary. Cloud acceptance is still pending. The separate private runner
is documented in `cd-retained-dev-proof-role-bootstrap.md`; importing the
factory constructs no client and performs no operation.

## Why this is separate

The deployed retained-dev executor policy was accepted with its existing
four-resource factory. Its boundary is already close to the 6,144-byte IAM
policy ceiling (the offline boundary snapshot is approximately 5.3 KiB).
Adding artifact-stack, controls-stack and IAM document reads to that policy
would require a new boundary review and could silently exceed the limit. The
executor also does not currently have all of those reads. Therefore an
executor run must not label the current partial inventory as a complete owner
proof.

The immediate safe design is a separately injected, read-only owner-proof
session (or a separately reviewed dev-only proof role). It has no write
actions, no `iam:PassRole`, no `sts:AssumeRole`, no Lambda invocation, no API
execution, no S3 object access and no CloudFormation update. A later role
change is a distinct authorization and must provide a new exact template,
boundary-size proof and live readback.

## Exact read map

All calls are one-attempt, direct TLS clients in `eu-west-1`, with explicit
account/region bindings, no pagination, and mandatory HTTP 200 metadata. The
resource values below are exact private bindings; no ARN is derived from an
untrusted response.

| Client | Actions | Allowed resources and purpose |
| --- | --- | --- |
| STS | `sts:GetCallerIdentity` | `*`; bind returned account and caller ARN to the fresh authorization |
| CloudFormation | `DescribeStacks`, `DescribeStackResources`, `GetTemplate` | existing application stack ARN; prove status, termination protection, exact resource types and original template |
| CloudFormation | `DescribeStacks`, `DescribeStackResources`, `GetTemplate`, `DescribeStackEvents` | exact `honda-mapit-mcp-dev-retained-runtime-artifacts` stack ARN; prove bucket stack, resource type and closed template |
| CloudFormation | `DescribeStacks`, `DescribeStackResources`, `GetTemplate`, `DescribeStackEvents` | exact `honda-mapit-mcp-dev-retained-controls` stack ARN; prove the five fixed control resources and disabled/closed state |
| S3 | `GetBucketLocation`, `GetBucketPublicAccessBlock`, `GetEncryptionConfiguration`, `GetBucketOwnershipControls`, `GetBucketVersioning`, `GetBucketPolicyStatus`, `GetBucketTagging`, `GetBucketPolicy`, `GetLifecycleConfiguration` | exact retained artifact bucket ARN only; no `ListBucket`, object reads or object writes |
| API Gateway | `apigateway:GET` | exact API root ARN and exact `/routes` child ARN; prove API ID/name/protocol, disabled execute endpoint and empty route inventory |
| Lambda | `GetFunction`, `GetFunctionConfiguration`, `GetFunctionConcurrency`, `ListTags` | exact retained handler ARN; prove code/configuration, reserved concurrency zero, active state and tags; never invoke |
| IAM role | `GetRole`, `ListRolePolicies`, `GetRolePolicy`, `ListAttachedRolePolicies`, `ListRoleTags` | exact proof, existing executor, retained CloudFormation service, Lambda execution and two control-role ARNs; prove path, trust, tags, inline policy and managed attachments |
| IAM boundary | `GetPolicy`, `GetPolicyVersion` | exact proof, executor and CloudFormation boundary ARNs; prove path/name, default version and exact boundary document; never invent a Lambda execution-role boundary |
| Step Functions/EventBridge/CloudWatch | `states:DescribeStateMachine`, `states:ListTagsForResource`, `events:DescribeRule`, `events:ListTargetsByRule`, `events:ListTagsForResource`, `cloudwatch:DescribeAlarms`, `cloudwatch:ListTagsForResource` | exact retained shutdown state machine, tripwire rule and alarm ARNs only; no start, put, enable or invocation actions |

`DescribeStackEvents` is needed only for the controls/artifact ownership
receipt and is bounded to a fixed recent page; a response containing any
pagination marker is failure, not an invitation to continue. No action accepts
`Resource: "*"` except the unavoidable caller-identity read and any AWS API
operation whose IAM model genuinely requires it; that exception must be
verified against the pinned SDK model before a role is drafted.

## Binding and receipt changes required before implementation

The private binding must add an exact
`controls_stack_arn` for
`honda-mapit-mcp-dev-retained-controls`. The existing `controls` receipt must
be redefined to describe that stack (fixed five resource types/statuses); the
application stack remains independently checked by the app-stack, prior
template, Lambda and API receipts. Every receipt must include the complete
resource snapshot needed for comparison, not only a digest:

- stack ARN/name/status, termination protection and sorted resource types;
- Lambda configuration/code digest/concurrency/state/tags;
- API ID/name/protocol/disabled flag and exact empty-route assertion;
- role path/trust/tags, inline policy name/document, managed attachment list,
  boundary ARN/path/name/default-version/document;
- S3 security response snapshots and exact seven ownership tags.

The journal write is a strict compare-and-set over the loaded version (null
for a new record). A successful proof receipt is written only after every
readback and deadline check succeeds. A missing action, malformed shape,
pagination marker, non-200 response, stale binding or CAS conflict returns a
categorical failure and cannot produce `preflight_verified`.

## Boundary decision

Do not mutate the accepted executor factory to fit this map. The compact
candidate proof policy should be generated as a separate dev-only role draft,
with exact role/boundary names and only the rows above; its canonical policy
and boundary documents must each be measured at build time and remain below
6,144 bytes. The boundary must repeat the exact read action/resource grants
and include an explicit deny for every unlisted action. No managed-policy
attachment or boundary update is authorized by this design document.

The current draft measures both its inline policy and boundary at build time;
tests reject writes, invocation, PassRole, shutdown-start, object reads and
unbounded resource grants. Its two-resource shape remains separate from the
existing four-resource executor/service-role factory.

This two-resource read-only proof requirement is unchanged. The separately
approved four-resource multiuser CFN KMS recovery uses a different size contract:
its attached managed boundary is limited to 6,144 bytes, and its sole inline
policy to 10,240 bytes. The explicit deny for unlisted actions moves to that
inline policy while the boundary retains exact KMS key/service/context denies.
That reviewed combined-role contract does not authorize changing this proof
role or the executor; see `dev-multiuser-hosted-contract.md`.

If the candidate cannot fit without wildcard resources or omitted readbacks,
keep the scoped owner-proof session and stop. Do not trade away controls,
artifact, IAM, API-route or S3-security evidence to reuse the existing
executor role.

## Acceptance gates

Offline acceptance requires exact action/resource tests, policy-size tests,
unknown-action and write-action negatives, receipt/CAS regressions, and fake
SDK responses for every listed read. A future live gate additionally requires
fresh owner approval, source/protection checks, the exact private bindings and
a separately reviewed role/boundary readback. Until then this remains a
reviewer-ready capability map, not a deployment or ownership receipt.
