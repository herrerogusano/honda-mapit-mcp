# Retained-dev update coordinator (offline prototype)

Status: injected, SDK-free, offline-only steppingstone. This document and
`scripts/aws_retained_dev_delivery_update.py` do not prove an AWS update,
CloudFormation service-role association, artifact publication, or a live
`develop` workflow. No AWS client, credential lookup, network call, or
production module is used.

Operation reconciliation requires the exact top-level stack event (stack
resource type, logical/physical identity, name and request token), not any
child resource's `UPDATE_COMPLETE`. AWS assigns the same operation token to
all events, so child events neither substitute for nor invalidate the single
matching stack completion. See [AWS StackEvent](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackEvent.html).

## Bound contract

The coordinator accepts a sealed private binding for the existing closed
retained-dev application stack: account, stack ARN, API ID, source/run
identity, exact prior template body and SHA-256, prior ZIP digest, candidate
ZIP/manifest/JWKS receipt, accepted publisher receipts, execution window,
caller ARN, and authority window. Preflight performs a fixed STS
`GetCallerIdentity` read and requires the exact non-root account/ARN binding.
For an S3-backed prior runtime, an immutable publisher receipt and fresh
`HeadObject` readback must prove the exact retained-dev bucket and
`runtime/<prior-sha256>.zip` key. The initial inline `ZipFile` scaffold is
accepted only with a separately typed `PriorCodeSnapshot` containing the exact
template and ZIP bytes captured by the bounded prior-code reader; a digest-only
substitute or reconstructed body is rejected with
`prior_recovery_unavailable`.

The candidate is constructed only by
`build_retained_dev_runtime_template`; callers cannot inject an arbitrary
CloudFormation template. Its fixed properties remain synthetic and closed:
HTTP API execute endpoint disabled, empty routes, ARM Python runtime,
reserved concurrency zero, and the exact content-addressed S3 key. Candidate
manifest digest and all binding fields are sealed into the journal identity.

The preflight Lambda tag readback uses the real SDK shape (`ListTags.Tags` is
a map), while receipts and CloudFormation stack tags remain row lists. The
original app-stack receipt must contain exactly the fixed retained-dev tags
plus its positive decimal `OperatorRunId`. That receipt is converted to the
typed `RetainedDevCreationTagBinding`; only its exact `OperatorRunId` and the
three CloudFormation-owned tags derived from the app stack ARN/name/logical ID
may appear in the Lambda map. Foreign `RunId`/`OperatorRunId` values or
foreign system tags fail closed. See
[`cd-retained-dev-lambda-tag-binding.md`](cd-retained-dev-lambda-tag-binding.md).

## Bounded sequence

Each step runs under the supplied authority window and a 30-second local
monotonic deadline, while the journal persists only a wall-clock fence (a
monotonic reading is not comparable across process restarts). The journal lock
and CAS revision fence prevent concurrent replay:

1. `preflight` performs read-only checks for caller identity, candidate
   publication receipt, the exact stack/status/
   CloudFormation `RoleARN`, canonical current template, five owned resources,
   closed API/routes, Lambda role/runtime/handler/architecture/memory/timeout/
   environment, separate reserved-concurrency and tag readbacks, and the
   expected old Lambda code digest. It persists only a
   redacted intent state.
2. `request-update` persists the update intent first, repeats the prior closed
   template/API/routes/Lambda/artifact readback, and only then makes at most one
   `UpdateStack` with the exact stack ARN, candidate canonical `TemplateBody`,
   CloudFormation `RoleARN`, `Capabilities=["CAPABILITY_NAMED_IAM"]`, and the
   run UUID as `ClientRequestToken`. A timeout, exception, malformed response,
   or non-200 response is `update_outcome_unknown`; it is never retried.
3. `check-update` reconciles read-only with `DescribeStacks`. Pending status is
   reported as `update_pending`; only `UPDATE_COMPLETE` proceeds to exact
   template/resource/status/role/code/API-closure readback. A matching
   CloudFormation stack event carrying the exact client request token is also
   required before a verified CAS receipt is written. If the original write
   response was ambiguous, the event is recorded separately and the
   coordinator does not synthesize `update_acknowledged` or success.

The injected clients are deliberately limited to STS, CloudFormation, Lambda,
API Gateway v2, and S3. Every response must have integer HTTP status 200 and no
pagination marker. The exact caller identity is rechecked immediately before
the one update write; Lambda reservation is read through
`get_function_concurrency`, not inferred from function configuration. The safe
result contains only step/category/call-count and
bounded booleans; raw templates, IDs, ZIP bytes, coordinates, and payloads are
not emitted by the coordinator.

## Recovery boundary

Unknown write results leave the durable intent present and fence subsequent
`request-update` calls. The coordinator can only reconcile an accepted exact
prior/candidate receipt; it cannot synthesize a rollback ZIP or infer a
historical readback. Operational rollback, artifact publication, service-role
association, and workflow wiring remain a separately authorized next gate.

The eight synthetic tests cover successful role/capability/readback, one
ambiguous update with no replay, an uncorrelated complete-stack response,
persisted-clock rollback, inline-scaffold rejection, and API-route closure
failure. They are not live acceptance.
