# Phase 8 — closed infrastructure rehearsal

This is the next concrete AWS acceptance step after local preparation. It needs
renewed account authority because the previous two-hour window expired. The
existing account confirmation, region `eu-west-1`, quota 10, synthetic-only scope
and USD 1 gross allowance remain the intended boundaries. The application stays
closed throughout this rehearsal. No OAuth login or model call is involved.

## Renewed execution authority — 2026-10-02

The user approved continuing autonomously for two hours, conservatively
13:29–15:29 UTC (15:29–17:29 Europe/Madrid), including temporary display/system
wakefulness. Keep the boundaries above and do not treat absence as permission
to bypass first human login/MFA. The initial STS/Lambda preflight confirmed the
previously accepted account, non-root identity and regional/unreserved capacity
10/10. No resources were created by that preflight. The selected control stack
name is `honda-mapit-mcp-dev-control`; it must be absent before creation.

The one-step runner is `scripts/run_aws_closed_rehearsal.py`. Its state directory
must be outside Git/OneDrive with operator/SYSTEM-only ACLs verified separately.
The supervisor verified those ACLs before use. Set the expected account and
authorized-until epoch only in the command environment; no credentials enter
the journal. Each write records intent durably before dispatch, uses one SDK
attempt and requires readback after an ambiguous result. Provisioning/arming
cannot extend the saved authorization deadline. Owned-resource cleanup remains
permitted after it expires; partial-stack recovery does not require a successful
creation or a previously armed cleanup schedule.

Independent review accepted 35 runner tests, including actual SDK shape stubs,
incorrect targets/roles/retries, false shutdown flags and partial cleanup.
The full checkpoint passed 1,232 tests with five Windows symlink skips.
The live preflight then passed with 21 single-attempt reads: two stacks and
17 checked names absent. A separate AWS template syntax validation passed.
The initial closed app creation was requested at approximately 14:03 UTC;
actual creation/shutdown/deletion results must be recorded separately below.

## Resources and purpose

`scripts/build_aws_dev_bootstrap.py` derives six resources from the existing
scaffold, restricted to stack `honda-mapit-mcp-dev` in `eu-west-1`:

| Resource | Rehearsal behavior |
|---|---|
| HTTP API and default stage | Endpoint disabled; no routes or integrations |
| Cognito user pool | Empty, administrator-created users only; no clients or domain |
| Handler execution role | Existing own-log-group write policy only |
| Handler log group | Seven-day retention, explicitly deleted with the stack |
| Handler Lambda | Fixed inline 503 response, reserved concurrency zero |

The separate twelve-resource control stack supplies the existing Step Functions shutdown,
disabled request alarm/EventBridge rule, shutdown schedule and a cleanup schedule
with a dedicated CloudFormation deletion role. It requires no second Lambda
execution slot. The cleanup target is the exact newly returned application
stack ID, including its UUID, rather than every stack with the same name.

The deployment ZIP and artifact bucket are unnecessary for this rehearsal. A
later runtime deployment will use a private, project-owned, unversioned bucket
and content-addressed object key; CloudFormation will reference `S3Bucket` and
`S3Key`. It will not reuse the other project's retained SAM bucket. The accepted
standalone shutdown-Lambda draft is not deployed by this workflow and keeps its
separate historical packaging contract.

## Deletion permissions

`DeleteStack` accepts an explicit `RoleARN`, so the scheduled request can supply
a deletion role without relying on a role previously associated with the app.
The Scheduler execution role receives only deletion of the exact app stack and
permission to pass the exact deletion role to CloudFormation. The deletion role
cannot create or activate resources. Its scope is the six-resource bootstrap,
not the full future OAuth application.

The following evidence comes from cfn-lint 1.57.1's bundled `eu-west-1` provider
schemas. These describe handler permissions by resource type; runtime acceptance
is still required.

| Resource/schema identifier | Deletion role scope |
|---|---|
| API `dc4ae064d6ce6511`, stage `7ad209d7d756607a` | GET/DELETE of the exact API and its default stage |
| Pool `5b17d9ae2cc10895` | DeleteUserPool on the exact generated pool |
| IAM role `fc1cc88c36933c6f` | DeleteRole, DetachRolePolicy, DeleteRolePolicy, GetRole, ListAttachedRolePolicies, ListRolePolicies, TagRole and UntagRole on the handler role only |
| Lambda `137fa0c392feb97f` | DeleteFunction/GetFunction on the handler only |
| Log group `8614d83fb64a3f33` | DeleteLogGroup/DeleteDataProtectionPolicy on the handler group; DescribeLogGroups is the regional read-only inventory exception |

There is no API OpenAPI/S3 import and no Lambda VPC configuration, so this
composition excludes S3 object access and EC2 network-interface permissions.
The builder rejects those properties. The exclusion is specific to this
bootstrap; it is not a general minimum policy for all API/Lambda resources.
No automatic permission expansion follows an AccessDenied result.

## Execution sequence under renewed authority

1. Check the intended non-root account and region, quota/unreserved pool 10/10,
   and absence of the fixed app/control stacks and named handler resources.
   Do not adopt, update or delete pre-existing resources. Validate the exact
   generated templates before creation; keep private outputs outside Git.
2. Record time immediately before the first resource-creation attempt. Create
   the six-resource closed app using the operator's authority. Capture its
   exact stack ID, API ID and pool ID. Verify endpoint disabled, reserve zero,
   expected resources and no unexpected routes/users/clients.
3. Build the control template with those observed IDs and explicit times. Keep
   the original first-resource timestamp when recalculating a future schedule.
   Create/read back the controls while the application remains closed. Require
   exact roles, targets, static inputs and retry policies before arming anything.
4. Arm the one-time shutdown schedule and verify its readback. Observe its
   workflow result, then independently read back endpoint disabled and reserve
   zero. Do not remove reserve zero, invoke the handler or enable the endpoint.
   The request alarm/rule remain disabled because this rehearsal creates no API
   traffic; delivery of that alarm remains a later acceptance case.
5. Arm application cleanup for an earlier explicit future time within the
   existing 45-minute cleanup target and verify the exact stack/role target.
   Observe completed stack deletion, then verify the owned resources' final
   states. A requested deletion, timeout or `DELETE_FAILED` is not success.
6. Only after application deletion is confirmed, delete the owned control stack
   and verify removal of its roles, workflow, schedules, group and alarm/rule.
   Report any remaining resource and use the already-authorized operator cleanup
   path for these newly created resources. Do not force-delete a stack or retain
   failed resources merely to obtain a successful status.

Use bounded polling and single-attempt SDK/CLI calls. Capture only stages,
booleans, closed error categories and counts. On failure, preserve the owned
control resources until the app is closed/deleted; their survival is part of
recovery. The operator performs fallback cleanup if the independent path fails.

Deletion at 45 minutes leaves a nominal 15-minute tail within the one-hour
resource target. AWS deletion and event delivery are asynchronous, so neither
that target nor USD 1 is an AWS-enforced guarantee. Cognito retains a deleted
pool in an inactive state before physical cleanup; this rehearsal creates no
users or credentials in it.

## Acceptance and next step

Acceptance requires real scheduled shutdown with both readbacks, successful
application deletion using the scoped role, and final control-resource cleanup.
It establishes operational cleanup for this bootstrap only. Afterwards, prepare
the OAuth client/callback, owner's enrollment, public JWKS and real runtime
artifact using the generated identifiers in a separate deployment session.
The five-minute public endpoint window belongs to that later session.

## Live rehearsal progress — 2026-10-02

- The six-resource app reached `CREATE_COMPLETE`; independent API/Lambda
  readbacks confirmed disabled endpoint and reserved concurrency zero. Routes,
  users and OAuth clients were all empty.
- The observed-ID control template passed AWS syntax validation and all twelve
  resources reached `CREATE_COMPLETE`. Original template, event/alarm targets
  and disabled schedules passed the runner's readbacks.
- The first `check-controls` exposed a local initialization-order defect: its
  EventBridge target comparison read a journal ARN before the first successful
  verification could store it. No schedule was armed by that failed read step.
  The fix derives and validates the ARN from the observed stack resources first;
  36 focused tests, including a first-verification regression, passed independent
  review before the successful readback.
- At approximately 14:12 UTC, one update armed the shutdown schedule. Immediate
  readback confirmed its safe target/settings and closed app; execution remained
  pending at that point.
- At approximately 14:19 UTC, one real scheduled workflow execution was verified:
  both control-plane writes returned successfully, both workflow readbacks were
  true, and independent API/Lambda reads confirmed the closed state.
- One update armed exact-stack cleanup for approximately 14:21:58 UTC. By
  14:23 UTC the application was `DELETE_COMPLETE`; all six resource deletion
  records and named-resource absence checks passed. The archived stack record
  confirmed the exact dedicated deletion role was used. No operator fallback
  app deletion or IAM expansion was needed.
- The operator then deleted the owned control stack. By 14:27 UTC, its twelve
  resource records were `DELETE_COMPLETE` and the final 21-read check confirmed
  absence of all named app/control resources, roles, schedules, groups, alarm,
  rule and state machine. First resource request was 14:03:16 UTC: operational
  cleanup was verified within approximately 24 minutes, below the one-hour target.

**Closed rehearsal accepted.** Endpoint activation, Lambda handler invocation,
OAuth login, real MAPIT data, Telegram and model inference were not exercised.
The request-tripwire event delivery remains untested because its rule stayed
disabled. Final Lambda capacity remained 10 total / 10 unreserved. No additional
resource deployment is implied by this result. Actual billed cost was not
queried or measured; the gross USD 1 allowance was not an enforced billing cap.
AWS can retain CloudFormation/execution audit records and an inactive deleted
Cognito pool after operational deletion; absence checks do not erase service
audit history or claim instantaneous physical data destruction.

The initial runner CI found an optional-SDK test import outside its dedicated
environment. Its SDK-only case now uses a per-test dependency guard and is also
explicitly run in the pinned SDK job. The corrected checkpoint `5017363` passed
all seven CI jobs. This test correction did not modify the deployed resources.

Primary references: [DeleteStack RoleARN](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DeleteStack.html),
[Lambda package properties](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-code.html),
[API import configuration](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigatewayv2-api.html),
[Lambda VPC deletion](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-function-vpcconfig.html),
[Cognito pool deletion](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DeleteUserPool.html).
