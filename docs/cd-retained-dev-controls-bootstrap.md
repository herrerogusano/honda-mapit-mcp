# Retained-dev controls bootstrap

This is a separate, injected, read-before-write bootstrap for the closed
retained-dev control stack. It is not the production CD path and does not open
the API endpoint, add routes, invoke Lambda, or change reserved concurrency.

## Fixed contract

- Stack: `honda-mapit-mcp-dev-retained-controls` in `eu-west-1`.
- Template source: `build_retained_dev_controls(api_id)`; callers cannot supply
  an arbitrary template.
- Resources: exactly `ShutdownWorkflowRole`, `ShutdownStateMachine`,
  `RequestTripwireAlarm`, `RequestTripwireEventRole`, and
  `RequestTripwireAlarmRule`.
- The retained five-resource stack contains no Scheduler resources or
  schedule. Its EventBridge rule remains disabled and the alarm has actions
  disabled. A fresh, separately reviewed scheduled-close component is required
  before any future activation. The generated template must retain its
  `NoActivation` and `NoControlLambda` metadata.

## Safety boundary

`RetainedDevControlsCoordinator` constructs no SDK clients and performs no work
at import time. A caller injects direct TLS clients and a private journal. Each
step has a one-hour authorization ceiling, a 30-second monotonic budget and a
32-call ceiling. The coordinator requires STS caller identity to match the
private authorization, verifies exact CloudFormation absence before creation,
saves the deterministic create intent before the one `CreateStack`, and never
replays an uncertain create. The app binding is revalidated again after intent
save immediately before `CreateStack`; a failed revalidation leaves the intent
durable and performs no write. An uncertain create may later produce a
readback receipt while retaining `acknowledged=false`; that receipt carries and
validates the original token and stack ownership, so reload cannot replay the
create. Readback accepts only the exact stack/template,
five resource identities/statuses, tags, matching create event, role ARNs,
active STANDARD state machine, disabled EventBridge rule, and action-disabled
CloudWatch alarm. Optional CloudFormation `DriftInformation` is accepted only
as `{"StackResourceDriftStatus":"NOT_CHECKED"}`.

The private runner uses the existing seven-field authorization envelope plus a
separate API binding produced by retained-dev binding discovery (`account`,
`stack_id`, `api_id`). The coordinator re-reads that exact app stack before
creating controls and after control readback: current template/resource shape,
physical API ID, closed endpoint, and reserved-zero handler are required. It
rejects OneDrive/reparse locations, invalid ACLs, proxy/custom endpoint
variables, and mismatched account bindings. It emits only the coordinator's
categorical projection.

The final control readback also verifies each role's trust policy, exact inline
policy set/document, absence of attached policies and permissions boundary,
tags, the state-machine definition/role/logging/tracing/tags, the disabled
EventBridge pattern/target/tags, and the tripwire alarm dimensions/settings/
tags. No identity, policy document, event payload, or provider response is
included in the result projection.

## Offline verification

The coordinator and runner are independently accepted offline: 40 focused
synthetic tests pass, including named-IAM capability, resolved CloudFormation
intrinsics, SDK service names, typed HTTP status, uncertainty and closure
negatives. This is not live controls acceptance. No controls stack has yet
been created, and delivery remains in progress.

The subsequent SDK-shape repair recognizes lowercase Step Functions tag
pairs only at its dedicated readback call, retaining duplicate/unknown-field
rejection and the uppercase model elsewhere. Bootstrap also requires the
entire exact initial app template, not a permissive handler-properties subset.
Offline botocore inspection confirms the lowercase Step Functions tag fields.

The focused synthetic suite is:

```text
python -m pytest -q tests/test_aws_retained_dev_controls_bootstrap.py tests/test_run_aws_retained_dev_controls_bootstrap.py
```

Creation supplies exactly `CAPABILITY_NAMED_IAM`. Readback resolves only the
factory's known pseudo-parameters/resource intrinsics before comparing real
SDK IAM documents and EventBridge patterns; unknown intrinsics fail closed.

No AWS, MAPIT, credential, endpoint activation, or model operation is part of
these tests. A future live run still requires independently reviewed source/CI
and private authorization, the existing app API binding, and a fresh decision
to create this separate controls stack.
