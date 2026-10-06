# Retained-dev closed recovery coordinator

Status: injected SDK-free offline prototype; not live acceptance.

Reconciliation accepts only the exact top-level CloudFormation stack completion
with the original request token. Child resource events sharing that token are
not stack receipts; [AWS documents the shared event token](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackEvent.html).

`scripts/aws_retained_dev_delivery_recovery.py` is the separate rollback
coordinator for the captured initial scaffold. It accepts only the typed
`RetainedDevRecoveryTemplate`, its verified S3 artifact receipt, and a sealed
current `RetainedDevBuildReceipt`. The current template is reconstructed only
through the retained-dev runtime factory; callers cannot inject a template.

The recovery target is closed: `index.handler`, no Lambda `Environment`,
reserved concurrency zero, disabled HTTP API, empty routes, exact handler tags,
and the persistent CloudFormation service-role ARN. The coordinator validates
the five resource rows, canonical template, S3 checksum/encryption/type and
owner, Lambda configuration and code hash, separate concurrency read, API
closure, tags, and the exact CloudFormation role association.

The sequence is bounded and journaled:

1. `preflight` verifies caller, captured ZIP, current closed runtime, and
   caller again before saving intent state.
2. `request-update` saves intent first, rechecks all current readbacks and
   caller, then performs exactly one `UpdateStack` with the recovery template,
   service role, named-IAM capability, and run token.
3. `check-update` reconciles read-only. It requires `UPDATE_COMPLETE`, exact
   recovery readbacks, and exactly one matching stack event with the run token.
   Ambiguous writes never synthesize acknowledgement or replay the update.

The prototype deliberately has no `UpdateFunctionCode` path. Clock rollback,
call budgets, CAS revisions, restart state, wrong event tokens, missing role
association, and ambiguous outcomes are covered by offline tests. Actual
service-role association, S3 publication, CloudFormation update, rollback,
and reopening require a separate reviewed operational gate.
