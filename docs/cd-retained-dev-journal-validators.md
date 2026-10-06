# Retained-dev journal validators

Status: offline implementation and tests only. No S3 client, credentials, or
AWS call is constructed by this module.

The retained-dev coordinators use typed bindings rather than caller-supplied
state callbacks: `ArtifactJournalBinding`, `PreflightJournalBinding`,
`UpdateJournalBinding`, `RecoveryJournalBinding`, and
`RecoveryUpdateJournalBinding`. Each binds the actual
coordinator fields (artifact/manifest digests, prior and candidate update
digests, stack ARN, recovery caller/key, or the preflight binding digest) to
the expected account, source revision, run UUID, and positive UTC authority
window no longer than one hour. Their representations are redacted.
`ValidatedRetainedDevS3Journal` supplies the fixed concrete validator
internally; an operational caller cannot replace it with a permissive
callback. The older `RetainedDevJournalBinding`/`make_phase_state` API remains
only as a compatibility prototype for its existing offline tests.

`RecoveryUpdateJournalBinding` is intentionally separate from
`RecoveryJournalBinding`: the former protects the CloudFormation rollback
state machine under the `recovery-update` journal phase, while the latter
protects the recovery ZIP publication. This prevents same-run keys and state
schemas from being reused across those operations.

Concrete inner states are closed metadata only. They contain no route/history
facts, payloads, credentials, object contents, or arbitrary receipts. Artifact
and recovery states are exact intent/verified two-step schemas with bounded
observed timestamps; preflight is the exact closed read-count schema; update
states carry only the fixed prior/candidate digests, request-token intent,
stack binding, and monotonic acknowledgement/event/verification flags. The S3
journal's outer `revision` (or preflight `version`) must equal the concrete
inner counter. A state cannot clear an intent or move a completed status or
update flag backward.

The adapter delegates conditional writes and read-only reconciliation to the
existing `RetainedDevS3Journal`. A known 412 is reconciled once and may proceed
from the exact winner; an uncertain write remains fenced and requires a fresh
adapter instance. The concrete integration tests exercise create-first CAS
without an existence read, second CAS, unknown-write fencing and fresh
reconciliation, plus the four actual state shapes and adversarial bindings.
These are offline tests only, not an AWS acceptance receipt, and do not
authorize a live operation.

The integration tests execute the concrete preflight, runtime publication,
recovery publication, normal update, and rollback coordinators through this
CAS adapter, including ambiguous-write reconciliation. They use injected SDK
shape fixtures only; no cloud acceptance is implied.
