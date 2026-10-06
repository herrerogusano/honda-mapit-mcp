# Retained-dev delivery contract (offline preparation)

Status: contract and executable data-model only; no AWS operation is authorized
or implemented by this document. The receipts below are required inputs to a
future operator, not evidence that any readback has already occurred. The
existing application stack is fixed as
`honda-mapit-mcp-dev-retained`; its exact ARN is a private binding and is never
invented or derived from a new stack name.

## Immutable private bindings

Every run must supply one bounded, duplicate-free private binding envelope with
the exact fields represented by `RetainedDevDeliveryBinding`:

- source SHA-1/commit binding, UUID run ID, positive UTC authority start/end,
  expected non-root STS caller ARN and account ID;
- exact application stack ARN, retained artifact-stack ARN, artifact bucket,
  persistent CloudFormation role ARN and the exact dev environment/API binding;
- complete private readback receipts, not only hashes: controls receipt,
  artifact receipt, prior closed template receipt, prior Lambda code/config/
  concurrency receipt, API closure receipt and IAM role/permission receipt.

Receipts are bounded canonical mappings and are validated structurally. A hash
alone cannot establish that a private resource inventory was actually read.
The envelope contains no password, session token, ZIP body, MAPIT data or
runtime history.

For the preflight gate, every receipt must be a closed, read-only AWS
readback (`closure.state=closed`, `permissions.mode=read_only`). Receipt
security/configuration fields are compared with the accepted retained-dev
factories and fixed Lambda/API/IAM baselines; a self-consistent arbitrary
receipt is not an authority grant.

S3 checks use normalized SDK readback shapes (for example
`ServerSideEncryptionConfiguration.Rules` and lifecycle `Expiration.Days`),
not raw CloudFormation property shapes. Initial inline scaffold readbacks
retain the factory's `index.handler`; S3 runtime readbacks require the runtime
handler.

Each receipt also has an exact resource shape. Controls and the artifact stack
carry stack IDs, statuses, resource-type inventories and bounded CloudFormation
event receipts; the controls receipt additionally carries fresh snapshots for
the shutdown state machine, EventBridge rule/targets, tripwire alarm and each
control IAM role. The artifact receipt additionally carries the bucket security
snapshots (location, public access, encryption, ownership, versioning,
lifecycle, policy status, tags and policy). Prior template/code receipts carry
their exact stack/function and digest bindings. Lambda carries configuration,
separate reserved-concurrency and tags readbacks, API carries ID/name/protocol,
disabled endpoint and an empty-routes assertion, and IAM carries the role
trust/path/tags, inline policy document and permissions-boundary ARN/name/path,
document and version. A receipt with only a name or digest is rejected.

## Closed delivery sequence

The future injected coordinator has four bounded stages: preflight, publish,
update and readback. Preflight re-reads the exact app/artifact/control/role
bindings and proves the application is closed (API disabled, Lambda reserved
concurrency zero, no invocation). Runtime templates are generated only through
the keyword-only retained-dev factory with source SHA and immutable
`runtime/<zip-sha>.zip` content addressing.

Publication is one S3 `PutObject` with `If-None-Match: *`, expected owner,
SSE-S3 and checksum, followed by bounded head/readback. The journal is a
separate CAS record; it contains metadata and receipts, never ZIP bytes or
private historical facts. Every PUT and UpdateStack requires a durable prior
intent. An uncertain response fences the run and permits read-only
reconciliation only; it never replays a write.

UpdateStack uses the exact existing application stack and persistent dev
CloudFormation role. Readback must match the prior closed template/code
receipt where required, the new content-addressed artifact, API closure,
reserved concurrency zero, Lambda configuration/code, IAM controls and exact
resource ownership. Recovery targets the last exact closed template/artifact,
including the first inline-503 migration case, through a fresh intent and
bounded polling. No production workflow, model, Telegram, MAPIT business
query, activation, invocation or credential migration is part of this block.

## Explicit non-goals

No default credentials, SDK client construction at import, live AWS call,
workflow mutation, production parameterization, automatic retry, deletion,
public artifact, or persistence of ZIP/private data is allowed. This contract
must pass independent offline review before any live gate is considered. The
preflight's pinned botocore model check validates operation names and known
input/output members offline; it does not construct a client or contact AWS.
