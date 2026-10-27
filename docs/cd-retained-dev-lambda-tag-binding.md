# Retained-dev Lambda creation-tag binding

Status: narrow offline contract; no AWS readback or deployment is claimed.

The original retained-dev CloudFormation create path supplies four stack tags:

```text
Project=honda-mapit-mcp
Environment=dev
Purpose=retained-dev
OperatorRunId=<positive decimal creation run id>
```

`OperatorRunId` is the integer run identifier of the original stack creation.
It is not the UUID used by a later code update or recovery operation.  Lambda's
`ListTags` response is a map, while CloudFormation tag inputs/readbacks are
`[{"Key": ..., "Value": ...}]` rows; the verifier must keep those SDK shapes
separate.

## Narrow acceptance rule

`RetainedDevCreationTagBinding.from_stack_tags(...)` is the only supported way
to allow a propagated `OperatorRunId` in a Lambda tag readback.  It requires a
complete, duplicate-free tag list, the exact four keys and values above, the
fixed retained-dev stack name/ARN, and a canonical positive decimal (no leading
zero) creation run id.  The binding is immutable and is included in the
coordinator's SHA-256 binding identity, so changing it across a restart is a
binding mismatch.

Without this typed binding, Lambda readback accepts only the fixed base tags and
the three exact CloudFormation-owned tags derived from the known stack identity.
An arbitrary `RunId`, `OperatorRunId`, foreign CloudFormation tag, or generic
"allowed extra" is rejected.  The same binding is used by the update and
recovery readbacks.

The caller must construct the binding from a fresh, private, authorized stack
receipt.  This type validates shape and identity; it does not itself prove
freshness, account ownership, or caller authority.  Until such a receipt is
available, propagated `OperatorRunId` remains intentionally fail-closed.  No
raw tag values are emitted in safe results or logs.
