# Retained-dev read-only proof role bootstrap

Status: independently accepted offline and subsequently accepted in AWS on
2026-10-06, after PR 43 and eight green develop checks on `ee0cfec`
(CI `37485087411`). Five preflight reads passed; the one create was
acknowledged. An early two-read check returned `stack_readback_mismatch`;
the later eleven-read check verified the exact role/boundary configuration.
The private original authorization/journal is immutable and the create intent
is consumed. Never replay it. This is not STS trust exchange, secret binding,
runtime delivery or complete dev CD.

The bootstrap does not modify the already accepted four-resource role factory,
production roles, OIDC provider, private bindings, or workflow.

`aws_retained_dev_proof_bootstrap.py` consumes only the exact private inputs
required by `build_cd_retained_dev_proof_role`. It constructs no SDK clients at
import time. The three bounded steps are:

1. `preflight`: fixed STS caller identity read; exact absence checks for the
   proof stack, proof role, and proof boundary; and a read-only check that the
   existing GitHub OIDC provider still has the exact issuer and audience. The
   provider is never created or changed.
2. `create`: persist the intent first, then make at most one
   `CreateStack` with the canonical factory template,
   `CAPABILITY_NAMED_IAM`, termination protection, fixed tags, and a UUID
   client token. Exceptions or malformed responses are
   `create_outcome_unknown`; the intent fences every retry.
3. `readback`: require `CREATE_COMPLETE`, termination protection, the exact
   create token in bounded CloudFormation events, exact stack
   tags/template/resources, then verify the role trust/path/ARN/session
   duration, permissions-boundary ARN/type, exact tags, one exact inline policy,
   no attached policies, boundary metadata/default version, and decoded policy
   documents. JSON documents reject duplicate keys, malformed percent escapes,
   oversized input, and unknown shapes. Boundary type accepts only AWS's
   observed `Policy` or `PermissionsBoundaryPolicy` spellings.

All calls require HTTP 200, reject pagination markers, use a 32-call and
30-second monotonic budget, and fail closed on wall-clock or monotonic-clock
regression. The private runner uses direct TLS, one-attempt clients, two/three
second timeouts, `eu-west-1` for STS/CloudFormation and the canonical global
IAM endpoint/signing region `us-east-1`; proxy/custom endpoints are rejected.
It emits only step/category/call count.

The runner's default journal is a `FileCasJournal` adapter over the
existing ACL-checked, fsynced `FileJournal`; it is not a plain last-write-wins
save. Each CAS reloads the file, requires the exact expected revision and the
next revision, rejects malformed proof envelopes, and preserves the immutable
caller and authorization-window binding. It also rejects clock/window values
outside the bounded one-hour authorization interval before replacing a state
file. The numeric authorization `run_id` is never used as the AWS request
token: the runner derives one deterministic UUIDv5 from a fixed project
namespace, source commit SHA, and authorization run number. The same UUID is
therefore recovered on every step without accepting an arbitrary caller token.

Readback receipts retain whether the `CreateStack` response was acknowledged;
an unknown create is never rewritten as acknowledged merely because a later
read finds the stack. The receipt keeps the original UUID token and exact
template hash. A private synthetic integration test exercises the actual
default runner, three separate step invocations, the real file CAS adapter,
fixed fake SDK response shapes, and exactly one create call. This remains
offline evidence only; it does not establish AWS acceptance or authorize a
live operation.

The tests cover a complete synthetic create/readback, unknown-create fencing
without replay, provider mismatch, exact IAM documents/tags/boundary, and the
two-resource CloudFormation readback. They do not prove AWS acceptance or
authorize any live operation.
