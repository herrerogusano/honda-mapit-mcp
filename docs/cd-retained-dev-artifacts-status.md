# Retained-dev artifact bootstrap status

Status: offline implementation delivered; not executed against AWS and not deploy-ready.

The bounded operator prepares exactly one CloudFormation stack named
`honda-mapit-mcp-dev-retained-runtime-artifacts` from the reviewed two-resource
artifact factory (private S3 bucket plus its bucket policy). It performs an
exact caller-identity read and CloudFormation stack-absence check, persists a
fresh immutable create intent before the single `CreateStack`, and never replays
an acknowledged or ambiguous write. A subsequent readback verifies the stack,
template, resource identities, termination protection, expected-owner S3
controls, encryption, ownership, versioning, lifecycle, tags, and TLS-only
policy. The readback records a separate immutable binding receipt.

S3 `HeadBucket`/listing is intentionally not used as an absence proof because
AWS can make inaccessible and absent buckets indistinguishable. Bucket
ownership is verified only after the closed CloudFormation create and the
expected-owner readbacks; this operator never adopts an existing bucket.
Create collisions are terminal and require a new
operator decision; no import, adoption, update, delete, credential upload, or
production resource is included.

All clients, journals, clocks, and authorization are injected in the core
tests. The runner validates the private authorization/source-CI gates first,
uses direct TLS clients with one attempt and no proxies, and emits only safe
step/category/call-count projections. No AWS call, credential exchange, or
artifact publication was made for this implementation.

Independent acceptance covers 22 focused core/runner tests, including durable
intent fencing, unknown-outcome read-only reconciliation and reload of the
separate readback receipt. Three actual SDK clients were constructed with
synthetic credentials and Python networking denied: fixed eu-west-1 endpoints,
TLS verification, 2/3-second connect/read timeouts, one attempt and no proxies
were verified. SDK credential-provider INFO output is suppressed by the runner.
Parent full offline verification passed 2,676 tests with eleven environment
skips; compilation and model-free evaluation (12/12) passed.

Normal `CreateStack` is the one-attempt creation boundary, not resource import.
In eu-west-1, an existing S3 bucket name is a creation conflict, not permission
to adopt it; see [CreateBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateBucket.html)
and [CloudFormation resource import](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/import-resources.html).
Only one exact terminal-journal lifecycle rule is accepted, using the S3
`Filter.And` readback shape; pending journals and runtime packages never expire.
