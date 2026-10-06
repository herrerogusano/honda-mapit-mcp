# Retained-dev artifact bootstrap status

Status: the one-shot AWS creation was acknowledged and the stack reached
`CREATE_COMPLETE`; full readback acceptance is pending. Not deploy-ready.

On 2026-10-06, source `b8e5a23f18c6e0ac38e346b7a0ae67f4b9f6d2db`
passed all eight develop CI jobs (run `37469969070`) and fresh repository/dev
protection checks. A new private, immutable authorization and journal fenced
the two-read preflight and one acknowledged `CreateStack`. Never repeat that
creation intent. The subsequent bounded readback stopped at the resource
envelope: AWS included its documented optional `DriftInformation` metadata.
One additional read-only diagnostic confirmed both exact resource identities,
types, completed states, stack bindings and bucket physical IDs; it did not
complete the S3 control checks or persist raw account responses.

The compatibility verifier accepts only the optional exact object
`{"StackResourceDriftStatus":"NOT_CHECKED"}` and rejects timestamps, extra
fields and every other status. Its absence remains compatible with older
fixtures. This is not proof that drift detection was performed; current S3
controls still require all original exact readbacks. See the official
[StackResourceDriftInformation schema](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackResourceDriftInformation.html).
The separate read-only verification source must pass fresh CI and preserve
the original creation source/window/token; it must never be used for a write.
Offline SDK-shape review also corrected the encryption readback to the documented
`ServerSideEncryptionConfiguration.Rules[].ApplyServerSideEncryptionByDefault`
envelope, accepting only one AES256 rule with an absent or false bucket-key flag.
The previous fixture had incorrectly copied the CloudFormation property shape.
No encryption setting is changed by this correction; see
[GetBucketEncryption response](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/get_bucket_encryption.html).

The bounded operator prepares exactly one CloudFormation stack named
`honda-mapit-mcp-dev-retained-runtime-artifacts` from the reviewed two-resource
artifact factory (private S3 bucket plus its bucket policy). It performs an
exact caller-identity read and CloudFormation stack-absence check, persists a
fresh immutable create intent before the single `CreateStack`, and never replays
an acknowledged or ambiguous write. A subsequent readback verifies the stack,
template, resource identities, termination protection, expected-owner S3
controls, encryption, ownership, versioning, lifecycle, tags, and TLS-only
policy. A successful readback records a separate immutable binding receipt.

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
step/category/call-count projections. The original offline acceptance involved
no account calls; the bounded creation described above is a subsequent live gate.
No runtime artifact has been published, and no production resource was changed.

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
