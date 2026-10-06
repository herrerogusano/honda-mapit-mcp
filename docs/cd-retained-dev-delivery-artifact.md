# Retained-dev artifact publisher (offline steppingstone)

Status: independently testable injected core; no AWS client construction,
credential lookup, workflow, or activation. This publisher is not evidence of
a live bucket or successful delivery.

`scripts/aws_retained_dev_delivery_artifact.py` accepts an injected S3 client,
an injected durable CAS journal, a private archive path, and the opaque,
immutable `RetainedDevBuildReceipt` emitted by
`build_retained_dev_archive.build_retained_dev_archive`. Plain caller-supplied
source/hash/manifest mappings are not accepted. The receipt binds the builder's
source allowlist, wheel lock, source proof, runtime metadata, manifest digest,
archive digest, and entry counts. The publisher regenerates the expected
manifest through `build_retained_dev_manifest`; callers cannot supply an
arbitrary manifest mapping. It verifies before any S3 call:

- account/bucket/run/source/hash input shapes and fixed `runtime/<sha256>.zip`
  addressing;
- bounded ZIP body, entry count, entry size, total uncompressed size, safe
  relative names, duplicate rejection, and no directory/symlink entries;
- exact canonical `mapit/retained-dev.manifest.json` bytes emitted by the
  retained-dev builder and the receipt's manifest digest;
- the complete archive SHA-256 against the builder receipt, so a counterfeit
  ZIP with a copied manifest cannot be published;
- immutable synthetic manifest fields from `build_retained_dev_runtime`
  (dev environment, source commit, API binding, JWKS digest, and bounded
  synthetic execution window).

The journal must expose `load`, `compare_and_set`, and `locked`; arbitrary
`save` methods are rejected. Its only valid states are `intent` at revision 1
and `verified` at revision 2; status/revision mismatches are rejected. It
records an exact publication intent before the only `PutObject` and carries a
bounded revision fence.
The write uses `If-None-Match: *`, `ExpectedBucketOwner`, `AES256`, checksum,
and `application/zip`. A successful or matching-412 write is accepted only
after one exact `HeadObject` readback of length, checksum, and SSE-S3. The
journal then records a verified receipt containing only the key and digests.

Any non-confirmed PUT result, head failure/mismatch, or post-write journal
failure leaves the intent present and fenced. A later invocation returns
`intent_present` rather than replaying the object write. A mismatched journal
or build receipt fails closed. A verified identical intent performs a fresh exact
`HeadObject` read before returning `artifact_already_verified`; it never
asserts historical verification without current evidence. Every stage is
bounded by the supplied UTC authority window and a 30-second monotonic step
deadline; a monotonic-clock regression fails closed.

The core deliberately does not prove bucket ownership, CloudFormation stack
binding, IAM policy, service-role association, or runtime template ownership;
those remain separate preflight/readback responsibilities before a future
`develop` workflow gate.
