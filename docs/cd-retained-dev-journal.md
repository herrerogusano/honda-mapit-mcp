# Retained-dev S3 CAS journal

Status: injected SDK-free offline component; no AWS client construction,
credential lookup, list/delete, lifecycle/tag mutation, retention expiry, or
deployment. This is separate from `src/mapit/aws_cd_journal.py` and its
production schema.

`RetainedDevS3Journal` derives the deterministic bucket
`honda-mapit-mcp-dev-retained-{account}-eu-west-1` and key
`journals/{runUUID}/{phase}.json`, where phase is exactly one of `preflight`,
`artifact`, `update`, or `recovery`. The constructor requires a phase-specific
state validator; it never accepts an arbitrary unvalidated state schema.

The bounded JSON envelope binds schema/kind, account, source SHA, run UUID,
phase, and a phase-normalized counter: `version` for `preflight`, `revision`
for every other phase. It also binds the previous body SHA-256 and state. JSON
duplicate keys, non-finite values, unknown envelope shape, invalid counters,
oversized bodies, malformed responses, missing checksums, non-SSE-S3 objects,
and non-JSON content type fail closed. The body is streamed only up to 64 KiB
and closed with deadline checks.

The first CAS requires `expected_revision=None` and sends `If-None-Match: *`.
Later CAS requires the loaded integer revision and sends the exact loaded ETag
with `If-Match`. Every write includes `ExpectedBucketOwner`, `AES256`,
`application/json`, and SHA-256 checksum. A successful write is freshly read
back and compared before unblocking the instance. A transport/response
uncertainty permanently blocks that instance; a new journal instance may only
perform a fresh read-only reconciliation. A known conditional conflict returns
false after that fresh read and does not retry.

The local lock is non-reentrant; S3 conditional writes provide the distributed
fence. Pending journals are retained indefinitely. No terminal tag or expiry
operation is performed by this component; any future retention policy requires
a separately accepted operation.

For a genuinely new UUID/phase, callers may opt into `create_first=True`.
That mode suppresses the initial `GetObject` entirely: `load()` returns an
unestablished empty state, and the first CAS is the atomic ownership test using
`If-None-Match: *`. It never interprets a 403 as absence and never needs
`ListBucket`. A 412 performs one exact read of the existing envelope and
returns `False`; if that read is missing or malformed, the instance remains
fenced as ambiguous. After a valid 412 read, the caller may continue from the
loaded revision with `If-Match`. The default (`create_first=False`) remains
resume mode and always reads S3 first, treating forbidden reads as failure.
`create_first` must be an explicit boolean and is not inferred from the UUID.
