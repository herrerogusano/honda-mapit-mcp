# Initial retained-dev prior code capture

Status: independently accepted offline; no live capture or download performed.

`aws_retained_dev_prior_code.py` is a separate injected read-only core. It
requires the entire initial five-resource inline503 template, exact caller,
Lambda configuration, code digest/size and current API/Lambda closure. Its
bounded downloader interface is not an implemented transport. The provisional
allowlist is the fixed regional Lambda task S3 hostname; a different actual
service-issued hostname fails closed and needs evidence/review, not broadening.

The returned private snapshot preserves the actual ZIP bytes and exact initial
template, with a redacted representation. The archive must contain only
`index.py`, whose bytes equal the original inline handler. No reconstruction
from a hash, write, artifact upload or rollback follows from this capture.
An operational direct-TLS/no-redirect downloader, private snapshot publication,
durable journal, fresh source/IAM/closure proof and recovery acceptance remain
separate requirements before first migration.

The eight focused tests are synthetic. No MAPIT, guest, secret, model or AWS
operation is part of this offline acceptance.
