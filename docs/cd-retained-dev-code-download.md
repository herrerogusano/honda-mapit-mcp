# Initial dev recovery ZIP transport

`retained_dev_code_download.py` provides the separately injected transport
needed by `capture_initial_prior_code`. Importing it performs no network work.
It makes one HTTPS GET to the exact already-reviewed Lambda regional S3 host,
with system certificate verification, no proxy discovery, no redirects,
identity encoding, one bounded Content-Length and at most 1 MiB.

Socket timeouts debit the supplied monotonic budget (at most thirty seconds),
including partial body reads. Late results, backward/non-finite clocks,
duplicate lengths, transfer encoding, compressed/truncated bodies and error
statuses fail with one fixed category. The URL and query never appear in the
result or exception. Connections and responses close on every exit.

The twenty synthetic transport tests do not prove the actual AWS hostname,
code download, private snapshot persistence or recovery. A different
AWS-issued host is rejected and needs bounded evidence and review, not an
automatic allowlist expansion. This helper does not publish anything to S3.
