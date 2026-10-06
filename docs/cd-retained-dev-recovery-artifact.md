# Retained-dev initial recovery artifact (offline draft)

Status: offline-only, injected prototype. No AWS client, credential lookup,
network call, publication, CloudFormation update, or rollback has occurred.

`validate_initial_prior_snapshot` accepts only the typed snapshot produced by
the bounded prior-code reader. It independently verifies the canonical
initial scaffold template, the SHA-256 values, a bounded ZIP containing only
`index.py`, and the exact closed `HANDLER_CODE`. A digest-only mapping,
reconstructed template, extra ZIP member, or changed handler is rejected.

`build_initial_recovery_template` derives the exact retained-dev artifact
bucket and `runtime/<sha256>.zip` key, then changes only the initial Lambda
`Code` from inline `ZipFile` to S3. The recovery template remains closed:
`index.handler`, no `Environment`, and reserved concurrency zero. The exact
CloudFormation service role ARN is returned as a separate binding; this
factory does not claim that the recovery template is byte-identical to the
historical inline template.

`publish_initial_recovery_artifact` saves an immutable journal intent before
one `PutObject` using `IfNoneMatch="*"`, `ExpectedBucketOwner`, AES256,
`ContentType="application/zip"`, and the SHA-256 checksum. It performs one
bounded `HeadObject` readback with checksum mode, owner binding, size, SHA,
encryption, and content type checks. The journal state binds the source SHA,
caller ARN, authorization window, and snapshot observation epoch; revisions
are strict integers. A local wall-clock monotonicity fence is checked before
and after each S3 or journal operation. A 412 is reconciled only by an exact
readback. Exceptions or malformed responses leave the intent fenced and are
never retried. A later invocation can reconcile an existing exact object but
cannot repeat the PUT.

The returned recovery template is deeply frozen and its receipt/result
representations are redacted. The snapshot observation must fall within the
supplied authorization interval; stale or misattributed snapshots are
rejected.

This artifact is a preparation step for a future closed-recovery coordinator.
Operational CloudFormation service-role association, publication, rollback,
and live readback still require a separately reviewed gate.
