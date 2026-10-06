"""Offline-injected publisher for the captured retained-dev recovery ZIP.

The publisher accepts only a verified ``PriorCodeSnapshot``.  It saves a
durable intent before one conditional S3 PUT, performs one exact HEAD
readback, and never retries an uncertain write.  It constructs no SDK client,
credentials, network transport, or local artifact file.
"""

from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass
import math
import re
import time
from typing import Any

from scripts.aws_retained_dev_prior_code import PriorCodeSnapshot
from scripts.build_aws_retained_dev_recovery import (
    RetainedDevRecoveryBuildError,
    validate_initial_prior_snapshot,
)
from scripts.build_aws_retained_dev_runtime import retained_dev_artifact_bucket

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_CALLER = re.compile(r"arn:aws:(?:iam::[0-9]{12}:(?:user|role)/[^\s:]+|sts::[0-9]{12}:assumed-role/[^\s:/]+/[^\s:/]+)\Z")
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0


class RetainedDevRecoveryArtifactError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True, repr=False)
class RetainedDevRecoveryArtifactReceipt:
    bucket: str
    key: str
    sha256: str
    template_sha256: str
    size_bytes: int
    server_side_encryption: str = "AES256"

    def __repr__(self) -> str:
        return "RetainedDevRecoveryArtifactReceipt(private=True)"


@dataclass(frozen=True, repr=False)
class RetainedDevRecoveryArtifactResult:
    success: bool
    category: str
    put_attempted: bool = False
    put_succeeded: bool = False
    put_outcome_unknown: bool = False
    head_verified: bool = False
    idempotent_existing: bool = False
    journal_intent_saved: bool = False
    receipt: RetainedDevRecoveryArtifactReceipt | None = None

    def __repr__(self) -> str:
        return f"RetainedDevRecoveryArtifactResult(success={self.success!r}, category={self.category!r}, private=True)"


def _status(value: Any, expected: int = 200) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == expected


def _error(exc: Exception) -> tuple[str, int | None]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return (
        code if type(code) is str else "",
        status if type(status) is int and not isinstance(status, bool) else None,
    )


def _state(*, account_id: str, bucket: str, run_id: str, source_sha: str, expected_caller_arn: str, authorized_from_epoch: int, authorized_until_epoch: int, snapshot: PriorCodeSnapshot, key: str, status: str, revision: int) -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": "retained-dev-recovery-publication",
        "account_id": account_id,
        "bucket": bucket,
        "run_id": run_id,
        "source_sha": source_sha,
        "expected_caller_arn": expected_caller_arn,
        "authorized_from_epoch": authorized_from_epoch,
        "authorized_until_epoch": authorized_until_epoch,
        "observed_epoch": snapshot.observed_epoch,
        "key": key,
        "zip_sha256": snapshot.zip_sha256,
        "template_sha256": snapshot.template_sha256,
        "size_bytes": len(snapshot.archive_bytes),
        "intent": {"operation": "publish-initial-recovery", "key": key, "zip_sha256": snapshot.zip_sha256},
        "status": status,
        "revision": revision,
    }


def _valid_state(value: Any, expected: Mapping[str, Any]) -> bool:
    if not isinstance(value, Mapping) or set(value) != set(expected):
        return False
    if any(value.get(key) != item for key, item in expected.items() if key not in {"status", "revision"}):
        return False
    revision, status = value.get("revision"), value.get("status")
    if type(revision) is not int:
        return False
    return (status == "intent" and revision == 1) or (status == "verified" and revision == 2)


def _clock(value: Any) -> float:
    result = value()
    if type(result) not in (int, float) or isinstance(result, bool) or not math.isfinite(result):
        raise RetainedDevRecoveryArtifactError("window_invalid")
    return float(result)


def publish_initial_recovery_artifact(
    s3_client: Any,
    journal: Any,
    *,
    account_id: str,
    run_id: str,
    source_sha: str,
    expected_caller_arn: str,
    snapshot: PriorCodeSnapshot,
    authorized_from_epoch: int,
    authorized_until_epoch: int,
    wall_clock: Any = time.time,
    monotonic: Any = time.monotonic,
) -> RetainedDevRecoveryArtifactResult:
    """Publish one exact snapshot ZIP with durable intent and no retry."""
    put_attempted = False
    try:
        if (
            type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000"
            or type(run_id) is not str or _UUID.fullmatch(run_id) is None
            or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40
            or type(expected_caller_arn) is not str or _CALLER.fullmatch(expected_caller_arn) is None
            or not expected_caller_arn.startswith(f"arn:aws:") or f"::{account_id}:" not in expected_caller_arn
            or type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int
            or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS
            or not callable(getattr(s3_client, "put_object", None))
            or not callable(getattr(s3_client, "head_object", None))
            or not all(callable(getattr(journal, name, None)) for name in ("load", "compare_and_set", "locked"))
        ):
            return RetainedDevRecoveryArtifactResult(False, "artifact_input_invalid")
        checked = validate_initial_prior_snapshot(snapshot)
        if not (authorized_from_epoch <= checked.observed_epoch < authorized_until_epoch):
            return RetainedDevRecoveryArtifactResult(False, "snapshot_stale")
        bucket = retained_dev_artifact_bucket(account_id)
        key = f"runtime/{checked.zip_sha256}.zip"
        expected = _state(account_id=account_id, bucket=bucket, run_id=run_id, source_sha=source_sha, expected_caller_arn=expected_caller_arn, authorized_from_epoch=authorized_from_epoch, authorized_until_epoch=authorized_until_epoch, snapshot=checked, key=key, status="intent", revision=1)
        receipt = RetainedDevRecoveryArtifactReceipt(bucket, key, checked.zip_sha256, checked.template_sha256, len(checked.archive_bytes))
        started = _clock(monotonic)
        last_mono = started
        last_wall: float | None = None

        def guard() -> None:
            nonlocal last_mono, last_wall
            wall = _clock(wall_clock)
            mono = _clock(monotonic)
            if wall < authorized_from_epoch or wall >= authorized_until_epoch or (last_wall is not None and wall < last_wall) or mono < last_mono or mono - started >= MAX_STEP_SECONDS:
                raise RetainedDevRecoveryArtifactError("window_expired")
            last_mono, last_wall = mono, wall

        def head_verify() -> None:
            guard()
            try:
                try:
                    reply = s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED", ExpectedBucketOwner=account_id)
                finally:
                    guard()
            except Exception:
                raise RetainedDevRecoveryArtifactError("artifact_head_failed") from None
            checksum = base64.b64encode(bytes.fromhex(checked.zip_sha256)).decode("ascii")
            if (
                not _status(reply)
                or type(reply.get("ContentLength")) is not int or reply["ContentLength"] != len(checked.archive_bytes)
                or reply.get("ChecksumSHA256") != checksum
                or reply.get("ServerSideEncryption") != "AES256"
                or reply.get("ContentType") != "application/zip"
            ):
                raise RetainedDevRecoveryArtifactError("artifact_readback_mismatch")

        with journal.locked():
            def journal_load() -> Any:
                guard()
                try:
                    return journal.load()
                finally:
                    guard()

            def journal_cas(expected_revision: int | None, state: Mapping[str, Any]) -> bool:
                guard()
                try:
                    return journal.compare_and_set(expected_revision, state) is True
                finally:
                    guard()

            guard()
            prior = journal_load()
            if prior is not None:
                if not _valid_state(prior, expected):
                    return RetainedDevRecoveryArtifactResult(False, "journal_conflict")
                # Existing intent is reconciled read-only.  It is never
                # replayed, even if a previous process died after PUT.
                try:
                    head_verify()
                    if prior.get("status") == "intent":
                        verified = dict(prior); verified["status"] = "verified"; verified["revision"] = 2
                        if not journal_cas(1, verified):
                            return RetainedDevRecoveryArtifactResult(False, "journal_conflict", head_verified=True, journal_intent_saved=True, receipt=receipt)
                    return RetainedDevRecoveryArtifactResult(True, "idempotent_existing", head_verified=True, idempotent_existing=True, journal_intent_saved=True, receipt=receipt)
                except RetainedDevRecoveryArtifactError as exc:
                    return RetainedDevRecoveryArtifactResult(False, "publication_outcome_unknown" if prior.get("status") == "intent" else exc.category, put_outcome_unknown=prior.get("status") == "intent", journal_intent_saved=True, receipt=receipt)

            if not journal_cas(None, expected):
                return RetainedDevRecoveryArtifactResult(False, "journal_conflict")
            guard()
            checksum = base64.b64encode(bytes.fromhex(checked.zip_sha256)).decode("ascii")
            put_attempted = True
            try:
                try:
                    reply = s3_client.put_object(
                        Bucket=bucket, Key=key, Body=checked.archive_bytes,
                        ExpectedBucketOwner=account_id, ServerSideEncryption="AES256",
                        ContentType="application/zip", ChecksumSHA256=checksum, IfNoneMatch="*",
                    )
                finally:
                    guard()
                if not _status(reply) or reply.get("ChecksumSHA256") != checksum:
                    raise RetainedDevRecoveryArtifactError("publication_outcome_unknown")
            except Exception as exc:
                code, status = _error(exc)
                if code == "PreconditionFailed" and status == 412:
                    try:
                        head_verify()
                        verified = dict(expected); verified["status"] = "verified"; verified["revision"] = 2
                        if not journal_cas(1, verified):
                            raise RetainedDevRecoveryArtifactError("journal_conflict")
                        return RetainedDevRecoveryArtifactResult(True, "idempotent_existing", put_attempted=True, head_verified=True, idempotent_existing=True, journal_intent_saved=True, receipt=receipt)
                    except RetainedDevRecoveryArtifactError as head_exc:
                        return RetainedDevRecoveryArtifactResult(False, "publication_outcome_unknown", put_attempted=True, put_outcome_unknown=True, journal_intent_saved=True, receipt=receipt)
                return RetainedDevRecoveryArtifactResult(False, "publication_outcome_unknown", put_attempted=True, put_outcome_unknown=True, journal_intent_saved=True, receipt=receipt)
            try:
                head_verify()
                verified = dict(expected); verified["status"] = "verified"; verified["revision"] = 2
                if not journal_cas(1, verified):
                    return RetainedDevRecoveryArtifactResult(False, "journal_conflict", put_attempted=True, put_succeeded=True, head_verified=True, journal_intent_saved=True, receipt=receipt)
            except RetainedDevRecoveryArtifactError:
                return RetainedDevRecoveryArtifactResult(False, "publication_outcome_unknown", put_attempted=True, put_succeeded=True, put_outcome_unknown=True, journal_intent_saved=True, receipt=receipt)
            return RetainedDevRecoveryArtifactResult(True, "published", put_attempted=True, put_succeeded=True, head_verified=True, journal_intent_saved=True, receipt=receipt)
    except (RetainedDevRecoveryBuildError, RetainedDevRecoveryArtifactError) as exc:
        return RetainedDevRecoveryArtifactResult(False, exc.category, put_attempted=put_attempted)
    except Exception:
        return RetainedDevRecoveryArtifactResult(False, "coordinator_internal_error", put_attempted=put_attempted)


__all__ = [
    "RetainedDevRecoveryArtifactError",
    "RetainedDevRecoveryArtifactReceipt",
    "RetainedDevRecoveryArtifactResult",
    "publish_initial_recovery_artifact",
]
