"""Injected, closed retained-dev runtime publication core.

This module is an offline-testable steppingstone.  It constructs no AWS
client and has no credential or workflow entrypoint.  A caller supplies an
injected S3 client and a durable journal.  The journal intent is saved before
the single conditional object write; an uncertain write permanently fences
that intent and is never replayed by this core.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import zipfile

from scripts.build_aws_dev_runtime import (
    MAX_ARCHIVE_BYTES,
    MAX_ENTRY_BYTES,
    MAX_FILE_COUNT,
    MAX_MANIFEST_BYTES,
    MAX_TOTAL_BYTES,
    _has_symlink_or_reparse_ancestor,
    _outside_repo_and_onedrive,
)
from scripts.build_aws_dev_runtime_template import RuntimeTemplateError, _validate_bucket_name
from scripts.build_aws_retained_dev_runtime import (
    RETAINED_DEV_MANIFEST_FILENAME,
    RetainedDevRuntimeTemplateError,
    build_retained_dev_manifest,
    retained_dev_artifact_bucket,
)
from scripts.build_aws_retained_dev_archive import RetainedDevBuildReceipt

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
MANIFEST_PATH = "mapit/" + RETAINED_DEV_MANIFEST_FILENAME
MAX_BODY_BYTES = MAX_ARCHIVE_BYTES
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0


class RetainedDevArtifactError(ValueError):
    """Stable category without provider, path, bucket, or secret text."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True)
class RetainedDevArtifactReceipt:
    key: str
    sha256: str
    manifest_sha256: str
    size_bytes: int
    server_side_encryption: str


@dataclass(frozen=True)
class RetainedDevArtifactResult:
    success: bool
    category: str
    put_attempted: bool = False
    put_succeeded: bool = False
    put_outcome_unknown: bool = False
    head_verified: bool = False
    idempotent_existing: bool = False
    journal_intent_saved: bool = False
    receipt: RetainedDevArtifactReceipt | None = None


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise RetainedDevArtifactError("manifest_invalid") from None


def _status(value: Any, expected: int = 200) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == expected


def _error_code(exc: Exception) -> tuple[str | None, int | None]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return (
        code if type(code) is str else None,
        status if type(status) is int and not isinstance(status, bool) else None,
    )


def _read_archive(path: Path, *, receipt: RetainedDevBuildReceipt) -> tuple[bytes, str]:
    if not isinstance(receipt, RetainedDevBuildReceipt) or not receipt.validate():
        raise RetainedDevArtifactError("build_receipt_invalid")
    if (
        type(receipt.source_sha) is not str or _SHA1.fullmatch(receipt.source_sha) is None
        or type(receipt.api_id) is not str or _API.fullmatch(receipt.api_id) is None
        or type(receipt.jwks_sha256) is not str or _SHA256.fullmatch(receipt.jwks_sha256) is None
        or type(receipt.zip_sha256) is not str or _SHA256.fullmatch(receipt.zip_sha256) is None
        or type(receipt.manifest_sha256) is not str or _SHA256.fullmatch(receipt.manifest_sha256) is None
        or type(receipt.execution_start_epoch) is not int or type(receipt.execution_end_epoch) is not int
        or receipt.execution_start_epoch <= 0 or receipt.execution_end_epoch <= receipt.execution_start_epoch
        or receipt.execution_end_epoch - receipt.execution_start_epoch > 300
        or type(receipt.archive_entries) is not int or receipt.archive_entries <= 0
    ):
        raise RetainedDevArtifactError("build_receipt_invalid")
    expected_sha256 = receipt.zip_sha256
    if not isinstance(path, Path) or _has_symlink_or_reparse_ancestor(path) or not path.is_file():
        raise RetainedDevArtifactError("artifact_source_invalid")
    try:
        resolved = _outside_repo_and_onedrive(path, Path(__file__).resolve().parents[1], "artifact_source_invalid")
        if resolved.stat().st_size <= 0 or resolved.stat().st_size > MAX_BODY_BYTES:
            raise RetainedDevArtifactError("artifact_source_invalid")
        with resolved.open("rb") as stream:
            body = stream.read(MAX_BODY_BYTES + 1)
    except RetainedDevArtifactError:
        raise
    except Exception:
        raise RetainedDevArtifactError("artifact_source_invalid") from None
    if type(body) is not bytes or not 1 <= len(body) <= MAX_BODY_BYTES:
        raise RetainedDevArtifactError("artifact_source_invalid")
    if hashlib.sha256(body).hexdigest() != expected_sha256:
        raise RetainedDevArtifactError("artifact_hash_mismatch")
    try:
        manifest = build_retained_dev_manifest(
            receipt.source_sha, receipt.api_id, receipt.jwks_sha256,
            receipt.execution_start_epoch, receipt.execution_end_epoch,
        )
        manifest_bytes = _canonical(manifest)
    except (RetainedDevRuntimeTemplateError, RetainedDevArtifactError):
        raise RetainedDevArtifactError("manifest_invalid") from None
    try:
        with zipfile.ZipFile(io.BytesIO(body), "r") as archive:
            infos = archive.infolist()
            if len(infos) != receipt.archive_entries or not 1 <= len(infos) <= MAX_FILE_COUNT:
                raise ValueError
            names: set[str] = set()
            total = 0
            for info in infos:
                name = info.filename
                parts = name.split("/") if isinstance(name, str) else []
                mode = (info.external_attr >> 16) & 0xFFFF
                if (
                    type(name) is not str or not name or name.startswith("/") or "\\" in name
                    or any(part in {"", ".", ".."} for part in parts)
                    or info.is_dir() or (mode & 0o170000) not in (0, 0o100000)
                    or name.casefold() in names or info.file_size < 0
                    or info.file_size > MAX_ENTRY_BYTES
                ):
                    raise ValueError
                names.add(name.casefold())
                total += info.file_size
                if total > MAX_TOTAL_BYTES:
                    raise ValueError
            info = archive.getinfo(MANIFEST_PATH)
            if info.file_size > MAX_MANIFEST_BYTES:
                raise ValueError
            if archive.read(info) != manifest_bytes:
                raise ValueError
            if hashlib.sha256(manifest_bytes).hexdigest() != receipt.manifest_sha256:
                raise ValueError
    except RetainedDevArtifactError:
        raise
    except Exception:
        raise RetainedDevArtifactError("manifest_invalid") from None
    return body, hashlib.sha256(manifest_bytes).hexdigest()


def _journal_state(*, account_id: str, bucket: str, run_id: str, source_sha: str, key: str, sha256: str, manifest_sha256: str, size_bytes: int, authorized_from_epoch: int, authorized_until_epoch: int, last_observed_epoch: float, status: str, revision: int) -> dict[str, Any]:
    return {
        "schema": 1,
        "kind": "retained-dev-artifact-publication",
        "account_id": account_id,
        "bucket": bucket,
        "run_id": run_id,
        "source_sha": source_sha,
        "authorized_from_epoch": authorized_from_epoch,
        "authorized_until_epoch": authorized_until_epoch,
        "last_observed_epoch": last_observed_epoch,
        "artifact_key": key,
        "sha256": sha256,
        "manifest_sha256": manifest_sha256,
        "size_bytes": size_bytes,
        "intent": {"operation": "publish", "artifact_key": key, "sha256": sha256, "manifest_sha256": manifest_sha256},
        "revision": revision,
        "status": status,
    }


def _valid_state(value: Any, expected: Mapping[str, Any]) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == set(expected)
        and type(value.get("schema")) is int
        and all(value.get(key) == val for key, val in expected.items() if key not in {"status", "revision", "last_observed_epoch"})
        and type(value.get("last_observed_epoch")) in (int, float)
        and math.isfinite(value["last_observed_epoch"])
        and expected["authorized_from_epoch"] <= value["last_observed_epoch"] < expected["authorized_until_epoch"]
        and type(value.get("revision")) is int and value["revision"] in {1, 2}
        and ((value.get("status") == "intent" and value["revision"] == 1)
             or (value.get("status") == "verified" and value["revision"] == 2))
    )


def _clock_value(clock: Any) -> float:
    value = clock()
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise RetainedDevArtifactError("window_invalid")
    return float(value)


def publish_retained_dev_runtime(
    s3_client: Any,
    journal: Any,
    *,
    bucket: str,
    expected_owner: str,
    run_id: str,
    archive_path: Path,
    build_receipt: RetainedDevBuildReceipt,
    authorized_from_epoch: int,
    authorized_until_epoch: int,
    wall_clock: Any = time.time,
    monotonic: Any = time.monotonic,
) -> RetainedDevArtifactResult:
    """Save intent, conditionally publish one ZIP, and verify exact readback."""
    try:
        if (
            type(bucket) is not str
            or (type(expected_owner) is not str or bucket != retained_dev_artifact_bucket(expected_owner))
            or not _ACCOUNT.fullmatch(expected_owner or "")
            or type(run_id) is not str or _UUID.fullmatch(run_id) is None
            or not isinstance(build_receipt, RetainedDevBuildReceipt)
            or not callable(getattr(s3_client, "put_object", None))
            or not callable(getattr(s3_client, "head_object", None))
            or type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
            or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS
            or not callable(wall_clock) or not callable(monotonic)
            or not all(callable(getattr(journal, name, None)) for name in ("load", "compare_and_set", "locked"))
        ):
            return RetainedDevArtifactResult(False, "artifact_input_invalid")
        try:
            _validate_bucket_name(bucket)
        except (RuntimeTemplateError, TypeError, ValueError):
            return RetainedDevArtifactResult(False, "artifact_input_invalid")
        started_mono = _clock_value(monotonic)
        last_mono = started_mono
        last_wall = _clock_value(wall_clock)

        def guard() -> None:
            nonlocal last_mono, last_wall
            now = _clock_value(wall_clock)
            current_mono = _clock_value(monotonic)
            if (
                now < authorized_from_epoch or now >= authorized_until_epoch
                or now < last_wall
                or current_mono < last_mono
                or current_mono - started_mono >= MAX_STEP_SECONDS
            ):
                raise RetainedDevArtifactError("window_expired")
            last_mono = current_mono
            last_wall = now

        guard()
        body, manifest_sha256 = _read_archive(
            archive_path, receipt=build_receipt,
        )
        guard()
        sha256_hex = build_receipt.zip_sha256
        checksum = base64.b64encode(bytes.fromhex(sha256_hex)).decode("ascii")
        key = f"runtime/{sha256_hex}.zip"
        expected = _journal_state(
            account_id=expected_owner, bucket=bucket, run_id=run_id, source_sha=build_receipt.source_sha,
            key=key, sha256=sha256_hex, manifest_sha256=manifest_sha256, size_bytes=len(body), status="intent", revision=1,
            authorized_from_epoch=authorized_from_epoch, authorized_until_epoch=authorized_until_epoch,
            last_observed_epoch=last_wall,
        )
        with journal.locked():
            guard()
            prior = journal.load()
            guard()
            if prior is not None:
                if not _valid_state(prior, expected):
                    return RetainedDevArtifactResult(False, "journal_conflict")
                last_wall = max(last_wall, float(prior["last_observed_epoch"]))
                guard()
                if prior.get("status") == "verified":
                    guard()
                    try:
                        head = s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED", ExpectedBucketOwner=expected_owner)
                    except Exception:
                        return RetainedDevArtifactResult(False, "artifact_head_failed")
                    guard()
                    if (
                        not _status(head)
                        or type(head.get("ContentLength")) is not int or head["ContentLength"] != len(body)
                        or head.get("ChecksumSHA256") != checksum or head.get("ServerSideEncryption") != "AES256"
                        or head.get("ContentType") != "application/zip"
                    ):
                        return RetainedDevArtifactResult(False, "artifact_head_mismatch")
                    receipt = RetainedDevArtifactReceipt(key, sha256_hex, manifest_sha256, len(body), "AES256")
                    return RetainedDevArtifactResult(True, "artifact_already_verified", head_verified=True, receipt=receipt)
                return RetainedDevArtifactResult(False, "intent_present", journal_intent_saved=True)
            try:
                if journal.compare_and_set(None, expected) is not True:
                    return RetainedDevArtifactResult(False, "journal_intent_failed")
            except Exception:
                return RetainedDevArtifactResult(False, "journal_intent_failed")
            guard()
            try:
                reply = s3_client.put_object(
                    Bucket=bucket, Key=key, Body=body, IfNoneMatch="*", ExpectedBucketOwner=expected_owner,
                    ServerSideEncryption="AES256", ChecksumSHA256=checksum, ContentType="application/zip",
                )
            except Exception as exc:
                code, status = _error_code(exc)
                if not (code == "PreconditionFailed" and status == 412):
                    return RetainedDevArtifactResult(False, "artifact_put_ambiguous", put_attempted=True, put_outcome_unknown=True, journal_intent_saved=True)
                idempotent = True
                put_succeeded = False
            else:
                if not _status(reply):
                    return RetainedDevArtifactResult(False, "artifact_put_ambiguous", put_attempted=True, put_outcome_unknown=True, journal_intent_saved=True)
                idempotent = False
                put_succeeded = True
            guard()
            try:
                head = s3_client.head_object(Bucket=bucket, Key=key, ChecksumMode="ENABLED", ExpectedBucketOwner=expected_owner)
            except Exception:
                return RetainedDevArtifactResult(False, "artifact_head_failed", put_attempted=True, put_succeeded=put_succeeded, journal_intent_saved=True)
            if (
                not _status(head)
                or type(head.get("ContentLength")) is not int or head["ContentLength"] != len(body)
                or head.get("ChecksumSHA256") != checksum or head.get("ServerSideEncryption") != "AES256"
                or head.get("ContentType") != "application/zip"
            ):
                return RetainedDevArtifactResult(False, "artifact_head_mismatch", put_attempted=True, put_succeeded=put_succeeded, journal_intent_saved=True)
            guard()
            verified = dict(expected)
            verified["status"] = "verified"
            verified["revision"] = 2
            verified["last_observed_epoch"] = last_wall
            try:
                if journal.compare_and_set(1, verified) is not True:
                    return RetainedDevArtifactResult(False, "journal_verified_failed", put_attempted=True, put_succeeded=put_succeeded, journal_intent_saved=True)
            except Exception:
                return RetainedDevArtifactResult(False, "journal_verified_failed", put_attempted=True, put_succeeded=put_succeeded, journal_intent_saved=True)
            guard()
            receipt = RetainedDevArtifactReceipt(key, sha256_hex, manifest_sha256, len(body), "AES256")
            return RetainedDevArtifactResult(True, "artifact_already_present_verified" if idempotent else "artifact_uploaded_verified", put_attempted=True, put_succeeded=put_succeeded, head_verified=True, idempotent_existing=idempotent, journal_intent_saved=True, receipt=receipt)
    except RetainedDevArtifactError as exc:
        return RetainedDevArtifactResult(False, exc.category)
    except Exception:
        return RetainedDevArtifactResult(False, "artifact_internal_error")


__all__ = ["MANIFEST_PATH", "RetainedDevArtifactReceipt", "RetainedDevArtifactResult", "publish_retained_dev_runtime"]
