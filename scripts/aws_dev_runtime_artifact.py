"""Publish one already-built dev runtime ZIP through an injected S3 client.

This module never constructs an SDK client or discovers credentials. The caller
must independently establish that the injected client is configured for one
attempt and that the destination is the privately owned, unversioned bucket
created for this rehearsal. ``ExpectedBucketOwner`` guards account mismatch; it
does not prove that the bucket belongs to the expected stack. This operation
does not clean up, overwrite, retry, or delete an uploaded object.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from scripts.build_aws_dev_runtime import (
    MAX_ARCHIVE_BYTES,
    _has_symlink_or_reparse_ancestor,
    _outside_repo_and_onedrive,
)
from scripts.build_aws_dev_runtime_template import RuntimeTemplateError, _validate_bucket_name

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OWNER = re.compile(r"^[0-9]{12}$")
_REPO = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class PublishResult:
    success: bool
    category: str
    put_attempted: bool = False
    put_succeeded: bool = False
    put_outcome_unknown: bool = False
    head_verified: bool = False
    idempotent_existing: bool = False


def _invalid(category: str) -> PublishResult:
    return PublishResult(success=False, category=category)


def _s3_error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None
    error = response.get("Error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("Code")
    return code if type(code) is str else None


def _s3_http_status(exc: Exception) -> int | str | None:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, Mapping):
        return None
    status = metadata.get("HTTPStatusCode")
    return status if type(status) in (int, str) else None


def _confirmed_precondition_failure(exc: Exception) -> bool:
    return _s3_error_code(exc) == "PreconditionFailed" and _s3_http_status(exc) in (412, "412")


def _head_matches(response: Any, *, size: int, checksum: str) -> bool:
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata[
        "HTTPStatusCode"
    ] != 200:
        return False
    return (
        type(response.get("ContentLength")) is int
        and response["ContentLength"] == size
        and type(response.get("ChecksumSHA256")) is str
        and response["ChecksumSHA256"] == checksum
        and type(response.get("ServerSideEncryption")) is str
        and response["ServerSideEncryption"] == "AES256"
    )


def publish_runtime_zip(
    s3_client: Any,
    *,
    bucket: str,
    expected_owner: str,
    archive_path: Path,
    sha256_hex: str,
    size_bytes: int,
) -> PublishResult:
    """Conditionally upload and verify a content-addressed runtime ZIP.

    The injected S3 client must use a single-attempt configuration. The caller
    is responsible for independently confirming ownership, privacy, and that
    the bucket is unversioned; ``ExpectedBucketOwner`` alone is not ownership
    proof. Only a matching 412 precondition response is eligible for
    idempotent-success verification. All results are categorical and omit
    bucket, key, path, response bodies, and provider exception text.
    """
    try:
        if type(bucket) is not str:
            return _invalid("artifact_input_invalid")
        try:
            _validate_bucket_name(bucket)
        except (RuntimeTemplateError, TypeError, ValueError):
            return _invalid("artifact_input_invalid")
        if type(expected_owner) is not str or not _OWNER.fullmatch(expected_owner):
            return _invalid("artifact_input_invalid")
        if type(sha256_hex) is not str or not _SHA256.fullmatch(sha256_hex):
            return _invalid("artifact_input_invalid")
        if type(size_bytes) is not int or size_bytes <= 0 or size_bytes > MAX_ARCHIVE_BYTES:
            return _invalid("artifact_input_invalid")
        if not isinstance(archive_path, Path):
            return _invalid("artifact_input_invalid")
        if not callable(getattr(s3_client, "put_object", None)) or not callable(
            getattr(s3_client, "head_object", None)
        ):
            return _invalid("artifact_client_invalid")
        if _has_symlink_or_reparse_ancestor(archive_path) or not archive_path.is_file():
            return _invalid("artifact_source_invalid")
        try:
            resolved = _outside_repo_and_onedrive(archive_path, _REPO, "artifact_source_invalid")
            stat_size = resolved.stat().st_size
        except Exception:
            return _invalid("artifact_source_invalid")
        if stat_size != size_bytes or stat_size > MAX_ARCHIVE_BYTES:
            return _invalid("artifact_source_invalid")
        try:
            with resolved.open("rb") as stream:
                body = stream.read(MAX_ARCHIVE_BYTES + 1)
        except OSError:
            return _invalid("artifact_source_invalid")
        if len(body) != size_bytes or len(body) > MAX_ARCHIVE_BYTES:
            return _invalid("artifact_source_invalid")
        actual_digest = hashlib.sha256(body).digest()
        if actual_digest.hex() != sha256_hex:
            return _invalid("artifact_hash_mismatch")
        checksum = base64.b64encode(actual_digest).decode("ascii")
        key = f"runtime/{sha256_hex}.zip"
        try:
            put_response = s3_client.put_object(
                Bucket=bucket,
                Key=key,
                Body=body,
                IfNoneMatch="*",
                ChecksumSHA256=checksum,
                ExpectedBucketOwner=expected_owner,
                ServerSideEncryption="AES256",
                ContentType="application/zip",
            )
        except Exception as exc:
            if not _confirmed_precondition_failure(exc):
                return PublishResult(False, "artifact_put_ambiguous", put_attempted=True, put_outcome_unknown=True)
            return _verify_head(
                s3_client,
                bucket=bucket,
                key=key,
                expected_owner=expected_owner,
                size=size_bytes,
                checksum=checksum,
                idempotent=True,
                put_succeeded=False,
            )
        if not _http_status_is(put_response, 200):
            return PublishResult(False, "artifact_put_ambiguous", put_attempted=True, put_outcome_unknown=True)
        return _verify_head(
            s3_client,
            bucket=bucket,
            key=key,
            expected_owner=expected_owner,
            size=size_bytes,
            checksum=checksum,
            idempotent=False,
            put_succeeded=True,
        )
    except Exception:
        return _invalid("artifact_publish_failed")


def _http_status_is(response: Any, expected: int) -> bool:
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata[
        "HTTPStatusCode"
    ] == expected


def _verify_head(
    s3_client: Any,
    *,
    bucket: str,
    key: str,
    expected_owner: str,
    size: int,
    checksum: str,
    idempotent: bool,
    put_succeeded: bool,
) -> PublishResult:
    try:
        response = s3_client.head_object(
            Bucket=bucket,
            Key=key,
            ChecksumMode="ENABLED",
            ExpectedBucketOwner=expected_owner,
        )
    except Exception:
        return PublishResult(False, "artifact_head_failed", put_attempted=True, put_succeeded=put_succeeded)
    if not _head_matches(response, size=size, checksum=checksum):
        return PublishResult(False, "artifact_head_mismatch", put_attempted=True, put_succeeded=put_succeeded)
    return PublishResult(
        success=True,
        category="artifact_already_present_verified" if idempotent else "artifact_uploaded_verified",
        put_attempted=True,
        put_succeeded=put_succeeded,
        head_verified=True,
        idempotent_existing=idempotent,
    )
