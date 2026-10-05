"""Operator-only, exact-key S3 runtime-artifact retirement core.

This module accepts an injected single-attempt client and never constructs an
SDK session, discovers credentials, retries, paginates, deletes other objects,
aborts multipart uploads, or deletes a bucket. The caller must freshly confirm
the owned/private bucket, absence of concurrent writers, and no versioning
changes for the duration of this operation. The boolean ``app_deleted`` is an
orchestration precondition, not an identity proof. ExpectedBucketOwner guards
account mismatch but does not establish stack ownership.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from scripts.build_aws_dev_runtime import MAX_ARCHIVE_BYTES
from scripts.build_aws_dev_runtime_template import RuntimeTemplateError, _validate_bucket_name

_OWNER = re.compile(r"^[0-9]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NOT_FOUND_CODES = frozenset({"404", "NoSuchKey", "NotFound"})
_MARKER_KEYS = (
    "ContinuationToken", "NextContinuationToken", "KeyMarker", "NextKeyMarker",
    "UploadIdMarker", "NextUploadIdMarker", "NextMarker", "StartAfter", "Prefix", "Delimiter",
)


@dataclass(frozen=True)
class RetirementResult:
    success: bool
    category: str
    object_absent_verified: bool = False
    bucket_empty_verified: bool = False
    delete_attempted: bool = False
    delete_succeeded: bool = False
    delete_outcome_unknown: bool = False


def _result(category: str, **flags: bool) -> RetirementResult:
    return RetirementResult(success=False, category=category, **flags)


def _response_status(value: Any) -> int | None:
    if not isinstance(value, Mapping):
        return None
    metadata = value.get("ResponseMetadata")
    if not isinstance(metadata, Mapping):
        return None
    status = metadata.get("HTTPStatusCode")
    return status if type(status) is int else None


def _exception_error(exc: Exception) -> tuple[str | None, int | None]:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return None, None
    error = response.get("Error")
    code = error.get("Code") if isinstance(error, Mapping) else None
    metadata = response.get("ResponseMetadata")
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return (code if type(code) is str else None, status if type(status) is int else None)


def _known_not_found(exc: Exception) -> bool:
    code, status = _exception_error(exc)
    return code in _NOT_FOUND_CODES and status == 404


def _head_is_exact_object(
    response: Any,
    *,
    size_bytes: int,
    checksum: str,
) -> str | None:
    if not isinstance(response, Mapping) or _response_status(response) != 200:
        return None
    if (
        type(response.get("ContentLength")) is not int
        or response["ContentLength"] != size_bytes
        or type(response.get("ChecksumSHA256")) is not str
        or response["ChecksumSHA256"] != checksum
        or response.get("ServerSideEncryption") != "AES256"
        or "DeleteMarker" in response
    ):
        return None
    if "VersionId" in response and response["VersionId"] != "null":
        return None
    etag = response.get("ETag")
    if (
        type(etag) is not str
        or not etag
        or len(etag) > 256
        or any(ord(char) < 0x20 or ord(char) > 0x7E or char == "*" for char in etag)
    ):
        return None
    return etag


def _empty_optional_list(response: Mapping[str, Any], key: str) -> bool:
    if key not in response:
        return True
    value = response[key]
    return type(value) is list and not value


def _markers_empty(response: Mapping[str, Any]) -> bool:
    return all(key not in response or (type(response[key]) is str and response[key] == "") for key in _MARKER_KEYS)


def _object_listing_is_empty(response: Any) -> bool:
    if not isinstance(response, Mapping) or _response_status(response) != 200:
        return False
    return (
        type(response.get("IsTruncated")) is bool
        and response["IsTruncated"] is False
        and type(response.get("KeyCount")) is int
        and response["KeyCount"] == 0
        and _empty_optional_list(response, "Contents")
        and _empty_optional_list(response, "CommonPrefixes")
        and _markers_empty(response)
    )


def _multipart_listing_is_empty(response: Any) -> bool:
    if not isinstance(response, Mapping) or _response_status(response) != 200:
        return False
    return (
        type(response.get("IsTruncated")) is bool
        and response["IsTruncated"] is False
        and _empty_optional_list(response, "Uploads")
        and _empty_optional_list(response, "CommonPrefixes")
        and _markers_empty(response)
    )


def retire_runtime_zip(
    s3_client: Any,
    *,
    bucket: str,
    expected_owner: str,
    sha256_hex: str,
    size_bytes: int,
    app_deleted: bool,
) -> RetirementResult:
    """Retire only ``runtime/<sha256>.zip`` and verify absence/bucket emptiness.

    No cleanup is safe while another writer or versioning mutation can race
    this bounded read-delete-read sequence. The injected client must be
    configured for a single attempt. Successful completion uses at most six
    calls: versioning read, object HEAD, conditional delete, absence HEAD, and
    one bounded listing each for objects and multipart uploads.
    """
    if type(bucket) is not str:
        return _result("retirement_input_invalid")
    try:
        _validate_bucket_name(bucket)
    except (RuntimeTemplateError, TypeError, ValueError):
        return _result("retirement_input_invalid")
    if (
        type(expected_owner) is not str
        or not _OWNER.fullmatch(expected_owner)
        or type(sha256_hex) is not str
        or not _SHA256.fullmatch(sha256_hex)
        or type(size_bytes) is not int
        or size_bytes <= 0
        or size_bytes > MAX_ARCHIVE_BYTES
    ):
        return _result("retirement_input_invalid")
    if app_deleted is not True:
        return _result("retirement_app_not_deleted")
    method_names = (
        "get_bucket_versioning", "head_object", "delete_object", "list_objects_v2", "list_multipart_uploads",
    )
    try:
        has_client_methods = all(callable(getattr(s3_client, name, None)) for name in method_names)
    except Exception:
        has_client_methods = False
    if not has_client_methods:
        return _result("retirement_client_invalid")

    key = f"runtime/{sha256_hex}.zip"
    checksum = base64.b64encode(bytes.fromhex(sha256_hex)).decode("ascii")
    try:
        versioning = s3_client.get_bucket_versioning(Bucket=bucket, ExpectedBucketOwner=expected_owner)
    except Exception:
        return _result("retirement_versioning_read_failed")
    if (
        not isinstance(versioning, Mapping)
        or _response_status(versioning) != 200
        or "Status" in versioning
        or "MFADelete" in versioning
    ):
        return _result("retirement_versioning_not_unconfigured")

    try:
        initial_head = s3_client.head_object(
            Bucket=bucket,
            Key=key,
            ChecksumMode="ENABLED",
            ExpectedBucketOwner=expected_owner,
        )
    except Exception as exc:
        if _known_not_found(exc):
            return _verify_empty_bucket(s3_client, bucket=bucket, expected_owner=expected_owner)
        return _result("retirement_initial_head_failed")
    etag = _head_is_exact_object(initial_head, size_bytes=size_bytes, checksum=checksum)
    if etag is None:
        return _result("retirement_object_mismatch")

    try:
        deleted = s3_client.delete_object(
            Bucket=bucket,
            Key=key,
            ExpectedBucketOwner=expected_owner,
            IfMatch=etag,
        )
    except Exception:
        return _result("retirement_delete_ambiguous", delete_attempted=True, delete_outcome_unknown=True)
    if _response_status(deleted) != 204:
        return _result("retirement_delete_ambiguous", delete_attempted=True, delete_outcome_unknown=True)
    if (
        not isinstance(deleted, Mapping)
        or deleted.get("DeleteMarker") is True
        or ("VersionId" in deleted and deleted.get("VersionId") != "null")
    ):
        return _result("retirement_versioning_changed", delete_attempted=True, delete_succeeded=True)

    try:
        final_head = s3_client.head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=expected_owner)
    except Exception as exc:
        if not _known_not_found(exc):
            return _result("retirement_absence_unverified", delete_attempted=True, delete_succeeded=True)
    else:
        if _response_status(final_head) == 200:
            return _result("retirement_object_still_present", delete_attempted=True, delete_succeeded=True)
        return _result("retirement_absence_unverified", delete_attempted=True, delete_succeeded=True)
    empty = _verify_empty_bucket(s3_client, bucket=bucket, expected_owner=expected_owner)
    if not empty.bucket_empty_verified:
        return RetirementResult(
            success=False,
            category=empty.category,
            object_absent_verified=True,
            bucket_empty_verified=False,
            delete_attempted=True,
            delete_succeeded=True,
        )
    return RetirementResult(
        success=True,
        category="artifact_absent_bucket_empty_verified",
        object_absent_verified=True,
        bucket_empty_verified=True,
        delete_attempted=True,
        delete_succeeded=True,
    )


def _verify_empty_bucket(s3_client: Any, *, bucket: str, expected_owner: str) -> RetirementResult:
    try:
        objects = s3_client.list_objects_v2(
            Bucket=bucket,
            MaxKeys=1,
            ExpectedBucketOwner=expected_owner,
        )
    except Exception:
        return _result("retirement_object_listing_failed", object_absent_verified=True)
    if not _object_listing_is_empty(objects):
        return _result("retirement_bucket_not_empty_or_truncated", object_absent_verified=True)
    try:
        multipart = s3_client.list_multipart_uploads(
            Bucket=bucket,
            MaxUploads=1,
            ExpectedBucketOwner=expected_owner,
        )
    except Exception:
        return _result("retirement_multipart_listing_failed", object_absent_verified=True)
    if not _multipart_listing_is_empty(multipart):
        return _result("retirement_bucket_not_empty_or_truncated", object_absent_verified=True)
    return RetirementResult(
        success=True,
        category="artifact_absent_bucket_empty_verified",
        object_absent_verified=True,
        bucket_empty_verified=True,
    )


__all__ = ["RetirementResult", "retire_runtime_zip"]
