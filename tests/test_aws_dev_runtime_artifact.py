from __future__ import annotations

import base64
import hashlib
from pathlib import Path

import pytest

from scripts import aws_dev_runtime_artifact as publisher


OWNER = "123456789012"
BUCKET = "honda-runtime-artifact-test-bucket"
BODY = b"synthetic-runtime-zip-bytes"
DIGEST = hashlib.sha256(BODY).hexdigest()
CHECKSUM = base64.b64encode(hashlib.sha256(BODY).digest()).decode("ascii")


class FakeS3:
    def __init__(self, *, put_response=None, put_error=None, head_response=None, head_error=None):
        self.put_response = put_response or {"ResponseMetadata": {"HTTPStatusCode": 200}}
        self.put_error = put_error
        self.head_response = head_response or {
            "ContentLength": len(BODY),
            "ChecksumSHA256": CHECKSUM,
            "ServerSideEncryption": "AES256",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }
        self.head_error = head_error
        self.put_calls = []
        self.head_calls = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        if self.put_error:
            raise self.put_error
        return self.put_response

    def head_object(self, **kwargs):
        self.head_calls.append(kwargs)
        if self.head_error:
            raise self.head_error
        return self.head_response


class S3Error(Exception):
    def __init__(self, code: str, status: int | None = None, canary: str = "private-canary"):
        super().__init__(canary)
        self.response = {
            "Error": {"Code": code, "Message": canary},
            "ResponseMetadata": {"HTTPStatusCode": status} if status is not None else {},
        }


def _archive(tmp_path: Path) -> Path:
    path = tmp_path / "runtime.zip"
    path.write_bytes(BODY)
    return path


def _publish(path: Path, client: FakeS3, **overrides):
    kwargs = {
        "bucket": BUCKET,
        "expected_owner": OWNER,
        "archive_path": path,
        "sha256_hex": DIGEST,
        "size_bytes": len(BODY),
    }
    kwargs.update(overrides)
    return publisher.publish_runtime_zip(client, **kwargs)


def test_put_then_exact_head_verification_and_fixed_request(tmp_path: Path):
    client = FakeS3()
    result = _publish(_archive(tmp_path), client)

    assert result.success
    assert result.category == "artifact_uploaded_verified"
    assert result.put_succeeded and result.head_verified and not result.idempotent_existing
    assert client.put_calls == [{
        "Bucket": BUCKET,
        "Key": f"runtime/{DIGEST}.zip",
        "Body": BODY,
        "IfNoneMatch": "*",
        "ChecksumSHA256": CHECKSUM,
        "ExpectedBucketOwner": OWNER,
        "ServerSideEncryption": "AES256",
        "ContentType": "application/zip",
    }]
    assert client.head_calls == [{
        "Bucket": BUCKET,
        "Key": f"runtime/{DIGEST}.zip",
        "ChecksumMode": "ENABLED",
        "ExpectedBucketOwner": OWNER,
    }]


@pytest.mark.parametrize("kwargs", [
    {"bucket": "INVALID_BUCKET"},
    {"expected_owner": "12345678901x"},
    {"sha256_hex": "A" * 64},
    {"size_bytes": True},
    {"size_bytes": len(BODY) + 1},
    {"sha256_hex": "f" * 64},
])
def test_invalid_arguments_or_artifact_fail_before_s3(tmp_path: Path, kwargs):
    client = FakeS3()
    result = _publish(_archive(tmp_path), client, **kwargs)
    assert not result.success
    assert result.category in {"artifact_input_invalid", "artifact_hash_mismatch", "artifact_source_invalid"}
    assert client.put_calls == []
    assert client.head_calls == []


def test_nonpath_source_fails_without_s3(tmp_path: Path):
    client = FakeS3()
    result = _publish(str(_archive(tmp_path)), client)
    assert result.category == "artifact_input_invalid"
    assert not client.put_calls and not client.head_calls


def test_repository_and_onedrive_sources_fail_before_s3(tmp_path: Path):
    client = FakeS3()
    repo_file = Path(publisher.__file__).resolve()
    result = _publish(repo_file, client)
    assert result.category == "artifact_source_invalid"
    assert not client.put_calls and not client.head_calls

    synced = tmp_path / "OneDrive - Example Org"
    synced.mkdir()
    synced_file = synced / "runtime.zip"
    synced_file.write_bytes(BODY)
    result = _publish(synced_file, client)
    assert result.category == "artifact_source_invalid"
    assert not client.put_calls and not client.head_calls


def test_matching_412_is_idempotent_only_after_exact_head(tmp_path: Path):
    client = FakeS3(put_error=S3Error("PreconditionFailed", 412))
    result = _publish(_archive(tmp_path), client)
    assert result.success
    assert result.category == "artifact_already_present_verified"
    assert not result.put_succeeded and result.head_verified and result.idempotent_existing
    assert len(client.put_calls) == len(client.head_calls) == 1


@pytest.mark.parametrize("error", [
    S3Error("PreconditionFailed"),
    S3Error("PreconditionFailed", 409),
    S3Error("ConditionalRequestConflict", 412),
])
def test_inconsistent_precondition_error_is_not_idempotent(error, tmp_path: Path):
    client = FakeS3(put_error=error)
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_put_ambiguous"
    assert not result.success and result.put_outcome_unknown
    assert len(client.put_calls) == 1 and client.head_calls == []


@pytest.mark.parametrize("head_response", [
    {"ContentLength": len(BODY) + 1, "ChecksumSHA256": CHECKSUM, "ServerSideEncryption": "AES256", "ResponseMetadata": {"HTTPStatusCode": 200}},
    {"ContentLength": len(BODY), "ChecksumSHA256": "wrong", "ServerSideEncryption": "AES256", "ResponseMetadata": {"HTTPStatusCode": 200}},
    {"ContentLength": len(BODY), "ChecksumSHA256": CHECKSUM, "ServerSideEncryption": "aws:kms", "ResponseMetadata": {"HTTPStatusCode": 200}},
    {"ContentLength": True, "ChecksumSHA256": CHECKSUM, "ServerSideEncryption": "AES256", "ResponseMetadata": {"HTTPStatusCode": 200}},
    {"ContentLength": len(BODY), "ChecksumSHA256": CHECKSUM, "ServerSideEncryption": "AES256", "ResponseMetadata": {"HTTPStatusCode": 404}},
])
def test_412_mismatch_fails_closed(head_response, tmp_path: Path):
    client = FakeS3(put_error=S3Error("PreconditionFailed", 412), head_response=head_response)
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_head_mismatch"
    assert not result.success
    assert len(client.put_calls) == len(client.head_calls) == 1


@pytest.mark.parametrize("error", [S3Error("ConditionalRequestConflict", 409), S3Error("AccessDenied", 403)])
def test_non_412_put_failure_does_not_head_or_retry(error, tmp_path: Path):
    client = FakeS3(put_error=error)
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_put_ambiguous"
    assert not result.success and result.put_outcome_unknown
    assert len(client.put_calls) == 1
    assert client.head_calls == []


def test_ambiguous_put_exception_is_not_reported_as_absent_or_retried(tmp_path: Path):
    client = FakeS3(put_error=RuntimeError("exception-private-canary"))
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_put_ambiguous"
    assert not result.success and result.put_attempted and result.put_outcome_unknown
    assert len(client.put_calls) == 1
    assert client.head_calls == []


def test_bad_put_response_fails_without_followup(tmp_path: Path):
    client = FakeS3(put_response={"ResponseMetadata": {"HTTPStatusCode": 202}})
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_put_ambiguous"
    assert result.put_outcome_unknown
    assert len(client.put_calls) == 1 and client.head_calls == []


def test_normal_412_response_without_precondition_exception_is_ambiguous(tmp_path: Path):
    client = FakeS3(put_response={"ResponseMetadata": {"HTTPStatusCode": 412}})
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_put_ambiguous"
    assert result.put_outcome_unknown
    assert len(client.put_calls) == 1 and client.head_calls == []


def test_head_error_and_sensitive_exception_are_sanitized(tmp_path: Path, capsys):
    client = FakeS3(head_error=RuntimeError("head-private-canary"))
    result = _publish(_archive(tmp_path), client)
    assert result.category == "artifact_head_failed"
    assert not result.success and result.put_succeeded
    assert "head-private-canary" not in capsys.readouterr().out


def test_optional_botocore_request_shape_validation(tmp_path: Path):
    botocore = pytest.importorskip("botocore")
    from botocore.session import get_session
    from botocore.stub import Stubber

    client = get_session().create_client(
        "s3",
        region_name="eu-west-1",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
        endpoint_url="https://s3.eu-west-1.amazonaws.com",
    )
    expected_put = {
        "Bucket": BUCKET,
        "Key": f"runtime/{DIGEST}.zip",
        "Body": BODY,
        "IfNoneMatch": "*",
        "ChecksumSHA256": CHECKSUM,
        "ExpectedBucketOwner": OWNER,
        "ServerSideEncryption": "AES256",
        "ContentType": "application/zip",
    }
    expected_head = {
        "Bucket": BUCKET,
        "Key": f"runtime/{DIGEST}.zip",
        "ChecksumMode": "ENABLED",
        "ExpectedBucketOwner": OWNER,
    }
    with Stubber(client) as stubber:
        stubber.add_response("put_object", {"ResponseMetadata": {"HTTPStatusCode": 200}}, expected_put)
        stubber.add_response("head_object", {
            "ContentLength": len(BODY),
            "ChecksumSHA256": CHECKSUM,
            "ServerSideEncryption": "AES256",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }, expected_head)
        result = _publish(_archive(tmp_path), client)
    assert result.success, getattr(botocore, "__version__", "")
