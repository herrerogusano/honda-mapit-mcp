from __future__ import annotations

import base64

import pytest

from scripts.aws_dev_runtime_artifact_retirement import retire_runtime_zip


OWNER = "123456789012"
BUCKET = "honda-runtime-artifact-test-bucket"
HASH = "ab" * 32
SIZE = 123
CHECKSUM = base64.b64encode(bytes.fromhex(HASH)).decode("ascii")
KEY = f"runtime/{HASH}.zip"


class S3Error(Exception):
    def __init__(self, code: str, status: int, canary: str = "private-error-canary"):
        super().__init__(canary)
        self.response = {
            "Error": {"Code": code, "Message": canary},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


def _meta(status: int):
    return {"ResponseMetadata": {"HTTPStatusCode": status}}


def _versioning():
    return _meta(200)


def _object_head():
    return {
        "ContentLength": SIZE,
        "ChecksumSHA256": CHECKSUM,
        "ServerSideEncryption": "AES256",
        "ETag": '"etag-123"',
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }


def _empty_objects(**updates):
    value = {"IsTruncated": False, "KeyCount": 0, **_meta(200)}
    value.update(updates)
    return value


def _empty_multipart(**updates):
    value = {"IsTruncated": False, **_meta(200)}
    value.update(updates)
    return value


class FakeS3:
    def __init__(self, *, versioning=None, heads=None, deleted=None, objects=None, multipart=None):
        self.versioning_response = _versioning() if versioning is None else versioning
        self.head_responses = [_object_head(), S3Error("NoSuchKey", 404)] if heads is None else list(heads)
        self.delete_response = _meta(204) if deleted is None else deleted
        self.object_listing = _empty_objects() if objects is None else objects
        self.multipart_listing = _empty_multipart() if multipart is None else multipart
        self.calls = []

    def get_bucket_versioning(self, **kwargs):
        self.calls.append(("get_bucket_versioning", kwargs))
        if isinstance(self.versioning_response, Exception):
            raise self.versioning_response
        return self.versioning_response

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        result = self.head_responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    def delete_object(self, **kwargs):
        self.calls.append(("delete_object", kwargs))
        if isinstance(self.delete_response, Exception):
            raise self.delete_response
        return self.delete_response

    def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects_v2", kwargs))
        if isinstance(self.object_listing, Exception):
            raise self.object_listing
        return self.object_listing

    def list_multipart_uploads(self, **kwargs):
        self.calls.append(("list_multipart_uploads", kwargs))
        if isinstance(self.multipart_listing, Exception):
            raise self.multipart_listing
        return self.multipart_listing


def _retire(client, **overrides):
    values = {
        "bucket": BUCKET,
        "expected_owner": OWNER,
        "sha256_hex": HASH,
        "size_bytes": SIZE,
        "app_deleted": True,
    }
    values.update(overrides)
    return retire_runtime_zip(client, **values)


def test_successful_retirement_is_single_key_conditional_and_bounded():
    client = FakeS3()
    result = _retire(client)
    assert result.success and result.category == "artifact_absent_bucket_empty_verified"
    assert result.object_absent_verified and result.bucket_empty_verified
    assert result.delete_attempted and result.delete_succeeded and not result.delete_outcome_unknown
    assert [call[0] for call in client.calls] == [
        "get_bucket_versioning", "head_object", "delete_object", "head_object", "list_objects_v2", "list_multipart_uploads"
    ]
    assert client.calls[0][1] == {"Bucket": BUCKET, "ExpectedBucketOwner": OWNER}
    assert client.calls[1][1] == {
        "Bucket": BUCKET,
        "Key": KEY,
        "ChecksumMode": "ENABLED",
        "ExpectedBucketOwner": OWNER,
    }
    assert client.calls[2][1] == {
        "Bucket": BUCKET,
        "Key": KEY,
        "ExpectedBucketOwner": OWNER,
        "IfMatch": '"etag-123"',
    }
    assert client.calls[3][1] == {"Bucket": BUCKET, "Key": KEY, "ExpectedBucketOwner": OWNER}
    assert client.calls[4][1] == {"Bucket": BUCKET, "MaxKeys": 1, "ExpectedBucketOwner": OWNER}
    assert client.calls[5][1] == {"Bucket": BUCKET, "MaxUploads": 1, "ExpectedBucketOwner": OWNER}


def test_exact_initial_404_skips_delete_but_still_verifies_empty():
    client = FakeS3(heads=[S3Error("404", 404)])
    result = _retire(client)
    assert result.success and result.object_absent_verified and result.bucket_empty_verified
    assert not result.delete_attempted
    assert [name for name, _ in client.calls] == ["get_bucket_versioning", "head_object", "list_objects_v2", "list_multipart_uploads"]


@pytest.mark.parametrize("app_deleted", [False, None, 1, "true"])
def test_app_deletion_gate_is_exact_and_precedes_every_request(app_deleted):
    client = FakeS3()
    result = _retire(client, app_deleted=app_deleted)
    assert not result.success and result.category == "retirement_app_not_deleted"
    assert client.calls == []


@pytest.mark.parametrize("overrides", [
    {"bucket": "BAD_BUCKET"},
    {"expected_owner": "12345678901x"},
    {"sha256_hex": "A" * 64},
    {"size_bytes": True},
    {"size_bytes": 0},
    {"size_bytes": 50 * 1024 * 1024 + 1},
])
def test_invalid_inputs_fail_before_requests(overrides):
    client = FakeS3()
    result = _retire(client, **overrides)
    assert not result.success and result.category == "retirement_input_invalid"
    assert client.calls == []


@pytest.mark.parametrize("versioning", [
    {"ResponseMetadata": {"HTTPStatusCode": 403}},
    {"ResponseMetadata": {"HTTPStatusCode": 200}, "Status": "Suspended"},
    {"ResponseMetadata": {"HTTPStatusCode": 200}, "Status": "Enabled"},
    {"ResponseMetadata": {"HTTPStatusCode": 200}, "MFADelete": "Disabled"},
    {"ResponseMetadata": {"HTTPStatusCode": True}},
])
def test_versioning_must_be_unconfigured_before_head(versioning):
    client = FakeS3(versioning=versioning)
    result = _retire(client)
    assert result.category == "retirement_versioning_not_unconfigured"
    assert [name for name, _ in client.calls] == ["get_bucket_versioning"]


@pytest.mark.parametrize("head", [
    {**_object_head(), "ContentLength": SIZE + 1},
    {**_object_head(), "ChecksumSHA256": "wrong"},
    {**_object_head(), "ServerSideEncryption": "aws:kms"},
    {**_object_head(), "VersionId": "abc123"},
    {**_object_head(), "VersionId": None},
    {**_object_head(), "DeleteMarker": False},
    {**_object_head(), "ETag": "*"},
    {**_object_head(), "ETag": "etag\r\n"},
    {**_object_head(), "ETag": "x" * 257},
    {**_object_head(), "ResponseMetadata": {"HTTPStatusCode": 206}},
])
def test_object_metadata_mismatch_never_deletes(head):
    client = FakeS3(heads=[head])
    result = _retire(client)
    assert result.category == "retirement_object_mismatch"
    assert not result.delete_attempted
    assert [name for name, _ in client.calls] == ["get_bucket_versioning", "head_object"]


@pytest.mark.parametrize("error", [
    S3Error("AccessDenied", 403),
    S3Error("NoSuchKey", 403),
    S3Error("NotFound", 403),
    RuntimeError("provider-private-canary"),
])
def test_initial_head_error_is_not_treated_as_absence(error):
    client = FakeS3(heads=[error])
    result = _retire(client)
    assert not result.success and result.category == "retirement_initial_head_failed"
    assert not result.object_absent_verified
    assert len(client.calls) == 2


@pytest.mark.parametrize("delete_response", [
    {"ResponseMetadata": {"HTTPStatusCode": 200}},
    {"ResponseMetadata": {"HTTPStatusCode": 412}},
    {"ResponseMetadata": {"HTTPStatusCode": True}},
])
def test_delete_requires_exact_204_and_never_retries(delete_response):
    client = FakeS3(deleted=delete_response)
    result = _retire(client)
    assert result.category == "retirement_delete_ambiguous"
    assert result.delete_attempted and result.delete_outcome_unknown and not result.delete_succeeded
    assert [name for name, _ in client.calls] == ["get_bucket_versioning", "head_object", "delete_object"]


@pytest.mark.parametrize("delete_response", [
    {**_meta(204), "DeleteMarker": True},
    {**_meta(204), "VersionId": "version123"},
])
def test_delete_response_version_evidence_stops_before_absence_claim(delete_response):
    client = FakeS3(deleted=delete_response)
    result = _retire(client)
    assert result.category == "retirement_versioning_changed"
    assert result.delete_attempted and result.delete_succeeded
    assert not result.object_absent_verified
    assert [name for name, _ in client.calls] == ["get_bucket_versioning", "head_object", "delete_object"]


def test_delete_timeout_is_ambiguous_without_readback_or_retry():
    client = FakeS3(deleted=RuntimeError("delete-private-canary"))
    result = _retire(client)
    assert result.category == "retirement_delete_ambiguous"
    assert result.delete_outcome_unknown and not result.object_absent_verified
    assert [name for name, _ in client.calls] == ["get_bucket_versioning", "head_object", "delete_object"]


@pytest.mark.parametrize("error", [S3Error("AccessDenied", 403), S3Error("NoSuchKey", 403), RuntimeError("canary")])
def test_post_delete_non404_does_not_claim_absence(error):
    client = FakeS3(heads=[_object_head(), error])
    result = _retire(client)
    assert result.category == "retirement_absence_unverified"
    assert result.delete_succeeded and not result.object_absent_verified
    assert [name for name, _ in client.calls][-1] == "head_object"


@pytest.mark.parametrize("response", [None, {"ResponseMetadata": {"HTTPStatusCode": 403}}])
def test_malformed_post_delete_head_is_unverified_not_still_present(response):
    client = FakeS3(heads=[_object_head(), response])
    result = _retire(client)
    assert result.category == "retirement_absence_unverified"
    assert result.delete_succeeded and not result.object_absent_verified


@pytest.mark.parametrize("response", [
    {"IsTruncated": True, "KeyCount": 0, **_meta(200)},
    {"IsTruncated": False, "KeyCount": 1, "Contents": [{"Key": "other"}], **_meta(200)},
    {"IsTruncated": False, "KeyCount": 0, "NextContinuationToken": "marker", **_meta(200)},
    {"IsTruncated": False, "KeyCount": True, **_meta(200)},
    {"IsTruncated": 0, "KeyCount": 0, **_meta(200)},
    {"IsTruncated": False, "KeyCount": 0, "Contents": None, **_meta(200)},
    {"IsTruncated": False, "KeyCount": 0, **_meta(403)},
])
def test_object_listing_must_be_empty_untruncated_and_well_typed(response):
    client = FakeS3(heads=[S3Error("NoSuchKey", 404)], objects=response)
    result = _retire(client)
    assert not result.success and result.category == "retirement_bucket_not_empty_or_truncated"
    assert result.object_absent_verified
    assert [name for name, _ in client.calls] == ["get_bucket_versioning", "head_object", "list_objects_v2"]


@pytest.mark.parametrize("response", [
    {"IsTruncated": True, **_meta(200)},
    {"IsTruncated": False, "Uploads": [{"Key": "other", "UploadId": "private"}], **_meta(200)},
    {"IsTruncated": False, "NextUploadIdMarker": "marker", **_meta(200)},
    {"IsTruncated": 0, **_meta(200)},
    {"IsTruncated": False, "CommonPrefixes": None, **_meta(200)},
    {"IsTruncated": False, **_meta(403)},
])
def test_multipart_listing_must_be_empty_untruncated_and_well_typed(response):
    client = FakeS3(heads=[S3Error("NoSuchKey", 404)], multipart=response)
    result = _retire(client)
    assert not result.success and not result.bucket_empty_verified
    assert result.object_absent_verified
    assert result.category == "retirement_bucket_not_empty_or_truncated"
    assert [name for name, _ in client.calls] == [
        "get_bucket_versioning", "head_object", "list_objects_v2", "list_multipart_uploads"
    ]


def test_provider_exception_text_never_reaches_output(capsys):
    client = FakeS3(versioning=RuntimeError("private-canary"))
    result = _retire(client)
    captured = capsys.readouterr()
    assert result.category == "retirement_versioning_read_failed"
    assert "private-canary" not in captured.out + captured.err


def test_optional_botocore_shapes_validate_exact_bounded_requests():
    pytest.importorskip("botocore")
    from botocore.session import get_session
    from botocore.stub import Stubber

    client = get_session().create_client(
        "s3",
        region_name="eu-west-1",
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
        endpoint_url="https://s3.eu-west-1.amazonaws.com",
    )
    with Stubber(client) as stubber:
        stubber.add_response(
            "get_bucket_versioning",
            {"ResponseMetadata": {"HTTPStatusCode": 200}},
            {"Bucket": BUCKET, "ExpectedBucketOwner": OWNER},
        )
        stubber.add_client_error(
            "head_object",
            service_error_code="NoSuchKey",
            http_status_code=404,
            expected_params={
                "Bucket": BUCKET,
                "Key": KEY,
                "ChecksumMode": "ENABLED",
                "ExpectedBucketOwner": OWNER,
            },
        )
        stubber.add_response(
            "list_objects_v2",
            {"IsTruncated": False, "KeyCount": 0, "ResponseMetadata": {"HTTPStatusCode": 200}},
            {"Bucket": BUCKET, "MaxKeys": 1, "ExpectedBucketOwner": OWNER},
        )
        stubber.add_response(
            "list_multipart_uploads",
            {"IsTruncated": False, "ResponseMetadata": {"HTTPStatusCode": 200}},
            {"Bucket": BUCKET, "MaxUploads": 1, "ExpectedBucketOwner": OWNER},
        )
        result = _retire(client)
    assert result.success and result.object_absent_verified and result.bucket_empty_verified
