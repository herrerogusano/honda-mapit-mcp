from __future__ import annotations

import base64
import hashlib

from mapit.aws_dev_runtime import cognito_dev_policy
from scripts.aws_dev_runtime_artifact import publish_runtime_zip
from scripts.aws_dev_runtime_artifact_retirement import retire_runtime_zip
from scripts.build_aws_dev_oauth_template import build_dev_oauth_template


OWNER = "123456789012"
BUCKET = "honda-runtime-artifact-test-bucket"
BODY = b"synthetic-runtime-zip-bytes-for-lifecycle-only"
ZIP_SHA = hashlib.sha256(BODY).hexdigest()
JWKS_SHA = hashlib.sha256(b"separate-synthetic-public-jwks-bytes").hexdigest()
POOL = "eu-west-1_AbCdEf123"
API = "abc123def4"
CLIENT = "syntheticclient123"
SUBJECT = "00000000-0000-4000-8000-000000000001"
ETAG = '"synthetic-etag"'


class FakeS3Error(Exception):
    def __init__(self, code: str, status: int):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class StatefulS3:
    """Small stateful double; it proves composition only, not S3 behavior."""

    def __init__(self):
        self.objects = {}
        self.calls = []
        self.deleted_keys = []

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs))
        key = kwargs["Key"]
        if key in self.objects:
            raise FakeS3Error("PreconditionFailed", 412)
        body = kwargs["Body"]
        self.objects[key] = {
            "Body": body,
            "ContentLength": len(body),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
            "ServerSideEncryption": "AES256",
            "ETag": ETAG,
        }
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_bucket_versioning(self, **kwargs):
        self.calls.append(("get_bucket_versioning", kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def head_object(self, **kwargs):
        self.calls.append(("head_object", kwargs))
        item = self.objects.get(kwargs["Key"])
        if item is None:
            raise FakeS3Error("NoSuchKey", 404)
        return {key: item[key] for key in ("ContentLength", "ChecksumSHA256", "ServerSideEncryption", "ETag")} | {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }

    def delete_object(self, **kwargs):
        self.calls.append(("delete_object", kwargs))
        item = self.objects.get(kwargs["Key"])
        if item is None or kwargs.get("IfMatch") != item["ETag"]:
            raise FakeS3Error("PreconditionFailed", 412)
        self.deleted_keys.append(kwargs["Key"])
        del self.objects[kwargs["Key"]]
        return {"ResponseMetadata": {"HTTPStatusCode": 204}}

    def list_objects_v2(self, **kwargs):
        self.calls.append(("list_objects_v2", kwargs))
        keys = list(self.objects)
        contents = [{"Key": key} for key in keys[:1]]
        return {
            "IsTruncated": len(keys) > 1,
            "KeyCount": len(contents),
            **({"Contents": contents} if contents else {}),
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def list_multipart_uploads(self, **kwargs):
        self.calls.append(("list_multipart_uploads", kwargs))
        return {"IsTruncated": False, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _publish(client, artifact):
    return publish_runtime_zip(client, bucket=BUCKET, expected_owner=OWNER, archive_path=artifact,
                               sha256_hex=ZIP_SHA, size_bytes=len(BODY))


def _retire(client, app_deleted):
    return retire_runtime_zip(client, bucket=BUCKET, expected_owner=OWNER, sha256_hex=ZIP_SHA,
                              size_bytes=len(BODY), app_deleted=app_deleted)


def test_synthetic_publish_compose_gate_and_exact_retirement(tmp_path):
    artifact = tmp_path / "synthetic-runtime.zip"
    artifact.write_bytes(BODY)
    client = StatefulS3()

    published = _publish(client, artifact)
    assert published.success and published.head_verified
    key = f"runtime/{ZIP_SHA}.zip"
    assert set(client.objects) == {key}

    template = build_dev_oauth_template(
        cognito_dev_policy(user_pool_id=POOL, api_id=API, client_id=CLIENT, owner_subject=SUBJECT),
        bucket=BUCKET,
        zip_sha256=ZIP_SHA,
        jwks_sha256=JWKS_SHA,
        callback_url="http://localhost:39031/callback/synthetic",
        execution_start=1_800_000_000,
        execution_end=1_800_000_300,
    )
    resources = template["Resources"]
    handler = resources["McpHandler"]["Properties"]
    variables = handler["Environment"]["Variables"]
    assert handler["Code"]["S3Key"] == next(iter(client.objects)) == key
    assert variables["MAPIT_COGNITO_JWKS_SHA256"] == JWKS_SHA
    assert variables["MAPIT_COGNITO_JWKS_SHA256"] != ZIP_SHA
    assert variables["MAPIT_COGNITO_USER_POOL_ID"] == POOL
    assert variables["MAPIT_API_ID"] == API
    assert variables["MAPIT_COGNITO_CLIENT_ID"] == CLIENT
    assert variables["MAPIT_OWNER_SUBJECT"] == SUBJECT
    assert variables["MAPIT_DEV_EXECUTION_START_EPOCH"] == "1800000000"
    assert variables["MAPIT_DEV_EXECUTION_END_EPOCH"] == "1800000300"
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert handler["ReservedConcurrentExecutions"] == 0

    before_calls = len(client.calls)
    gated = _retire(client, app_deleted=False)
    assert not gated.success and gated.category == "retirement_app_not_deleted"
    assert len(client.calls) == before_calls
    assert set(client.objects) == {key}

    # This synthetic boolean only exercises the caller precondition. It is not
    # evidence of an actual CloudFormation stack-deletion readback.
    retired = _retire(client, app_deleted=True)
    assert retired.success and retired.object_absent_verified and retired.bucket_empty_verified
    assert retired.delete_attempted and retired.delete_succeeded and not retired.delete_outcome_unknown
    assert client.deleted_keys == [key]
    assert client.objects == {}
    assert len(client.calls) - before_calls == 6  # no retry, no pagination
    assert [name for name, _ in client.calls[before_calls:]] == [
        "get_bucket_versioning", "head_object", "delete_object", "head_object", "list_objects_v2", "list_multipart_uploads"
    ]


def test_checksum_drift_prevents_lifecycle_delete(tmp_path):
    artifact = tmp_path / "synthetic-runtime.zip"
    artifact.write_bytes(BODY)
    client = StatefulS3()
    assert _publish(client, artifact).success
    client.objects[f"runtime/{ZIP_SHA}.zip"]["ChecksumSHA256"] = "drift"
    result = _retire(client, app_deleted=True)
    assert not result.success and result.category == "retirement_object_mismatch"
    assert not result.delete_attempted and not client.deleted_keys
    assert len(client.objects) == 1
