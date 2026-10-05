from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.aws_dev_runtime_artifact import publish_runtime_zip


BODY = b"independent synthetic runtime artifact"
BUCKET = "honda-runtime-artifact-independent-test"
OWNER = "123456789012"


class Returned412Client:
    def __init__(self) -> None:
        self.put_calls: list[dict] = []
        self.head_calls: list[dict] = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        # A returned response has no service error code proving that this is
        # the recognized If-None-Match precondition failure.
        return {"ResponseMetadata": {"HTTPStatusCode": 412}}

    def head_object(self, **kwargs):
        self.head_calls.append(kwargs)
        return {
            "ContentLength": len(BODY),
            "ChecksumSHA256": "matching-but-not-authoritative",
            "ServerSideEncryption": "AES256",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


def test_plain_412_put_response_without_known_error_code_is_ambiguous(tmp_path: Path):
    archive = tmp_path / "runtime.zip"
    archive.write_bytes(BODY)
    client = Returned412Client()

    result = publish_runtime_zip(
        client,
        bucket=BUCKET,
        expected_owner=OWNER,
        archive_path=archive,
        sha256_hex=hashlib.sha256(BODY).hexdigest(),
        size_bytes=len(BODY),
    )

    assert result.success is False
    assert result.category == "artifact_put_ambiguous"
    assert result.put_attempted is True
    assert result.put_outcome_unknown is True
    assert client.put_calls and client.head_calls == []
