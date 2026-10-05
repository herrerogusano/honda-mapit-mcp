"""Independent malformed-response checks for the injected S3 delivery journal."""

import base64
import hashlib
import io
import json

import pytest

from mapit.aws_cd_journal import DeliveryJournalError, MAX_BYTES
from test_aws_cd_journal import ACCOUNT, BUCKET, S3, journal, state


class TrackedBody(io.BytesIO):
    def __init__(self, value):
        super().__init__(value)
        self.was_closed = False

    def close(self):
        self.was_closed = True
        super().close()


def _seed(s3):
    raw = b'{"untrusted":"PRIVATE_CANARY"}'
    s3.object = (raw, '"etag-ok"')
    return raw


@pytest.mark.parametrize("mutation", ["status", "encryption", "length", "checksum", "etag"])
def test_poisoned_getobject_readback_fails_closed_and_closes_body(mutation):
    s3 = S3()
    raw = _seed(s3)
    if mutation == "etag":
        envelope = {
            "schema": 1,
            "run_id": "123456",
            "source_sha": "a" * 40,
            "revision": 1,
            "previous_sha256": None,
            "state": state(),
        }
        raw = json.dumps(envelope, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        s3.object = (raw, '"etag-ok"')
    body = TrackedBody(raw)

    def get_object(**kwargs):
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Body": body,
            "ContentLength": len(raw),
            "ETag": '"etag-ok"',
            "ServerSideEncryption": "AES256",
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii"),
        }

    response = get_object()
    if mutation == "status":
        response["ResponseMetadata"]["HTTPStatusCode"] = True
    elif mutation == "encryption":
        response["ServerSideEncryption"] = "aws:kms"
    elif mutation == "length":
        response["ContentLength"] += 1
    elif mutation == "checksum":
        response["ChecksumSHA256"] = "not-the-body-checksum"
    elif mutation == "etag":
        response["ETag"] = "unquoted"
    s3.get_object = lambda **kwargs: response

    store = journal(s3)
    with store.locked(), pytest.raises(DeliveryJournalError) as error:
        store.load()
    assert error.value.args == ("journal_response_invalid",)
    assert body.was_closed
    assert "PRIVATE_CANARY" not in str(error.value)


def test_declared_oversized_object_is_rejected_without_reading_body_beyond_limit():
    class Body:
        def __init__(self):
            self.requests = []
            self.closed = False

        def read(self, size=-1):
            self.requests.append(size)
            return b"x" * (MAX_BYTES + 1)

        def close(self):
            self.closed = True

    body = Body()
    s3 = S3()
    s3.get_object = lambda **kwargs: {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Body": body,
        "ContentLength": MAX_BYTES + 1,
        "ETag": '"etag-ok"',
        "ServerSideEncryption": "AES256",
        "ChecksumSHA256": "unused",
    }
    store = journal(s3)
    with store.locked(), pytest.raises(DeliveryJournalError, match="journal_response_invalid"):
        store.load()
    assert body.requests == []
    assert body.closed


def test_corrupt_put_ack_blocks_this_writer_without_retry_or_canary_leak():
    s3 = S3()
    store = journal(s3)
    value = state()
    with store.locked():
        store.load()

        def poisoned_put(**kwargs):
            s3.calls.append(("put", kwargs))
            raw = kwargs["Body"]
            etag = '"written"'
            s3.object = (raw, etag)
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "ETag": etag,
                    "ChecksumSHA256": "PRIVATE_CANARY"}

        s3.put_object = poisoned_put
        with pytest.raises(DeliveryJournalError, match="journal_write_ambiguous") as error:
            store.save(value)
        assert "PRIVATE_CANARY" not in str(error.value)
        with pytest.raises(DeliveryJournalError, match="journal_write_blocked"):
            store.save(value)
    assert sum(name == "put" for name, _ in s3.calls) == 1
