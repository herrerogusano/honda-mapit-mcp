from __future__ import annotations

import base64
import hashlib
import json
from contextlib import contextmanager
from pathlib import Path
import zipfile

import pytest

from scripts.aws_retained_dev_delivery_artifact import MANIFEST_PATH, publish_retained_dev_runtime
from scripts.build_aws_retained_dev_archive import _make_receipt
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest, retained_dev_artifact_bucket


ACCOUNT = "123456789012"
BUCKET = retained_dev_artifact_bucket(ACCOUNT)
SOURCE = "a" * 40
RUN = "12345678-1234-4234-8234-123456789abc"
MANIFEST = build_retained_dev_manifest(SOURCE, "a1b2c3d4e5", "b" * 64)


def _manifest_bytes() -> bytes:
    return json.dumps(MANIFEST, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _archive(tmp_path: Path, *, manifest: bytes | None = None, payload: bytes = b"synthetic-runtime") -> tuple[Path, bytes, str]:
    path = tmp_path / "retained-runtime.zip"
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(MANIFEST_PATH, _manifest_bytes() if manifest is None else manifest)
        archive.writestr("mapit/index.py", payload)
    body = path.read_bytes()
    return path, body, hashlib.sha256(body).hexdigest()


class Journal:
    def __init__(self, *, fail_save=False):
        self.state = None
        self.saves = []
        self.fail_save = fail_save

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return self.state.copy() if isinstance(self.state, dict) else self.state

    def compare_and_set(self, expected_revision, value):
        if self.fail_save:
            raise RuntimeError("journal-private")
        current_revision = self.state.get("revision") if isinstance(self.state, dict) else None
        if current_revision != expected_revision:
            return False
        self.state = dict(value)
        self.saves.append(dict(value))
        return True


class S3:
    def __init__(self, *, put_error=None, head=None, event_log=None):
        self.put_error = put_error
        self.head = head
        self.put_calls = []
        self.head_calls = []
        self.event_log = event_log if event_log is not None else []

    def put_object(self, **kwargs):
        self.event_log.append("put")
        self.put_calls.append(kwargs)
        if self.put_error:
            raise self.put_error
        body = kwargs["Body"]
        checksum = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        return {"ChecksumSHA256": checksum, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def head_object(self, **kwargs):
        self.event_log.append("head")
        self.head_calls.append(kwargs)
        if isinstance(self.head, Exception):
            raise self.head
        if self.head is not None:
            return self.head
        body = self.put_calls[-1]["Body"]
        return {
            "ContentLength": len(body),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
            "ServerSideEncryption": "AES256",
            "ContentType": "application/zip",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }


class S3Error(Exception):
    def __init__(self, code, status):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


def _publish(path, body_sha, s3, journal, **kwargs):
    receipt = _make_receipt(
        source_sha=SOURCE, api_id="a1b2c3d4e5", jwks_sha256="b" * 64,
        execution_start_epoch=1_893_456_000, execution_end_epoch=1_893_456_300,
        zip_sha256=body_sha, manifest_sha256=hashlib.sha256(_manifest_bytes()).hexdigest(),
        source_allowlist_sha256="f" * 64, source_proof_sha256="e" * 64,
        wheel_lock_sha256="d" * 64, wheel_proof_sha256="c" * 64,
        archive_entries=2, wheel_count=0, source_modules=0, public_key_count=0,
    )
    values = {
        "bucket": BUCKET,
        "expected_owner": ACCOUNT,
        "run_id": RUN,
        "archive_path": path,
        "build_receipt": receipt,
        "authorized_from_epoch": 1_893_455_000,
        "authorized_until_epoch": 1_893_458_000,
        "wall_clock": lambda: 1_893_456_100,
        "monotonic": lambda: 1.0,
    }
    values.update(kwargs)
    return publish_retained_dev_runtime(s3, journal, **values)


def test_intent_precedes_one_conditional_put_and_exact_receipt(tmp_path):
    path, body, digest = _archive(tmp_path)
    events = []
    journal = Journal()
    s3 = S3(event_log=events)
    result = _publish(path, digest, s3, journal)

    assert result.success and result.category == "artifact_uploaded_verified"
    assert result.receipt is not None and result.receipt.key == f"runtime/{digest}.zip"
    assert [state["status"] for state in journal.saves] == ["intent", "verified"]
    assert events == ["put", "head"]
    assert s3.put_calls == [{
        "Bucket": BUCKET, "Key": f"runtime/{digest}.zip", "Body": body,
        "IfNoneMatch": "*", "ExpectedBucketOwner": ACCOUNT,
        "ServerSideEncryption": "AES256",
        "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
        "ContentType": "application/zip",
    }]


def test_matching_precondition_is_idempotent_only_after_exact_head(tmp_path):
    path, body, digest = _archive(tmp_path)
    s3 = S3(put_error=S3Error("PreconditionFailed", 412))
    journal = Journal()
    result = _publish(path, digest, s3, journal)
    assert result.success and result.category == "artifact_already_present_verified"
    assert result.idempotent_existing and result.head_verified
    assert [state["status"] for state in journal.saves] == ["intent", "verified"]


def test_verified_intent_requires_fresh_head_and_never_puts_again(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal(); s3 = S3()
    first = _publish(path, digest, s3, journal)
    second = _publish(path, digest, s3, journal)
    assert first.success and second.success and second.category == "artifact_already_verified"
    assert second.head_verified and len(s3.put_calls) == 1 and len(s3.head_calls) == 2


def test_ambiguous_put_fences_intent_and_second_call_never_replays(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal()
    s3 = S3(put_error=RuntimeError("provider-private"))
    first = _publish(path, digest, s3, journal)
    second = _publish(path, digest, s3, journal)
    assert first.category == "artifact_put_ambiguous" and first.put_outcome_unknown
    assert second.category == "intent_present"
    assert len(s3.put_calls) == 1 and s3.head_calls == []
    assert [state["status"] for state in journal.saves] == ["intent"]


@pytest.mark.parametrize("manifest", [b"{}", _manifest_bytes().replace(b'\"synthetic\":true', b'\"synthetic\":false')])
def test_manifest_mismatch_fails_before_s3(tmp_path, manifest):
    path, _, digest = _archive(tmp_path, manifest=manifest)
    journal = Journal(); s3 = S3()
    result = _publish(path, digest, s3, journal)
    assert result.category == "manifest_invalid"
    assert not s3.put_calls and not journal.saves


def test_wrong_digest_and_head_mismatch_fail_closed(tmp_path):
    path, body, digest = _archive(tmp_path)
    journal = Journal(); s3 = S3()
    wrong = _publish(path, "c" * 64, s3, journal)
    assert wrong.category == "artifact_hash_mismatch" and not journal.saves

    bad_head = {
        "ContentLength": len(body) + 1,
        "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
        "ServerSideEncryption": "AES256",
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    journal = Journal(); s3 = S3(head=bad_head)
    result = _publish(path, digest, s3, journal)
    assert result.category == "artifact_head_mismatch" and result.journal_intent_saved
    assert [state["status"] for state in journal.saves] == ["intent"]


def test_journal_failure_prevents_put(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal(fail_save=True); s3 = S3()
    result = _publish(path, digest, s3, journal)
    assert result.category == "journal_intent_failed"
    assert not s3.put_calls


def test_exact_bucket_and_authority_window_are_required(tmp_path):
    path, _, digest = _archive(tmp_path)
    journal = Journal(); s3 = S3()
    wrong_bucket = _publish(path, digest, s3, journal, bucket="honda-runtime-artifact-test-bucket")
    assert wrong_bucket.category == "artifact_input_invalid" and not s3.put_calls
    expired = _publish(path, digest, s3, Journal(), wall_clock=lambda: 1_893_459_000)
    assert expired.category == "window_expired"


def test_monotonic_clock_regression_fails_closed_before_journal(tmp_path):
    path, _, digest = _archive(tmp_path)
    values = iter((1.0, 0.5))
    result = _publish(path, digest, S3(), Journal(), monotonic=lambda: next(values))
    assert result.category == "window_expired"
