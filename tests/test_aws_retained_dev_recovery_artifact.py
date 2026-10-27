from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
from dataclasses import replace
import hashlib
import io
import zipfile

from scripts.aws_retained_dev_prior_code import HANDLER_CODE, PriorCodeSnapshot
from scripts.aws_retained_dev_recovery_artifact import publish_initial_recovery_artifact
from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_recovery import build_initial_recovery_template


ACCOUNT = "123456789012"
RUN = "12345678-1234-4234-8234-123456789abc"
SOURCE = "a" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-dev-executor"


def _ok(**value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Journal:
    def __init__(self):
        self.state = None

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def compare_and_set(self, expected, value):
        current = self.state.get("revision") if isinstance(self.state, dict) else None
        if current != expected:
            return False
        self.state = copy.deepcopy(value)
        return True


class S3:
    def __init__(self, body, *, preexisting=False, ambiguous=False, content_type="application/zip"):
        self.body = body
        self.preexisting = preexisting
        self.ambiguous = ambiguous
        self.content_type = content_type
        self.put_calls = []
        self.head_calls = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        if self.preexisting:
            raise FakeError("PreconditionFailed", 412)
        if self.ambiguous:
            self.body = kwargs["Body"]
            raise RuntimeError("connection-closed")
        self.body = kwargs["Body"]
        return _ok(ChecksumSHA256=kwargs["ChecksumSHA256"])

    def head_object(self, **kwargs):
        self.head_calls.append(kwargs)
        digest = base64.b64encode(hashlib.sha256(self.body).digest()).decode("ascii")
        return _ok(
            ContentLength=len(self.body), ChecksumSHA256=digest,
            ServerSideEncryption="AES256", ContentType=self.content_type,
        )


class FakeError(Exception):
    def __init__(self, code, status):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


def _snapshot() -> PriorCodeSnapshot:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("index.py", HANDLER_CODE)
    body = stream.getvalue()
    template = build_retained_dev_template()
    template_bytes = __import__("json").dumps(template, sort_keys=True, separators=(",", ":")).encode()
    return PriorCodeSnapshot(
        archive_bytes=body,
        template_bytes=template_bytes,
        zip_sha256=hashlib.sha256(body).hexdigest(),
        template_sha256=hashlib.sha256(template_bytes).hexdigest(),
        observed_epoch=1_893_456_100,
    )


def _kwargs(snapshot):
    return dict(
        account_id=ACCOUNT, run_id=RUN, snapshot=snapshot,
        source_sha=SOURCE, expected_caller_arn=CALLER,
        authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000,
        wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0,
    )


def test_recovery_factory_is_s3_backed_closed_and_role_bound():
    snapshot = _snapshot()
    result = build_initial_recovery_template(ACCOUNT, snapshot)
    props = result.template["Resources"]["McpHandler"]["Properties"]
    assert props["Handler"] == "index.handler"
    assert "Environment" not in props
    assert props["Code"] == {"S3Bucket": result.bucket, "S3Key": result.key}
    assert result.cfn_role_arn.endswith(":role/honda-mapit-mcp-dev-retained-cfn-update")
    assert result.original_template_sha256 == snapshot.template_sha256
    assert result.recovery_template_sha256 != result.original_template_sha256


def test_publish_saves_intent_then_one_conditional_put_and_exact_head():
    snapshot = _snapshot(); s3 = S3(snapshot.archive_bytes); journal = Journal()
    result = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert result.success and result.category == "published"
    assert result.put_succeeded and result.head_verified
    assert len(s3.put_calls) == 1 and s3.put_calls[0]["IfNoneMatch"] == "*"
    assert s3.put_calls[0]["ExpectedBucketOwner"] == ACCOUNT
    assert s3.put_calls[0]["ServerSideEncryption"] == "AES256"
    assert s3.put_calls[0]["ChecksumSHA256"] == base64.b64encode(bytes.fromhex(snapshot.zip_sha256)).decode("ascii")
    assert s3.head_calls[0]["ChecksumMode"] == "ENABLED"
    assert s3.head_calls[0]["ExpectedBucketOwner"] == ACCOUNT
    assert journal.state["status"] == "verified" and journal.state["revision"] == 2


def test_precondition_existing_exact_object_is_idempotent_without_replay():
    snapshot = _snapshot(); s3 = S3(snapshot.archive_bytes, preexisting=True); journal = Journal()
    result = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert result.success and result.idempotent_existing and result.head_verified
    assert len(s3.put_calls) == 1 and journal.state["status"] == "verified"


def test_ambiguous_put_fences_then_next_run_only_reconciles():
    snapshot = _snapshot(); s3 = S3(snapshot.archive_bytes, ambiguous=True); journal = Journal()
    first = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert not first.success and first.put_outcome_unknown and journal.state["status"] == "intent"
    second = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert second.success and second.idempotent_existing
    assert len(s3.put_calls) == 1


def test_wrong_head_content_type_does_not_become_a_recovery_receipt():
    snapshot = _snapshot(); s3 = S3(snapshot.archive_bytes, content_type="text/plain"); journal = Journal()
    result = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert not result.success and result.put_outcome_unknown
    assert journal.state["status"] == "intent"


def test_snapshot_observation_must_be_fresh_and_inside_authority_window():
    snapshot = replace(_snapshot(), observed_epoch=1_893_454_100)
    s3 = S3(snapshot.archive_bytes)
    result = publish_initial_recovery_artifact(s3, Journal(), **_kwargs(snapshot))
    assert not result.success and result.category == "snapshot_stale"
    assert not s3.put_calls


def test_bool_revision_is_not_a_valid_recovery_journal_revision():
    snapshot = _snapshot(); s3 = S3(snapshot.archive_bytes); journal = Journal()
    first = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert first.success
    journal.state["revision"] = True
    second = publish_initial_recovery_artifact(s3, journal, **_kwargs(snapshot))
    assert not second.success and second.category == "journal_conflict"
    assert len(s3.put_calls) == 1


def test_wall_clock_regression_fences_before_the_single_put():
    snapshot = _snapshot(); s3 = S3(snapshot.archive_bytes); journal = Journal()
    values = iter([1_893_456_100, 1_893_456_099])
    kwargs = _kwargs(snapshot)
    kwargs["wall_clock"] = lambda: next(values)
    result = publish_initial_recovery_artifact(
        s3, journal, **kwargs,
    )
    assert not result.success and result.category == "window_expired"
    assert not s3.put_calls and journal.state is None
