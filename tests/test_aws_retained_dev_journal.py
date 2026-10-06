from __future__ import annotations

import base64
import copy
from contextlib import contextmanager

import pytest

from scripts.aws_retained_dev_journal import RetainedDevJournalError, RetainedDevS3Journal


ACCOUNT = "123456789012"
RUN = "12345678-1234-4234-8234-123456789abc"
SOURCE = "a" * 40


class S3Error(Exception):
    def __init__(self, code="NoSuchKey", status=404):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class S3:
    def __init__(self):
        self.objects = {}
        self.calls = []
        self.counter = 0

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        if kwargs["Key"] not in self.objects:
            raise S3Error()
        body, etag = self.objects[kwargs["Key"]]
        return {"Body": Body(body), "ContentLength": len(body), "ChecksumSHA256": base64.b64encode(__import__("hashlib").sha256(body).digest()).decode("ascii"), "ServerSideEncryption": "AES256", "ContentType": "application/json", "ETag": etag, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_object(self, **kwargs):
        self.calls.append(("put", kwargs))
        key = kwargs["Key"]
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise S3Error("PreconditionFailed", 412)
        if kwargs.get("IfMatch") is not None and (key not in self.objects or self.objects[key][1] != kwargs["IfMatch"]):
            raise S3Error("PreconditionFailed", 412)
        self.counter += 1; etag = f'"etag{self.counter}"'; self.objects[key] = (kwargs["Body"], etag)
        return {"ChecksumSHA256": kwargs["ChecksumSHA256"], "ETag": etag, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Body:
    def __init__(self, body): self.body, self.closed = body, False
    def read(self, size=-1): return self.body[:size]
    def close(self): self.closed = True


class Clock:
    def __init__(self): self.wall = 1_893_456_100; self.mono = 1.0
    def w(self): return self.wall
    def m(self): return self.mono


def valid(state):
    return isinstance(state, dict) and set(state) == {"value"} and type(state["value"]) is int


def _journal(s3=None, phase="artifact", clock=None, create_first=False):
    clock = clock or Clock(); s3 = s3 or S3()
    return RetainedDevS3Journal(s3, account_id=ACCOUNT, run_id=RUN, source_sha=SOURCE, phase=phase, state_validator=valid, create_first=create_first, wall_clock=clock.w, monotonic=clock.m), s3


def test_first_cas_uses_deterministic_key_and_conditional_headers():
    journal, s3 = _journal(phase="preflight")
    with journal.locked():
        assert journal.load() is None
        assert journal.compare_and_set(None, {"value": 1})
        assert journal.load() == {"value": 1}
    put = next(kwargs for name, kwargs in s3.calls if name == "put")
    assert put["Key"] == f"journals/{RUN}/preflight.json"
    assert put["IfNoneMatch"] == "*" and put["ServerSideEncryption"] == "AES256"
    assert "IfMatch" not in put


def test_second_cas_uses_loaded_etag_and_revision_envelope():
    journal, s3 = _journal()
    with journal.locked():
        assert journal.load() is None
        assert journal.compare_and_set(None, {"value": 1})
        assert journal.compare_and_set(1, {"value": 2})
    put = [kwargs for name, kwargs in s3.calls if name == "put"][-1]
    assert put["IfMatch"] == '"etag1"' and put["Body"].find(b'"revision":2') >= 0


def test_known_conditional_conflict_returns_false_after_fresh_read():
    journal, s3 = _journal()
    other, _ = _journal(s3)
    with journal.locked():
        assert journal.load() is None
        with other.locked():
            assert other.load() is None
            assert other.compare_and_set(None, {"value": 9})
        assert journal.compare_and_set(None, {"value": 1}) is False


def test_create_first_suppresses_initial_get_and_uses_atomic_if_none_match():
    journal, s3 = _journal(create_first=True, phase="preflight")
    with journal.locked():
        assert journal.load() is None
        assert journal.load() is None
        assert [name for name, _ in s3.calls] == []
        assert journal.compare_and_set(None, {"value": 1})
    assert [name for name, _ in s3.calls] == ["put", "get"]
    put = s3.calls[0][1]
    assert put["IfNoneMatch"] == "*" and "IfMatch" not in put


def test_create_first_is_one_use_and_reopens_in_resume_mode():
    journal, s3 = _journal(create_first=True)
    with journal.locked():
        assert journal.load() is None
        assert journal.compare_and_set(None, {"value": 1})
    get_count = [name for name, _ in s3.calls].count("get")
    with journal.locked():
        assert journal.load() == {"value": 1}
    assert [name for name, _ in s3.calls].count("get") == get_count + 1


def test_create_first_existing_key_returns_false_after_exact_read_and_can_progress():
    s3 = S3()
    existing, _ = _journal(s3)
    with existing.locked():
        assert existing.load() is None
        assert existing.compare_and_set(None, {"value": 9})
    journal, _ = _journal(s3, create_first=True)
    with journal.locked():
        assert journal.load() is None
        get_count = [name for name, _ in s3.calls].count("get")
        put_count = [name for name, _ in s3.calls].count("put")
        assert journal.compare_and_set(None, {"value": 1}) is False
        assert [name for name, _ in s3.calls].count("get") == get_count + 1
        assert journal.compare_and_set(1, {"value": 2}) is True
    assert [name for name, _ in s3.calls].count("put") == put_count + 2


def test_412_without_an_exact_existing_object_remains_fenced():
    class LostRace(S3):
        def put_object(self, **kwargs):
            self.calls.append(("put", kwargs))
            raise S3Error("PreconditionFailed", 412)

    journal, s3 = _journal(LostRace(), create_first=True)
    with journal.locked():
        assert journal.load() is None
        with pytest.raises(RetainedDevJournalError, match="journal_write_ambiguous"):
            journal.compare_and_set(None, {"value": 1})
        with pytest.raises(RetainedDevJournalError, match="journal_write_blocked"):
            journal.compare_and_set(None, {"value": 1})
    assert [name for name, _ in s3.calls] == ["put", "get"]


def test_default_mode_never_treats_forbidden_get_as_absence():
    class Forbidden(S3):
        def get_object(self, **kwargs):
            self.calls.append(("get", kwargs))
            raise S3Error("AccessDenied", 403)

    journal, s3 = _journal(Forbidden())
    with journal.locked():
        with pytest.raises(RetainedDevJournalError, match="journal_read_failed"):
            journal.load()
    assert [name for name, _ in s3.calls] == ["get"]


def test_constructor_rejects_non_boolean_create_first():
    with pytest.raises(RetainedDevJournalError, match="journal_inputs_invalid"):
        RetainedDevS3Journal(S3(), account_id=ACCOUNT, run_id=RUN, source_sha=SOURCE, phase="artifact", state_validator=valid, create_first=1)


def test_uncertain_put_blocks_instance_and_new_reader_can_reconcile():
    journal, s3 = _journal()
    original = s3.put_object
    def uncertain(**kwargs):
        original(**kwargs)
        raise RuntimeError("ambiguous")
    s3.put_object = uncertain
    with journal.locked():
        assert journal.load() is None
        with pytest.raises(RetainedDevJournalError, match="journal_write_ambiguous"):
            journal.compare_and_set(None, {"value": 1})
        with pytest.raises(RetainedDevJournalError, match="journal_write_blocked"):
            journal.compare_and_set(None, {"value": 1})
    fresh, _ = _journal(s3)
    with fresh.locked():
        assert fresh.load() == {"value": 1}


def test_duplicate_envelope_and_invalid_state_fail_closed():
    journal, s3 = _journal()
    body = b'{"schema":1,"schema":1}'
    s3.objects[journal.key] = (body, '"etag0"')
    with journal.locked():
        with pytest.raises(RetainedDevJournalError, match="journal_invalid"):
            journal.load()
    journal, _ = _journal()
    with journal.locked():
        assert journal.load() is None
        assert journal.compare_and_set(None, {"wrong": 1}) is False


def test_nonreentrant_lock_and_monotonic_regression_fail_closed():
    clock = Clock(); journal, _ = _journal(clock=clock)
    with journal.locked():
        with pytest.raises(RetainedDevJournalError, match="journal_lock_invalid"):
            with journal.locked():
                pass
        clock.mono = 0.5
        with pytest.raises(RetainedDevJournalError, match="window_expired"):
            journal.load()
