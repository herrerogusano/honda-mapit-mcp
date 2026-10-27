from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

import pytest

from scripts.aws_retained_dev_journal import RetainedDevJournalError
from scripts.aws_retained_dev_journal_validators import (
    JournalValidatorError,
    RetainedDevJournalBinding,
    create_validated_retained_dev_journal,
    make_phase_state,
    validate_phase_state,
)


ACCOUNT = "123456789012"
RUN = "12345678-1234-4234-8234-123456789abc"
SOURCE = "a" * 40
BINDING = "b" * 64
TEMPLATE = "c" * 64
START = 1_900_000_000


class S3Error(Exception):
    def __init__(self, code: str = "NoSuchKey", status: int = 404):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


class Body:
    def __init__(self, body: bytes):
        self.body = body
        self.closed = False

    def read(self, size: int = -1) -> bytes:
        return self.body if size < 0 else self.body[:size]

    def close(self) -> None:
        self.closed = True


class S3:
    def __init__(self):
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.counter = 0

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get", kwargs))
        if kwargs["Key"] not in self.objects:
            raise S3Error()
        body, etag = self.objects[kwargs["Key"]]
        return {
            "Body": Body(body),
            "ContentLength": len(body),
            "ChecksumSHA256": base64.b64encode(hashlib.sha256(body).digest()).decode("ascii"),
            "ServerSideEncryption": "AES256",
            "ContentType": "application/json",
            "ETag": etag,
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

    def put_object(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("put", kwargs))
        key = kwargs["Key"]
        if kwargs.get("IfNoneMatch") == "*" and key in self.objects:
            raise S3Error("PreconditionFailed", 412)
        if kwargs.get("IfMatch") is not None and (key not in self.objects or self.objects[key][1] != kwargs["IfMatch"]):
            raise S3Error("PreconditionFailed", 412)
        self.counter += 1
        etag = f'"etag{self.counter}"'
        self.objects[key] = (kwargs["Body"], etag)
        return {"ChecksumSHA256": kwargs["ChecksumSHA256"], "ETag": etag, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Clock:
    def __init__(self):
        self.wall = START + 5
        self.mono = 1.0

    def w(self) -> float:
        return self.wall

    def m(self) -> float:
        return self.mono


def binding(phase: str = "artifact") -> RetainedDevJournalBinding:
    return RetainedDevJournalBinding(ACCOUNT, SOURCE, RUN, phase, BINDING, TEMPLATE, START, START + 900)


def journal(s3: S3 | None = None, *, phase: str = "artifact", create_first: bool = True):
    clock = Clock()
    s3 = s3 or S3()
    return create_validated_retained_dev_journal(
        s3,
        binding(phase),
        create_first=create_first,
        wall_clock=clock.w,
        monotonic=clock.m,
    ), s3


def state(b: RetainedDevJournalBinding, version: int, *, intent: str | None = None, acknowledged: bool = False, readback: bool = False):
    return make_phase_state(
        b,
        version=version,
        intent=intent,
        acknowledged=acknowledged,
        readback=readback,
        last_observed_epoch=START + 5,
    )


def test_binding_is_strict_and_repr_is_redacted():
    assert "123456789012" not in repr(binding())
    assert "a" * 40 not in repr(binding())
    with pytest.raises(JournalValidatorError, match="journal_binding_invalid"):
        RetainedDevJournalBinding(ACCOUNT, SOURCE, RUN, "artifact", BINDING, TEMPLATE, True, START + 1)
    with pytest.raises(JournalValidatorError, match="journal_binding_invalid"):
        RetainedDevJournalBinding(ACCOUNT, SOURCE, RUN, "artifact", BINDING, TEMPLATE, START, START + 3601)
    with pytest.raises(JournalValidatorError, match="journal_binding_invalid"):
        RetainedDevJournalBinding(ACCOUNT, SOURCE, RUN, [], BINDING, TEMPLATE, START, START + 1)


def test_state_schema_binds_all_fields_and_rejects_payload_or_impossible_states():
    b = binding()
    first = state(b, 1)
    assert validate_phase_state(first, b)
    assert not validate_phase_state({**first, "template_sha256": "d" * 64}, b)
    assert not validate_phase_state({**first, "payload": "private"}, b)
    assert not validate_phase_state({**first, "acknowledged": True}, b)
    assert not validate_phase_state({**first, "readback": True}, b)
    assert not validate_phase_state({**first, "version": True}, b)
    assert not validate_phase_state({**first, "last_observed_epoch": START + 901}, b)
    assert not validate_phase_state({**first, "last_observed_epoch": START + 900}, b)
    ready = state(b, 2, intent="artifact", acknowledged=True, readback=True)
    assert validate_phase_state(ready, b)


def test_create_first_then_second_cas_binds_outer_and_inner_counters():
    j, s3 = journal()
    b = binding()
    with j.locked():
        assert j.load() is None
        assert j.compare_and_set(None, state(b, 1))
        assert j.compare_and_set(1, state(b, 2, intent="artifact", acknowledged=True, readback=True))
        assert j.load()["version"] == 2
    assert [name for name, _ in s3.calls].count("put") == 2


def test_outer_expected_revision_and_inner_version_must_advance_together():
    j, _ = journal()
    b = binding()
    with j.locked():
        assert j.load() is None
        assert j.compare_and_set(None, state(b, 1))
        with pytest.raises(JournalValidatorError, match="journal_revision_invalid"):
            j.compare_and_set(1, state(b, 3, intent="artifact"))


def test_returned_snapshots_are_detached_from_adapter_state():
    j, _ = journal()
    b = binding()
    candidate = state(b, 1)
    with j.locked():
        assert j.load() is None
        assert j.compare_and_set(None, candidate)
        observed = j.load()
        observed["version"] = 99
        assert j.load()["version"] == 1


def test_adapter_rejects_clearing_intent_or_acknowledgement():
    j, _ = journal()
    b = binding()
    with j.locked():
        assert j.load() is None
        assert j.compare_and_set(None, state(b, 1, intent="artifact", acknowledged=True))
        with pytest.raises(JournalValidatorError, match="journal_state_transition_invalid"):
            j.compare_and_set(1, state(b, 2))


def test_conditional_412_reconciles_exact_winner_and_allows_followup():
    s3 = S3()
    winner, _ = journal(s3)
    b = binding()
    with winner.locked():
        assert winner.load() is None
        assert winner.compare_and_set(None, state(b, 1))
    loser, _ = journal(s3)
    with loser.locked():
        assert loser.load() is None
        assert loser.compare_and_set(None, state(b, 1)) is False
        observed = loser.load()
        assert observed is not None and observed["version"] == 1
        assert loser.compare_and_set(1, state(b, 2, intent="artifact", acknowledged=True, readback=True))


def test_unknown_write_fences_instance_but_fresh_adapter_can_reconcile():
    s3 = S3()
    original = s3.put_object

    def ambiguous(**kwargs: Any):
        original(**kwargs)
        raise RuntimeError("private transport detail")

    s3.put_object = ambiguous  # type: ignore[method-assign]
    j, _ = journal(s3)
    b = binding()
    with j.locked():
        assert j.load() is None
        with pytest.raises(RetainedDevJournalError, match="journal_write_ambiguous"):
            j.compare_and_set(None, state(b, 1))
        with pytest.raises(RetainedDevJournalError, match="journal_write_blocked"):
            j.compare_and_set(None, state(b, 1))
    fresh, _ = journal(s3, create_first=False)
    with fresh.locked():
        assert fresh.load()["version"] == 1


def test_factory_has_no_custom_validator_escape_hatch():
    import inspect

    signature = inspect.signature(create_validated_retained_dev_journal)
    assert "state_validator" not in signature.parameters
