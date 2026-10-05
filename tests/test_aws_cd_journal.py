import base64
import hashlib
import io

import pytest

from mapit.aws_cd_journal import DeliveryJournalError, S3DeliveryJournal
from test_aws_cd_delivery_authorization import fresh_core
from test_aws_prod_geography_upgrade import ACCOUNT, BUCKET


class Failure(Exception):
    def __init__(self, code="NoSuchKey", status=404):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}
        super().__init__("PRIVATE_PROVIDER_CANARY")


class S3:
    def __init__(self):
        self.object = None
        self.calls = []
        self.ambiguous = False

    def get_object(self, **kw):
        self.calls.append(("get", kw))
        if self.object is None:
            raise Failure()
        raw, etag = self.object
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Body": io.BytesIO(raw),
                "ContentLength": len(raw), "ETag": etag, "ServerSideEncryption": "AES256",
                "ChecksumSHA256": base64.b64encode(hashlib.sha256(raw).digest()).decode()}

    def put_object(self, **kw):
        self.calls.append(("put", kw))
        if self.object and (kw.get("IfNoneMatch") == "*" or kw.get("IfMatch") != self.object[1]):
            raise Failure("PreconditionFailed", 412)
        raw = kw["Body"]
        etag = '"' + hashlib.sha256(raw).hexdigest() + '"'
        self.object = raw, etag
        if self.ambiguous:
            raise TimeoutError("PRIVATE_PROVIDER_CANARY")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "ETag": etag,
                "ChecksumSHA256": kw["ChecksumSHA256"]}


def journal(s3, **overrides):
    fields = dict(bucket=BUCKET, account_id=ACCOUNT, run_id="123456", source_sha="a" * 40)
    fields.update(overrides)
    return S3DeliveryJournal(s3, **fields)


def state():
    core, _ = fresh_core()
    core._step_started = core.monotonic()
    return core._save_new_state()


def test_initial_and_subsequent_writes_are_conditional_and_read_back():
    s3 = S3()
    store = journal(s3)
    value = state()
    with store.locked():
        assert store.load() is None
        store.save(value)
        value["preflight_verified"] = True
        store.save(value)
    puts = [kw for name, kw in s3.calls if name == "put"]
    assert puts[0]["IfNoneMatch"] == "*" and "IfMatch" not in puts[0]
    assert "IfMatch" in puts[1] and "IfNoneMatch" not in puts[1]
    assert all(p["ExpectedBucketOwner"] == ACCOUNT and p["ServerSideEncryption"] == "AES256" for p in puts)
    other = journal(s3)
    with other.locked():
        assert other.load() == value


def test_two_writers_cannot_dispatch_after_losing_cas():
    s3 = S3()
    a, b = journal(s3), journal(s3)
    value = state()
    with a.locked():
        a.load()
        a.save(value)
    with a.locked(), b.locked():
        first, stale = a.load(), b.load()
        first["preflight_verified"] = True
        a.save(first)
        stale["preflight_verified"] = True
        with pytest.raises(DeliveryJournalError, match="journal_write_ambiguous"):
            b.save(stale)
        b.load()
        with pytest.raises(DeliveryJournalError, match="journal_write_blocked"):
            b.save(first)
    assert len([kw for name, kw in s3.calls if name == "put"]) == 3


def test_ambiguous_put_is_not_replayed_and_new_reader_recovers_intent():
    s3, value = S3(), state()
    value["update_intent"] = {"client_request_token": "11111111-2222-4333-8444-555555555555"}
    store = journal(s3)
    s3.ambiguous = True
    with store.locked():
        store.load()
        with pytest.raises(DeliveryJournalError, match="journal_write_ambiguous") as error:
            store.save(value)
        assert "CANARY" not in str(error.value)
        with pytest.raises(DeliveryJournalError, match="journal_write_blocked"):
            store.save(value)
    recovered = journal(s3)
    with recovered.locked():
        assert recovered.load()["update_intent"] == value["update_intent"]
    assert sum(name == "put" for name, _ in s3.calls) == 1


@pytest.mark.parametrize("field,value", [("credentials", "TOKEN"), ("tripwire_fingerprint", "TOKEN"),
    ("preflight_verified", "TOKEN"), ("api_id", "TOKEN"), ("old_zip_sha256", "TOKEN")])
def test_unapproved_fields_and_non_metadata_values_never_persist(field, value):
    s3 = S3()
    store = journal(s3)
    payload = state()
    payload[field] = value
    with store.locked():
        store.load()
        with pytest.raises(DeliveryJournalError, match="journal_invalid"):
            store.save(payload)
    assert not any(name == "put" for name, _ in s3.calls)


def test_wrong_run_or_source_cannot_load_existing_journal():
    s3 = S3()
    original = journal(s3)
    with original.locked():
        original.load()
        original.save(state())
    for overrides in ({"run_id": "654321"}, {"source_sha": "b" * 40}):
        changed = journal(s3, **overrides)
        with changed.locked(), pytest.raises(DeliveryJournalError, match="journal_invalid"):
            changed.load()


@pytest.mark.parametrize("attachment", [False, True])
def test_initial_service_role_attachment_is_persisted_as_an_exact_boolean(attachment):
    s3 = S3()
    store = journal(s3)
    value = state()
    value["delivery_binding"]["initial_service_role_attachment"] = attachment
    with store.locked():
        assert store.load() is None
        store.save(value)
    recovered = journal(s3)
    with recovered.locked():
        assert recovered.load()["delivery_binding"]["initial_service_role_attachment"] is attachment


def test_journal_rejects_non_boolean_initial_role_attachment():
    s3 = S3()
    store = journal(s3)
    value = state()
    value["delivery_binding"]["initial_service_role_attachment"] = 1
    with store.locked():
        assert store.load() is None
        with pytest.raises(DeliveryJournalError, match="journal_invalid"):
            store.save(value)
    assert not any(name == "put" for name, _ in s3.calls)


def test_unknown_absence_is_not_treated_as_empty():
    s3 = S3()
    s3.get_object = lambda **kw: (_ for _ in ()).throw(Failure("AccessDenied", 403))
    store = journal(s3)
    with store.locked(), pytest.raises(DeliveryJournalError, match="journal_read_failed"):
        store.load()


def test_save_requires_lock_and_prior_read():
    store = journal(S3())
    with pytest.raises(DeliveryJournalError, match="journal_write_blocked"):
        store.save(state())
    with store.locked(), pytest.raises(DeliveryJournalError, match="journal_write_blocked"):
        store.save(state())


def test_recorded_intent_cannot_be_erased_or_changed_to_enable_replay():
    s3, payload = S3(), state()
    payload["update_intent"] = {"client_request_token": "11111111-2222-4333-8444-555555555555"}
    store = journal(s3)
    with store.locked():
        store.load()
        store.save(payload)
        del payload["update_intent"]
        with pytest.raises(DeliveryJournalError, match="journal_invalid"):
            store.save(payload)
    assert sum(name == "put" for name, _ in s3.calls) == 1
