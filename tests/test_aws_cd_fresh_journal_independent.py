"""Independent synthetic failure fences for explicit journal creation."""

import pytest

from mapit.aws_cd_journal import DeliveryJournalError
from test_aws_cd_delivery_authorization import fresh_core
from test_aws_cd_journal import Failure, S3, journal, state


def test_failed_initial_write_readback_consumes_creation_mode_and_fences_writes():
    class UnreadableAfterPut(S3):
        def get_object(self, **kwargs):
            self.calls.append(("get", kwargs))
            raise Failure("AccessDenied", 403)

    s3 = UnreadableAfterPut()
    store = journal(s3, initialize_new=True)
    with store.locked():
        assert store.load() is None
        with pytest.raises(DeliveryJournalError, match="journal_write_ambiguous"):
            store.save(state())
        assert s3.object is not None
        with pytest.raises(DeliveryJournalError, match="journal_read_failed"):
            store.load()
        with pytest.raises(DeliveryJournalError, match="journal_write_blocked"):
            store.save(state())
    assert [name for name, _ in s3.calls] == ["put", "get", "get"]
    assert s3.calls[0][1]["IfNoneMatch"] == "*"


def test_existing_journal_collision_stops_core_before_any_control_or_application_call():
    s3 = S3()
    existing = journal(s3)
    with existing.locked():
        existing.load()
        existing.save(state())
    original = s3.object
    core, _ = fresh_core()
    core.journal = journal(s3, initialize_new=True)
    dispatched = []

    def forbidden_call(*args, **kwargs):
        dispatched.append((args, kwargs))
        raise AssertionError("collision must stop before dispatch")

    core._call = forbidden_call
    result = core.run_step("preflight")
    assert result["category"] == "journal_invalid"
    assert not dispatched and s3.object == original
    assert sum(name == "put" for name, _ in s3.calls) == 2
    repeated = core.run_step("preflight")
    assert repeated["category"] == "journal_not_fresh"
    assert not dispatched and s3.object == original
    assert sum(name == "put" for name, _ in s3.calls) == 2
