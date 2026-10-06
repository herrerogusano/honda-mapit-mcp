from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.dev_multiuser_journal import KIND, PlainFileJournal, MultiuserJournalError
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_dev_multiuser_runtime_update import CasFileJournal
from scripts.dev_multiuser_closed_update import ClosedDevUpdate
from tests.test_dev_multiuser_closed_update import (
    ACCOUNT, APP_ARN, CALLER, SERVICE_ROLE, SOURCE, TOKEN,
    _closed_template, _complete_readback, _core,
)


def test_envelope_roundtrip_survives_new_process_instance(tmp_path: Path):
    first = PlainFileJournal(tmp_path)
    value = {"binding": {"account": ACCOUNT, "source": SOURCE}, "phase": "ready"}
    first.save(value)
    raw = json.loads((tmp_path / "rehearsal-state.json").read_text(encoding="utf-8"))
    assert raw == {"schema": 1, "kind": KIND, "value": value}
    assert PlainFileJournal(tmp_path).load() == value


def test_plain_journal_rejects_legacy_unwrapped_state(tmp_path: Path):
    FileJournal(tmp_path).save({"schema": 1, "binding": {}, "phase": "ready"})
    with pytest.raises(MultiuserJournalError) as error:
        PlainFileJournal(tmp_path).load()
    assert error.value.category == "journal_invalid"


def test_cas_adapter_roundtrip_and_revision_conflict(tmp_path: Path):
    journal = CasFileJournal(tmp_path)
    value = {"schema": 1, "kind": "retained-dev-multiuser-artifact-publication",
             "revision": 1, "status": "intent"}
    assert journal.compare_and_set(None, value) is True
    assert journal.load() == value
    assert journal.compare_and_set(None, {**value, "revision": 2}) is False
    assert journal.compare_and_set(1, {**value, "revision": 2}) is True
    assert PlainFileJournal(tmp_path).load()["revision"] == 2


def test_closed_update_preflight_update_readback_survives_new_instances(tmp_path: Path):
    journal = PlainFileJournal(tmp_path)
    core, cfn, clients = _core(journal=journal)
    assert core.run("preflight") == {"ok": True, "phase": "ready"}

    prior = _closed_template("prior")
    target = _closed_template("target")
    kwargs = dict(
        account=ACCOUNT, caller_arn=CALLER, stack_arn=APP_ARN,
        prior_template=prior, target_template=target,
        service_role_arn=SERVICE_ROLE, source_sha=SOURCE,
        start=1_900_000_000, end=1_900_000_300, token=TOKEN,
        clock=lambda: 1_900_000_001,
    )
    assert ClosedDevUpdate(clients, PlainFileJournal(tmp_path), **kwargs).run("update") == {
        "ok": True, "phase": "acknowledged"
    }
    _complete_readback(cfn)
    assert ClosedDevUpdate(clients, PlainFileJournal(tmp_path), **kwargs).run("readback") == {
        "ok": True, "phase": "accepted"
    }
