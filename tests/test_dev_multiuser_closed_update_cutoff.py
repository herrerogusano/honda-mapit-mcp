"""Do not dispatch a closed update if persisting intent crosses the cutoff."""
import pytest

from scripts.dev_multiuser_closed_update import ClosedUpdateError
from tests.test_dev_multiuser_closed_update import Journal, _core


def test_intent_save_crossing_exclusive_cutoff_fences_update_and_replay():
    now = [1900000001]

    class DelayedIntentJournal(Journal):
        def save(self, state):
            super().save(state)
            if state["phase"] == "intent":
                now[0] = 1900000300

    journal = DelayedIntentJournal()
    core, cfn, _ = _core(journal=journal, clock=lambda: now[0])
    assert core.run("preflight")["phase"] == "ready"
    with pytest.raises(ClosedUpdateError, match="window_closed"):
        core.run("update")
    assert cfn.update_calls == []
    assert journal.load()["phase"] == "intent"
    now[0] = 1900000001
    with pytest.raises(ClosedUpdateError, match="write_fenced"):
        core.run("update")
    assert cfn.update_calls == []
