import json

from mapit.telegram_bot import TelegramPollResult
from scripts.run_telegram_once import main, run_bounded_cycles


class FakePoller:
    def __init__(self, results):
        self.results = list(results)
        self.calls = 0

    def poll_once(self):
        self.calls += 1
        return self.results.pop(0)


def test_bounded_cycles_process_onboarding_then_query_and_stop_on_send():
    poller = FakePoller(
        [
            TelegramPollResult(True, "success", update_processed=True, message_sent=False),
            TelegramPollResult(True, "success", update_processed=True, message_sent=True),
        ]
    )
    result = run_bounded_cycles(poller)
    assert result == {
        "success": True,
        "category": "success",
        "cycles": 2,
        "update_processed": True,
        "message_sent": True,
    }
    assert poller.calls == 2


def test_bounded_cycles_keeps_same_poller_after_empty_first_cycle():
    poller = FakePoller(
        [
            TelegramPollResult(True, "success"),
            TelegramPollResult(True, "success", update_processed=True, message_sent=True),
        ]
    )
    result = run_bounded_cycles(poller)
    assert result["success"] is True and result["cycles"] == 2
    assert poller.calls == 2


def test_bounded_cycles_stops_on_safe_error_without_retry():
    poller = FakePoller([TelegramPollResult(False, "transport_failed", update_processed=False)])
    assert run_bounded_cycles(poller) == {
        "success": False,
        "category": "transport_failed",
        "cycles": 1,
        "update_processed": False,
        "message_sent": False,
    }
    assert poller.calls == 1


def test_send_flag_on_failed_cycle_does_not_fake_success():
    result = run_bounded_cycles(FakePoller([TelegramPollResult(False, "send_failed", True, True)]))
    assert result["success"] is False
    assert result["category"] == "send_failed"
    assert result["message_sent"] is True


def test_unknown_error_category_is_redacted():
    result = run_bounded_cycles(FakePoller([TelegramPollResult(False, "secret-token-url", True, False)]))
    assert result["category"] == "poll_failed"
    assert "secret" not in json.dumps(result)


def test_cli_requires_all_explicit_flags_without_constructing_dependencies(capsys):
    calls = []
    result = main(
        [],
        store_factory=lambda: calls.append("store"),
        backend_factory=lambda: calls.append("backend"),
        poller_factory=lambda *_: calls.append("poller"),
    )
    assert result == 1
    assert calls == []
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "success": False,
        "category": "confirmation_required",
        "cycles": 0,
        "update_processed": False,
        "message_sent": False,
    }
