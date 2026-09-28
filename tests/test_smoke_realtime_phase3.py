from __future__ import annotations

from scripts.smoke_realtime_phase3 import perform_realtime_phase3_smoke


class _FakeService:
    def __init__(self, callback, *, emit: bool = True, stop_result: bool = True):
        self.callback = callback
        self.emit = emit
        self.stop_result = stop_result
        self.started = False

    def start(self):
        self.started = True
        if self.emit:
            self.callback(object())
        return True

    def stop(self):
        return self.stop_result


def test_smoke_success_only_after_observation_and_clean_stop():
    captured = {}

    def builder(*, on_state):
        captured["service"] = _FakeService(on_state)
        return captured["service"]

    result = perform_realtime_phase3_smoke(service_builder=builder, max_wait_seconds=0)

    assert result == {
        "success": True,
        "started": True,
        "observed_valid_state": True,
        "stopped_cleanly": True,
    }


def test_smoke_times_out_without_valid_state_and_still_stops():
    result = perform_realtime_phase3_smoke(
        service_builder=lambda *, on_state: _FakeService(on_state, emit=False),
        max_wait_seconds=0,
    )

    assert result == {
        "success": False,
        "started": True,
        "observed_valid_state": False,
        "stopped_cleanly": True,
        "category": "state_timeout",
    }


def test_smoke_fails_when_stop_is_not_clean():
    result = perform_realtime_phase3_smoke(
        service_builder=lambda *, on_state: _FakeService(on_state, stop_result=False),
        max_wait_seconds=0,
    )

    assert result["success"] is False
    assert result["started"] is True
    assert result["observed_valid_state"] is True
    assert result["stopped_cleanly"] is False
    assert result["category"] == "shutdown_timeout"


def test_smoke_redacts_factory_error_and_never_reads_service_data():
    def builder(*, on_state):
        raise RuntimeError("secret-id coordinates token")

    result = perform_realtime_phase3_smoke(service_builder=builder)

    assert result == {
        "success": False,
        "started": False,
        "observed_valid_state": False,
        "stopped_cleanly": False,
        "category": "factory_failed",
    }
    assert "secret" not in str(result)


def test_smoke_redacts_unallowlisted_realtime_category():
    class BrokenService:
        def start(self):
            from mapit.realtime import RealtimeError

            raise RealtimeError("secret-token-category")

        def stop(self):
            return True

    result = perform_realtime_phase3_smoke(
        service_builder=lambda *, on_state: BrokenService(),
        max_wait_seconds=0,
    )

    assert result["success"] is False
    assert result["category"] == "service_failed"
    assert "secret" not in str(result)
