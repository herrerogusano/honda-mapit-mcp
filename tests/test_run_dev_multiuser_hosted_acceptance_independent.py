from __future__ import annotations

from scripts.run_dev_multiuser_hosted_acceptance import _poll_update


def test_poll_update_does_not_treat_write_acknowledgement_as_completion():
    calls = []
    replies = iter((
        {"success": True, "category": "update_acknowledged"},
        {"success": True, "category": "readback_verified"},
    ))

    assert _poll_update(
        lambda step: calls.append(step) or next(replies),
        sleep=lambda _seconds: None,
        clock=lambda: 0,
        deadline=100,
    ) is True
    assert calls == ["request-update", "check-update"]


def test_poll_update_does_not_dispatch_after_deadline():
    calls = []

    assert _poll_update(
        lambda step: calls.append(step) or {"success": True, "category": "readback_verified"},
        sleep=lambda _seconds: None,
        clock=lambda: 100,
        deadline=100,
    ) is False
    assert calls == []
