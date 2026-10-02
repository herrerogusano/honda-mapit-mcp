from __future__ import annotations

import copy
from types import SimpleNamespace

import pytest

from scripts import aws_dev_oauth_setup_coordinator as coordinator_module
from scripts.aws_dev_oauth_setup_coordinator import OAuthSetupCoordinator
from test_aws_dev_oauth_setup_coordinator import (
    ACCOUNT, APP_ARN, CALLBACK, CONTROL_ARN, Journal, _state, _response,
)


class Cloud:
    def __init__(self, journal, *, fail=False):
        self.journal = journal
        self.fail = fail
        self.update_calls = []
        self.template = None

    def get_template(self, **kwargs):
        return _response(TemplateBody=self.template)

    def update_stack(self, **kwargs):
        assert self.journal.state.get("oauth_setup_controls_update_attempted") is True
        assert self.journal.state.get("oauth_setup_controls_update_token") == kwargs.get("ClientRequestToken")
        self.update_calls.append(kwargs)
        if self.fail:
            raise RuntimeError("synthetic ambiguous write")
        return _response(StackId=kwargs["StackName"])


def _coordinator(journal, cloud, *, monotonic=lambda: 10.0, scheduler=None):
    clients = {
        "cloudformation": cloud, "apigatewayv2": object(), "lambda": object(),
        "cognito": object(), "iam": object(), "scheduler": scheduler or object(),
    }
    now = journal.state["resource_started_epoch"] + 100
    return OAuthSetupCoordinator(
        clients, journal, expected_account_id=ACCOUNT, callback_url=CALLBACK,
        authorized_until_epoch=now + 1200, wall_clock=lambda: now, monotonic=monotonic,
    )


def _bypass_readbacks(coordinator, monkeypatch):
    monkeypatch.setattr(coordinator, "_verify_bootstrap", lambda _state: {})
    monkeypatch.setattr(coordinator, "_describe_owned_stack", lambda **_kwargs: {"StackStatus": "UPDATE_COMPLETE"})
    monkeypatch.setattr(coordinator, "_resource_map", lambda *_args: {})
    monkeypatch.setattr(coordinator, "_verify_control_role_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(coordinator, "_verify_disabled_cleanup_schedule", lambda *_args: None)


@pytest.mark.parametrize("fail", [False, True])
def test_control_update_persists_single_attempt_token_before_dispatch(monkeypatch, fail):
    now = 1_798_000_000
    journal = Journal(_state(now))
    cloud = Cloud(journal, fail=fail)
    cloud.template = OAuthSetupCoordinator._baseline_control_template(journal.state)
    coordinator = _coordinator(journal, cloud)
    _bypass_readbacks(coordinator, monkeypatch)

    result = coordinator.run_step("update-controls")
    assert len(cloud.update_calls) == 1
    sent = cloud.update_calls[0]
    persisted = journal.history[-2] if fail else journal.history[-2]
    assert persisted["oauth_setup_controls_update_attempted"] is True
    assert sent["ClientRequestToken"] == persisted["oauth_setup_controls_update_token"]
    assert sent["StackName"] == CONTROL_ARN
    if fail:
        assert result["category"] == "controls_update_ambiguous"
        again = coordinator.run_step("update-controls")
        assert again["category"] == "controls_update_already_attempted"
        assert len(cloud.update_calls) == 1
    else:
        assert result["category"] == "controls_update_requested"


def test_wrong_immutable_stack_uuid_is_rejected_before_any_provider_call():
    now = 1_798_000_000
    state = _state(now)
    state["stack_uuid"] = "99999999-9999-4999-8999-999999999999"
    journal = Journal(state)
    cloud = Cloud(journal)
    coordinator = _coordinator(journal, cloud)

    result = coordinator.run_step("check-bootstrap")

    assert result["category"] == "app_stack_uuid_mismatch"
    assert result["calls"] == 0
    assert not cloud.update_calls


def test_wrong_cleanup_timer_or_role_is_rejected_without_mutation():
    now = 1_798_000_000
    journal = Journal(_state(now))
    schedule = journal.state["resource_started_epoch"] + 2700
    from datetime import datetime, timezone

    at = datetime.fromtimestamp(schedule, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    class Scheduler:
        def get_schedule(self, **_kwargs):
            return _response(**{
                "Arn": f"arn:aws:scheduler:eu-west-1:{ACCOUNT}:schedule/{coordinator_module.CLEANUP_GROUP}/{coordinator_module.CLEANUP_SCHEDULE}",
                "Name": coordinator_module.CLEANUP_SCHEDULE,
                "GroupName": coordinator_module.CLEANUP_GROUP,
                "State": "ENABLED", "ScheduleExpression": f"at({at})",
                "ScheduleExpressionTimezone": "UTC", "FlexibleTimeWindow": {"Mode": "OFF"},
                "Target": {
                    "Arn": coordinator_module.CLEANUP_TARGET,
                    "RoleArn": "arn:aws:iam::123456789012:role/wrong-role",
                    "Input": "{}",
                    "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
                },
            })

    coordinator = _coordinator(journal, Cloud(journal), monotonic=lambda: 1.0, scheduler=Scheduler())
    coordinator._step_started = 0.0

    with pytest.raises(coordinator_module._FlowError, match="cleanup_schedule_target_invalid"):
        coordinator._cleanup_schedule(journal.state, now)


def test_late_successful_readback_does_not_commit_client_id(monkeypatch):
    now = 1_798_000_000
    state = _state(now)
    state["oauth_setup_update_attempted"] = True
    state["oauth_setup_callback_url"] = CALLBACK
    journal = Journal(state)
    cloud = Cloud(journal)
    ticks = iter([10.0, 41.0])
    coordinator = _coordinator(journal, cloud, monotonic=lambda: next(ticks))
    monkeypatch.setattr(coordinator_module, "check_oauth_setup_readback", lambda *_a, **_k: SimpleNamespace(
        verified=True, category="oauth_setup_verified", client_id="SyntheticClient123",
    ))

    result = coordinator.run_step("check-oauth-setup")

    assert result["category"] == "step_budget_exhausted"
    assert "oauth_setup_verified" not in journal.state
    assert "oauth_setup_client_id" not in journal.state
