from __future__ import annotations

import contextlib
import copy
import json
import uuid
from types import SimpleNamespace

from scripts import aws_dev_oauth_setup_coordinator as coordinator_module
from scripts.aws_dev_oauth_setup_coordinator import OAuthSetupCoordinator


ACCOUNT = "123456789012"
RUN_ID = "11111111-1111-4111-8111-111111111111"
STACK_UUID = "22222222-2222-4222-8222-222222222222"
CONTROL_UUID = "33333333-3333-4333-8333-333333333333"
CALLBACK = "http://localhost:39031/callback"
APP_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev/{STACK_UUID}"
CONTROL_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-control/{CONTROL_UUID}"


class Journal:
    def __init__(self, state):
        self.state = copy.deepcopy(state)
        self.history = []

    @contextlib.contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)
        self.history.append(copy.deepcopy(state))


class Cloud:
    def __init__(self, journal):
        self.journal = journal
        self.updates = []
        self.fail_update = False

    def update_stack(self, **kwargs):
        assert self.journal.state.get("oauth_setup_controls_update_attempted") or self.journal.state.get("oauth_setup_update_attempted")
        self.updates.append(kwargs)
        if self.fail_update:
            raise RuntimeError("canary provider details")
        return {"StackId": kwargs["StackName"], "ResponseMetadata": {"HTTPStatusCode": 200}}


def _state(now):
    return {
        "schema": 1, "region": "eu-west-1", "account_id": ACCOUNT, "run_id": RUN_ID,
        "app_stack_id": APP_ARN, "stack_uuid": STACK_UUID, "control_stack_id": CONTROL_ARN,
        "api_id": "abcdefghij", "user_pool_id": "eu-west-1_Abcdefghi",
        "resource_started_epoch": now - 100,
        "authorized_until_epoch": now + 1200,
        "activation_start_epoch": now + 200,
        "controls_created_at_epoch": now - 50,
    }


def _response(**fields):
    return {**fields, "ResponseMetadata": {"HTTPStatusCode": 200}}


def test_stateful_five_step_flow_records_intent_and_never_replays_ambiguous_update(monkeypatch):
    now = 1_798_000_000
    journal = Journal(_state(now))
    cloud = Cloud(journal)
    baseline_control = OAuthSetupCoordinator._baseline_control_template(journal.state)
    setup_control = OAuthSetupCoordinator._setup_control_template(journal.state)
    cloud.get_template_response = _response(TemplateBody=baseline_control)

    coordinator = OAuthSetupCoordinator(
        {"cloudformation": cloud, "apigatewayv2": object(), "lambda": object(),
         "cognito": object(), "iam": object(), "scheduler": object()},
        journal, expected_account_id=ACCOUNT, callback_url=CALLBACK,
        authorized_until_epoch=now + 1200, wall_clock=lambda: now, monotonic=lambda: 10.0,
    )
    monkeypatch.setattr(coordinator, "_verify_bootstrap", lambda state: {"stack_arn": APP_ARN})
    monkeypatch.setattr(coordinator, "_describe_owned_stack", lambda **kwargs: {"StackStatus": "UPDATE_COMPLETE"})
    monkeypatch.setattr(coordinator, "_resource_map", lambda *args: {})
    monkeypatch.setattr(coordinator, "_verify_control_role_policy", lambda *args, **kwargs: None)
    monkeypatch.setattr(coordinator, "_verify_disabled_cleanup_schedule", lambda *args: None)
    monkeypatch.setattr(coordinator, "_verify_control_resources", lambda *args, **kwargs: {"StackStatus": "UPDATE_COMPLETE"})
    monkeypatch.setattr(coordinator, "_verify_setup_control_template", lambda *args: None)
    monkeypatch.setattr(coordinator, "_cleanup_schedule", lambda *args: {})
    monkeypatch.setattr(coordinator, "_step_check_bootstrap", lambda: {"step": "check-bootstrap", "ok": True, "category": "closed_bootstrap_verified", "calls": 0})
    monkeypatch.setattr(coordinator, "_step_check_controls", lambda: {"step": "check-controls", "ok": True, "category": "controls_and_cleanup_verified", "calls": 0})
    monkeypatch.setattr(coordinator_module, "check_oauth_setup_readback", lambda *args, **kwargs: SimpleNamespace(verified=True, category="oauth_setup_verified", client_id="syntheticclient123"))
    monkeypatch.setattr(cloud, "get_template", lambda **kwargs: cloud.get_template_response, raising=False)

    assert coordinator.run_step("check-bootstrap")["ok"] is True
    result = coordinator.run_step("update-controls")
    assert result["category"] == "controls_update_requested"
    assert journal.history[-1]["oauth_setup_controls_update_attempted"] is True
    assert "CleanupScheduleEnabledByCoordinator" in json.loads(cloud.updates[-1]["TemplateBody"])["Metadata"]
    assert coordinator.run_step("check-controls")["ok"] is True
    journal.state["oauth_setup_controls_verified"] = True

    # App update is attempted once; a lost/failed response is not replayed.
    cloud.fail_update = True
    failed = coordinator.run_step("update-oauth-setup")
    assert failed["category"] == "oauth_setup_update_ambiguous"
    assert journal.state["oauth_setup_update_attempted"] is True
    assert len(cloud.updates) == 2
    assert coordinator.run_step("update-oauth-setup")["category"] == "oauth_setup_update_already_attempted"
    assert len(cloud.updates) == 2
    assert coordinator.run_step("check-oauth-setup")["ok"] is True


def test_update_stack_request_is_bounded_and_uses_exact_dev_bindings(monkeypatch):
    now = 1_798_000_000
    initial = _state(now)
    initial.update({"oauth_setup_controls_update_attempted": True, "oauth_setup_controls_verified": True})
    journal = Journal(initial)
    cloud = Cloud(journal)
    coordinator = OAuthSetupCoordinator(
        {"cloudformation": cloud, "apigatewayv2": object(), "lambda": object(),
         "cognito": object(), "iam": object(), "scheduler": object()},
        journal, expected_account_id=ACCOUNT, callback_url=CALLBACK,
        authorized_until_epoch=now + 1200, wall_clock=lambda: now, monotonic=lambda: 10.0,
    )
    monkeypatch.setattr(coordinator, "_verify_bootstrap", lambda state: {})
    monkeypatch.setattr(coordinator, "_verify_control_resources", lambda *args, **kwargs: {"StackStatus": "UPDATE_COMPLETE"})
    monkeypatch.setattr(coordinator, "_verify_setup_control_template", lambda *args: None)
    monkeypatch.setattr(coordinator, "_verify_control_role_policy", lambda *args, **kwargs: None)
    monkeypatch.setattr(coordinator, "_cleanup_schedule", lambda *args: {})
    assert coordinator.run_step("update-oauth-setup")["ok"] is True
    request = cloud.updates[0]
    assert request["StackName"] == APP_ARN
    assert request["Parameters"] == [
        {"ParameterKey": "EnvironmentName", "ParameterValue": "dev"},
        {"ParameterKey": "McpResourceUri", "ParameterValue": "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp"},
        {"ParameterKey": "OAuthCallbackURL", "ParameterValue": CALLBACK},
    ]
    assert len(request["TemplateBody"].encode("ascii")) <= 51200
    assert "RoleARN" not in request
    botocore_session = __import__("pytest").importorskip("botocore.session")
    from botocore.validate import validate_parameters

    model = botocore_session.get_session().get_service_model("cloudformation")
    validate_parameters(request, model.operation_model("UpdateStack").input_shape)


def test_oauth_readback_expiring_authority_does_not_commit_client_binding(monkeypatch):
    now = 1_798_000_000
    state = _state(now)
    state.update({
        "oauth_setup_update_attempted": True,
        "oauth_setup_callback_url": CALLBACK,
    })
    journal = Journal(state)
    wall = [now]
    coordinator = OAuthSetupCoordinator(
        {"cloudformation": object(), "apigatewayv2": object(), "lambda": object(),
         "cognito": object(), "iam": object(), "scheduler": object()},
        journal, expected_account_id=ACCOUNT, callback_url=CALLBACK,
        authorized_until_epoch=now + 1200, wall_clock=lambda: wall[0], monotonic=lambda: 10.0,
    )

    def verified_but_late(*args, **kwargs):
        wall[0] = now + 1200
        return SimpleNamespace(verified=True, category="oauth_setup_verified", client_id="syntheticclient123")

    monkeypatch.setattr(coordinator_module, "check_oauth_setup_readback", verified_but_late)
    result = coordinator.run_step("check-oauth-setup")
    assert result["ok"] is False
    assert result["category"] == "authorization_or_resource_window_expired"
    assert "oauth_setup_client_id" not in journal.state
    assert "oauth_setup_verified" not in journal.state
