from __future__ import annotations

import json

import pytest

from mapit.aws_dev_activation import _tripwire_is_armed, activate_synthetic_dev_window
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy

ACCOUNT = "123456789012"
API_ID = "a1b2c3d4e5"
START = 1_800_000_000
END = START + 300
RESOURCE_STARTED = START - 2_000
STACK_UUID = "12345678-1234-4234-8234-123456789abc"
APP_STACK_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev/{STACK_UUID}"
SM_ARN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-shutdown"
META = {"ResponseMetadata": {"HTTPStatusCode": 200}}


class FakeClient:
    def __init__(self, methods):
        self.methods = methods
        self.calls = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def invoke(**kwargs):
            self.calls.append((name, kwargs))
            value = self.methods[name]
            if isinstance(value, BaseException):
                raise value
            return value(**kwargs) if callable(value) else value

        return invoke


class Clock:
    def __init__(self, wall=START, mono=10.0):
        self.wall = wall
        self.mono = mono

    def wall_now(self):
        return self.wall

    def mono_now(self):
        return self.mono


def _schedule(*, name, group, at, target_arn, role_arn, input_value="{}"):
    return {
        **META,
        "Arn": f"arn:aws:scheduler:eu-west-1:{ACCOUNT}:schedule/{group}/{name}",
        "Name": name,
        "GroupName": group,
        "State": "ENABLED",
        "ScheduleExpression": f"at({at})",
        "ScheduleExpressionTimezone": "UTC",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {
            "Arn": target_arn,
            "RoleArn": role_arn,
            "Input": input_value,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        },
    }


def _clients(*, api=None, capacity=10, stage_rate=1, shutdown=None, cleanup=None, rule_state="ENABLED", alarm=True):
    api_state = {"closed": True}
    function_state = {"reserved": 0}

    def get_api(**_kwargs):
        return {**META, "ApiId": API_ID, "Name": "honda-mapit-mcp-dev-api", "DisableExecuteApiEndpoint": api_state["closed"]}

    def update_api(**kwargs):
        if kwargs == {"ApiId": API_ID, "DisableExecuteApiEndpoint": False}:
            api_state["closed"] = False
        elif kwargs == {"ApiId": API_ID, "DisableExecuteApiEndpoint": True}:
            api_state["closed"] = True
        else:
            raise AssertionError("unexpected API update")
        return {**META, "ApiId": API_ID, "DisableExecuteApiEndpoint": api_state["closed"]}

    def get_concurrency(**_kwargs):
        val = function_state["reserved"]
        response = dict(META)
        if val is not None:
            response["ReservedConcurrentExecutions"] = val
        return response

    def delete_concurrency(**_kwargs):
        function_state["reserved"] = None
        return dict(META)

    def put_concurrency(**kwargs):
        assert kwargs == {"FunctionName": "honda-mapit-mcp-dev-handler", "ReservedConcurrentExecutions": 0}
        function_state["reserved"] = 0
        return {**META, "ReservedConcurrentExecutions": 0}

    settings = {**META, "AccountLimit": {"ConcurrentExecutions": 10, "UnreservedConcurrentExecutions": capacity}}
    shutdown_at = _epoch_iso(END - 120)
    cleanup_at = _epoch_iso(RESOURCE_STARTED + 2700)
    shutdown_value = shutdown or _schedule(
        name="honda-mapit-mcp-dev-close-once",
        group="honda-mapit-mcp-dev-safety",
        at=shutdown_at,
        target_arn=SM_ARN,
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-shutdown-scheduler",
    )
    cleanup_value = cleanup or _schedule(
        name="honda-mapit-mcp-dev-bootstrap-delete-once",
        group="honda-mapit-mcp-dev-bootstrap-cleanup",
        at=cleanup_at,
        target_arn="arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack",
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-bootstrap-cleanup-scheduler",
        input_value=json.dumps({
            "StackName": APP_STACK_ARN,
            "RoleARN": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-bootstrap-delete",
        }, separators=(",", ":")),
    )
    events = FakeClient({
        "describe_rule": {
            **META,
            "Name": "honda-mapit-mcp-dev-request-tripwire-alarm-rule",
            "Arn": f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/honda-mapit-mcp-dev-request-tripwire-alarm-rule",
            "State": rule_state,
            "EventPattern": json.dumps({
                "source": ["aws.cloudwatch"],
                "detail-type": ["CloudWatch Alarm State Change"],
                "account": [ACCOUNT],
                "region": ["eu-west-1"],
                "resources": [f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-dev-request-tripwire"],
                "detail": {"alarmName": ["honda-mapit-mcp-dev-request-tripwire"], "state": {"value": ["ALARM"]}},
            }, separators=(",", ":")),
        },
        "list_targets_by_rule": {
            **META,
            "Targets": [{
                "Id": "StartFixedDevShutdownWorkflow",
                "Arn": SM_ARN,
                "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-request-tripwire",
                "Input": "{}",
                "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
            }],
        },
    })
    return {
        "apigatewayv2": FakeClient({
            "get_api": get_api,
            "get_stage": {**META, "StageName": "$default", "DefaultRouteSettings": {"ThrottlingBurstLimit": 1, "ThrottlingRateLimit": stage_rate}, "RouteSettings": {}},
            "update_api": update_api,
        }),
        "lambda": FakeClient({
            "get_function_concurrency": get_concurrency,
            "delete_function_concurrency": delete_concurrency,
            "put_function_concurrency": put_concurrency,
            "get_account_settings": settings,
        }),
        "scheduler": FakeClient({"get_schedule": lambda Name, GroupName: shutdown_value if "safety" in GroupName else cleanup_value}),
        "stepfunctions": FakeClient({"describe_state_machine": {**META, "stateMachineArn": SM_ARN, "name": "honda-mapit-mcp-dev-shutdown", "roleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-shutdown-workflow", "status": "ACTIVE"}}),
        "cloudwatch": FakeClient({"describe_alarms": {**META, "MetricAlarms": [{
            "AlarmName": "honda-mapit-mcp-dev-request-tripwire",
            "Namespace": "AWS/ApiGateway", "MetricName": "Count",
            "Dimensions": [{"Name": "ApiId", "Value": API_ID}, {"Name": "Stage", "Value": "$default"}],
            "Period": 60, "Statistic": "SampleCount", "Threshold": 100,
            "ComparisonOperator": "GreaterThanOrEqualToThreshold", "EvaluationPeriods": 1,
            "DatapointsToAlarm": 1, "TreatMissingData": "notBreaching", "ActionsEnabled": False,
        }] if alarm else []}}),
        "events": events,
    }


def _epoch_iso(epoch):
    from datetime import datetime, timezone
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _evidence(**overrides):
    value = {
        "private_journal_verified": True,
        "runtime_readback_verified": True,
        "control_readback_verified": True,
        "oauth_setup_verified": True,
        "account_id": ACCOUNT,
        "api_id": API_ID,
        "app_stack_arn": APP_STACK_ARN,
        "runtime_start_epoch": START,
        "runtime_end_epoch": END,
        "resource_started_epoch": RESOURCE_STARTED,
    }
    value.update(overrides)
    return value


def _run(clients=None, *, evidence=None, callback=None, clock=None):
    clients = clients or _clients()
    clock = clock or Clock()
    intents = []
    result = activate_synthetic_dev_window(
        clients,
        policy=AwsDevShutdownPolicy(API_ID),
        evidence=_evidence() if evidence is None else evidence,
        smoke_callback=callback or (lambda deadline: {"success": True, "category": "success", "tool_call_count": 2}),
        record_intent=intents.append,
        wall_clock=clock.wall_now,
        monotonic=clock.mono_now,
    )
    return result, clients, intents, clock


def test_success_checks_all_gates_removes_reservation_enables_once_smokes_then_closes():
    deadlines = []
    result, clients, intents, clock = _run(
        callback=lambda deadline: (
            deadlines.append(deadline)
            or {"success": True, "category": "success", "tool_call_count": 2}
        )
    )
    assert result.safe_projection() == {
        "success": True,
        "category": "activation_and_shutdown_verified",
        "calls": result.calls,
        "reservation_removed": True,
        "api_enabled": True,
        "smoke_verified": True,
        "endpoint_closed": True,
        "function_reserved_zero": True,
    }
    assert result.calls == sum(len(client.calls) for client in clients.values())
    assert deadlines == [10 + (END - START)]
    assert intents == ["remove_reserved_concurrency", "enable_api_endpoint"]
    api_writes = [kwargs for name, kwargs in clients["apigatewayv2"].calls if name == "update_api"]
    assert api_writes == [
        {"ApiId": API_ID, "DisableExecuteApiEndpoint": False},
        {"ApiId": API_ID, "DisableExecuteApiEndpoint": True},
    ]
    lambda_writes = [name for name, _ in clients["lambda"].calls if name in {"delete_function_concurrency", "put_function_concurrency"}]
    assert lambda_writes == ["delete_function_concurrency", "put_function_concurrency"]


@pytest.mark.parametrize("change,category", [
    ({"capacity": 9}, "capacity_not_10"),
    ({"stage_rate": 2}, "stage_throttle_mismatch"),
    ({"rule_state": "DISABLED"}, "tripwire_not_armed"),
    ({"alarm": False}, "tripwire_not_armed"),
])
def test_failed_preflight_never_enables_but_always_runs_close_core(change, category):
    clients = _clients(**change)
    result, clients, _intents, _clock = _run(clients)
    assert result.category == category
    assert result.api_enabled is False
    assert result.endpoint_closed is True and result.function_reserved_zero is True
    assert not any(name == "delete_function_concurrency" for name, _ in clients["lambda"].calls)
    assert [kwargs["DisableExecuteApiEndpoint"] for name, kwargs in clients["apigatewayv2"].calls if name == "update_api"] == [True]


def test_schedule_drift_fails_closed_before_any_activation_write():
    schedule = _schedule(
        name="honda-mapit-mcp-dev-close-once", group="honda-mapit-mcp-dev-safety",
        at=_epoch_iso(END - 120), target_arn="arn:aws:states:eu-west-1:123456789012:stateMachine:other",
        role_arn=f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-shutdown-scheduler",
    )
    clients = _clients(shutdown=schedule)
    result, clients, _intents, _clock = _run(clients)
    assert result.category == "shutdown_schedule_mismatch"
    assert not any(name == "delete_function_concurrency" for name, _ in clients["lambda"].calls)
    assert [kwargs["DisableExecuteApiEndpoint"] for name, kwargs in clients["apigatewayv2"].calls if name == "update_api"] == [True]


def test_disabled_tripwire_precheck_requires_exact_disabled_rule_and_target():
    clients = _clients(rule_state="DISABLED")

    def read(service, method, **kwargs):
        return getattr(clients[service], method)(**kwargs)

    args = {
        "account": ACCOUNT,
        "state_machine_arn": SM_ARN,
        "api_id": API_ID,
        "call": read,
    }
    assert _tripwire_is_armed(clients, **args, expected_state="DISABLED") is True
    assert _tripwire_is_armed(clients, **args) is False
    assert _tripwire_is_armed(clients, **args, expected_state="disabled") is False

    events = clients["events"].methods
    events["describe_rule"]["EventPattern"] = "{}"
    assert _tripwire_is_armed(clients, **args, expected_state="DISABLED") is False
    events["describe_rule"]["EventPattern"] = json.dumps({
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "account": [ACCOUNT],
        "region": ["eu-west-1"],
        "resources": [f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-dev-request-tripwire"],
        "detail": {"alarmName": ["honda-mapit-mcp-dev-request-tripwire"], "state": {"value": ["ALARM"]}},
    })
    events["list_targets_by_rule"]["Targets"][0]["Arn"] = "arn:aws:states:eu-west-1:999999999999:stateMachine:wrong"
    assert _tripwire_is_armed(clients, **args, expected_state="DISABLED") is False


def test_service_quota_if_supplied_must_be_ten_and_is_never_retried():
    clients = _clients()
    quota = FakeClient({"get_service_quota": {**META, "Quota": {"Value": 20}}})
    clients["servicequotas"] = quota
    result, clients, _intents, _clock = _run(clients)
    assert result.category == "service_quota_not_10"
    assert len(quota.calls) == 1
    assert not any(name == "delete_function_concurrency" for name, _ in clients["lambda"].calls)


def test_smoke_exception_still_closes_endpoint_and_restores_zero_reservation():
    clients = _clients()
    def callback(_deadline):
        raise RuntimeError("private canary")
    result, clients, _intents, _clock = _run(clients, callback=callback)
    assert result.category == "activation_failed"
    assert result.api_enabled is True
    assert result.endpoint_closed is True and result.function_reserved_zero is True
    assert "canary" not in str(result.safe_projection())


def test_late_or_rolled_back_clock_aborts_smoke_and_always_shuts_down():
    clients = _clients()
    clock = Clock()
    def callback(deadline):
        assert deadline <= clock.mono + (END - clock.wall)
        clock.wall = END
        clock.mono += 1
        return {"success": True, "category": "success", "tool_call_count": 2}
    result, clients, _intents, _clock = _run(clients, callback=callback, clock=clock)
    assert result.category == "smoke_deadline_exceeded"
    assert result.smoke_verified is False
    assert result.endpoint_closed is True and result.function_reserved_zero is True


def test_invalid_evidence_skips_activation_and_still_attempts_fixed_shutdown():
    clients = _clients()
    result, clients, _intents, _clock = _run(clients, evidence=_evidence(runtime_readback_verified=1))
    assert result.category == "prerequisite_unverified"
    assert result.endpoint_closed is True and result.function_reserved_zero is True
    assert not any(name == "delete_function_concurrency" for name, _ in clients["lambda"].calls)


def test_clock_failure_is_sanitized_and_still_runs_fixed_shutdown():
    clients = _clients()

    def broken_clock():
        raise RuntimeError("clock canary")

    result = activate_synthetic_dev_window(
        clients,
        policy=AwsDevShutdownPolicy(API_ID),
        evidence=_evidence(),
        smoke_callback=lambda _deadline: {"success": True, "category": "success", "tool_call_count": 2},
        record_intent=lambda _step: None,
        wall_clock=lambda: START,
        monotonic=broken_clock,
    )
    assert result.category == "activation_failed"
    assert result.endpoint_closed is True and result.function_reserved_zero is True
    assert not any(name == "delete_function_concurrency" for name, _ in clients["lambda"].calls)
    assert "canary" not in str(result.safe_projection())
