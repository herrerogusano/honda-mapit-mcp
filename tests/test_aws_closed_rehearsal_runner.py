from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from scripts.run_aws_closed_rehearsal import (
    APP_STACK_NAME,
    CONTROL_ROLE_NAMES,
    SCHEDULE_GROUP_NAMES,
    SCHEDULE_NAMES,
    STATE_MACHINE_NAME,
    AwsClosedRehearsal,
    FileJournal,
    MemoryJournal,
    RehearsalError,
    _is_reparse_or_symlink,
    _json_bytes,
)

ACCOUNT = "123456789012"
APP_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{APP_STACK_NAME}/12345678-1234-4234-8234-123456789abc"
CONTROL_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-control/12345678-1234-4234-8234-123456789abd"


class AwsError(Exception):
    def __init__(self, code: str = "ResourceNotFoundException", message: str = "not found"):
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeClient:
    def __init__(self, methods: dict[str, Any] | None = None):
        self.methods = methods or {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)

        def invoke(**kwargs):
            self.calls.append((name, kwargs))
            if name not in self.methods:
                raise AwsError()
            result = self.methods[name]
            if isinstance(result, BaseException):
                raise result
            return result(**kwargs) if callable(result) else result

        return invoke


def make_clients() -> dict[str, FakeClient]:
    return {
        "sts": FakeClient({"get_caller_identity": {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator"}}),
        "cloudformation": FakeClient({
            "describe_stacks": AwsError("ValidationError", "Stack with id does not exist"),
            "create_stack": {"StackId": APP_ARN},
        }),
        "lambda": FakeClient({"get_account_settings": {"AccountLimit": {"ConcurrentExecutions": 10, "UnreservedConcurrentExecutions": 10}}}),
        "apigatewayv2": FakeClient({"get_apis": {"Items": []}}),
        "cognito": FakeClient({"list_user_pools": {"UserPools": []}}),
        "iam": FakeClient({"get_role": AwsError()}),
        "logs": FakeClient({"describe_log_groups": {"logGroups": []}}),
        "scheduler": FakeClient({"get_schedule_group": AwsError(), "get_schedule": AwsError()}),
        "events": FakeClient({"describe_rule": AwsError()}),
        "cloudwatch": FakeClient({"describe_alarms": {"MetricAlarms": []}}),
        "stepfunctions": FakeClient({"describe_state_machine": AwsError()}),
    }


def runner(clients=None, journal=None, *, until=2_000_000_000, now=1_900_000_000):
    return AwsClosedRehearsal(
        clients or make_clients(), journal or MemoryJournal(), ACCOUNT,
        authorized_until_epoch=until, wall_clock=lambda: now,
    )


def test_preflight_uses_real_shapes_and_checks_fixed_control_names():
    clients = make_clients()
    journal = MemoryJournal()
    result = runner(clients, journal).run_step("preflight")
    assert result == {
        "step": "preflight", "ok": True, "category": "preflight_passed",
        "calls": result["calls"], "stacks_absent": 2, "named_resources_absent": 17,
    }
    assert len([call for call in clients["iam"].calls if call[1]["RoleName"] in CONTROL_ROLE_NAMES]) == 5
    sm_calls = [call for call in clients["stepfunctions"].calls if call[0] == "describe_state_machine"]
    assert sm_calls == [("describe_state_machine", {
        "stateMachineArn": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-shutdown"
    })]
    assert journal.load()["schema"] == 1


@pytest.mark.parametrize("bad", [None, {}, {"logGroups": None}, {"logGroups": [] , "nextToken": "more"}])
def test_preflight_fails_closed_on_malformed_or_paginated_inventory(bad):
    clients = make_clients()
    clients["logs"].methods["describe_log_groups"] = bad
    journal = MemoryJournal()
    result = runner(clients, journal).run_step("preflight")
    assert not result["ok"]
    assert journal.load() is None


def test_preflight_reads_unreserved_capacity_from_account_limit():
    clients = make_clients()
    clients["lambda"].methods["get_account_settings"] = {
        "AccountLimit": {"ConcurrentExecutions": 10},
        "AccountUsage": {"UnreservedConcurrentExecutions": 10},
    }
    result = runner(clients).run_step("preflight")
    assert result["category"] == "capacity_preflight_failed"


def test_file_journal_can_create_new_state_file_in_precreated_private_dir(tmp_path: Path):
    journal = FileJournal(tmp_path)
    assert not _is_reparse_or_symlink(journal.path)
    with journal.locked():
        journal.save({"schema": 1, "region": "eu-west-1"})
        assert journal.load() == {"schema": 1, "region": "eu-west-1"}


def test_create_app_persists_intent_before_one_write_and_uses_named_iam():
    clients = make_clients()
    journal = MemoryJournal()

    def create_stack(**kwargs):
        state = journal.load()
        assert state["app_create_attempted"] is True
        assert state["resource_started_epoch"] == 1_900_000_000
        assert kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
        assert kwargs["OnFailure"] == "DO_NOTHING"
        assert kwargs["Tags"][0]["Value"] == state["run_id"]
        return {"StackId": APP_ARN}

    clients["cloudformation"].methods["create_stack"] = create_stack
    subject = runner(clients, journal)
    assert subject.run_step("preflight")["ok"]
    created = subject.run_step("create-app")
    assert created["category"] == "app_create_requested"
    assert journal.load()["app_stack_id"] == APP_ARN
    assert len([c for c in clients["cloudformation"].calls if c[0] == "create_stack"]) == 1
    assert subject.run_step("create-app")["category"] == "write_already_attempted"
    assert len([c for c in clients["cloudformation"].calls if c[0] == "create_stack"]) == 1


def test_new_resource_write_denied_after_authorization_window_without_dispatch():
    clients = make_clients()
    journal = MemoryJournal()
    subject = runner(clients, journal, until=1_900_000_000, now=1_900_000_000)
    assert subject.run_step("preflight")["ok"]
    result = subject.run_step("create-app")
    assert result["category"] == "authorization_window_expired"
    assert not any(name == "create_stack" for name, _ in clients["cloudformation"].calls)
    assert journal.load()["app_create_attempted"] is False


def test_reinvocation_cannot_extend_deadline_recorded_at_preflight():
    clients = make_clients()
    journal = MemoryJournal()
    first = runner(clients, journal, until=1_900_000_010, now=1_900_000_000)
    assert first.run_step("preflight")["ok"]
    later = runner(clients, journal, until=2_000_000_000, now=1_900_000_010)
    result = later.run_step("create-app")
    assert result["category"] == "authorization_window_expired"
    assert not any(name == "create_stack" for name, _ in clients["cloudformation"].calls)


@pytest.mark.parametrize("arn", ["", "arn:aws:iam::123456789012:root", "not-an-arn"])
def test_identity_requires_a_nonroot_aws_principal_arn(arn):
    clients = make_clients()
    clients["sts"].methods["get_caller_identity"] = {"Account": ACCOUNT, "Arn": arn}
    result = runner(clients).run_step("preflight")
    assert result["category"] == "root_identity_rejected"
    assert not any(name == "create_stack" for name, _ in clients["cloudformation"].calls)


def test_describe_stacks_malformed_response_is_not_treated_as_absence():
    clients = make_clients()
    clients["cloudformation"].methods["describe_stacks"] = {}
    result = runner(clients).run_step("preflight")
    assert result["category"] == "stack_inventory_invalid"


def test_fallback_delete_requires_run_owned_closed_partial_stack_and_saves_intent():
    journal = MemoryJournal()
    journal.save({
        "schema": 1, "region": "eu-west-1", "account_id": ACCOUNT,
        "run_id": "run-1", "app_client_token": "token-1", "app_create_attempted": True,
        "app_stack_id": APP_ARN, "app_verified": False,
    })
    clients = make_clients()
    clients["cloudformation"].methods.update({
        "describe_stacks": {"Stacks": [{"StackId": APP_ARN, "StackName": APP_STACK_NAME,
                                           "Tags": [{"Key": "ClosedRehearsalRunId", "Value": "run-1"}]}]},
        "describe_stack_resources": {"StackResources": [
            {"LogicalResourceId": "McpApi", "PhysicalResourceId": "abc123def4"},
            {"LogicalResourceId": "McpHandler", "PhysicalResourceId": "honda-mapit-mcp-dev-handler"},
        ]},
        "delete_stack": lambda **kw: (journal.load()["app_delete_attempted"] is True) or {},
    })
    clients["apigatewayv2"].methods["get_api"] = {"DisableExecuteApiEndpoint": True}
    clients["lambda"].methods["get_function_concurrency"] = {"ReservedConcurrentExecutions": 0}
    result = runner(clients, journal).run_step("fallback-delete-app")
    assert result["category"] == "app_delete_requested"
    assert journal.load()["app_delete_attempted"] is True
    call = [c for c in clients["cloudformation"].calls if c[0] == "delete_stack"]
    assert len(call) == 1 and call[0][1] == {"StackName": APP_ARN}


def test_fallback_delete_rejects_unowned_stack_before_delete():
    journal = MemoryJournal()
    journal.save({"schema": 1, "region": "eu-west-1", "account_id": ACCOUNT,
                  "run_id": "run-1", "app_client_token": "token-1", "app_create_attempted": True,
                  "app_stack_id": APP_ARN})
    clients = make_clients()
    clients["cloudformation"].methods["describe_stacks"] = {"Stacks": [{
        "StackId": APP_ARN, "StackName": APP_STACK_NAME, "Tags": []
    }]}
    result = runner(clients, journal).run_step("fallback-delete-app")
    assert result["category"] == "stack_ownership_unverified"
    assert not any(name == "delete_stack" for name, _ in clients["cloudformation"].calls)


@pytest.mark.parametrize("api_physical,function_physical", [(None, None), ("", "")])
def test_fallback_delete_accepts_partial_resources_without_physical_ids(api_physical, function_physical):
    journal = MemoryJournal()
    journal.save({"schema": 1, "region": "eu-west-1", "account_id": ACCOUNT,
                  "run_id": "run-1", "app_client_token": "token-1", "app_create_attempted": True,
                  "app_stack_id": APP_ARN})
    clients = make_clients()
    clients["cloudformation"].methods.update({
        "describe_stacks": {"Stacks": [{"StackId": APP_ARN, "StackName": APP_STACK_NAME,
                                           "Tags": [{"Key": "ClosedRehearsalRunId", "Value": "run-1"}]}]},
        "describe_stack_resources": {"StackResources": [
            {"LogicalResourceId": "McpApi", "PhysicalResourceId": api_physical},
            {"LogicalResourceId": "McpHandler", "PhysicalResourceId": function_physical},
        ]},
        "delete_stack": {},
    })
    result = runner(clients, journal).run_step("fallback-delete-app")
    assert result["category"] == "app_delete_requested"
    assert not clients["apigatewayv2"].calls
    assert not any(name == "get_function_concurrency" for name, _ in clients["lambda"].calls)


def test_fallback_delete_treats_confirmed_missing_partial_resource_as_absent():
    journal = MemoryJournal()
    journal.save({"schema": 1, "region": "eu-west-1", "account_id": ACCOUNT,
                  "run_id": "run-1", "app_client_token": "token-1", "app_create_attempted": True,
                  "app_stack_id": APP_ARN})
    clients = make_clients()
    clients["cloudformation"].methods.update({
        "describe_stacks": {"Stacks": [{"StackId": APP_ARN, "StackName": APP_STACK_NAME,
                                           "Tags": [{"Key": "ClosedRehearsalRunId", "Value": "run-1"}]}]},
        "describe_stack_resources": {"StackResources": [
            {"LogicalResourceId": "McpApi", "PhysicalResourceId": "abc123def4"},
            {"LogicalResourceId": "McpHandler", "PhysicalResourceId": "honda-mapit-mcp-dev-handler"},
        ]},
        "delete_stack": {},
    })
    clients["apigatewayv2"].methods["get_api"] = AwsError("NotFoundException", "gone")
    clients["lambda"].methods["get_function_concurrency"] = AwsError("ResourceNotFoundException", "gone")
    result = runner(clients, journal).run_step("fallback-delete-app")
    assert result["category"] == "app_delete_requested"
    assert len([c for c in clients["cloudformation"].calls if c[0] == "delete_stack"]) == 1


def control_state(now: int = 1_900_000_000) -> dict[str, Any]:
    from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle
    from mapit.aws_dev_shutdown import AwsDevShutdownPolicy

    resource_started = now - 600
    activation_start = now + 180
    template = build_dev_bootstrap_control_bundle(
        AwsDevShutdownPolicy("abc123def4"),
        user_pool_id="eu-west-1_ABCDEFGHI",
        stack_uuid="12345678-1234-4234-8234-123456789abc",
        resource_started_epoch=resource_started,
        activation_start_epoch=activation_start,
        now_epoch=now,
    )
    return {
        "schema": 1, "region": "eu-west-1", "account_id": ACCOUNT, "run_id": "run-1",
        "authorized_until_epoch": now + 1000,
        "app_client_token": "app-token", "control_client_token": "control-token",
        "app_create_attempted": True, "app_verified": True, "controls_create_attempted": False,
        "controls_verified": True, "api_id": "abc123def4", "user_pool_id": "eu-west-1_ABCDEFGHI",
        "stack_uuid": "12345678-1234-4234-8234-123456789abc",
        "app_stack_id": APP_ARN, "resource_started_epoch": resource_started,
        "activation_start_epoch": activation_start, "controls_created_at_epoch": now,
        "shutdown_schedule_expression": template["Resources"]["ShutdownSchedule"]["Properties"]["ScheduleExpression"],
        "cleanup_schedule_expression": template["Resources"]["BootstrapCleanupSchedule"]["Properties"]["ScheduleExpression"],
        "state_machine_arn": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:{STATE_MACHINE_NAME}",
    }


def schedule_response(kind: str, *, state: str = "DISABLED", expression: str | None = None, account: str = ACCOUNT):
    if kind == "shutdown":
        name, group = SCHEDULE_NAMES[0], SCHEDULE_GROUP_NAMES[0]
        arn = f"arn:aws:states:eu-west-1:{account}:stateMachine:{STATE_MACHINE_NAME}"
        role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-shutdown-scheduler"
        input_value = "{}"
        expression = expression or "at(2030-01-01T00:00:00)"
    else:
        name, group = SCHEDULE_NAMES[1], SCHEDULE_GROUP_NAMES[1]
        arn = "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
        role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-bootstrap-cleanup-scheduler"
        input_value = __import__("json").dumps({
            "StackName": APP_ARN,
            "RoleARN": f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-bootstrap-delete",
        }, separators=(",", ":"))
        expression = expression or "at(2030-01-01T00:00:00)"
    return {
        "Name": name, "GroupName": group, "State": state,
        "ScheduleExpression": expression, "ScheduleExpressionTimezone": "UTC",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {
            "Arn": arn, "RoleArn": role, "Input": input_value,
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        },
    }


def test_schedule_guard_requires_exact_role_and_retry_policy():
    subject = runner()
    good = schedule_response("shutdown")
    subject._verify_schedule_safety(good, kind="shutdown", desired_state="DISABLED")
    for key, bad_value in (
        ("RoleArn", f"arn:aws:iam::{ACCOUNT}:role/similar-name"),
        ("Arn", f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:other"),
        ("Input", '{"unsafe":true}'),
        ("RetryPolicy", {"MaximumRetryAttempts": 1, "MaximumEventAgeInSeconds": 60}),
    ):
        broken = schedule_response("shutdown")
        broken["Target"][key] = bad_value
        with pytest.raises(RehearsalError):
            subject._verify_schedule_safety(broken, kind="shutdown", desired_state="DISABLED")


def test_arm_shutdown_persists_intent_and_moves_one_time_target_into_future():
    now = 1_900_000_000
    journal = MemoryJournal()
    state = control_state(now)
    state["shutdown_schedule_expression"] = "at(2030-01-01T00:00:00)"
    journal.save(state)
    clients = make_clients()
    clients["apigatewayv2"].methods["get_api"] = {"DisableExecuteApiEndpoint": True}
    clients["lambda"].methods["get_function_concurrency"] = {"ReservedConcurrentExecutions": 0}

    def update_schedule(**kwargs):
        assert journal.load()["shutdown_arm_attempted"] is True
        assert kwargs["State"] == "ENABLED"
        assert kwargs["ScheduleExpression"].startswith("at(")
        assert kwargs["ScheduleExpression"] != "at(2030-01-01T00:00:00)"
        return {}

    clients["scheduler"].methods["get_schedule"] = schedule_response("shutdown", expression="at(2030-01-01T00:00:00)")
    clients["scheduler"].methods["update_schedule"] = update_schedule
    subject = runner(clients, journal, until=now + 1000, now=now)
    result = subject.run_step("arm-shutdown")
    assert result["category"] == "shutdown_arm_requested"
    assert journal.load()["shutdown_armed_schedule_expression"].startswith("at(")
    assert len([c for c in clients["scheduler"].calls if c[0] == "update_schedule"]) == 1


def test_arm_cleanup_is_still_inside_authorized_window_and_never_retries():
    now = 1_900_000_000
    journal = MemoryJournal()
    state = control_state(now)
    state.update({"shutdown_verified": True, "shutdown_arm_attempted": True,
                  "cleanup_schedule_expression": "at(2030-01-01T00:00:00)",
                  "authorized_until_epoch": now})
    journal.save(state)
    clients = make_clients()
    clients["apigatewayv2"].methods["get_api"] = {"DisableExecuteApiEndpoint": True}
    clients["lambda"].methods["get_function_concurrency"] = {"ReservedConcurrentExecutions": 0}
    clients["scheduler"].methods["get_schedule"] = schedule_response("cleanup", expression="at(2030-01-01T00:00:00)")
    clients["scheduler"].methods["update_schedule"] = {}
    result = runner(clients, journal, until=now, now=now).run_step("arm-cleanup")
    assert result["category"] == "authorization_window_expired"
    assert not any(name == "update_schedule" for name, _ in clients["scheduler"].calls)


def test_shutdown_check_requires_successful_safe_execution_output():
    now = 1_900_000_000
    journal = MemoryJournal()
    state = control_state(now)
    state.update({"shutdown_arm_attempted": True, "shutdown_armed_schedule_expression": "at(2030-01-01T00:00:00)"})
    journal.save(state)
    clients = make_clients()
    clients["scheduler"].methods["get_schedule"] = schedule_response("shutdown", state="ENABLED", expression=state["shutdown_armed_schedule_expression"])
    clients["apigatewayv2"].methods["get_api"] = {"DisableExecuteApiEndpoint": True}
    clients["lambda"].methods["get_function_concurrency"] = {"ReservedConcurrentExecutions": 0}
    execution_arn = f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:{STATE_MACHINE_NAME}:run"
    clients["stepfunctions"].methods.update({
        "list_executions": {"executions": [{"status": "SUCCEEDED", "executionArn": execution_arn}]},
        "describe_execution": {
            "stateMachineArn": state["state_machine_arn"], "status": "SUCCEEDED",
            "output": '{"verified":true,"api_closed":true,"function_reserved":true,"api_write_call_returned":false,"function_write_call_returned":true,"category":"shutdown_unverified"}',
        },
    })
    result = runner(clients, journal, now=now).run_step("check-shutdown")
    assert result["category"] == "shutdown_execution_unverified"
    assert journal.load().get("shutdown_verified") is None


def test_fallback_delete_readback_works_without_arming_cleanup_schedule():
    journal = MemoryJournal()
    state = control_state()
    state.update({"app_delete_attempted": True, "cleanup_arm_attempted": False})
    journal.save(state)
    clients = make_clients()
    clients["cloudformation"].methods["describe_stacks"] = {"Stacks": []}
    result = runner(clients, journal).run_step("check-cleanup")
    assert result["category"] == "app_deleted_verified"
    assert journal.load()["app_deleted_verified"] is True


def test_final_absence_check_allows_app_only_run_with_no_control_stack():
    journal = MemoryJournal()
    state = control_state()
    state.update({"app_deleted_verified": True, "controls_create_attempted": False})
    journal.save(state)
    clients = make_clients()
    clients["cloudformation"].methods["describe_stacks"] = {"Stacks": []}
    result = runner(clients, journal).run_step("check-final")
    assert result["category"] == "rehearsal_resources_removed"
    assert result["stacks_remaining"] == 0


def test_delete_controls_can_remove_an_owned_partial_control_stack_after_app_gone():
    journal = MemoryJournal()
    state = control_state()
    state.update({"app_deleted_verified": True, "controls_create_attempted": True,
                  "control_stack_id": CONTROL_ARN, "control_delete_attempted": False})
    journal.save(state)
    clients = make_clients()
    clients["cloudformation"].methods["describe_stacks"] = lambda StackName: (
        {"Stacks": []} if StackName == APP_ARN else {"Stacks": [{
            "StackId": CONTROL_ARN, "StackName": "honda-mapit-mcp-dev-control",
            "StackStatus": "CREATE_FAILED",
            "Tags": [{"Key": "ClosedRehearsalRunId", "Value": "run-1"}],
        }]}
    )
    clients["cloudformation"].methods["describe_stack_resources"] = {"StackResources": [
        {"LogicalResourceId": "ShutdownWorkflowRole", "ResourceStatus": "CREATE_COMPLETE"},
        {"LogicalResourceId": "ShutdownStateMachine", "ResourceStatus": "CREATE_FAILED"},
    ]}
    clients["cloudformation"].methods["delete_stack"] = {}
    result = runner(clients, journal).run_step("delete-controls")
    assert result["category"] == "control_delete_requested"
    assert journal.load()["control_delete_attempted"] is True
    assert [c for c in clients["cloudformation"].calls if c[0] == "delete_stack"] == [
        ("delete_stack", {"StackName": CONTROL_ARN})
    ]


def test_check_controls_derives_machine_arn_before_journal_has_it():
    from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
    from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle

    now = 1_900_000_000
    state = control_state(now)
    state.update({"controls_create_attempted": True, "control_stack_id": CONTROL_ARN})
    # This matches the state immediately after create-controls: the generated
    # machine ARN has not yet been copied into the journal by check-controls.
    state.pop("state_machine_arn")
    template = build_dev_bootstrap_control_bundle(
        AwsDevShutdownPolicy(state["api_id"]),
        user_pool_id=state["user_pool_id"], stack_uuid=state["stack_uuid"],
        resource_started_epoch=state["resource_started_epoch"],
        activation_start_epoch=state["activation_start_epoch"],
        now_epoch=state["controls_created_at_epoch"],
    )
    machine_arn = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:{STATE_MACHINE_NAME}"
    resources = []
    for logical_id in template["Resources"]:
        physical_id = {
            "SchedulerGroup": SCHEDULE_GROUP_NAMES[0],
            "BootstrapCleanupScheduleGroup": SCHEDULE_GROUP_NAMES[1],
            "ShutdownStateMachine": machine_arn,
        }.get(logical_id, logical_id)
        resources.append({"LogicalResourceId": logical_id, "PhysicalResourceId": physical_id, "ResourceStatus": "CREATE_COMPLETE"})

    clients = make_clients()
    clients["cloudformation"].methods.update({
        "describe_stacks": {"Stacks": [{
            "StackId": CONTROL_ARN, "StackName": "honda-mapit-mcp-dev-control", "StackStatus": "CREATE_COMPLETE",
            "Tags": [{"Key": "ClosedRehearsalRunId", "Value": state["run_id"]}],
        }]},
        "get_template": {"TemplateBody": _json_bytes(template).decode("utf-8")},
        "describe_stack_resources": {"StackResources": resources},
    })
    clients["apigatewayv2"].methods["get_api"] = {"DisableExecuteApiEndpoint": True}
    clients["lambda"].methods["get_function_concurrency"] = {"ReservedConcurrentExecutions": 0}
    clients["scheduler"].methods["get_schedule"] = lambda Name, GroupName: schedule_response(
        "shutdown" if Name == SCHEDULE_NAMES[0] else "cleanup",
        expression=state["shutdown_schedule_expression"] if Name == SCHEDULE_NAMES[0] else state["cleanup_schedule_expression"],
    )
    alarm_arn = f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-dev-request-tripwire"
    clients["cloudwatch"].methods["describe_alarms"] = {"MetricAlarms": [{
        "AlarmName": "honda-mapit-mcp-dev-request-tripwire", "AlarmArn": alarm_arn,
        "Namespace": "AWS/ApiGateway", "MetricName": "Count",
        "Dimensions": [{"Name": "ApiId", "Value": state["api_id"]}, {"Name": "Stage", "Value": "$default"}],
        "Period": 60, "Statistic": "SampleCount", "Threshold": 100.0,
        "ComparisonOperator": "GreaterThanOrEqualToThreshold", "EvaluationPeriods": 1,
        "DatapointsToAlarm": 1, "TreatMissingData": "notBreaching", "ActionsEnabled": False,
        "AlarmActions": [],
    }]}
    pattern = {
        "source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"],
        "account": [ACCOUNT], "region": ["eu-west-1"], "resources": [alarm_arn],
        "detail": {"alarmName": ["honda-mapit-mcp-dev-request-tripwire"], "state": {"value": ["ALARM"]}},
    }
    clients["events"].methods.update({
        "describe_rule": {"Name": "honda-mapit-mcp-dev-request-tripwire-alarm-rule", "State": "DISABLED", "EventPattern": __import__("json").dumps(pattern)},
        "list_targets_by_rule": {"Targets": [{
            "Id": "StartFixedDevShutdownWorkflow", "Arn": machine_arn,
            "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-request-tripwire",
            "Input": "{}", "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        }]},
    })
    clients["stepfunctions"].methods["describe_state_machine"] = {"status": "ACTIVE"}
    journal = MemoryJournal()
    journal.save(state)

    result = runner(clients, journal, now=now).run_step("check-controls")
    assert result["category"] == "controls_verified_disabled"
    assert journal.load()["state_machine_arn"] == machine_arn
