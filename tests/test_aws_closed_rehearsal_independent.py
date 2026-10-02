from __future__ import annotations

import boto3
from botocore.stub import Stubber
import json
import pytest

from scripts.run_aws_closed_rehearsal import (
    AwsClosedRehearsal,
    MemoryJournal,
    RehearsalError,
    SCHEDULE_GROUP_NAMES,
    SCHEDULE_NAMES,
    STATE_MACHINE_NAME,
)
from tests.test_aws_closed_rehearsal_runner import ACCOUNT, APP_ARN, AwsError, make_clients


def test_preflight_uses_real_stepfunctions_sdk_arn_and_not_found_shape():
    client = boto3.client(
        "stepfunctions",
        region_name="eu-west-1",
        aws_access_key_id="synthetic-access-key",
        aws_secret_access_key="synthetic-secret-key",
    )
    expected = {
        "stateMachineArn": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-shutdown"
    }
    stubber = Stubber(client)
    stubber.add_client_error(
        "describe_state_machine",
        service_error_code="StateMachineDoesNotExist",
        expected_params=expected,
    )
    clients = make_clients()
    clients["stepfunctions"] = client
    journal = MemoryJournal()
    runner = AwsClosedRehearsal(
        clients, journal, ACCOUNT, authorized_until_epoch=2_000_000_000,
        wall_clock=lambda: 1_900_000_000,
    )
    with stubber:
        result = runner.run_step("preflight")
    assert result["ok"] is True
    assert journal.load()["account_id"] == ACCOUNT
    stubber.assert_no_pending_responses()


def test_create_app_rechecks_deadline_after_intent_is_durable_before_dispatch():
    journal = MemoryJournal()
    journal.save({
        "schema": 1,
        "region": "eu-west-1",
        "account_id": ACCOUNT,
        "authorized_until_epoch": 1_900_000_010,
        "run_id": "synthetic-run",
        "app_client_token": "synthetic-client-token",
        "app_create_attempted": False,
    })
    clients = make_clients()
    clock_values = iter([1_900_000_000, 1_900_000_000, 1_900_000_010])
    runner = AwsClosedRehearsal(
        clients, journal, ACCOUNT,
        authorized_until_epoch=1_900_000_010,
        wall_clock=lambda: next(clock_values),
    )
    result = runner.run_step("create-app")
    assert result["category"] == "authorization_window_expired"
    assert journal.load()["app_create_attempted"] is True
    assert not any(name == "create_stack" for name, _ in clients["cloudformation"].calls)


def _shutdown_schedule(state: str = "DISABLED") -> dict:
    return {
        "Name": SCHEDULE_NAMES[0],
        "GroupName": SCHEDULE_GROUP_NAMES[0],
        "ScheduleExpression": "at(2030-01-01T00:03:00)",
        "ScheduleExpressionTimezone": "UTC",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "State": state,
        "Target": {
            "Arn": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:{STATE_MACHINE_NAME}",
            "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-shutdown-scheduler",
            "Input": "{}",
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        },
    }


@pytest.mark.parametrize("mutate", [
    lambda response: response["Target"].update(RoleArn=f"arn:aws:iam::{ACCOUNT}:role/unrelated"),
    lambda response: response["Target"]["RetryPolicy"].update(MaximumRetryAttempts=1),
    lambda response: response["Target"].update(Input='{"target":"unrelated"}'),
    lambda response: response.update(ScheduleExpressionTimezone="America/Los_Angeles"),
    lambda response: response.update(FlexibleTimeWindow={"Mode": "FLEXIBLE", "MaximumWindowInMinutes": 5}),
])
def test_schedule_safety_rejects_target_role_retry_input_timezone_or_flex_drift(mutate):
    journal = MemoryJournal()
    journal.save({"schema": 1, "region": "eu-west-1", "app_stack_id": APP_ARN})
    subject = AwsClosedRehearsal(make_clients(), journal, ACCOUNT, authorized_until_epoch=2_000_000_000)
    response = _shutdown_schedule()
    mutate(response)
    with pytest.raises(RehearsalError):
        subject._verify_schedule_safety(response, kind="shutdown", desired_state="DISABLED")


def test_succeeded_workflow_with_false_write_output_is_not_shutdown_acceptance():
    journal = MemoryJournal()
    machine_arn = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:{STATE_MACHINE_NAME}"
    execution_arn = f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:{STATE_MACHINE_NAME}:synthetic-exec"
    journal.save({
        "schema": 1, "region": "eu-west-1", "account_id": ACCOUNT,
        "authorized_until_epoch": 2_000_000_000, "run_id": "synthetic-run",
        "shutdown_arm_attempted": True,
        "shutdown_armed_schedule_expression": "at(2030-01-01T00:03:00)",
        "state_machine_arn": machine_arn, "api_id": "abc123def4",
    })
    clients = make_clients()
    clients["scheduler"].methods["get_schedule"] = _shutdown_schedule("ENABLED")
    clients["apigatewayv2"].methods["get_api"] = {"DisableExecuteApiEndpoint": True}
    clients["lambda"].methods["get_function_concurrency"] = {"ReservedConcurrentExecutions": 0}
    clients["stepfunctions"].methods.update({
        "list_executions": {"executions": [{"status": "SUCCEEDED", "executionArn": execution_arn}]},
        "describe_execution": {"stateMachineArn": machine_arn, "status": "SUCCEEDED", "output": json.dumps({
            "category": "shutdown_verified", "verified": True, "api_closed": True,
            "function_reserved": True, "api_write_call_returned": False,
            "function_write_call_returned": True,
        })},
    })
    subject = AwsClosedRehearsal(clients, journal, ACCOUNT, authorized_until_epoch=2_000_000_000)
    result = subject.run_step("check-shutdown")
    assert result["category"] == "shutdown_execution_unverified"
    assert journal.load().get("shutdown_verified") is not True


def test_final_cleanup_readback_fails_if_an_owned_control_role_remains():
    journal = MemoryJournal()
    journal.save({
        "schema": 1, "region": "eu-west-1", "account_id": ACCOUNT,
        "app_deleted_verified": True, "controls_create_attempted": False,
    })
    clients = make_clients()
    def get_role(**kwargs):
        if kwargs["RoleName"] == "honda-mapit-mcp-dev-shutdown-workflow":
            return {"Role": {"RoleName": kwargs["RoleName"]}}
        raise AwsError("NoSuchEntity", "not found")
    clients["iam"].methods["get_role"] = get_role
    clients["logs"].methods["describe_log_groups"] = {"logGroups": []}
    clients["apigatewayv2"].methods["get_apis"] = {"Items": []}
    clients["cognito"].methods["list_user_pools"] = {"UserPools": []}
    subject = AwsClosedRehearsal(clients, journal, ACCOUNT, authorized_until_epoch=2_000_000_000)
    result = subject.run_step("check-final")
    assert result["ok"] is False
    assert result["category"] == "preexisting_resource_rejected", {
        name: client.calls for name, client in clients.items() if client.calls
    }
