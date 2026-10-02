from __future__ import annotations

from typing import Any

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control
from mapit.aws_dev_shutdown_workflow import build_dev_shutdown_workflow


_API_ID = "a1b2c3d4e5"
_FUNCTION = "honda-mapit-mcp-dev-handler"
_STATE_MACHINE = "honda-mapit-mcp-dev-shutdown"
_GROUP = "honda-mapit-mcp-dev-safety"


def _control(timestamp: str = "2026-10-02T18:00:00") -> dict[str, Any]:
    return build_dev_shutdown_control(AwsDevShutdownPolicy(_API_ID), timestamp)


def _all_values(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _all_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from _all_values(child)


def test_template_is_only_the_five_gated_resources_with_no_lambda_function_or_trigger():
    template = _control()
    resources = template["Resources"]
    assert set(resources) == {
        "ShutdownWorkflowRole", "ShutdownStateMachine", "SchedulerGroup",
        "SchedulerInvokeRole", "ShutdownSchedule",
    }
    assert all(resource.get("Condition") == "SupportedRegion" for resource in resources.values())
    assert {resource["Type"] for resource in resources.values()} == {
        "AWS::IAM::Role", "AWS::StepFunctions::StateMachine",
        "AWS::Scheduler::ScheduleGroup", "AWS::Scheduler::Schedule",
    }
    assert not any("AWS::Lambda::Function" == value for value in _all_values(template))
    assert not any(str(value).startswith("AWS::Lambda::") for value in _all_values(template))
    assert "Outputs" not in template
    assert "Parameters" not in template


def test_iam_resources_and_actions_are_scoped_without_wildcards():
    template = _control()
    resources = template["Resources"]
    workflow_statements = resources["ShutdownWorkflowRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    scheduler_statements = resources["SchedulerInvokeRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]

    assert workflow_statements == [
        {
            "Effect": "Allow",
            "Action": "apigateway:PATCH",
            "Resource": {
                "Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{_API_ID}"
            },
            "Condition": {
                "Bool": {"apigateway:Request/DisableExecuteApiEndpoint": "true"}
            },
        },
        {
            "Effect": "Allow",
            "Action": "apigateway:GET",
            "Resource": {
                "Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{_API_ID}"
            },
        },
        {
            "Effect": "Allow",
            "Action": ["lambda:PutFunctionConcurrency", "lambda:GetFunctionConcurrency"],
            "Resource": {
                "Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{_FUNCTION}"
            },
        },
    ]
    assert scheduler_statements == [{
        "Effect": "Allow",
        "Action": "states:StartExecution",
        "Resource": {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]},
    }]
    assert not any(value == "*" for value in _all_values(workflow_statements + scheduler_statements))
    assert not any("lambda:*" == value or "apigateway:*" == value or "states:*" == value for value in _all_values(template))


def test_trust_relationships_are_bound_to_account_and_machine_or_schedule_group():
    resources = _control()["Resources"]
    workflow_trust = resources["ShutdownWorkflowRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    scheduler_trust = resources["SchedulerInvokeRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert workflow_trust == [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
            "ArnLike": {
                "aws:SourceArn": {
                    "Fn::Sub": (
                        f"arn:${{AWS::Partition}}:states:${{AWS::Region}}:${{AWS::AccountId}}:"
                        f"stateMachine:{_STATE_MACHINE}"
                    )
                }
            },
        },
    }]
    assert scheduler_trust == [{
        "Effect": "Allow",
        "Principal": {"Service": "scheduler.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
            "ArnLike": {
                "aws:SourceArn": {
                    "Fn::Sub": (
                        f"arn:${{AWS::Partition}}:scheduler:${{AWS::Region}}:${{AWS::AccountId}}:"
                        f"schedule-group/{_GROUP}"
                    )
                }
            },
        },
    }]
    assert _GROUP not in workflow_trust[0]["Condition"]["ArnLike"]["aws:SourceArn"]["Fn::Sub"]
    assert _STATE_MACHINE not in scheduler_trust[0]["Condition"]["ArnLike"]["aws:SourceArn"]["Fn::Sub"]


def test_schedule_is_disabled_exact_utc_one_shot_with_no_activation_surface():
    template = _control()
    schedule = template["Resources"]["ShutdownSchedule"]["Properties"]
    assert schedule == {
        "Name": "honda-mapit-mcp-dev-close-once",
        "GroupName": {"Ref": "SchedulerGroup"},
        "State": "DISABLED",
        "ScheduleExpression": "at(2026-10-02T18:00:00)",
        "ScheduleExpressionTimezone": "UTC",
        "FlexibleTimeWindow": {"Mode": "OFF"},
        "Target": {
            "Arn": {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]},
            "RoleArn": {"Fn::GetAtt": ["SchedulerInvokeRole", "Arn"]},
            "Input": "{}",
            "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
        },
    }
    assert "ActionAfterCompletion" not in schedule
    assert template["Metadata"]["NoActivation"] is True


@pytest.mark.parametrize("timestamp", [None, 0, False, b"2026-10-02T18:00:00", object()])
def test_non_string_timestamp_values_fail_closed(timestamp: Any):
    with pytest.raises(ValueError):
        build_dev_shutdown_control(AwsDevShutdownPolicy(_API_ID), timestamp)


def test_metadata_disclaims_deploy_readiness_and_requires_runtime_future_guard():
    metadata = _control()["Metadata"]
    assert metadata["Readiness"] == "COMPONENT_NOT_DEPLOY_READY"
    assert metadata["NoActivation"] is True
    assert metadata["IntendedActionAfterCompletion"] == "NONE"
    assert "syntax only" in metadata["ScheduleTimestampPolicy"]
    assert "deployment-time future guard" in metadata["ScheduleTimestampPolicy"]
    assert "cleanup procedure" in " ".join(metadata["MissingPrerequisites"])
    assert "future" in " ".join(metadata["MissingPrerequisites"])


def test_forged_frozen_policy_with_invalid_api_id_is_rejected():
    policy = AwsDevShutdownPolicy(_API_ID)
    object.__setattr__(policy, "api_id", "bad/${AWS::AccountId}/*")
    with pytest.raises(ValueError):
        build_dev_shutdown_control(policy, "2026-10-02T18:00:00")
    with pytest.raises(ValueError):
        build_dev_shutdown_workflow(policy)
