from __future__ import annotations

import pytest
import json

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control


def _template(schedule_at: str = "2026-10-02T18:00:00") -> dict:
    return build_dev_shutdown_control(AwsDevShutdownPolicy("a1b2c3d4e5"), schedule_at)


def test_control_is_disabled_fixed_dev_only_review_artifact() -> None:
    template = _template()
    assert template["Metadata"]["Readiness"] == "COMPONENT_NOT_DEPLOY_READY"
    assert template["Metadata"]["NoActivation"] is True
    assert template["Metadata"]["Region"] == "eu-west-1"
    assert template["Metadata"]["IntendedActionAfterCompletion"] == "NONE"
    assert "schema does not expose" in template["Metadata"]["ActionAfterCompletionNote"]
    assert "deployment-time future guard" in template["Metadata"]["ScheduleTimestampPolicy"]
    assert set(template["Resources"]) == {
        "ShutdownWorkflowRole", "ShutdownStateMachine", "SchedulerGroup",
        "SchedulerInvokeRole", "ShutdownSchedule", "RequestTripwireAlarm",
        "RequestTripwireEventRole", "RequestTripwireAlarmRule",
    }
    assert all(item.get("Condition") == "SupportedRegion" for item in template["Resources"].values())
    assert template["Conditions"]["SupportedRegion"] == {
        "Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]
    }
    assert "Outputs" not in template
    serialized = repr(template)
    assert "AWS::Lambda::Function" not in serialized
    assert "Custom::" not in serialized


def test_step_functions_resource_uses_generated_workflow_and_no_observability() -> None:
    props = _template()["Resources"]["ShutdownStateMachine"]["Properties"]
    assert props["StateMachineName"] == "honda-mapit-mcp-dev-shutdown"
    assert props["StateMachineType"] == "STANDARD"
    assert "Definition" not in props
    definition = json.loads(props["DefinitionString"])
    assert definition["TimeoutSeconds"] == 45
    assert definition["States"]["DisableApiEndpoint"]["ResultPath"] is None
    assert props["LoggingConfiguration"] == {"Level": "OFF"}
    assert props["TracingConfiguration"] == {"Enabled": False}
    assert props["RoleArn"] == {"Fn::GetAtt": ["ShutdownWorkflowRole", "Arn"]}
    assert "honda-mapit-mcp-dev-handler" in repr(definition)


def test_workflow_role_is_trusted_only_for_exact_named_state_machine_and_has_exact_actions() -> None:
    props = _template()["Resources"]["ShutdownWorkflowRole"]["Properties"]
    trust = props["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust["Principal"] == {"Service": "states.amazonaws.com"}
    assert trust["Condition"]["StringEquals"] == {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}
    assert "stateMachine:honda-mapit-mcp-dev-shutdown" in trust["Condition"]["ArnLike"]["aws:SourceArn"]["Fn::Sub"]
    policy_statements = props["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(policy_statements) == 3
    assert policy_statements[0]["Action"] == "apigateway:PATCH"
    assert "/apis/a1b2c3d4e5" in policy_statements[0]["Resource"]["Fn::Sub"]
    assert policy_statements[0]["Condition"] == {
        "Bool": {"apigateway:Request/DisableExecuteApiEndpoint": "true"}
    }
    assert policy_statements[1]["Action"] == "apigateway:GET"
    assert "/apis/a1b2c3d4e5" in policy_statements[1]["Resource"]["Fn::Sub"]
    assert "Condition" not in policy_statements[1]
    assert policy_statements[2]["Action"] == ["lambda:PutFunctionConcurrency", "lambda:GetFunctionConcurrency"]
    assert "function:honda-mapit-mcp-dev-handler" in policy_statements[2]["Resource"]["Fn::Sub"]
    assert all(statement["Effect"] == "Allow" for statement in policy_statements)


def test_scheduler_role_can_only_start_exact_workflow_and_is_group_trusted() -> None:
    props = _template()["Resources"]["SchedulerInvokeRole"]["Properties"]
    trust = props["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust["Principal"] == {"Service": "scheduler.amazonaws.com"}
    assert trust["Condition"]["StringEquals"] == {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}
    assert trust["Condition"]["ArnLike"]["aws:SourceArn"]["Fn::Sub"].endswith(
        ":schedule-group/honda-mapit-mcp-dev-safety"
    )
    statements = props["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{
        "Effect": "Allow",
        "Action": "states:StartExecution",
        "Resource": {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]},
    }]


def test_schedule_is_disabled_utc_one_shot_with_no_retry_and_empty_input() -> None:
    template = _template()
    resources = template["Resources"]
    group = resources["SchedulerGroup"]["Properties"]
    assert group["Name"] == "honda-mapit-mcp-dev-safety"
    schedule = resources["ShutdownSchedule"]["Properties"]
    assert schedule["State"] == "DISABLED"
    assert schedule["GroupName"] == {"Ref": "SchedulerGroup"}
    assert schedule["ScheduleExpression"] == "at(2026-10-02T18:00:00)"
    assert schedule["ScheduleExpressionTimezone"] == "UTC"
    assert schedule["FlexibleTimeWindow"] == {"Mode": "OFF"}
    target = schedule["Target"]
    assert target["Arn"] == {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]}
    assert target["RoleArn"] == {"Fn::GetAtt": ["SchedulerInvokeRole", "Arn"]}
    assert target["Input"] == "{}"
    assert target["RetryPolicy"] == {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
    assert "ActionAfterCompletion" not in schedule


def test_request_tripwire_alarm_is_scoped_sample_count_and_inert() -> None:
    alarm = _template()["Resources"]["RequestTripwireAlarm"]["Properties"]
    assert alarm["AlarmName"] == "honda-mapit-mcp-dev-request-tripwire"
    assert alarm["Namespace"] == "AWS/ApiGateway"
    assert alarm["MetricName"] == "Count"
    assert alarm["Dimensions"] == [
        {"Name": "ApiId", "Value": "a1b2c3d4e5"},
        {"Name": "Stage", "Value": "$default"},
    ]
    assert alarm["Period"] == 60
    assert alarm["Statistic"] == "SampleCount"
    assert alarm["Threshold"] == 100
    assert alarm["ComparisonOperator"] == "GreaterThanOrEqualToThreshold"
    assert alarm["EvaluationPeriods"] == alarm["DatapointsToAlarm"] == 1
    assert alarm["TreatMissingData"] == "notBreaching"
    assert alarm["ActionsEnabled"] is False
    assert {tag["Key"]: tag["Value"] for tag in alarm["Tags"]} == {
        "Project": "honda-mapit-mcp",
        "Environment": "dev",
        "Purpose": "request-tripwire",
    }


def test_tripwire_rule_is_disabled_and_matches_only_its_alarm_in_this_account_region() -> None:
    rule = _template()["Resources"]["RequestTripwireAlarmRule"]["Properties"]
    assert rule["Name"] == "honda-mapit-mcp-dev-request-tripwire-alarm-rule"
    assert rule["State"] == "DISABLED"
    pattern = rule["EventPattern"]
    assert pattern["source"] == ["aws.cloudwatch"]
    assert pattern["detail-type"] == ["CloudWatch Alarm State Change"]
    assert pattern["account"] == [{"Ref": "AWS::AccountId"}]
    assert pattern["region"] == ["eu-west-1"]
    assert pattern["resources"] == [{
        "Fn::Sub": "arn:${AWS::Partition}:cloudwatch:${AWS::Region}:${AWS::AccountId}:alarm:honda-mapit-mcp-dev-request-tripwire"
    }]
    assert pattern["detail"] == {
        "alarmName": ["honda-mapit-mcp-dev-request-tripwire"],
        "state": {"value": ["ALARM"]},
    }
    assert rule["Targets"] == [{
        "Id": "StartFixedDevShutdownWorkflow",
        "Arn": {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]},
        "RoleArn": {"Fn::GetAtt": ["RequestTripwireEventRole", "Arn"]},
        "Input": "{}",
        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
    }]


def test_tripwire_role_is_trusted_by_exact_rule_and_can_only_start_fixed_workflow() -> None:
    props = _template()["Resources"]["RequestTripwireEventRole"]["Properties"]
    trust = props["AssumeRolePolicyDocument"]["Statement"]
    assert trust == [{
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sts:AssumeRole",
        "Condition": {
            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
            "ArnEquals": {"aws:SourceArn": {
                "Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/honda-mapit-mcp-dev-request-tripwire-alarm-rule"
            }},
        },
    }]
    statements = props["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{
        "Effect": "Allow",
        "Action": "states:StartExecution",
        "Resource": {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]},
    }]


def test_tripwire_has_no_resource_dependency_cycle_or_activation_path() -> None:
    resources = _template()["Resources"]
    rule_role_trust = resources["RequestTripwireEventRole"]["Properties"][
        "AssumeRolePolicyDocument"
    ]["Statement"][0]["Condition"]["ArnEquals"]["aws:SourceArn"]
    assert rule_role_trust == {
        "Fn::Sub": "arn:${AWS::Partition}:events:${AWS::Region}:${AWS::AccountId}:rule/honda-mapit-mcp-dev-request-tripwire-alarm-rule"
    }
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert "RequestTripwireAlarmRule" not in repr(rule_role_trust)


def test_each_resource_and_call_definition_are_fresh_values() -> None:
    first = _template()
    second = _template()
    assert first == second and first is not second
    first["Resources"]["ShutdownSchedule"]["Properties"]["State"] = "ENABLED"
    assert second["Resources"]["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"


@pytest.mark.parametrize("timestamp", [
    "2026-1-02T18:00:00", "2026-02-30T18:00:00", "2026-10-02T18:00", "2026-10-02T18:00:00Z",
    " 2026-10-02T18:00:00", "2026-10-02T18:00:00\n", "2026-10-02T25:00:00", "2026-10-02T18:00:60",
    "2026-10-02T18:00:00.000", "2026-10-02T18:00:00+00:00",
])
def test_timestamp_must_be_canonical_calendar_valid_utc_second(timestamp: str) -> None:
    with pytest.raises(ValueError):
        _template(timestamp)


def test_timestamp_must_be_explicit_and_function_does_not_apply_clock_future_semantics() -> None:
    with pytest.raises(TypeError):
        build_dev_shutdown_control(AwsDevShutdownPolicy("a1b2c3d4e5"))  # type: ignore[call-arg]
    past = _template("2000-01-01T00:00:00")
    assert past["Resources"]["ShutdownSchedule"]["Properties"]["ScheduleExpression"] == "at(2000-01-01T00:00:00)"
    assert "future guard" in past["Metadata"]["ScheduleTimestampPolicy"]


def test_invalid_policy_fails_before_template_creation() -> None:
    with pytest.raises(ValueError):
        build_dev_shutdown_control(AwsDevShutdownPolicy("abc"), "2026-10-02T18:00:00")
    with pytest.raises(ValueError):
        build_dev_shutdown_control(object(), "2026-10-02T18:00:00")  # type: ignore[arg-type]


def test_mutated_frozen_policy_is_revalidated_before_generating_iam_targets() -> None:
    policy = AwsDevShutdownPolicy("a1b2c3d4e5")
    object.__setattr__(policy, "api_id", "not-an-api-id")
    with pytest.raises(ValueError):
        build_dev_shutdown_control(policy, "2026-10-02T18:00:00")
