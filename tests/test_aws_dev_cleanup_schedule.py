from __future__ import annotations

import json

import pytest

from mapit.aws_dev_cleanup_schedule import build_dev_cleanup_schedule


def _template(schedule_at: str = "2026-10-02T19:00:00") -> dict:
    return build_dev_cleanup_schedule(schedule_at)


def test_cleanup_schedule_is_disabled_fixed_app_stack_and_region_only() -> None:
    template = _template()
    assert template["Metadata"]["Readiness"] == "COMPONENT_NOT_DEPLOY_READY"
    assert template["Metadata"]["NoActivation"] is True
    assert template["Metadata"]["Region"] == "eu-west-1"
    assert template["Metadata"]["FixedTargetStack"] == "honda-mapit-mcp-dev"
    assert template["Metadata"]["NoHardBillingCap"] is True
    assert "associated CloudFormation service role" in template["Metadata"]["DeleteStackRoleNote"]
    assert "ActionAfterCompletion" in template["Metadata"]["ActionAfterCompletionNote"]
    assert "before control-stack cleanup" in " ".join(template["Metadata"]["MissingPrerequisites"])
    assert template["Conditions"]["SupportedRegion"] == {
        "Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]
    }
    resources = template["Resources"]
    assert set(resources) == {"CleanupScheduleGroup", "CleanupSchedulerRole", "CleanupSchedule"}
    assert all(resource.get("Condition") == "SupportedRegion" for resource in resources.values())
    assert "Outputs" not in template
    assert "AWS::CloudFormation::Stack" not in repr(template)


def test_scheduler_group_and_role_are_trusted_only_from_exact_group_and_account() -> None:
    resources = _template()["Resources"]
    assert resources["CleanupScheduleGroup"]["Properties"]["Name"] == "honda-mapit-mcp-dev-cleanup"
    role = resources["CleanupSchedulerRole"]["Properties"]
    assert role["RoleName"] == "honda-mapit-mcp-dev-cleanup-scheduler"
    statement = role["AssumeRolePolicyDocument"]["Statement"][0]
    assert statement["Principal"] == {"Service": "scheduler.amazonaws.com"}
    assert statement["Action"] == "sts:AssumeRole"
    assert statement["Condition"]["StringEquals"] == {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}
    assert statement["Condition"]["ArnLike"]["aws:SourceArn"]["Fn::Sub"].endswith(
        ":schedule-group/honda-mapit-mcp-dev-cleanup"
    )


def test_scheduler_can_only_delete_the_exact_named_stack_instance_family() -> None:
    role_props = _template()["Resources"]["CleanupSchedulerRole"]["Properties"]
    statements = role_props["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{
        "Effect": "Allow",
        "Action": "cloudformation:DeleteStack",
        "Resource": {
            "Fn::Sub": "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/honda-mapit-mcp-dev/*"
        },
    }]


def test_target_uses_universal_delete_stack_with_fixed_input_and_no_role_arn_override() -> None:
    schedule = _template()["Resources"]["CleanupSchedule"]["Properties"]
    target = schedule["Target"]
    assert target["Arn"] == "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
    assert json.loads(target["Input"]) == {"StackName": "honda-mapit-mcp-dev"}
    assert "RoleARN" not in json.loads(target["Input"])
    assert target["RoleArn"] == {"Fn::GetAtt": ["CleanupSchedulerRole", "Arn"]}
    assert target["RetryPolicy"] == {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}


def test_schedule_is_one_time_utc_disabled_nonflexible_and_does_not_self_delete() -> None:
    schedule = _template()["Resources"]["CleanupSchedule"]["Properties"]
    assert schedule["Name"] == "honda-mapit-mcp-dev-delete-once"
    assert schedule["GroupName"] == {"Ref": "CleanupScheduleGroup"}
    assert schedule["State"] == "DISABLED"
    assert schedule["ScheduleExpression"] == "at(2026-10-02T19:00:00)"
    assert schedule["ScheduleExpressionTimezone"] == "UTC"
    assert schedule["FlexibleTimeWindow"] == {"Mode": "OFF"}
    assert "ActionAfterCompletion" not in schedule


@pytest.mark.parametrize("value", [
    "2026-1-02T19:00:00", "2026-02-30T19:00:00", "2026-10-02T19:00", "2026-10-02T19:00:00Z",
    "2026-10-02T19:00:00\n", "2026-10-02T25:00:00", "2026-10-02T19:00:60", "2026-10-02T19:00:00.000",
])
def test_timestamp_is_strict_calendar_valid_utc_second(value: str) -> None:
    with pytest.raises(ValueError):
        build_dev_cleanup_schedule(value)


def test_timestamp_future_guard_is_not_claimed_by_this_pure_generator() -> None:
    template = _template("2000-01-01T00:00:00")
    assert template["Resources"]["CleanupSchedule"]["Properties"]["ScheduleExpression"] == "at(2000-01-01T00:00:00)"
    assert "deployment-time future/lifetime guard" in template["Metadata"]["ScheduleTimestampPolicy"]
