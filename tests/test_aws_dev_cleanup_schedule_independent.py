from __future__ import annotations

import json
from typing import Any

import pytest

from mapit.aws_dev_cleanup_schedule import build_dev_cleanup_schedule


_APP_STACK = "honda-mapit-mcp-dev"
_GROUP = "honda-mapit-mcp-dev-cleanup"
_SCHEDULE = "honda-mapit-mcp-dev-delete-once"


def _template(timestamp: str = "2026-10-02T19:00:00") -> dict[str, Any]:
    return build_dev_cleanup_schedule(timestamp)


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def test_only_the_three_region_gated_schedule_resources_exist():
    template = _template()
    resources = template["Resources"]
    assert set(resources) == {"CleanupScheduleGroup", "CleanupSchedulerRole", "CleanupSchedule"}
    assert {resource["Type"] for resource in resources.values()} == {
        "AWS::Scheduler::ScheduleGroup", "AWS::IAM::Role", "AWS::Scheduler::Schedule"
    }
    assert all(resource["Condition"] == "SupportedRegion" for resource in resources.values())
    assert template["Conditions"]["SupportedRegion"] == {
        "Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]
    }
    assert not any(str(value).startswith(("AWS::Lambda::", "AWS::CloudFormation::Stack", "AWS::StepFunctions::")) for value in _walk(template))
    assert "Outputs" not in template


def test_delete_permission_is_only_fixed_app_stack_and_unique_instance_suffix():
    role = _template()["Resources"]["CleanupSchedulerRole"]["Properties"]
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{
        "Effect": "Allow",
        "Action": "cloudformation:DeleteStack",
        "Resource": {
            "Fn::Sub": (
                "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:"
                f"stack/{_APP_STACK}/*"
            )
        },
    }]
    # The sole wildcard is CloudFormation's stack-instance suffix, not an
    # action/resource/account/region wildcard or another project's stack.
    resource_arn = statements[0]["Resource"]["Fn::Sub"]
    assert resource_arn.count("*") == 1
    assert resource_arn.endswith(f"stack/{_APP_STACK}/*")


def test_schedule_role_trust_is_account_and_exact_group_scoped():
    resources = _template()["Resources"]
    assert resources["CleanupScheduleGroup"]["Properties"]["Name"] == _GROUP
    trust = resources["CleanupSchedulerRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert trust == [{
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


def test_target_is_fixed_delete_stack_call_without_role_override_or_control_target():
    target = _template()["Resources"]["CleanupSchedule"]["Properties"]["Target"]
    assert target["Arn"] == "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
    assert target["Input"] == '{"StackName":"honda-mapit-mcp-dev"}'
    assert set(json.loads(target["Input"])) == {"StackName"}
    assert target["RoleArn"] == {"Fn::GetAtt": ["CleanupSchedulerRole", "Arn"]}
    assert target["RetryPolicy"] == {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
    assert _APP_STACK not in target["Arn"]


def test_schedule_stays_disabled_single_utc_shot_and_cannot_delete_its_own_stack():
    schedule = _template()["Resources"]["CleanupSchedule"]["Properties"]
    assert schedule["Name"] == _SCHEDULE
    assert schedule["GroupName"] == {"Ref": "CleanupScheduleGroup"}
    assert schedule["State"] == "DISABLED"
    assert schedule["ScheduleExpression"] == "at(2026-10-02T19:00:00)"
    assert schedule["ScheduleExpressionTimezone"] == "UTC"
    assert schedule["FlexibleTimeWindow"] == {"Mode": "OFF"}
    assert "ActionAfterCompletion" not in schedule
    assert schedule["Target"]["Input"] == '{"StackName":"honda-mapit-mcp-dev"}'


def test_documentation_requires_preassociated_role_and_manual_control_cleanup():
    template = _template()
    metadata = template["Metadata"]
    assert metadata["Readiness"] == "COMPONENT_NOT_DEPLOY_READY"
    assert metadata["NoActivation"] is True
    assert metadata["NoHardBillingCap"] is True
    assert "must already have an associated CloudFormation service role" in metadata["DeleteStackRoleNote"]
    prerequisites = " ".join(metadata["MissingPrerequisites"])
    assert "before control-stack cleanup" in prerequisites
    assert "associated CloudFormation service role" in prerequisites


@pytest.mark.parametrize("timestamp", [None, 0, False, b"2026-10-02T19:00:00", object()])
def test_non_string_timestamp_rejected_before_template_generation(timestamp: Any):
    with pytest.raises(ValueError):
        build_dev_cleanup_schedule(timestamp)


def test_old_but_syntactically_valid_timestamp_does_not_claim_runtime_future_validation():
    template = _template("2000-01-01T00:00:00")
    assert template["Resources"]["CleanupSchedule"]["Properties"]["ScheduleExpression"] == "at(2000-01-01T00:00:00)"
    assert "deployment-time future/lifetime guard" in template["Metadata"]["ScheduleTimestampPolicy"]
