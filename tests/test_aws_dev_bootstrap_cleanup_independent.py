from __future__ import annotations

import json

import mapit.aws_dev_bootstrap_cleanup as cleanup
import mapit.aws_dev_bootstrap_control_bundle as bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy


_POLICY = AwsDevShutdownPolicy("a1b2c3d4e5")
_POOL = "eu-west-1_123456789ABC"
_STACK_UUID = "12345678-1234-1234-1234-123456789abc"
_ACCOUNT = "123456789012"


def _cleanup():
    return cleanup.build_dev_bootstrap_cleanup(
        _POLICY, _POOL, _STACK_UUID, "2026-10-02T18:30:00"
    )


def _bundle():
    return bundle.build_dev_bootstrap_control_bundle(
        _POLICY,
        user_pool_id=_POOL,
        stack_uuid=_STACK_UUID,
        resource_started_epoch=1_800_000_000,
        activation_start_epoch=1_800_000_120,
        now_epoch=1_800_000_000,
    )


def _resolve_substitution(template: str, values: dict[str, str]) -> str:
    for key, value in values.items():
        template = template.replace("${" + key + "}", value)
    return template


def test_cleanup_role_deletes_only_exact_bootstrap_resources_with_one_regional_read_wildcard():
    resources = _cleanup()["Resources"]
    statements = resources["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(statements) == 6
    # The sole resource-level wildcard is the API that cannot be resource-scoped.
    assert sum(statement.get("Resource") == "*" for statement in statements) == 1
    describe = next(statement for statement in statements if statement["Action"] == "logs:DescribeLogGroups")
    assert describe["Condition"] == {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}
    assert describe["Resource"] == "*"
    assert all(statement.get("Resource") != "*" for statement in statements if statement is not describe)
    rendered = repr(statements)
    assert "honda-mapit-mcp-dev-handler" in rendered
    assert _POOL in rendered and _STACK_UUID not in rendered
    assert not any(action.startswith(prefix) for statement in statements
                   for action in ([statement["Action"]] if isinstance(statement["Action"], str) else statement["Action"])
                   for prefix in ("s3:", "ec2:", "cognito-idp:Create", "lambda:Invoke"))


def test_scheduler_passrole_and_delete_are_bound_to_exact_stack_and_cfn_target_input():
    template = _cleanup()
    resources = template["Resources"]
    scheduler = resources["BootstrapCleanupSchedulerRole"]["Properties"]
    statements = scheduler["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements[0]["Action"] == "cloudformation:DeleteStack"
    stack_arn_template = statements[0]["Resource"]["Fn::Sub"]
    assert stack_arn_template.endswith(f"/honda-mapit-mcp-dev/{_STACK_UUID}")
    assert "*" not in stack_arn_template
    pass_role = statements[1]
    assert pass_role["Action"] == "iam:PassRole"
    assert pass_role["Resource"] == {"Fn::GetAtt": ["BootstrapDeletionRole", "Arn"]}
    assert pass_role["Condition"] == {
        "StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}
    }

    target = resources["BootstrapCleanupSchedule"]["Properties"]["Target"]
    assert target["RoleArn"] == {"Fn::GetAtt": ["BootstrapCleanupSchedulerRole", "Arn"]}
    substitution = target["Input"]["Fn::Sub"]
    assert substitution[1] == {
        "StackArn": {"Fn::Sub": stack_arn_template},
        "DeletionRoleArn": {"Fn::GetAtt": ["BootstrapDeletionRole", "Arn"]},
    }
    resolved = _resolve_substitution(substitution[0], {
        "StackArn": _resolve_substitution(stack_arn_template, {
            "AWS::Partition": "aws", "AWS::Region": "eu-west-1", "AWS::AccountId": _ACCOUNT,
        }),
        "DeletionRoleArn": f"arn:aws:iam::{_ACCOUNT}:role/honda-mapit-mcp-dev-bootstrap-delete",
    })
    assert json.loads(resolved) == {
        "StackName": f"arn:aws:cloudformation:eu-west-1:{_ACCOUNT}:stack/honda-mapit-mcp-dev/{_STACK_UUID}",
        "RoleARN": f"arn:aws:iam::{_ACCOUNT}:role/honda-mapit-mcp-dev-bootstrap-delete",
    }


def test_wrapper_keeps_shutdown_eight_and_replaces_only_legacy_cleanup_three_with_four():
    template = _bundle()
    resources = template["Resources"]
    assert len(resources) == 12
    assert {
        "ShutdownWorkflowRole", "ShutdownStateMachine", "SchedulerGroup",
        "SchedulerInvokeRole", "ShutdownSchedule", "RequestTripwireAlarm",
        "RequestTripwireEventRole", "RequestTripwireAlarmRule",
    } <= set(resources)
    assert {
        "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup",
        "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
    } <= set(resources)
    assert not {"CleanupScheduleGroup", "CleanupSchedulerRole", "CleanupSchedule"} & set(resources)
    assert all(item["Condition"] == "SupportedRegion" for item in resources.values())
    assert resources["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert template["Metadata"]["NoActivation"] is True
    assert template["Metadata"]["EpochSnapshot"]["CleanupSchedule"] == 1_800_002_700
    assert template["Metadata"]["Components"]["ApplicationCleanup"]["FixedTargetStack"] == "honda-mapit-mcp-dev"
    assert "associated CloudFormation service role" not in repr(template["Metadata"])
