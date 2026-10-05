from __future__ import annotations

import pytest

from mapit.aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy


def _template(pool: str = "eu-west-1_123456789ABC", stack_uuid: str = "12345678-1234-1234-1234-123456789abc"):
    return build_dev_bootstrap_cleanup(
        AwsDevShutdownPolicy("a1b2c3d4e5"), pool, stack_uuid, "2026-10-02T18:30:00"
    )


def test_bootstrap_cleanup_is_four_fixed_disabled_resources_in_one_region() -> None:
    template = _template()
    resources = template["Resources"]
    assert set(resources) == {
        "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup",
        "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
    }
    assert all(resource["Condition"] == "SupportedRegion" for resource in resources.values())
    expected_tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "bootstrap-cleanup"},
    ]
    for name, resource in resources.items():
        if name == "BootstrapCleanupSchedule":
            assert "Tags" not in resource["Properties"]
        else:
            assert resource["Properties"]["Tags"] == expected_tags
    assert template["Conditions"] == {
        "SupportedRegion": {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]}
    }
    assert template["Metadata"]["Readiness"] == "COMPONENT_NOT_DEPLOY_READY"
    assert template["Metadata"]["NoActivation"] is True
    assert template["Metadata"]["NoHardBillingCap"] is True
    assert resources["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert "honda-mapit-mcp-dev-bootstrap-delete" not in repr(template["Metadata"])


def test_deletion_role_has_cloudformation_trust_and_only_scoped_resource_deletes() -> None:
    props = _template()["Resources"]["BootstrapDeletionRole"]["Properties"]
    assert props["RoleName"] == "honda-mapit-mcp-dev-bootstrap-delete"
    assert props["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow",
        "Principal": {"Service": "cloudformation.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]
    statements = props["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [
        {
            "Effect": "Allow",
            "Action": ["apigateway:GET", "apigateway:DELETE"],
            "Resource": [
                {"Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}::/apis/a1b2c3d4e5"},
                {"Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}::/apis/a1b2c3d4e5/stages/$default"},
            ],
        },
        {
            "Effect": "Allow",
            "Action": "cognito-idp:DeleteUserPool",
            "Resource": {"Fn::Sub": "arn:${AWS::Partition}:cognito-idp:${AWS::Region}:${AWS::AccountId}:userpool/eu-west-1_123456789ABC"},
        },
        {
            "Effect": "Allow",
            "Action": ["lambda:DeleteFunction", "lambda:GetFunction"],
            "Resource": {"Fn::Sub": "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:honda-mapit-mcp-dev-handler"},
        },
        {
            "Effect": "Allow",
            "Action": [
                "iam:DeleteRole", "iam:DetachRolePolicy", "iam:DeleteRolePolicy", "iam:GetRole",
                "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:TagRole", "iam:UntagRole",
            ],
            "Resource": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/honda-mapit-mcp-dev-handler-role"},
        },
        {
            "Effect": "Allow",
            "Action": "logs:DescribeLogGroups",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
        },
        {
            "Effect": "Allow",
            "Action": ["logs:DeleteLogGroup", "logs:DeleteDataProtectionPolicy"],
            "Resource": [
                {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/honda-mapit-mcp-dev-handler"},
                {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/honda-mapit-mcp-dev-handler:*"},
            ],
        },
    ]
    rendered = repr(statements)
    for excluded in ("s3:", "ec2:", "DeleteUserPoolClient", "DeleteUserPoolDomain", "DeleteStack", "Resource': '*' "):
        assert excluded not in rendered


def test_scheduler_role_can_delete_only_exact_stack_and_pass_only_exact_deletion_role() -> None:
    props = _template()["Resources"]["BootstrapCleanupSchedulerRole"]["Properties"]
    trust = props["AssumeRolePolicyDocument"]["Statement"][0]
    assert trust["Principal"] == {"Service": "scheduler.amazonaws.com"}
    assert trust["Condition"]["StringEquals"] == {"aws:SourceAccount": {"Ref": "AWS::AccountId"}}
    assert trust["Condition"]["ArnEquals"]["aws:SourceArn"]["Fn::Sub"].endswith(
        ":schedule-group/honda-mapit-mcp-dev-bootstrap-cleanup"
    )
    statements = props["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [
        {
            "Effect": "Allow",
            "Action": "cloudformation:DeleteStack",
            "Resource": {
                "Fn::Sub": "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/honda-mapit-mcp-dev/12345678-1234-1234-1234-123456789abc"
            },
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": {"Fn::GetAtt": ["BootstrapDeletionRole", "Arn"]},
            "Condition": {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}},
        },
    ]


def test_schedule_passes_exact_stack_arn_and_role_without_retry() -> None:
    props = _template()["Resources"]["BootstrapCleanupSchedule"]["Properties"]
    assert props["Name"] == "honda-mapit-mcp-dev-bootstrap-delete-once"
    assert props["GroupName"] == {"Ref": "BootstrapCleanupScheduleGroup"}
    assert props["ScheduleExpression"] == "at(2026-10-02T18:30:00)"
    assert props["ScheduleExpressionTimezone"] == "UTC"
    assert props["FlexibleTimeWindow"] == {"Mode": "OFF"}
    target = props["Target"]
    assert target["Arn"] == "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
    assert target["RoleArn"] == {"Fn::GetAtt": ["BootstrapCleanupSchedulerRole", "Arn"]}
    assert target["Input"] == {
        "Fn::Sub": [
            '{"StackName":"${StackArn}","RoleARN":"${DeletionRoleArn}"}',
            {
                "StackArn": {"Fn::Sub": "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/honda-mapit-mcp-dev/12345678-1234-1234-1234-123456789abc"},
                "DeletionRoleArn": {"Fn::GetAtt": ["BootstrapDeletionRole", "Arn"]},
            },
        ]
    }
    assert target["RetryPolicy"] == {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}


@pytest.mark.parametrize("pool", [
    "us-east-1_123456789", "eu-west-1_short", "eu-west-1_" + "x" * 46,
    "eu-west-1_123456789!", "eu-west-1_123456789\n",
])
def test_user_pool_id_must_be_canonical_eu_west_1_and_at_most_55_chars(pool: str) -> None:
    with pytest.raises(ValueError):
        _template(pool=pool)


@pytest.mark.parametrize("stack_uuid", [
    "", "00000000-0000-0000-0000-000000000000", "12345678123412341234123456789abc",
    "12345678-1234-1234-1234-123456789ABC", "not-a-uuid",
])
def test_stack_uuid_must_be_canonical_lowercase_and_non_null(stack_uuid: str) -> None:
    with pytest.raises(ValueError):
        _template(stack_uuid=stack_uuid)


@pytest.mark.parametrize("timestamp", [
    "2026-2-02T18:30:00", "2026-02-30T18:30:00", "2026-10-02T18:30:00Z",
    "2026-10-02T18:30", "2026-10-02T18:30:00\n",
])
def test_schedule_timestamp_requires_canonical_utc_second(timestamp: str) -> None:
    with pytest.raises(ValueError):
        build_dev_bootstrap_cleanup(AwsDevShutdownPolicy("a1b2c3d4e5"), "eu-west-1_123456789ABC", "12345678-1234-1234-1234-123456789abc", timestamp)


def test_mutated_policy_fails_closed() -> None:
    policy = AwsDevShutdownPolicy("a1b2c3d4e5")
    object.__setattr__(policy, "api_id", "bad")
    with pytest.raises(ValueError):
        build_dev_bootstrap_cleanup(policy, "eu-west-1_123456789ABC", "12345678-1234-1234-1234-123456789abc", "2026-10-02T18:30:00")
