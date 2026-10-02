"""Offline draft for scoped deletion of the fixed dev bootstrap resources.

The factory does not call AWS or activate its one-time cleanup schedule. The
schedule and its roles are review artifacts requiring separate deployment
approval and exact resource readbacks.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from .aws_dev_shutdown import AwsDevShutdownPolicy

_REGION = "eu-west-1"
_FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
_HANDLER_ROLE_NAME = "honda-mapit-mcp-dev-handler-role"
_LOG_GROUP_NAME = "/aws/lambda/honda-mapit-mcp-dev-handler"
_APP_STACK_NAME = "honda-mapit-mcp-dev"
_DELETION_ROLE_NAME = "honda-mapit-mcp-dev-bootstrap-delete"
_SCHEDULER_GROUP_NAME = "honda-mapit-mcp-dev-bootstrap-cleanup"
_SCHEDULE_NAME = "honda-mapit-mcp-dev-bootstrap-delete-once"
_SCHEDULE_TARGET_ARN = "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")
_UTC_SECOND = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")


def _validated_utc_schedule(value: str) -> str:
    if type(value) is not str or not _UTC_SECOND.fullmatch(value):
        raise ValueError("a canonical UTC timestamp is required")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValueError("a canonical UTC timestamp is required") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S") != value:
        raise ValueError("a canonical UTC timestamp is required")
    return value


def _validated_stack_uuid(value: str) -> str:
    if type(value) is not str:
        raise ValueError("a canonical stack UUID is required")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise ValueError("a canonical stack UUID is required") from None
    if str(parsed) != value or parsed.int == 0:
        raise ValueError("a canonical stack UUID is required")
    return value


def build_dev_bootstrap_cleanup(
    policy: AwsDevShutdownPolicy,
    user_pool_id: str,
    stack_uuid: str,
    schedule_at_utc: str,
) -> dict[str, Any]:
    """Build a disabled, exact-target cleanup schedule for bootstrap resources."""
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")
    policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    if policy.region != _REGION:
        raise ValueError("unsupported development region")
    if type(user_pool_id) is not str or not _POOL_ID.fullmatch(user_pool_id):
        raise ValueError("invalid development user pool target")
    stack_uuid = _validated_stack_uuid(stack_uuid)
    schedule_at = _validated_utc_schedule(schedule_at_utc)

    api_root_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}"
    }
    api_stage_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}/stages/$default"
    }
    pool_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{user_pool_id}"
    }
    function_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{_FUNCTION_NAME}"
    }
    handler_role_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:iam::${{AWS::AccountId}}:role/{_HANDLER_ROLE_NAME}"
    }
    log_group_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:{_LOG_GROUP_NAME}"
    }
    stack_arn = {
        "Fn::Sub": (
            f"arn:${{AWS::Partition}}:cloudformation:${{AWS::Region}}:${{AWS::AccountId}}:"
            f"stack/{_APP_STACK_NAME}/{stack_uuid}"
        )
    }
    schedule_group_arn = {
        "Fn::Sub": (
            f"arn:${{AWS::Partition}}:scheduler:${{AWS::Region}}:${{AWS::AccountId}}:"
            f"schedule-group/{_SCHEDULER_GROUP_NAME}"
        )
    }
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "bootstrap-cleanup"},
    ]
    delete_role_arn = {"Fn::GetAtt": ["BootstrapDeletionRole", "Arn"]}

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Review-only disabled bootstrap cleanup component; not deployment-ready.",
        "Metadata": {
            "Readiness": "COMPONENT_NOT_DEPLOY_READY",
            "Region": _REGION,
            "NoActivation": True,
            "FixedTargetStack": _APP_STACK_NAME,
            "FixedTargetFunction": _FUNCTION_NAME,
            "ScheduleTimestampPolicy": "Canonical UTC syntax only; deployment-time timing/lifetime guard is required.",
            "NoHardBillingCap": True,
            "MissingPrerequisites": [
                "reviewed stack UUID and pool/API readbacks",
                "deployment-time future schedule and resource-lifetime guard",
                "IAM and cleanup permissions independently reviewed",
                "operator confirms app stack absence before control cleanup",
            ],
        },
        "Conditions": {
            "SupportedRegion": {"Fn::Equals": [{"Ref": "AWS::Region"}, _REGION]}
        },
        "Resources": {
            "BootstrapDeletionRole": {
                "Type": "AWS::IAM::Role",
                "Condition": "SupportedRegion",
                "Properties": {
                    "RoleName": _DELETION_ROLE_NAME,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "cloudformation.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "delete-only-fixed-bootstrap-resources",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["apigateway:GET", "apigateway:DELETE"],
                                    "Resource": [api_root_arn, api_stage_arn],
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "cognito-idp:DeleteUserPool",
                                    "Resource": pool_arn,
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["lambda:DeleteFunction", "lambda:GetFunction"],
                                    "Resource": function_arn,
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:DeleteRole", "iam:DetachRolePolicy", "iam:DeleteRolePolicy",
                                        "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:ListRolePolicies",
                                        "iam:TagRole", "iam:UntagRole",
                                    ],
                                    "Resource": handler_role_arn,
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "logs:DescribeLogGroups",
                                    "Resource": "*",
                                    "Condition": {"StringEquals": {"aws:RequestedRegion": _REGION}},
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["logs:DeleteLogGroup", "logs:DeleteDataProtectionPolicy"],
                                    "Resource": [log_group_arn, {"Fn::Sub": f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:{_LOG_GROUP_NAME}:*"}],
                                },
                            ],
                        },
                    }],
                    "Tags": tags,
                },
            },
            "BootstrapCleanupScheduleGroup": {
                "Type": "AWS::Scheduler::ScheduleGroup",
                "Condition": "SupportedRegion",
                "Properties": {"Name": _SCHEDULER_GROUP_NAME, "Tags": tags},
            },
            "BootstrapCleanupSchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Condition": "SupportedRegion",
                "Properties": {
                    "RoleName": "honda-mapit-mcp-dev-bootstrap-cleanup-scheduler",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "scheduler.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                                "ArnEquals": {"aws:SourceArn": schedule_group_arn},
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "delete-only-fixed-bootstrap-stack-and-pass-role",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Effect": "Allow", "Action": "cloudformation:DeleteStack", "Resource": stack_arn},
                                {
                                    "Effect": "Allow",
                                    "Action": "iam:PassRole",
                                    "Resource": delete_role_arn,
                                    "Condition": {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}},
                                },
                            ],
                        },
                    }],
                    "Tags": tags,
                },
            },
            "BootstrapCleanupSchedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Condition": "SupportedRegion",
                "Properties": {
                    "Name": _SCHEDULE_NAME,
                    "GroupName": {"Ref": "BootstrapCleanupScheduleGroup"},
                    "State": "DISABLED",
                    "ScheduleExpression": f"at({schedule_at})",
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": _SCHEDULE_TARGET_ARN,
                        "RoleArn": {"Fn::GetAtt": ["BootstrapCleanupSchedulerRole", "Arn"]},
                        "Input": {
                            "Fn::Sub": [
                                '{"StackName":"${StackArn}","RoleARN":"${DeletionRoleArn}"}',
                                {"StackArn": stack_arn, "DeletionRoleArn": delete_role_arn},
                            ]
                        },
                        "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
                    },
                },
            },
        },
    }


__all__ = ["build_dev_bootstrap_cleanup"]
