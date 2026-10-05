"""Offline-only CloudFormation draft for a disabled one-time app deletion.

This component targets only the fixed development application stack. It does
not deploy, inspect, activate, or delete resources, and is not deployment-ready.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

_REGION = "eu-west-1"
_APP_STACK_NAME = "honda-mapit-mcp-dev"
_SCHEDULE_GROUP = "honda-mapit-mcp-dev-cleanup"
_SCHEDULE_NAME = "honda-mapit-mcp-dev-delete-once"
_SCHEDULE_TARGET_ARN = "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
_UTC_SECOND = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$")


def _validated_schedule_time(value: str) -> str:
    if type(value) is not str or not _UTC_SECOND.fullmatch(value):
        raise ValueError("a canonical UTC timestamp is required")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValueError("a canonical UTC timestamp is required") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%S") != value:
        raise ValueError("a canonical UTC timestamp is required")
    return value


def build_dev_cleanup_schedule(schedule_at_utc: str) -> dict[str, Any]:
    """Build a fixed, disabled CloudFormation cleanup-schedule draft.

    Only timestamp syntax/calendar validity is checked here. A deployment
    controller must separately enforce future timing, lifetime, and readbacks.
    """
    schedule_at = _validated_schedule_time(schedule_at_utc)
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "app-stack-cleanup"},
    ]
    group_arn = {
        "Fn::Sub": (
            f"arn:${{AWS::Partition}}:scheduler:${{AWS::Region}}:${{AWS::AccountId}}:"
            f"schedule-group/{_SCHEDULE_GROUP}"
        )
    }
    stack_arn = {
        "Fn::Sub": (
            f"arn:${{AWS::Partition}}:cloudformation:${{AWS::Region}}:${{AWS::AccountId}}:"
            f"stack/{_APP_STACK_NAME}/*"
        )
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Review-only disabled one-time app cleanup schedule; not deployment-ready.",
        "Metadata": {
            "Readiness": "COMPONENT_NOT_DEPLOY_READY",
            "Region": _REGION,
            "NoActivation": True,
            "FixedTargetStack": _APP_STACK_NAME,
            "ActionAfterCompletionNote": (
                "The CloudFormation Schedule schema omits ActionAfterCompletion; omission uses the Scheduler API default NONE. "
                "Retain the schedule as an operator-cleanup anchor and verify by readback."
            ),
            "DeleteStackRoleNote": (
                "Target input omits RoleARN; the app stack must already have an associated CloudFormation service role."
            ),
            "ScheduleTimestampPolicy": "Canonical UTC syntax only; deployment-time future/lifetime guard is required.",
            "MissingPrerequisites": [
                "app stack has the reviewed associated CloudFormation service role and deletion permissions",
                "deployment-time future schedule and before-deadline guard",
                "timing and resource-lifetime acceptance",
                "operator readback confirms app stack absence before control-stack cleanup",
                "control resources are manually cleaned up after app deletion verification",
            ],
            "NoHardBillingCap": True,
        },
        "Conditions": {
            "SupportedRegion": {"Fn::Equals": [{"Ref": "AWS::Region"}, _REGION]}
        },
        "Resources": {
            "CleanupScheduleGroup": {
                "Type": "AWS::Scheduler::ScheduleGroup",
                "Condition": "SupportedRegion",
                "Properties": {"Name": _SCHEDULE_GROUP, "Tags": tags},
            },
            "CleanupSchedulerRole": {
                "Type": "AWS::IAM::Role",
                "Condition": "SupportedRegion",
                "Properties": {
                    "RoleName": "honda-mapit-mcp-dev-cleanup-scheduler",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "scheduler.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                                "ArnLike": {"aws:SourceArn": group_arn},
                            },
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "delete-only-fixed-dev-app-stack",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "cloudformation:DeleteStack",
                                "Resource": stack_arn,
                            }],
                        },
                    }],
                    "Tags": tags,
                },
            },
            "CleanupSchedule": {
                "Type": "AWS::Scheduler::Schedule",
                "Condition": "SupportedRegion",
                "Properties": {
                    "Name": _SCHEDULE_NAME,
                    "GroupName": {"Ref": "CleanupScheduleGroup"},
                    "State": "DISABLED",
                    "ScheduleExpression": f"at({schedule_at})",
                    "ScheduleExpressionTimezone": "UTC",
                    "FlexibleTimeWindow": {"Mode": "OFF"},
                    "Target": {
                        "Arn": _SCHEDULE_TARGET_ARN,
                        "RoleArn": {"Fn::GetAtt": ["CleanupSchedulerRole", "Arn"]},
                        "Input": json.dumps({"StackName": _APP_STACK_NAME}, separators=(",", ":")),
                        "RetryPolicy": {
                            "MaximumRetryAttempts": 0,
                            "MaximumEventAgeInSeconds": 60,
                        },
                    },
                },
            },
        },
    }


__all__ = ["build_dev_cleanup_schedule"]
