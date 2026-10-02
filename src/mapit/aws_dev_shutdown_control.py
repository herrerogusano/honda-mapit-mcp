"""Offline-only CloudFormation component for a disabled dev shutdown schedule.

This is a review artifact, not a deployable or deployment-ready template. It
does not create resources, validate a future deadline against a clock, or call
AWS. Deployment-time guards and cleanup remain separate prerequisites.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from .aws_dev_shutdown import AwsDevShutdownPolicy
from .aws_dev_shutdown_workflow import build_dev_shutdown_workflow

_REGION = "eu-west-1"
_FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
_STATE_MACHINE_NAME = "honda-mapit-mcp-dev-shutdown"
_SCHEDULE_GROUP = "honda-mapit-mcp-dev-safety"
_SCHEDULE_NAME = "honda-mapit-mcp-dev-close-once"
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


def build_dev_shutdown_control(
    policy: AwsDevShutdownPolicy,
    schedule_at_utc: str,
) -> dict[str, Any]:
    """Build a fixed-target, disabled ASL/Scheduler/role review component.

    The timestamp is validated for canonical calendar syntax only. Whether it
    is sufficiently far in the future must be checked at deployment time.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")
    policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    if policy.region != _REGION or policy.function_name != _FUNCTION_NAME:
        raise ValueError("unsupported development shutdown target")
    schedule_at = _validated_schedule_time(schedule_at_utc)

    api_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}"
    }
    function_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{_FUNCTION_NAME}"
    }
    state_machine_arn = {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]}
    group_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:scheduler:${{AWS::Region}}:${{AWS::AccountId}}:schedule-group/{_SCHEDULE_GROUP}"
    }
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "shutdown-control"},
    ]

    resources: dict[str, Any] = {
        "ShutdownWorkflowRole": {
            "Type": "AWS::IAM::Role",
            "Condition": "SupportedRegion",
            "Properties": {
                "RoleName": "honda-mapit-mcp-dev-shutdown-workflow",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                        "Condition": {
                            "StringEquals": {"aws:SourceAccount": {"Ref": "AWS::AccountId"}},
                            "ArnLike": {
                                "aws:SourceArn": {
                                    "Fn::Sub": f"arn:${{AWS::Partition}}:states:${{AWS::Region}}:${{AWS::AccountId}}:stateMachine:{_STATE_MACHINE_NAME}"
                                }
                            },
                        },
                    }],
                },
                "Policies": [{
                    "PolicyName": "fixed-dev-shutdown-api-and-function",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "apigateway:PATCH",
                                "Resource": api_arn,
                                "Condition": {
                                    "Bool": {"apigateway:Request/DisableExecuteApiEndpoint": "true"}
                                },
                            },
                            {
                                "Effect": "Allow",
                                "Action": "apigateway:GET",
                                "Resource": api_arn,
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["lambda:PutFunctionConcurrency", "lambda:GetFunctionConcurrency"],
                                "Resource": function_arn,
                            },
                        ],
                    },
                }],
                "Tags": tags,
            },
        },
        "ShutdownStateMachine": {
            "Type": "AWS::StepFunctions::StateMachine",
            "Condition": "SupportedRegion",
            "Properties": {
                "StateMachineName": _STATE_MACHINE_NAME,
                "StateMachineType": "STANDARD",
                "RoleArn": {"Fn::GetAtt": ["ShutdownWorkflowRole", "Arn"]},
                "Definition": build_dev_shutdown_workflow(policy),
                "LoggingConfiguration": {"Level": "OFF"},
                "TracingConfiguration": {"Enabled": False},
                "Tags": tags,
            },
        },
        "SchedulerGroup": {
            "Type": "AWS::Scheduler::ScheduleGroup",
            "Condition": "SupportedRegion",
            "Properties": {"Name": _SCHEDULE_GROUP, "Tags": tags},
        },
        "SchedulerInvokeRole": {
            "Type": "AWS::IAM::Role",
            "Condition": "SupportedRegion",
            "Properties": {
                "RoleName": "honda-mapit-mcp-dev-shutdown-scheduler",
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
                    "PolicyName": "start-only-fixed-shutdown-workflow",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": "states:StartExecution",
                            "Resource": state_machine_arn,
                        }],
                    },
                }],
                "Tags": tags,
            },
        },
        "ShutdownSchedule": {
            "Type": "AWS::Scheduler::Schedule",
            "Condition": "SupportedRegion",
            "Properties": {
                "Name": _SCHEDULE_NAME,
                "GroupName": {"Ref": "SchedulerGroup"},
                "State": "DISABLED",
                "ScheduleExpression": f"at({schedule_at})",
                "ScheduleExpressionTimezone": "UTC",
                "FlexibleTimeWindow": {"Mode": "OFF"},
                "Target": {
                    "Arn": state_machine_arn,
                    "RoleArn": {"Fn::GetAtt": ["SchedulerInvokeRole", "Arn"]},
                    "Input": "{}",
                    "RetryPolicy": {
                        "MaximumRetryAttempts": 0,
                        "MaximumEventAgeInSeconds": 60,
                    },
                },
            },
        },
    }

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Review-only disabled development shutdown control component; not deployment-ready.",
        "Metadata": {
            "Readiness": "COMPONENT_NOT_DEPLOY_READY",
            "Region": _REGION,
            "NoActivation": True,
            "IntendedActionAfterCompletion": "NONE",
            "ActionAfterCompletionNote": (
                "AWS::Scheduler::Schedule CloudFormation schema does not expose this API field; "
                "it is omitted, whose Scheduler API default is NONE. Verify by readback before activation."
            ),
            "ScheduleTimestampPolicy": "Canonical UTC syntax only; deployment-time future guard is required.",
            "MissingPrerequisites": [
                "fresh quota and account binding",
                "verified resource readbacks and armed closure",
                "deployment-time schedule future guard and timing acceptance",
                "owned-resource cleanup procedure",
                "owner and callback binding",
            ],
        },
        "Conditions": {"SupportedRegion": {"Fn::Equals": [{"Ref": "AWS::Region"}, _REGION]}},
        "Resources": resources,
    }


__all__ = ["build_dev_shutdown_control"]
