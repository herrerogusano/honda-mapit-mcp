"""Pure generator for a fixed-target development shutdown ASL definition.

This module does not create or deploy a state machine. The resulting document
is an offline artifact for review; it is not evidence of AWS service behavior.
"""

from __future__ import annotations

from typing import Any

from .aws_dev_shutdown import AwsDevShutdownPolicy

_FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
_TASK_TIMEOUT_SECONDS = 5
_WORKFLOW_TIMEOUT_SECONDS = 45


def build_dev_shutdown_workflow(policy: AwsDevShutdownPolicy) -> dict[str, Any]:
    """Return a fresh ASL definition for the one approved development target.

    Caller input is replaced at the first Pass state. SDK responses are used
    only for typed readback checks and are excluded from the final projection.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")
    policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    if policy.function_name != _FUNCTION_NAME:
        raise ValueError("unsupported development function target")

    def task(resource: str, parameters: dict[str, Any], result_path: str | None, next_state: str,
             error_state: str) -> dict[str, Any]:
        return {
            "Type": "Task",
            "Resource": resource,
            "Parameters": parameters,
            "TimeoutSeconds": _TASK_TIMEOUT_SECONDS,
            "ResultPath": result_path,
            "Next": next_state,
            "Catch": [
                {"ErrorEquals": ["States.DataLimitExceeded"], "ResultPath": None, "Next": error_state},
                {"ErrorEquals": ["States.ALL"], "ResultPath": None, "Next": error_state},
            ],
        }

    def flag_pass(name: str, value: Any, next_state: str) -> dict[str, Any]:
        return {"Type": "Pass", "Result": value, "ResultPath": f"$.{name}", "Next": next_state}

    states: dict[str, Any] = {
        "Initialize": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned": False,
                "function_write_call_returned": False,
                "api_closed": False,
                "function_reserved": False,
                "api_status": "readback_not_checked",
                "function_status": "readback_not_checked",
                "verified": False,
                "category": "shutdown_unverified",
            },
            "ResultPath": "$",
            "Next": "DisableApiEndpoint",
        },
        "DisableApiEndpoint": task(
            "arn:aws:states:::aws-sdk:apigatewayv2:updateApi",
            {"ApiId": policy.api_id, "DisableExecuteApiEndpoint": True},
            None,
            "ApiWriteReturned",
            "ApiWriteFailed",
        ),
        "ApiWriteReturned": flag_pass("api_write_call_returned", True, "ReserveFunctionConcurrency"),
        "ApiWriteFailed": flag_pass("api_status", "api_write_call_failed", "ReserveFunctionConcurrency"),
        "ReserveFunctionConcurrency": task(
            "arn:aws:states:::aws-sdk:lambda:putFunctionConcurrency",
            {"FunctionName": _FUNCTION_NAME, "ReservedConcurrentExecutions": 0},
            None,
            "FunctionWriteReturned",
            "FunctionWriteFailed",
        ),
        "FunctionWriteReturned": flag_pass("function_write_call_returned", True, "ReadApiEndpoint"),
        "FunctionWriteFailed": flag_pass("function_status", "function_write_call_failed", "ReadApiEndpoint"),
        "ReadApiEndpoint": task(
            "arn:aws:states:::aws-sdk:apigatewayv2:getApi",
            {"ApiId": policy.api_id},
            "$.api_response",
            "CheckApiFieldPresent",
            "ApiReadFailed",
        ),
        "ApiReadFailed": flag_pass("api_status", "api_readback_failed", "ReadFunctionConcurrency"),
        "CheckApiFieldPresent": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.api_response.DisableExecuteApiEndpoint", "IsPresent": True, "Next": "CheckApiFieldType"}],
            "Default": "ApiReadInvalid",
        },
        "CheckApiFieldType": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.api_response.DisableExecuteApiEndpoint", "IsBoolean": True, "Next": "CheckApiClosed"}],
            "Default": "ApiReadInvalid",
        },
        "CheckApiClosed": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.api_response.DisableExecuteApiEndpoint", "BooleanEquals": True, "Next": "ApiReadClosed"}],
            "Default": "ApiNotClosed",
        },
        "ApiReadClosed": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned.$": "$.api_write_call_returned",
                "function_write_call_returned.$": "$.function_write_call_returned",
                "api_closed": True,
                "function_reserved.$": "$.function_reserved",
                "api_status": "api_closed",
                "function_status.$": "$.function_status",
                "verified": False,
                "category": "shutdown_unverified",
            },
            "ResultPath": "$",
            "Next": "ReadFunctionConcurrency",
        },
        "ApiNotClosed": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned.$": "$.api_write_call_returned",
                "function_write_call_returned.$": "$.function_write_call_returned",
                "api_closed": False,
                "function_reserved.$": "$.function_reserved",
                "api_status": "api_not_closed",
                "function_status.$": "$.function_status",
                "verified": False,
                "category": "shutdown_unverified",
            },
            "ResultPath": "$",
            "Next": "ReadFunctionConcurrency",
        },
        "ApiReadInvalid": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned.$": "$.api_write_call_returned",
                "function_write_call_returned.$": "$.function_write_call_returned",
                "api_closed": False,
                "function_reserved.$": "$.function_reserved",
                "api_status": "api_readback_invalid",
                "function_status.$": "$.function_status",
                "verified": False,
                "category": "shutdown_unverified",
            },
            "ResultPath": "$",
            "Next": "ReadFunctionConcurrency",
        },
        "ReadFunctionConcurrency": task(
            "arn:aws:states:::aws-sdk:lambda:getFunctionConcurrency",
            {"FunctionName": _FUNCTION_NAME},
            "$.function_response",
            "CheckFunctionFieldPresent",
            "FunctionReadFailed",
        ),
        "FunctionReadFailed": flag_pass("function_status", "function_readback_failed", "BuildFinalResult"),
        "CheckFunctionFieldPresent": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.function_response.ReservedConcurrentExecutions", "IsPresent": True, "Next": "CheckFunctionFieldType"}],
            "Default": "FunctionReadInvalid",
        },
        "CheckFunctionFieldType": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.function_response.ReservedConcurrentExecutions", "IsNumeric": True, "Next": "CheckFunctionReserved"}],
            "Default": "FunctionReadInvalid",
        },
        "CheckFunctionReserved": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.function_response.ReservedConcurrentExecutions", "NumericEquals": 0, "Next": "FunctionIsReserved"}],
            "Default": "FunctionNotReserved",
        },
        "FunctionIsReserved": flag_pass("function_reserved", True, "MarkFunctionVerified"),
        "MarkFunctionVerified": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned.$": "$.api_write_call_returned",
                "function_write_call_returned.$": "$.function_write_call_returned",
                "api_closed.$": "$.api_closed",
                "function_reserved.$": "$.function_reserved",
                "api_status.$": "$.api_status",
                "function_status": "function_reserved",
                "verified": False,
                "category": "shutdown_unverified",
            },
            "ResultPath": "$",
            "Next": "CheckFullyVerified",
        },
        "FunctionNotReserved": flag_pass("function_status", "function_not_reserved", "BuildFinalResult"),
        "FunctionReadInvalid": flag_pass("function_status", "function_readback_invalid", "BuildFinalResult"),
        "CheckFullyVerified": {
            "Type": "Choice",
            "Choices": [
                {"Variable": "$.api_closed", "IsPresent": True, "Next": "CheckApiVerifiedType"}
            ],
            "Default": "BuildFinalResult",
        },
        "CheckApiVerifiedType": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.api_closed", "IsBoolean": True, "Next": "CompareApiVerified"}],
            "Default": "BuildFinalResult",
        },
        "CompareApiVerified": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.api_closed", "BooleanEquals": True, "Next": "CheckFunctionVerifiedType"}],
            "Default": "BuildFinalResult",
        },
        "CheckFunctionVerifiedType": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.function_reserved", "IsPresent": True, "Next": "CheckFunctionVerifiedBoolean"}],
            "Default": "BuildFinalResult",
        },
        "CheckFunctionVerifiedBoolean": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.function_reserved", "IsBoolean": True, "Next": "CompareFunctionVerified"}],
            "Default": "BuildFinalResult",
        },
        "CompareFunctionVerified": {
            "Type": "Choice",
            "Choices": [{"Variable": "$.function_reserved", "BooleanEquals": True, "Next": "MarkVerified"}],
            "Default": "BuildFinalResult",
        },
        "MarkVerified": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned.$": "$.api_write_call_returned",
                "function_write_call_returned.$": "$.function_write_call_returned",
                "api_closed": True,
                "function_reserved": True,
                "api_status.$": "$.api_status",
                "function_status.$": "$.function_status",
                "verified": True,
                "category": "shutdown_verified",
            },
            "ResultPath": "$",
            "Next": "BuildFinalResult",
        },
        "BuildFinalResult": {
            "Type": "Pass",
            "Parameters": {
                "api_write_call_returned.$": "$.api_write_call_returned",
                "function_write_call_returned.$": "$.function_write_call_returned",
                "api_closed.$": "$.api_closed",
                "function_reserved.$": "$.function_reserved",
                "verified.$": "$.verified",
                "category.$": "$.category",
                "api_status.$": "$.api_status",
                "function_status.$": "$.function_status",
            },
            "ResultPath": "$",
            "End": True,
        },
    }

    return {
        "Comment": "Offline-generated fixed-target dev shutdown workflow; review only.",
        "StartAt": "Initialize",
        "TimeoutSeconds": _WORKFLOW_TIMEOUT_SECONDS,
        "States": states,
    }


__all__ = ["build_dev_shutdown_workflow"]
