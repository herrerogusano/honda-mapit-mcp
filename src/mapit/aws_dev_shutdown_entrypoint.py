"""Dedicated, fixed-target AWS Lambda entrypoint for dev shutdown.

The module does not inspect event/context data or construct SDK objects until
its environment is validated. It returns only the closed result schema from
the offline shutdown core; no provider diagnostics are logged or returned.
"""

from __future__ import annotations

import importlib
import os
import re
from typing import Any

from .aws_dev_shutdown import AwsDevShutdownPolicy, AwsDevShutdownResult, close_dev_runtime

ENV_MAPIT_MCP_ENV = "MAPIT_MCP_ENV"
ENV_AWS_REGION = "AWS_REGION"
ENV_API_ID = "MAPIT_API_ID"
ENV_LAMBDA_FUNCTION_NAME = "AWS_LAMBDA_FUNCTION_NAME"

DEV_REGION = "eu-west-1"
SHUTDOWN_LAMBDA_NAME = "honda-mapit-mcp-dev-shutdown"
_API_ID = re.compile(r"^[a-z0-9]{10}$")

_UNAVAILABLE_RESULT = {
    "api_write_call_returned": False,
    "function_write_call_returned": False,
    "api_closed": False,
    "function_reserved": False,
    "verified": False,
    "category": "shutdown_unavailable",
    "warnings": ("shutdown_setup_failed",),
}


class _UnavailableApiClient:
    """Fail the API operations safely while allowing Lambda closure to proceed."""

    @staticmethod
    def update_api(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError

    @staticmethod
    def get_api(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError


class _UnavailableLambdaClient:
    """Fail the Lambda operations safely while allowing API closure to proceed."""

    @staticmethod
    def put_function_concurrency(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError

    @staticmethod
    def get_function_concurrency(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError


def _validated_policy() -> AwsDevShutdownPolicy | None:
    if os.environ.get(ENV_MAPIT_MCP_ENV) != "dev":
        return None
    if os.environ.get(ENV_AWS_REGION) != DEV_REGION:
        return None
    if os.environ.get(ENV_LAMBDA_FUNCTION_NAME) != SHUTDOWN_LAMBDA_NAME:
        return None
    api_id = os.environ.get(ENV_API_ID)
    if not isinstance(api_id, str) or not _API_ID.fullmatch(api_id):
        return None
    try:
        return AwsDevShutdownPolicy(api_id=api_id, region=DEV_REGION)
    except (TypeError, ValueError):
        return None


def _public_result(result: AwsDevShutdownResult) -> dict[str, Any]:
    if type(result) is not AwsDevShutdownResult:
        return dict(_UNAVAILABLE_RESULT)
    if (
        type(result.api_write_call_returned) is not bool
        or type(result.function_write_call_returned) is not bool
        or type(result.api_closed) is not bool
        or type(result.function_reserved) is not bool
        or type(result.verified) is not bool
        or result.category not in {"shutdown_verified", "shutdown_unverified"}
        or type(result.warnings) is not tuple
        or any(type(item) is not str for item in result.warnings)
    ):
        return dict(_UNAVAILABLE_RESULT)
    allowed_warnings = {
        "api_write_failed",
        "function_write_failed",
        "api_readback_failed",
        "api_readback_invalid",
        "api_not_closed",
        "function_readback_failed",
        "function_readback_invalid",
        "function_not_reserved",
    }
    if any(item not in allowed_warnings for item in result.warnings):
        return dict(_UNAVAILABLE_RESULT)
    # Build a fresh closed projection; never serialize the dataclass/provider data.
    return {
        "api_write_call_returned": result.api_write_call_returned,
        "function_write_call_returned": result.function_write_call_returned,
        "api_closed": result.api_closed,
        "function_reserved": result.function_reserved,
        "verified": result.verified,
        "category": result.category,
        "warnings": result.warnings,
    }


def handler(event: Any, context: Any) -> dict[str, Any]:
    """Run only the fixed development shutdown; event and context are ignored."""
    del event, context
    policy = _validated_policy()
    if policy is None:
        return dict(_UNAVAILABLE_RESULT)

    # Lazy and strictly after environment validation, so the offline MCP package
    # does not acquire boto3 as a runtime dependency.
    try:
        boto3 = importlib.import_module("boto3")
        botocore_config = importlib.import_module("botocore.config")
        sdk_config = botocore_config.Config(
            retries={"mode": "standard", "total_max_attempts": 1},
            connect_timeout=2,
            read_timeout=3,
        )
        session = boto3.Session(region_name=DEV_REGION)
    except Exception:
        return dict(_UNAVAILABLE_RESULT)

    try:
        api_client = session.client("apigatewayv2", region_name=DEV_REGION, config=sdk_config)
    except Exception:
        api_client = _UnavailableApiClient()
    try:
        lambda_client = session.client("lambda", region_name=DEV_REGION, config=sdk_config)
    except Exception:
        lambda_client = _UnavailableLambdaClient()

    try:
        result = close_dev_runtime(policy, api_client, lambda_client)
    except Exception:
        return dict(_UNAVAILABLE_RESULT)
    return _public_result(result)


__all__ = [
    "DEV_REGION",
    "ENV_API_ID",
    "ENV_AWS_REGION",
    "ENV_LAMBDA_FUNCTION_NAME",
    "ENV_MAPIT_MCP_ENV",
    "SHUTDOWN_LAMBDA_NAME",
    "handler",
]
