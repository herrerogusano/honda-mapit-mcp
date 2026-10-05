"""Offline-only, fixed-target core for closing the synthetic dev runtime."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

_API_ID = re.compile(r"^[a-z0-9]{10}$")
_DEV_FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
_REGION = "eu-west-1"


class DevApiClient(Protocol):
    def update_api(self, *, ApiId: str, DisableExecuteApiEndpoint: bool) -> Any: ...

    def get_api(self, *, ApiId: str) -> Mapping[str, Any]: ...


class DevLambdaClient(Protocol):
    def put_function_concurrency(self, *, FunctionName: str, ReservedConcurrentExecutions: int) -> Any: ...

    def get_function_concurrency(self, *, FunctionName: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class AwsDevShutdownPolicy:
    """Exact dev API target; the Lambda target is a fixed derived constant."""

    api_id: str
    region: str = _REGION

    def __post_init__(self) -> None:
        if type(self.api_id) is not str or not _API_ID.fullmatch(self.api_id):
            raise ValueError("invalid development API target")
        if type(self.region) is not str or self.region != _REGION:
            raise ValueError("unsupported development region")

    @property
    def function_name(self) -> str:
        return _DEV_FUNCTION_NAME


@dataclass(frozen=True)
class AwsDevShutdownResult:
    """Closed, non-sensitive outcome; never contains provider response data."""

    api_write_call_returned: bool
    function_write_call_returned: bool
    api_closed: bool
    function_reserved: bool
    verified: bool
    category: str
    warnings: tuple[str, ...]


def _api_readback_is_closed(response: Any) -> tuple[bool, str | None]:
    if not isinstance(response, Mapping):
        return False, "api_readback_invalid"
    value = response.get("DisableExecuteApiEndpoint")
    if type(value) is not bool:
        return False, "api_readback_invalid"
    if value is not True:
        return False, "api_not_closed"
    return True, None


def _function_readback_is_reserved(response: Any) -> tuple[bool, str | None]:
    if not isinstance(response, Mapping):
        return False, "function_readback_invalid"
    value = response.get("ReservedConcurrentExecutions")
    if type(value) is not int:
        return False, "function_readback_invalid"
    if value != 0:
        return False, "function_not_reserved"
    return True, None


def close_dev_runtime(
    policy: AwsDevShutdownPolicy,
    api_client: DevApiClient,
    lambda_client: DevLambdaClient,
) -> AwsDevShutdownResult:
    """Attempt two fixed writes then both independent readbacks exactly once.

    This core has no SDK, credential, environment, or network construction. Its
    only effects are calls on the two explicitly injected client objects.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")

    warnings: list[str] = []
    try:
        api_client.update_api(ApiId=policy.api_id, DisableExecuteApiEndpoint=True)
        api_write_call_returned = True
    except Exception:
        api_write_call_returned = False
        warnings.append("api_write_failed")

    try:
        lambda_client.put_function_concurrency(
            FunctionName=policy.function_name,
            ReservedConcurrentExecutions=0,
        )
        function_write_call_returned = True
    except Exception:
        function_write_call_returned = False
        warnings.append("function_write_failed")

    try:
        api_response = api_client.get_api(ApiId=policy.api_id)
        api_closed, api_category = _api_readback_is_closed(api_response)
    except Exception:
        api_closed, api_category = False, "api_readback_failed"
    if api_category is not None:
        warnings.append(api_category)

    try:
        function_response = lambda_client.get_function_concurrency(FunctionName=policy.function_name)
        function_reserved, function_category = _function_readback_is_reserved(function_response)
    except Exception:
        function_reserved, function_category = False, "function_readback_failed"
    if function_category is not None:
        warnings.append(function_category)

    verified = api_closed and function_reserved
    return AwsDevShutdownResult(
        api_write_call_returned=api_write_call_returned,
        function_write_call_returned=function_write_call_returned,
        api_closed=api_closed,
        function_reserved=function_reserved,
        verified=verified,
        category="shutdown_verified" if verified else "shutdown_unverified",
        warnings=tuple(warnings),
    )


__all__ = ["AwsDevShutdownPolicy", "AwsDevShutdownResult", "DevApiClient", "DevLambdaClient", "close_dev_runtime"]
