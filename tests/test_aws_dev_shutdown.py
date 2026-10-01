from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy, close_dev_runtime

API_ID = "a1b2c3d4e5"
FUNCTION = "honda-mapit-mcp-dev-handler"
_UNSET = object()


class FakeAPI:
    def __init__(self, calls, *, fail=(), response=_UNSET):
        self.calls = calls
        self.fail = set(fail)
        self.response = {"DisableExecuteApiEndpoint": True} if response is _UNSET else response

    def update_api(self, **kwargs):
        self.calls.append(("update_api", kwargs))
        if "update_api" in self.fail:
            raise RuntimeError("provider-secret-canary")
        return {"ignored": "private-update-response"}

    def get_api(self, **kwargs):
        self.calls.append(("get_api", kwargs))
        if "get_api" in self.fail:
            raise RuntimeError("provider-secret-canary")
        return self.response


class FakeLambda:
    def __init__(self, calls, *, fail=(), response=_UNSET):
        self.calls = calls
        self.fail = set(fail)
        self.response = {"ReservedConcurrentExecutions": 0} if response is _UNSET else response

    def put_function_concurrency(self, **kwargs):
        self.calls.append(("put_function_concurrency", kwargs))
        if "put_function_concurrency" in self.fail:
            raise RuntimeError("provider-secret-canary")
        return {"ignored": "private-update-response"}

    def get_function_concurrency(self, **kwargs):
        self.calls.append(("get_function_concurrency", kwargs))
        if "get_function_concurrency" in self.fail:
            raise RuntimeError("provider-secret-canary")
        return self.response


def _clients(*, api_fail=(), lambda_fail=(), api_response=_UNSET, lambda_response=_UNSET):
    calls = []
    return calls, FakeAPI(calls, fail=api_fail, response=api_response), FakeLambda(calls, fail=lambda_fail, response=lambda_response)


def test_success_makes_exactly_four_fixed_calls_in_order_and_verifies_closed():
    policy = AwsDevShutdownPolicy(API_ID)
    calls, api, lambda_client = _clients()
    result = close_dev_runtime(policy, api, lambda_client)

    assert result.verified is True
    assert result.api_closed is True
    assert result.function_reserved is True
    assert result.api_write_call_returned is True
    assert result.function_write_call_returned is True
    assert result.category == "shutdown_verified"
    assert result.warnings == ()
    assert [name for name, _ in calls] == [
        "update_api", "put_function_concurrency", "get_api", "get_function_concurrency"
    ]
    assert calls == [
        ("update_api", {"ApiId": API_ID, "DisableExecuteApiEndpoint": True}),
        ("put_function_concurrency", {"FunctionName": FUNCTION, "ReservedConcurrentExecutions": 0}),
        ("get_api", {"ApiId": API_ID}),
        ("get_function_concurrency", {"FunctionName": FUNCTION}),
    ]


def test_already_closed_readback_can_verify_despite_ambiguous_write_failures():
    calls, api, lambda_client = _clients(api_fail={"update_api"}, lambda_fail={"put_function_concurrency"})
    result = close_dev_runtime(AwsDevShutdownPolicy(API_ID), api, lambda_client)

    assert result.verified is True
    assert result.api_write_call_returned is False
    assert result.function_write_call_returned is False
    assert result.warnings == ("api_write_failed", "function_write_failed")
    assert len(calls) == 4


@pytest.mark.parametrize(
    ("api_fail", "lambda_fail", "expected", "verified"),
    [
        ({"update_api"}, set(), "api_write_failed", True),
        (set(), {"put_function_concurrency"}, "function_write_failed", True),
        ({"get_api"}, set(), "api_readback_failed", False),
        (set(), {"get_function_concurrency"}, "function_readback_failed", False),
        ({"update_api", "get_api"}, {"put_function_concurrency", "get_function_concurrency"}, "api_write_failed", False),
    ],
)
def test_each_operation_failure_is_safe_and_does_not_skip_remaining_calls(api_fail, lambda_fail, expected, verified):
    calls, api, lambda_client = _clients(api_fail=api_fail, lambda_fail=lambda_fail)
    result = close_dev_runtime(AwsDevShutdownPolicy(API_ID), api, lambda_client)
    assert result.verified is verified
    assert result.category == ("shutdown_verified" if verified else "shutdown_unverified")
    assert expected in result.warnings
    assert len(calls) == 4
    assert "provider-secret-canary" not in repr(result)


@pytest.mark.parametrize(
    ("api_response", "lambda_response", "api_closed", "function_reserved", "categories"),
    [
        ({"DisableExecuteApiEndpoint": False}, {"ReservedConcurrentExecutions": 0}, False, True, ("api_not_closed",)),
        ({}, {"ReservedConcurrentExecutions": 0}, False, True, ("api_readback_invalid",)),
        ({"DisableExecuteApiEndpoint": 1}, {"ReservedConcurrentExecutions": 0}, False, True, ("api_readback_invalid",)),
        ({"DisableExecuteApiEndpoint": True}, {"ReservedConcurrentExecutions": 1}, True, False, ("function_not_reserved",)),
        ({"DisableExecuteApiEndpoint": True}, {"ReservedConcurrentExecutions": False}, True, False, ("function_readback_invalid",)),
        ({"DisableExecuteApiEndpoint": True}, {}, True, False, ("function_readback_invalid",)),
        (None, {"ReservedConcurrentExecutions": 0}, False, True, ("api_readback_invalid",)),
        ({"disableExecuteApiEndpoint": True}, {"ReservedConcurrentExecutions": 0}, False, True, ("api_readback_invalid",)),
    ],
)
def test_readbacks_require_exact_mapping_fields_and_scalar_types(api_response, lambda_response, api_closed, function_reserved, categories):
    calls, api, lambda_client = _clients(api_response=api_response, lambda_response=lambda_response)
    result = close_dev_runtime(AwsDevShutdownPolicy(API_ID), api, lambda_client)
    assert result.api_closed is api_closed
    assert result.function_reserved is function_reserved
    assert result.verified is (api_closed and function_reserved)
    assert result.warnings == categories
    assert len(calls) == 4


@pytest.mark.parametrize("api_id", ["", "A1b2c3d4e5", "a1b2c3d4", "a1b2c3d4e50", "../../etc/passwd", 1])
def test_invalid_policy_rejects_before_any_client_call(api_id):
    calls, api, lambda_client = _clients()
    with pytest.raises(ValueError):
        policy = AwsDevShutdownPolicy(api_id)
        close_dev_runtime(policy, api, lambda_client)
    assert calls == []


def test_non_dev_region_rejected_and_policy_is_immutable():
    with pytest.raises(ValueError):
        AwsDevShutdownPolicy(API_ID, region="us-east-1")
    policy = AwsDevShutdownPolicy(API_ID)
    with pytest.raises(FrozenInstanceError):
        policy.api_id = "z9y8x7w6v5"


def test_subclass_policy_is_not_accepted_and_makes_no_provider_calls():
    class DerivedPolicy(AwsDevShutdownPolicy):
        pass

    calls, api, lambda_client = _clients()
    with pytest.raises(ValueError):
        close_dev_runtime(DerivedPolicy(API_ID), api, lambda_client)
    assert calls == []
