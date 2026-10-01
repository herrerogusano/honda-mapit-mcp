from __future__ import annotations

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy, close_dev_runtime


API_ID = "a1b2c3d4e5"
FUNCTION_NAME = "honda-mapit-mcp-dev-handler"


def _clients(calls, *, fail=(), api_readback=None, lambda_readback=None):
    failures = set(fail)

    class APIClient:
        def update_api(self, **kwargs):
            calls.append(("update_api", kwargs))
            if "update_api" in failures:
                raise RuntimeError("credential-canary-must-not-escape")
            return {"private": "ignored"}

        def get_api(self, **kwargs):
            calls.append(("get_api", kwargs))
            if "get_api" in failures:
                raise RuntimeError("credential-canary-must-not-escape")
            return api_readback if api_readback is not None else {"DisableExecuteApiEndpoint": True}

    class LambdaClient:
        def put_function_concurrency(self, **kwargs):
            calls.append(("put_function_concurrency", kwargs))
            if "put_function_concurrency" in failures:
                raise RuntimeError("credential-canary-must-not-escape")
            return {"private": "ignored"}

        def get_function_concurrency(self, **kwargs):
            calls.append(("get_function_concurrency", kwargs))
            if "get_function_concurrency" in failures:
                raise RuntimeError("credential-canary-must-not-escape")
            return lambda_readback if lambda_readback is not None else {"ReservedConcurrentExecutions": 0}

    return APIClient(), LambdaClient()


@pytest.mark.parametrize(
    "failed_operation",
    ["update_api", "put_function_concurrency", "get_api", "get_function_concurrency"],
)
def test_each_individual_provider_failure_still_attempts_all_four_calls_and_sanitizes(
    failed_operation, capsys
):
    calls = []
    api, lambda_client = _clients(calls, fail={failed_operation})
    result = close_dev_runtime(AwsDevShutdownPolicy(API_ID), api, lambda_client)
    captured = capsys.readouterr()

    assert [name for name, _ in calls] == [
        "update_api", "put_function_concurrency", "get_api", "get_function_concurrency"
    ]
    assert result.category in {"shutdown_verified", "shutdown_unverified"}
    assert all("credential-canary" not in warning for warning in result.warnings)
    assert "credential-canary" not in repr(result)
    assert "credential-canary" not in captured.out
    assert "credential-canary" not in captured.err


@pytest.mark.parametrize(
    ("api_readback", "expected_closed", "expected_warning"),
    [
        ({"DisableExecuteApiEndpoint": True}, True, None),
        ({"DisableExecuteApiEndpoint": 0}, False, "api_readback_invalid"),
        ({"DisableExecuteApiEndpoint": 1}, False, "api_readback_invalid"),
        ({"disableExecuteApiEndpoint": True}, False, "api_readback_invalid"),
        ({"DisableExecuteApiEndpoint": False}, False, "api_not_closed"),
        ({"DisableExecuteApiEndpoint": "true"}, False, "api_readback_invalid"),
    ],
)
def test_api_readback_requires_exact_pascal_case_bool(api_readback, expected_closed, expected_warning):
    calls = []
    api, lambda_client = _clients(calls, api_readback=api_readback)
    result = close_dev_runtime(AwsDevShutdownPolicy(API_ID), api, lambda_client)
    assert result.api_closed is expected_closed
    assert result.function_reserved is True
    assert result.verified is expected_closed
    if expected_warning is None:
        assert result.warnings == ()
    else:
        assert result.warnings == (expected_warning,)
    assert len(calls) == 4


def test_successful_writes_do_not_override_contradictory_readbacks():
    calls = []
    api, lambda_client = _clients(
        calls,
        api_readback={"DisableExecuteApiEndpoint": False},
        lambda_readback={"ReservedConcurrentExecutions": 2},
    )
    result = close_dev_runtime(AwsDevShutdownPolicy(API_ID), api, lambda_client)
    assert result.api_write_call_returned is True
    assert result.function_write_call_returned is True
    assert result.api_closed is False
    assert result.function_reserved is False
    assert result.verified is False
    assert result.category == "shutdown_unverified"
    assert result.warnings == ("api_not_closed", "function_not_reserved")


@pytest.mark.parametrize("api_id,region", [("A1b2c3d4e5", "eu-west-1"), (API_ID, "us-east-1"), ("../../bad", "eu-west-1")])
def test_invalid_shutdown_policy_makes_zero_client_calls(api_id, region):
    calls = []
    api, lambda_client = _clients(calls)
    with pytest.raises(ValueError):
        policy = AwsDevShutdownPolicy(api_id, region=region)
        close_dev_runtime(policy, api, lambda_client)
    assert calls == []
