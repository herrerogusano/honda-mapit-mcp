from __future__ import annotations

import re

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_workflow import build_dev_shutdown_workflow


def _definition() -> dict:
    return build_dev_shutdown_workflow(AwsDevShutdownPolicy("a1b2c3d4e5"))


def test_generator_is_pure_fresh_and_discards_caller_payload() -> None:
    one = _definition()
    two = _definition()
    assert one == two and one is not two
    assert one["StartAt"] == "Initialize"
    assert one["TimeoutSeconds"] == 45
    initialize = one["States"]["Initialize"]
    assert initialize["Type"] == "Pass"
    assert initialize["ResultPath"] == "$"
    assert set(initialize["Parameters"]) == {
        "api_write_call_returned", "function_write_call_returned", "api_closed",
        "function_reserved", "api_status", "function_status", "verified", "category",
    }
    assert "InputPath" not in initialize and "Parameters.$" not in initialize
    one["States"]["Initialize"]["Parameters"]["verified"] = True
    assert two["States"]["Initialize"]["Parameters"]["verified"] is False


def test_exactly_four_fixed_sdk_tasks_have_bounded_timeouts_and_no_retries() -> None:
    definition = _definition()
    states = definition["States"]
    tasks = [(name, state) for name, state in states.items() if state["Type"] == "Task"]
    assert [name for name, _ in tasks] == [
        "DisableApiEndpoint", "ReserveFunctionConcurrency", "ReadApiEndpoint", "ReadFunctionConcurrency"
    ]
    assert [state["Resource"] for _, state in tasks] == [
        "arn:aws:states:::aws-sdk:apigatewayv2:updateApi",
        "arn:aws:states:::aws-sdk:lambda:putFunctionConcurrency",
        "arn:aws:states:::aws-sdk:apigatewayv2:getApi",
        "arn:aws:states:::aws-sdk:lambda:getFunctionConcurrency",
    ]
    assert [state["Parameters"] for _, state in tasks] == [
        {"ApiId": "a1b2c3d4e5", "DisableExecuteApiEndpoint": True},
        {"FunctionName": "honda-mapit-mcp-dev-handler", "ReservedConcurrentExecutions": 0},
        {"ApiId": "a1b2c3d4e5"},
        {"FunctionName": "honda-mapit-mcp-dev-handler"},
    ]
    for _, state in tasks:
        assert state["TimeoutSeconds"] == 5
        assert "Retry" not in state
        catches = state["Catch"]
        assert [catch["ErrorEquals"] for catch in catches] == [["States.DataLimitExceeded"], ["States.ALL"]]
        assert all(catch["ResultPath"] is None for catch in catches)
        assert all("Cause" not in catch for catch in catches)


def test_write_and_readback_paths_are_independent_and_sdk_results_are_transient() -> None:
    states = _definition()["States"]
    assert states["DisableApiEndpoint"]["Next"] == "ApiWriteReturned"
    assert states["DisableApiEndpoint"]["Catch"][0]["Next"] == "ApiWriteFailed"
    assert states["ApiWriteFailed"]["Next"] == "ReserveFunctionConcurrency"
    assert states["ReserveFunctionConcurrency"]["Catch"][1]["Next"] == "FunctionWriteFailed"
    assert states["FunctionWriteFailed"]["Next"] == "ReadApiEndpoint"
    assert states["ReadApiEndpoint"]["Catch"][0]["Next"] == "ApiReadFailed"
    assert states["ApiReadFailed"]["Next"] == "ReadFunctionConcurrency"
    assert states["ReadFunctionConcurrency"]["Catch"][1]["Next"] == "FunctionReadFailed"
    assert states["FunctionReadFailed"]["Next"] == "BuildFinalResult"
    assert states["ReadApiEndpoint"]["ResultPath"] == "$.api_response"
    assert states["ReadFunctionConcurrency"]["ResultPath"] == "$.function_response"
    final = states["BuildFinalResult"]["Parameters"]
    assert set(final) == {
        "api_write_call_returned.$", "function_write_call_returned.$", "api_closed.$",
        "function_reserved.$", "verified.$", "category.$", "api_status.$", "function_status.$",
    }
    assert not any("response" in key.lower() or "cause" in key.lower() for key in final)


def test_readback_choices_guard_presence_and_type_before_comparison() -> None:
    states = _definition()["States"]
    api_var = "$.api_response.DisableExecuteApiEndpoint"
    fn_var = "$.function_response.ReservedConcurrentExecutions"
    assert states["CheckApiFieldPresent"]["Choices"] == [
        {"Variable": api_var, "IsPresent": True, "Next": "CheckApiFieldType"}
    ]
    assert states["CheckApiFieldType"]["Choices"] == [
        {"Variable": api_var, "IsBoolean": True, "Next": "CheckApiClosed"}
    ]
    assert states["CheckApiClosed"]["Choices"] == [
        {"Variable": api_var, "BooleanEquals": True, "Next": "ApiReadClosed"}
    ]
    assert states["CheckFunctionFieldPresent"]["Choices"] == [
        {"Variable": fn_var, "IsPresent": True, "Next": "CheckFunctionFieldType"}
    ]
    assert states["CheckFunctionFieldType"]["Choices"] == [
        {"Variable": fn_var, "IsNumeric": True, "Next": "CheckFunctionReserved"}
    ]
    assert states["CheckFunctionReserved"]["Choices"] == [
        {"Variable": fn_var, "NumericEquals": 0, "Next": "FunctionIsReserved"}
    ]


def test_only_true_and_zero_readbacks_can_reach_verified_result() -> None:
    states = _definition()["States"]
    assert states["CheckFullyVerified"]["Default"] == "BuildFinalResult"
    assert states["CompareApiVerified"]["Default"] == "BuildFinalResult"
    assert states["CheckFunctionVerifiedType"]["Choices"][0]["IsPresent"] is True
    assert states["CheckFunctionVerifiedBoolean"]["Choices"][0]["IsBoolean"] is True
    assert states["CompareFunctionVerified"]["Choices"] == [
        {"Variable": "$.function_reserved", "BooleanEquals": True, "Next": "MarkVerified"}
    ]
    assert states["MarkVerified"]["Parameters"]["api_closed"] is True
    assert states["MarkVerified"]["Parameters"]["function_reserved"] is True
    assert states["MarkVerified"]["Parameters"]["verified"] is True
    for state_name in ("ApiNotClosed", "ApiReadInvalid", "FunctionNotReserved", "FunctionReadInvalid", "ApiReadFailed", "FunctionReadFailed"):
        assert states[state_name].get("Next") != "MarkVerified"


def test_transitions_are_closed_over_definition_and_target_cannot_be_overridden() -> None:
    definition = _definition()
    states = definition["States"]
    for state in states.values():
        if "Next" in state:
            assert state["Next"] in states
        if "Default" in state:
            assert state["Default"] in states
        for choice in state.get("Choices", []):
            assert choice["Next"] in states
        for catcher in state.get("Catch", []):
            assert catcher["Next"] in states
    serialized = repr(definition)
    assert not re.search(r"\$\.[A-Za-z0-9_]*(api_id|function_name|target)", serialized, re.I)
    assert "States.Runtime" not in serialized


@pytest.mark.parametrize("api_id", ["ABCDEF1234", "abc123", "abcdefghij/", "a" * 11])
def test_invalid_api_ids_are_rejected_before_definition_generation(api_id: str) -> None:
    with pytest.raises(ValueError):
        build_dev_shutdown_workflow(AwsDevShutdownPolicy(api_id))


def test_wrong_policy_type_is_rejected() -> None:
    with pytest.raises(ValueError):
        build_dev_shutdown_workflow(object())  # type: ignore[arg-type]


def test_mutated_policy_is_revalidated_before_api_target_is_embedded() -> None:
    policy = AwsDevShutdownPolicy("a1b2c3d4e5")
    object.__setattr__(policy, "api_id", "attacker-id")
    with pytest.raises(ValueError):
        build_dev_shutdown_workflow(policy)
