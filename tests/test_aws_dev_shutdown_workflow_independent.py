from __future__ import annotations

from copy import deepcopy
from collections.abc import Callable, Mapping
from typing import Any

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_workflow import build_dev_shutdown_workflow


_API_ID = "a1b2c3d4e5"
_FUNCTION = "honda-mapit-mcp-dev-handler"
_UNSET = object()


class _TaskFailure(Exception):
    def __init__(self, name: str):
        super().__init__(name)
        self.name = name


def _path(value: Any, path: str) -> tuple[bool, Any]:
    if not path.startswith("$."):
        raise AssertionError(f"unsupported test JSONPath: {path}")
    current = value
    for part in path[2:].split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _parameters(spec: Mapping[str, Any], state: Any) -> dict[str, Any]:
    resolved: dict[str, Any] = {}
    for key, value in spec.items():
        if key.endswith(".$"):
            exists, picked = _path(state, value)
            if not exists:
                raise AssertionError(f"test interpreter missing parameter path: {value}")
            resolved[key[:-2]] = picked
        else:
            resolved[key] = value
    return resolved


def _replace_path(state: Any, path: str, value: Any) -> Any:
    if path == "$":
        return value
    if not path.startswith("$."):
        raise AssertionError(f"unsupported test ResultPath: {path}")
    if not isinstance(state, dict):
        raise AssertionError("test ResultPath parent must be an object")
    result = dict(state)
    current = result
    parts = path[2:].split(".")
    for part in parts[:-1]:
        child = current.get(part)
        if not isinstance(child, dict):
            child = {}
            current[part] = child
        current = child
    current[parts[-1]] = value
    return result


def _choice_matches(choice: Mapping[str, Any], state: Any) -> bool:
    exists, value = _path(state, choice["Variable"])
    for operator, expected in choice.items():
        if operator == "Variable" or operator == "Next":
            continue
        if operator == "IsPresent" and exists is not expected:
            return False
        if operator == "IsBoolean" and (not exists or type(value) is not bool):
            return False
        if operator == "BooleanEquals" and (not exists or type(value) is not bool or value is not expected):
            return False
        if operator == "IsNumeric" and (not exists or type(value) not in (int, float)):
            return False
        if operator == "NumericEquals" and (not exists or type(value) not in (int, float) or value != expected):
            return False
        if operator not in {"Variable", "Next", "IsPresent", "IsBoolean", "BooleanEquals", "IsNumeric", "NumericEquals"}:
            raise AssertionError(f"unsupported test Choice operator: {operator}")
    return True


def _execute_subset(
    definition: Mapping[str, Any],
    caller_input: Any,
    task_callback: Callable[[str, Mapping[str, Any]], Any],
) -> tuple[Any, list[tuple[str, dict[str, Any]]]]:
    """Execute only Pass/Task/Choice constructs present in this generated definition.

    This deliberately small test interpreter checks dataflow and transitions;
    it is not an AWS Step Functions implementation or runtime-equivalence claim.
    """
    states = definition["States"]
    current_name = definition["StartAt"]
    current_input = caller_input
    calls: list[tuple[str, dict[str, Any]]] = []
    for _ in range(100):
        state = states[current_name]
        state_type = state["Type"]
        if state_type == "Pass":
            if "Parameters" in state:
                result = _parameters(state["Parameters"], current_input)
            else:
                result = state["Result"]
            result_path = state.get("ResultPath", "$")
            if result_path is not None:
                current_input = _replace_path(current_input, result_path, result)
            if state.get("End") is True:
                return current_input, calls
            current_name = state["Next"]
            continue
        if state_type == "Task":
            parameters = dict(state["Parameters"])
            calls.append((current_name, parameters))
            try:
                task_result = task_callback(current_name, parameters)
            except _TaskFailure as failure:
                matching = next(
                    (
                        catch
                        for catch in state["Catch"]
                        if failure.name in catch["ErrorEquals"]
                        or (
                            "States.ALL" in catch["ErrorEquals"]
                            and failure.name not in {"States.Runtime", "States.DataLimitExceeded"}
                        )
                    ),
                    None,
                )
                if matching is None:
                    raise
                if matching.get("ResultPath", "$") is not None:
                    current_input = _replace_path(current_input, matching["ResultPath"], {"Error": failure.name})
                current_name = matching["Next"]
                continue
            result_path = state.get("ResultPath", "$")
            if result_path is not None:
                current_input = _replace_path(current_input, result_path, task_result)
            current_name = state["Next"]
            continue
        if state_type == "Choice":
            current_name = next(
                (choice["Next"] for choice in state["Choices"] if _choice_matches(choice, current_input)),
                state["Default"],
            )
            continue
        raise AssertionError(f"unsupported ASL state type in test subset: {state_type}")
    raise AssertionError("test interpreter exceeded transition bound")


def _run(
    *,
    caller_input: Any = None,
    failures: Mapping[str, str] | None = None,
    api_readback: Any = _UNSET,
    function_readback: Any = _UNSET,
) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]]]:
    failures = dict(failures or {})
    if api_readback is _UNSET:
        api_readback = {"DisableExecuteApiEndpoint": True}
    if function_readback is _UNSET:
        function_readback = {"ReservedConcurrentExecutions": 0}

    def callback(state_name: str, parameters: Mapping[str, Any]) -> Any:
        if state_name in failures:
            raise _TaskFailure(failures[state_name])
        if state_name == "DisableApiEndpoint":
            return {"ResponseCanary": "provider-response-secret"}
        if state_name == "ReserveFunctionConcurrency":
            return {"ResponseCanary": "provider-response-secret"}
        if state_name == "ReadApiEndpoint":
            return api_readback
        if state_name == "ReadFunctionConcurrency":
            return function_readback
        raise AssertionError(f"unexpected task state: {state_name}")

    definition = build_dev_shutdown_workflow(AwsDevShutdownPolicy(_API_ID))
    result, calls = _execute_subset(definition, caller_input, callback)
    return result, calls


def test_behavioral_subset_discards_poison_input_uses_fixed_targets_and_projects_safe_success():
    poison = {
        "ApiId": "attacker-target",
        "FunctionName": "attacker-function",
        "api_closed": True,
        "function_reserved": True,
        "verified": True,
        "category": "forged",
        "api_response": {"DisableExecuteApiEndpoint": True},
        "function_response": {"ReservedConcurrentExecutions": 0},
        "canary": "caller-secret-canary",
    }
    output, calls = _run(caller_input=poison)
    assert [name for name, _ in calls] == [
        "DisableApiEndpoint", "ReserveFunctionConcurrency", "ReadApiEndpoint", "ReadFunctionConcurrency"
    ]
    assert calls == [
        ("DisableApiEndpoint", {"ApiId": _API_ID, "DisableExecuteApiEndpoint": True}),
        ("ReserveFunctionConcurrency", {"FunctionName": _FUNCTION, "ReservedConcurrentExecutions": 0}),
        ("ReadApiEndpoint", {"ApiId": _API_ID}),
        ("ReadFunctionConcurrency", {"FunctionName": _FUNCTION}),
    ]
    assert output == {
        "api_write_call_returned": True,
        "function_write_call_returned": True,
        "api_closed": True,
        "function_reserved": True,
        "verified": True,
        "category": "shutdown_verified",
        "api_status": "api_closed",
        "function_status": "function_reserved",
    }
    serialized = repr(output)
    assert "caller-secret-canary" not in serialized
    assert "provider-response-secret" not in serialized
    assert "attacker-target" not in serialized
    assert "attacker-function" not in serialized


@pytest.mark.parametrize(
    ("state_name", "error_name", "expected_field", "expected_status"),
    [
        ("DisableApiEndpoint", "States.TaskFailed", "api_write_call_returned", False),
        ("DisableApiEndpoint", "States.DataLimitExceeded", "api_write_call_returned", False),
        ("DisableApiEndpoint", "States.Timeout", "api_write_call_returned", False),
        ("ReserveFunctionConcurrency", "States.TaskFailed", "function_write_call_returned", False),
        ("ReserveFunctionConcurrency", "States.DataLimitExceeded", "function_write_call_returned", False),
        ("ReserveFunctionConcurrency", "States.Timeout", "function_write_call_returned", False),
        ("ReadApiEndpoint", "States.TaskFailed", "api_status", "api_readback_failed"),
        ("ReadApiEndpoint", "States.DataLimitExceeded", "api_status", "api_readback_failed"),
        ("ReadApiEndpoint", "States.Timeout", "api_status", "api_readback_failed"),
        ("ReadFunctionConcurrency", "States.TaskFailed", "function_status", "function_readback_failed"),
        ("ReadFunctionConcurrency", "States.DataLimitExceeded", "function_status", "function_readback_failed"),
        ("ReadFunctionConcurrency", "States.Timeout", "function_status", "function_readback_failed"),
    ],
)
def test_each_task_failure_is_independent_and_output_stays_safe(state_name, error_name, expected_field, expected_status):
    output, calls = _run(
        failures={state_name: error_name},
        caller_input={"poison": "caller-canary"},
    )
    assert len(calls) == 4
    assert output[expected_field] == expected_status
    assert "caller-canary" not in repr(output)
    assert "States." not in repr(output)
    if state_name in ("DisableApiEndpoint", "ReserveFunctionConcurrency"):
        # A failed/ambiguous write is not treated as proof of failure if both
        # independent readbacks confirm the desired state.
        assert output["category"] == "shutdown_verified"
        assert output["verified"] is True
        assert output["api_status"] == "api_closed"
        assert output["function_status"] == "function_reserved"
        assert [name for name, _ in calls] == [
            "DisableApiEndpoint", "ReserveFunctionConcurrency", "ReadApiEndpoint", "ReadFunctionConcurrency"
        ]
    elif state_name == "ReadApiEndpoint":
        assert output["category"] == "shutdown_unverified"
        assert output["verified"] is False
        assert output["api_closed"] is False
        assert output["api_status"] == "api_readback_failed"
        assert calls[-1][0] == "ReadFunctionConcurrency"
    else:
        assert state_name == "ReadFunctionConcurrency"
        assert output["category"] == "shutdown_unverified"
        assert output["verified"] is False
        assert output["function_reserved"] is False
        assert output["function_status"] == "function_readback_failed"


@pytest.mark.parametrize(
    ("api_response", "expected_status"),
    [
        (None, "api_readback_invalid"),
        ([{"DisableExecuteApiEndpoint": True}], "api_readback_invalid"),
        ({}, "api_readback_invalid"),
        ({"DisableExecuteApiEndpoint": None}, "api_readback_invalid"),
        ({"DisableExecuteApiEndpoint": "true"}, "api_readback_invalid"),
        ({"DisableExecuteApiEndpoint": 1}, "api_readback_invalid"),
        ({"DisableExecuteApiEndpoint": False}, "api_not_closed"),
    ],
)
def test_api_readback_malformed_or_false_never_verifies(api_response, expected_status):
    output, calls = _run(api_readback=api_response)
    assert len(calls) == 4
    assert output["api_closed"] is False
    assert output["api_status"] == expected_status
    assert output["function_reserved"] is True
    assert output["verified"] is False
    assert output["category"] == "shutdown_unverified"


@pytest.mark.parametrize(
    ("function_response", "expected_status"),
    [
        ({}, "function_readback_invalid"),
        ({"ReservedConcurrentExecutions": None}, "function_readback_invalid"),
        ({"ReservedConcurrentExecutions": False}, "function_readback_invalid"),
        ({"ReservedConcurrentExecutions": "0"}, "function_readback_invalid"),
        ({"ReservedConcurrentExecutions": 1}, "function_not_reserved"),
    ],
)
def test_function_readback_malformed_or_nonzero_never_verifies(function_response, expected_status):
    output, calls = _run(function_readback=function_response)
    assert len(calls) == 4
    assert output["api_closed"] is True
    assert output["function_reserved"] is False
    assert output["function_status"] == expected_status
    assert output["verified"] is False
    assert output["category"] == "shutdown_unverified"


def test_ambiguous_write_failures_can_be_confirmed_by_readbacks_without_leaking_errors():
    output, calls = _run(
        failures={
            "DisableApiEndpoint": "States.TaskFailed",
            "ReserveFunctionConcurrency": "States.Timeout",
        },
        caller_input={"secret": "caller-secret-canary"},
    )
    assert len(calls) == 4
    assert output["api_write_call_returned"] is False
    assert output["function_write_call_returned"] is False
    assert output["api_closed"] is True
    assert output["function_reserved"] is True
    assert output["verified"] is True
    assert output["category"] == "shutdown_verified"
    assert output["api_status"] == "api_closed"
    assert output["function_status"] == "function_reserved"
    assert "caller-secret-canary" not in repr(output)
    assert "States." not in repr(output)


def test_runtime_errors_escape_states_all_in_the_test_subset():
    definition = build_dev_shutdown_workflow(AwsDevShutdownPolicy(_API_ID))
    calls: list[tuple[str, dict[str, Any]]] = []

    def callback(state_name: str, parameters: Mapping[str, Any]) -> Any:
        calls.append((state_name, dict(parameters)))
        raise _TaskFailure("States.Runtime")

    with pytest.raises(_TaskFailure, match="States.Runtime"):
        _execute_subset(definition, {"poison": "not-used"}, callback)
    assert [name for name, _ in calls] == ["DisableApiEndpoint"]


def test_subset_executor_fails_closed_on_unknown_choice_operator():
    definition = deepcopy(build_dev_shutdown_workflow(AwsDevShutdownPolicy(_API_ID)))
    definition["States"]["CheckApiFieldPresent"]["Choices"][0]["UnsupportedOperator"] = True

    def callback(state_name: str, parameters: Mapping[str, Any]) -> Any:
        if state_name in {"DisableApiEndpoint", "ReserveFunctionConcurrency"}:
            return {}
        if state_name == "ReadApiEndpoint":
            return {"DisableExecuteApiEndpoint": True}
        raise AssertionError(f"unexpected callback: {state_name}")

    with pytest.raises(AssertionError, match="unsupported test Choice operator"):
        _execute_subset(definition, {}, callback)
