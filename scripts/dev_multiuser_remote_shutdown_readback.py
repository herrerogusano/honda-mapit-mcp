"""Read-only verification of the retained DEV remote shutdown path.

This module intentionally has no SDK construction and no write-capable calls.
The caller injects already-created clients and a :class:`PlainFileJournal`.
The execution name is derived exactly as ``DevTestWindow.open`` derives it;
an execution ARN supplied by a caller is never trusted.
"""

from __future__ import annotations

from collections.abc import Mapping
import json
import re
from typing import Any

from scripts.dev_multiuser_window import FUNCTION

REGION = "eu-west-1"
MACHINE_NAME = "honda-mapit-mcp-dev-retained-shutdown"
MACHINE_ARN_TEMPLATE = "arn:aws:states:eu-west-1:{account}:stateMachine:" + MACHINE_NAME
EXECUTION_ARN_TEMPLATE = "arn:aws:states:eu-west-1:{account}:execution:" + MACHINE_NAME + ":multiuser-{run_id}"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_RUN = re.compile(r"[0-9a-f]{32}\Z")
_CATEGORIES = frozenset({
    "shutdown_verified",
    "shutdown_pending",
    "shutdown_failed",
    "shutdown_runtime_not_closed",
    "shutdown_readback_invalid",
    "journal_invalid",
    "clients_invalid",
})
FUNCTION_ARN_TEMPLATE = "arn:aws:lambda:eu-west-1:{account}:function:" + FUNCTION
MAX_JSON_BYTES = 32 * 1024
_FINAL_OUTPUT_KEYS = frozenset({
    "api_write_call_returned", "function_write_call_returned", "api_closed",
    "function_reserved", "verified", "category", "api_status", "function_status",
})


class RemoteShutdownReadbackError(ValueError):
    """Stable local category; provider details are deliberately discarded."""

    def __init__(self, category: str) -> None:
        self.category = category if category in _CATEGORIES else "shutdown_readback_invalid"
        super().__init__(self.category)


def _result(category: str, *, success: bool, shutdown_verified: bool) -> dict[str, Any]:
    # Keep this output deliberately fixed and redacted.  In particular, no
    # account, ARN, execution name, response status, or payload is returned.
    return {
        "success": type(success) is bool and success,
        "category": category if category in _CATEGORIES else "shutdown_readback_invalid",
        "shutdown_verified": type(shutdown_verified) is bool and shutdown_verified,
    }


def _ok(response: Any) -> bool:
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    return (
        isinstance(metadata, Mapping)
        and type(metadata.get("HTTPStatusCode")) is int
        and metadata.get("HTTPStatusCode") == 200
    )


def _binding(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping) or set(value) != {
        "schema", "account", "api_id", "machine_arn", "source_sha", "run_id", "start", "end"
    }:
        return None
    account = value.get("account")
    api_id = value.get("api_id")
    source_sha = value.get("source_sha")
    run_id = value.get("run_id")
    start = value.get("start")
    end = value.get("end")
    if (type(value.get("schema")) is not int or value.get("schema") != 1
        or type(account) is not str or _ACCOUNT.fullmatch(account) is None
        or account == "0" * 12 or type(api_id) is not str or _API.fullmatch(api_id) is None
        or type(source_sha) is not str or _SHA.fullmatch(source_sha) is None
        or type(run_id) is not str or _RUN.fullmatch(run_id) is None
        or type(start) is not int or type(end) is not int or not 0 < end - start <= 300):
        return None
    machine = MACHINE_ARN_TEMPLATE.format(account=account)
    if value.get("machine_arn") != machine:
        return None
    return dict(value)


def _state(journal: Any) -> dict[str, Any] | None:
    if journal is None or not callable(getattr(journal, "load", None)):
        raise RemoteShutdownReadbackError("journal_invalid")
    try:
        value = journal.load()
    except Exception:
        raise RemoteShutdownReadbackError("journal_invalid") from None
    if not isinstance(value, Mapping) or set(value) != {"binding", "phase", "close_attempts"}:
        raise RemoteShutdownReadbackError("journal_invalid")
    if type(value.get("phase")) is not str or value.get("phase") != "closed":
        raise RemoteShutdownReadbackError("journal_invalid")
    attempts = value.get("close_attempts")
    if type(attempts) is not int or not 1 <= attempts <= 3:
        raise RemoteShutdownReadbackError("journal_invalid")
    binding = _binding(value.get("binding"))
    if binding is None:
        raise RemoteShutdownReadbackError("journal_invalid")
    return {"binding": binding, "phase": "closed", "close_attempts": attempts}


def _execution_input(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        raw = value.encode("utf-8", "strict")
        if len(raw) > 4096:
            return False
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")))
    except Exception:
        return False
    return type(parsed) is dict and set(parsed) == {"bounded_dev_probe"} and parsed["bounded_dev_probe"] is True


def _reject_duplicates(pairs: list[tuple[Any, Any]]) -> dict[Any, Any]:
    result: dict[Any, Any] = {}
    for key, item in pairs:
        if key in result:
            raise ValueError("duplicate_json_key")
        result[key] = item
    return result


def _final_output(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        raw = value.encode("utf-8", "strict")
    except Exception:
        return False
    if len(raw) > MAX_JSON_BYTES:
        return False
    try:
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("non-finite")))
    except Exception:
        return False
    if type(parsed) is not dict or set(parsed) != _FINAL_OUTPUT_KEYS:
        return False
    return (
        parsed.get("category") == "shutdown_verified"
        and parsed.get("api_status") == "api_closed"
        and parsed.get("function_status") == "function_reserved"
        and all(parsed.get(key) is True for key in (
            "api_write_call_returned", "function_write_call_returned", "api_closed",
            "function_reserved", "verified",
        ))
    )


def _client_set(clients: Any) -> bool:
    return isinstance(clients, Mapping) and set(clients) == {"stepfunctions", "lambda", "apigatewayv2"} and all(
        clients.get(name) is not None for name in clients
    )


def read_remote_shutdown_readback(journal: Any, clients: Mapping[str, Any]) -> dict[str, Any]:
    """Verify one already-recorded shutdown, using exactly three GET-style reads.

    Calls are made in the order ``DescribeExecution``, Lambda concurrency, and
    API ``GetApi``.  ``RUNNING`` is a safe pending result, while ``SUCCEEDED``
    is verified only after both endpoint-closed checks pass.  No state is
    written and no execution listing is used.
    """
    try:
        if not _client_set(clients):
            return _result("clients_invalid", success=False, shutdown_verified=False)
        state = _state(journal)
        assert state is not None
        binding = state["binding"]
        account = binding["account"]
        api_id = binding["api_id"]
        machine = binding["machine_arn"]
        execution = EXECUTION_ARN_TEMPLATE.format(account=account, run_id=binding["run_id"])
        describe = getattr(clients["stepfunctions"], "describe_execution", None)
        get_concurrency = getattr(clients["lambda"], "get_function_concurrency", None)
        get_api = getattr(clients["apigatewayv2"], "get_api", None)
        if not all(callable(item) for item in (describe, get_concurrency, get_api)):
            return _result("clients_invalid", success=False, shutdown_verified=False)

        response = describe(executionArn=execution)
        # The AWS SDK includes additional descriptive fields (dates, cause,
        # redrive metadata).  They are deliberately ignored; only the stable
        # ownership/input fields below participate in this proof.
        if not _ok(response):
            return _result("shutdown_readback_invalid", success=False, shutdown_verified=False)
        if (response.get("executionArn") != execution or response.get("stateMachineArn") != machine
            or not _execution_input(response.get("input"))):
            return _result("shutdown_readback_invalid", success=False, shutdown_verified=False)
        status = response.get("status")
        if status not in {"RUNNING", "SUCCEEDED"}:
            return _result("shutdown_failed", success=False, shutdown_verified=False)

        if status == "SUCCEEDED" and not _final_output(response.get("output")):
            return _result("shutdown_readback_invalid", success=False, shutdown_verified=False)

        function = get_concurrency(FunctionName=FUNCTION)
        api = get_api(ApiId=api_id)
        if (not _ok(function)
            or type(function.get("ReservedConcurrentExecutions")) is not int
            or function.get("ReservedConcurrentExecutions") != 0
            or not _ok(api)
            or api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True):
            return _result("shutdown_runtime_not_closed", success=False, shutdown_verified=False)
        if status == "RUNNING":
            return _result("shutdown_pending", success=True, shutdown_verified=False)
        return _result("shutdown_verified", success=True, shutdown_verified=True)
    except RemoteShutdownReadbackError as error:
        return _result(error.category, success=False, shutdown_verified=False)
    except Exception:
        return _result("shutdown_readback_invalid", success=False, shutdown_verified=False)


verify_remote_shutdown_readback = read_remote_shutdown_readback
check_remote_shutdown_readback = read_remote_shutdown_readback

__all__ = [
    "FUNCTION", "MACHINE_NAME", "RemoteShutdownReadbackError",
    "read_remote_shutdown_readback", "verify_remote_shutdown_readback",
    "check_remote_shutdown_readback",
]
