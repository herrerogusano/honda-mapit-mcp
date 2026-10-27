from __future__ import annotations

import json

from scripts.dev_multiuser_remote_shutdown_readback import (
    FUNCTION,
    MACHINE_ARN_TEMPLATE,
    read_remote_shutdown_readback,
)
from scripts.dev_multiuser_journal import PlainFileJournal

ACCOUNT = "123456789012"
API = "abcdefghij"
RUN = "b" * 32
SOURCE = "a" * 40
MACHINE = MACHINE_ARN_TEMPLATE.format(account=ACCOUNT)
EXECUTION = f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:honda-mapit-mcp-dev-retained-shutdown:multiuser-{RUN}"
OK = {"ResponseMetadata": {"HTTPStatusCode": 200}}


def _state(*, phase="closed", binding=None):
    return {
        "binding": binding or {
            "schema": 1, "account": ACCOUNT, "api_id": API, "machine_arn": MACHINE,
            "source_sha": SOURCE, "run_id": RUN, "start": 100, "end": 400,
        },
        "phase": phase,
        "close_attempts": 1,
    }


class Journal:
    def __init__(self, state):
        self.state = state
        self.writes = 0

    def load(self):
        return json.loads(json.dumps(self.state)) if self.state is not None else None

    def save(self, value):
        self.writes += 1
        raise AssertionError("readback must not write")


class StepFunctions:
    def __init__(self, status="SUCCEEDED", **changes):
        self.status = status
        self.changes = changes
        self.calls = []

    def describe_execution(self, **kwargs):
        self.calls.append(("describe_execution", kwargs))
        value = {
            **OK,
            "executionArn": EXECUTION,
            "stateMachineArn": MACHINE,
            "status": self.status,
            "input": '{"bounded_dev_probe":true}',
        }
        if self.status == "SUCCEEDED":
            value["output"] = json.dumps({
                "api_write_call_returned": True,
                "function_write_call_returned": True,
                "api_closed": True,
                "function_reserved": True,
                "verified": True,
                "category": "shutdown_verified",
                "api_status": "api_closed",
                "function_status": "function_reserved",
            }, separators=(",", ":"))
        value.update(self.changes)
        return value

    def list_executions(self, **kwargs):
        raise AssertionError("execution listing is forbidden")


class Lambda:
    def __init__(self, reserve=0):
        self.reserve = reserve
        self.calls = []

    def get_function_concurrency(self, **kwargs):
        self.calls.append(("get_function_concurrency", kwargs))
        return {**OK, "ReservedConcurrentExecutions": self.reserve}


class Api:
    def __init__(self, disabled=True):
        self.disabled = disabled
        self.calls = []

    def get_api(self, **kwargs):
        self.calls.append(("get_api", kwargs))
        return {**OK, "ApiId": API, "DisableExecuteApiEndpoint": self.disabled}


def clients(step=None, *, reserve=0, disabled=True):
    return {
        "stepfunctions": step or StepFunctions(),
        "lambda": Lambda(reserve),
        "apigatewayv2": Api(disabled),
    }


def test_succeeded_derives_exact_execution_and_verifies_closed_runtime_without_writes():
    step = StepFunctions()
    injected = clients(step)
    value = read_remote_shutdown_readback(Journal(_state()), injected)
    assert value == {"success": True, "category": "shutdown_verified", "shutdown_verified": True}
    assert step.calls == [("describe_execution", {"executionArn": EXECUTION})]
    assert len(injected) == 3


def test_running_is_safe_pending_but_still_checks_bounded_runtime_closure():
    step = StepFunctions("RUNNING")
    value = read_remote_shutdown_readback(Journal(_state()), clients(step))
    assert value == {"success": True, "category": "shutdown_pending", "shutdown_verified": False}


def test_plain_file_journal_envelope_is_read_only(tmp_path):
    journal = PlainFileJournal(tmp_path)
    journal.save(_state())
    value = read_remote_shutdown_readback(journal, clients())
    assert value["shutdown_verified"] is True
    assert json.loads((tmp_path / "rehearsal-state.json").read_text())["kind"] == "dev-multiuser-private-state"


def test_failed_execution_stops_before_runtime_reads():
    step = StepFunctions("FAILED")
    injected = clients(step)
    value = read_remote_shutdown_readback(Journal(_state()), injected)
    assert value == {"success": False, "category": "shutdown_failed", "shutdown_verified": False}
    assert step.calls and injected["lambda"].calls == []


def test_execution_ownership_input_and_status_are_fail_closed():
    for changes in (
        {"executionArn": EXECUTION + "x"},
        {"stateMachineArn": MACHINE + "x"},
        {"input": '{"bounded_dev_probe":true,"secret":"do-not-return"}'},
        {"input": "not-json"},
        {"input": '{"bounded_dev_probe":NaN}'},
        {"output": '{"category":"shutdown_verified","category":"poison"}'},
        {"status": "NOT_A_REAL_STATE"},
    ):
        step = StepFunctions(**changes)
        value = read_remote_shutdown_readback(Journal(_state()), clients(step))
        assert value["success"] is False
        assert value["category"] in {"shutdown_readback_invalid", "shutdown_failed"}
        assert "do-not-return" not in repr(value)


def test_succeeded_output_requires_exact_safe_contract_and_boolean_types():
    good = clients()
    assert read_remote_shutdown_readback(Journal(_state()), good)["shutdown_verified"] is True
    for output in (
        "{}",
        '{"api_write_call_returned":1}',
        '{"api_write_call_returned":true,"function_write_call_returned":true,"api_closed":true,"function_reserved":true,"verified":true,"category":"shutdown_verified","api_status":"api_closed","function_status":"function_reserved","extra":"secret"}',
        '{"api_write_call_returned":true,"api_write_call_returned":false}',
    ):
        value = read_remote_shutdown_readback(
            Journal(_state()), clients(StepFunctions(output=output))
        )
        assert value == {"success": False, "category": "shutdown_readback_invalid", "shutdown_verified": False}


def test_runtime_must_be_exactly_disabled_and_reserved_zero():
    for kwargs in ({"reserve": 1}, {"disabled": False}):
        value = read_remote_shutdown_readback(Journal(_state()), clients(**kwargs))
        assert value == {"success": False, "category": "shutdown_runtime_not_closed", "shutdown_verified": False}


def test_journal_phase_binding_and_clients_fail_closed_without_provider_details():
    cases = [
        _state(phase="open"),
        _state(binding={**_state()["binding"], "account": "foreign-secret-123"}),
        _state(binding={**_state()["binding"], "run_id": "x" * 32}),
        {"binding": _state()["binding"], "phase": "closed", "close_attempts": True},
        {"binding": _state()["binding"], "phase": "closed", "close_attempts": 0},
    ]
    for state in cases:
        value = read_remote_shutdown_readback(Journal(state), clients())
        assert value["success"] is False
        assert value["category"] in {"journal_invalid", "shutdown_readback_invalid"}
        assert "foreign-secret" not in repr(value)
    invalid_schema = _state(binding={**_state()["binding"], "schema": True})
    assert read_remote_shutdown_readback(Journal(invalid_schema), clients())["category"] == "journal_invalid"
    assert read_remote_shutdown_readback(Journal(_state()), {})["category"] == "clients_invalid"


def test_response_metadata_is_required_and_provider_exceptions_are_redacted():
    class BadStep(StepFunctions):
        def describe_execution(self, **kwargs):
            raise RuntimeError("arn:secret/token")

    value = read_remote_shutdown_readback(Journal(_state()), clients(BadStep()))
    assert value == {"success": False, "category": "shutdown_readback_invalid", "shutdown_verified": False}
    assert "arn:secret" not in repr(value)
