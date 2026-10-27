"""Independent holdouts for continuation timing around durable intents."""
from contextlib import nullcontext

import pytest

from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls
from scripts.dev_multiuser_window import DevTestWindow, FUNCTION


ACCOUNT = "123456789012"
API = "abcdefghij"
MACHINE = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"


class _Journal:
    def __init__(self, clock, expire_on):
        self.value = {"binding": None, "phase": "ready", "close_attempts": 0}
        self.clock = clock
        self.expire_on = expire_on

    def locked(self):
        return nullcontext()

    def load(self):
        return self.value

    def save(self, value):
        self.value = value
        if value["phase"] == self.expire_on:
            # Model a slow durable write crossing the immutable cutoff.
            self.clock[0] = 400


class _Clients:
    def __init__(self):
        self.started = 0
        self.reserve = 0
        self.api_open = False
        self.writes = []

    def get_function_concurrency(self, **_):
        return {} if self.reserve is None else {"ReservedConcurrentExecutions": self.reserve}

    def get_api(self, **_):
        return {"ApiId": API, "DisableExecuteApiEndpoint": not self.api_open}

    def describe_state_machine(self, **_):
        expected = build_dev_multiuser_timed_controls(API)["Resources"]["ShutdownStateMachine"]["Properties"]
        return {"stateMachineArn": MACHINE, "type": "STANDARD", "status": "ACTIVE",
                "roleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-shutdown-workflow",
                "loggingConfiguration": {"level": "OFF"}, "tracingConfiguration": {"enabled": False},
                "definition": expected["DefinitionString"]}

    def start_execution(self, **_):
        self.started += 1
        self.writes.append("arm")
        return {"executionArn": f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:honda-mapit-mcp-dev-retained-shutdown:multiuser-{'b' * 32}"}

    def describe_execution(self, **_):
        return {"executionArn": f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:honda-mapit-mcp-dev-retained-shutdown:multiuser-{'b' * 32}",
                "stateMachineArn": MACHINE, "status": "RUNNING", "input": '{"bounded_dev_probe":true}'}

    def delete_function_concurrency(self, **_):
        self.writes.append("lambda_open")
        self.reserve = None

    def update_api(self, **_):
        self.writes.append("api_open")
        self.api_open = True


@pytest.mark.parametrize(
    ("intent", "expected_writes"),
    [
        ("arm_intent", []),
        ("lambda_intent", ["arm"]),
        ("api_intent", ["arm", "lambda_open"]),
    ],
)
def test_window_rechecks_deadline_after_each_open_intent_before_dispatch(intent, expected_writes):
    clock = [399]
    clients = _Clients()
    journal = _Journal(clock, intent)
    window = DevTestWindow(
        {name: clients for name in ("lambda", "apigatewayv2", "stepfunctions")},
        journal,
        account=ACCOUNT,
        api_id=API,
        machine_arn=MACHINE,
        source_sha="a" * 40,
        run_id="b" * 32,
        execution_start=100,
        execution_end=400,
        clock=lambda: clock[0],
    )
    # This is the durable state immediately before the opening step.
    journal.value = {"binding": window.binding, "phase": "ready", "close_attempts": 0}

    with pytest.raises(ValueError, match="window_closed"):
        window.open()

    assert journal.value["phase"] == intent
    assert clients.writes == expected_writes
    assert clients.api_open is False
    if intent == "arm_intent":
        assert clients.started == 0
