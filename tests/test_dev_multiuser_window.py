import json
from contextlib import nullcontext

import pytest

from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls
from scripts.dev_multiuser_window import DevTestWindow, FUNCTION

ACCOUNT = "123456789012"
API = "abcdefghij"
MACHINE = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"


class Journal:
    value = None
    def locked(self): return nullcontext()
    def load(self): return self.value
    def save(self, value): self.value = value


class Clients:
    def __init__(self):
        self.reserve = 0
        self.closed = True
        self.operations = []
    def get_function_concurrency(self, **kwargs):
        return {} if self.reserve is None else {"ReservedConcurrentExecutions": self.reserve}
    def get_api(self, **kwargs): return {"ApiId": API, "DisableExecuteApiEndpoint": self.closed}
    def get_account_settings(self): return {"AccountLimit": {"ConcurrentExecutions": 10}}
    def get_function_configuration(self, **kwargs):
        return {"FunctionName": FUNCTION, "FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:{FUNCTION}",
            "Handler": "mapit.aws_dev_multiuser_entrypoint.handler", "Environment": {"Variables": {
                "MAPIT_MCP_ENV": "dev", "MAPIT_DEV_MULTIUSER_MODE": "synthetic", "MAPIT_SOURCE_SHA256": "a" * 40,
                "MAPIT_DEV_EXECUTION_START_EPOCH": "100", "MAPIT_DEV_EXECUTION_END_EPOCH": "400", "MAPIT_OBSERVED_API_ID": API}}}
    def describe_state_machine(self, **kwargs):
        return {"stateMachineArn": MACHINE, "type": "STANDARD", "status": "ACTIVE",
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-shutdown-workflow",
            "loggingConfiguration": {"level": "OFF"}, "tracingConfiguration": {"enabled": False},
            "definition": build_dev_multiuser_timed_controls(API)["Resources"]["ShutdownStateMachine"]["Properties"]["DefinitionString"]}
    def start_execution(self, **kwargs):
        self.operations.append("arm")
        self.run = f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:honda-mapit-mcp-dev-retained-shutdown:{kwargs['name']}"
        return {"executionArn": self.run}
    def describe_execution(self, **kwargs):
        return {"executionArn": self.run, "stateMachineArn": MACHINE, "status": "RUNNING", "input": '{"bounded_dev_probe":true}'}
    def delete_function_concurrency(self, **kwargs):
        self.operations.append("lambda_open"); self.reserve = None
    def update_api(self, **kwargs):
        self.operations.append("api_close" if kwargs["DisableExecuteApiEndpoint"] else "api_open")
        self.closed = kwargs["DisableExecuteApiEndpoint"]
        return {"ApiId": API}
    def put_function_concurrency(self, **kwargs):
        self.operations.append("lambda_close"); self.reserve = 0


def setup():
    client = Clients()
    journal = Journal()
    clock = [101]
    window = DevTestWindow({name: client for name in ("lambda", "apigatewayv2", "stepfunctions")}, journal,
        account=ACCOUNT, api_id=API, machine_arn=MACHINE, source_sha="a" * 40, run_id="b" * 32,
        execution_start=100, execution_end=400, clock=lambda: clock[0])
    return window, client, journal, clock


def test_independent_stop_armed_before_either_opening_and_expiration_does_not_block_close():
    window, client, _, clock = setup()
    assert window.preflight()["success"] is True
    assert client.operations == []
    assert window.open()["success"] is True
    assert client.operations == ["arm", "lambda_open", "api_open"]
    clock[0] = 999
    assert window.close()["success"] is True
    assert client.operations[-2:] == ["api_close", "lambda_close"]
    count = len(client.operations)
    assert window.close()["success"] is True
    assert len(client.operations) == count


def test_ambiguous_arm_is_never_replayed_and_can_close():
    window, client, journal, _ = setup()
    window.preflight()
    def unknown(**kwargs):
        client.operations.append("arm_unknown")
        raise RuntimeError("sensitive")
    client.start_execution = unknown
    with pytest.raises(RuntimeError): window.open()
    assert journal.value["phase"] == "arm_intent"
    with pytest.raises(ValueError, match="opening_fenced"): window.open()
    assert client.operations == ["arm_unknown"]
    assert window.close()["success"] is True


def test_close_attempts_both_stop_primitives_when_first_response_is_ambiguous():
    window, client, _, _ = setup()
    window.preflight(); window.open()
    def unknown(**kwargs):
        client.closed = True
        raise RuntimeError("sensitive")
    client.update_api = unknown
    result = window.close()
    assert result["success"] is True and result["ambiguous_response"] is True
    assert client.operations[-1] == "lambda_close"


def test_wrong_stop_definition_prevents_all_writes():
    window, client, _, _ = setup()
    original = client.describe_state_machine
    def changed(**kwargs):
        value = original(**kwargs)
        definition = json.loads(value["definition"])
        definition["States"]["WaitFiveMinutes"]["Seconds"] = 3600
        value["definition"] = json.dumps(definition)
        return value
    client.describe_state_machine = changed
    with pytest.raises(ValueError, match="independent_stop_mismatch"): window.preflight()
    assert client.operations == []
