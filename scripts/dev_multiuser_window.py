"""Injected five-minute DEV opening with an already verified independent stop.

No SDK construction, discovery, polling, credentials or production target.
Every write is preceded by a durable intent. Ambiguous opening is never
replayed. Closure permits at most three journaled attempts of both idempotent stop primitives;
the previously armed state machine remains a second, remote closure path.
"""
from __future__ import annotations

import json
import math
import re
import time

from scripts.build_dev_multiuser_timed_controls import build_dev_multiuser_timed_controls

FUNCTION = "honda-mapit-mcp-dev-retained-handler"


class DevTestWindow:
    def __init__(self, clients, journal, *, account, api_id, machine_arn, source_sha,
                 run_id, execution_start, execution_end, clock=time.time):
        if (type(clients) is not dict or set(clients) != {"lambda", "apigatewayv2", "stepfunctions"}
            or type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None
            or account == "0" * 12 or type(api_id) is not str or re.fullmatch(r"[a-z0-9]{10}", api_id) is None
            or type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
            or type(run_id) is not str or re.fullmatch(r"[0-9a-f]{32}", run_id) is None
            or type(execution_start) is not int or type(execution_end) is not int
            or not 0 < execution_end - execution_start <= 300):
            raise ValueError("binding_invalid")
        expected = f"arn:aws:states:eu-west-1:{account}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
        if machine_arn != expected:
            raise ValueError("binding_invalid")
        self.clients, self.journal, self.clock = clients, journal, clock
        self.account, self.api, self.machine = account, api_id, machine_arn
        self.binding = dict(schema=1, account=account, api_id=api_id, machine_arn=machine_arn,
            source_sha=source_sha, run_id=run_id, start=execution_start, end=execution_end)
        self.name = "multiuser-" + run_id
        self.execution = f"arn:aws:states:eu-west-1:{account}:execution:honda-mapit-mcp-dev-retained-shutdown:{self.name}"
        self.last = None

    def _guard(self):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
            or not self.binding["start"] <= now < self.binding["end"]
            or self.last is not None and now < self.last):
            raise ValueError("window_closed")
        self.last = now

    def _load(self):
        value = self.journal.load()
        if value is not None and (type(value) is not dict or set(value) != {"binding", "phase", "close_attempts"}
            or type(value["close_attempts"]) is not int or not 0 <= value["close_attempts"] <= 3
            or value["binding"] != self.binding or value["phase"] not in {
                "ready", "arm_intent", "armed", "lambda_intent", "lambda_open",
                "api_intent", "open", "close_intent", "closed"}):
            raise ValueError("journal_invalid")
        return value

    def _save(self, phase, close_attempts=None):
        prior = self._load()
        attempts = (prior["close_attempts"] if prior else 0) if close_attempts is None else close_attempts
        self.journal.save({"binding": self.binding, "phase": phase, "close_attempts": attempts})

    def _closed(self):
        value = self.clients["lambda"].get_function_concurrency(FunctionName=FUNCTION)
        api = self.clients["apigatewayv2"].get_api(ApiId=self.api)
        return value.get("ReservedConcurrentExecutions") == 0 and api.get("ApiId") == self.api and api.get("DisableExecuteApiEndpoint") is True

    def preflight(self):
        with self.journal.locked():
            self._guard()
            if self._load() is not None or not self._closed():
                raise ValueError("fresh_closed_window_required")
            quota = self.clients["lambda"].get_account_settings()
            if quota.get("AccountLimit", {}).get("ConcurrentExecutions") != 10:
                raise ValueError("quota_mismatch")
            function = self.clients["lambda"].get_function_configuration(FunctionName=FUNCTION)
            env = function.get("Environment", {}).get("Variables", {})
            if (function.get("FunctionName") != FUNCTION
                or function.get("FunctionArn") != f"arn:aws:lambda:eu-west-1:{self.account}:function:{FUNCTION}"
                or function.get("Handler") != "mapit.aws_dev_multiuser_entrypoint.handler"
                or env.get("MAPIT_MCP_ENV") != "dev" or env.get("MAPIT_DEV_MULTIUSER_MODE") != "synthetic"
                or env.get("MAPIT_SOURCE_SHA256") != self.binding["source_sha"]
                or env.get("MAPIT_DEV_EXECUTION_START_EPOCH") != str(self.binding["start"])
                or env.get("MAPIT_DEV_EXECUTION_END_EPOCH") != str(self.binding["end"])
                or env.get("MAPIT_OBSERVED_API_ID") != self.api):
                raise ValueError("runtime_mismatch")
            machine = self.clients["stepfunctions"].describe_state_machine(stateMachineArn=self.machine)
            expected = build_dev_multiuser_timed_controls(self.api)["Resources"]["ShutdownStateMachine"]["Properties"]
            if (machine.get("stateMachineArn") != self.machine or machine.get("type") != "STANDARD"
                or machine.get("status") != "ACTIVE"
                or json.loads(machine.get("definition", "{}")) != json.loads(expected["DefinitionString"])
                or machine.get("roleArn") != f"arn:aws:iam::{self.account}:role/honda-mapit-mcp-dev-retained-shutdown-workflow"
                or machine.get("loggingConfiguration", {}).get("level") != "OFF"
                or machine.get("tracingConfiguration", {}).get("enabled") is not False):
                raise ValueError("independent_stop_mismatch")
            self._guard()
            self._save("ready")
            return {"success": True, "phase": "ready"}

    def open(self):
        with self.journal.locked():
            self._guard()
            state = self._load()
            if state is None or state["phase"] != "ready" or not self._closed():
                raise ValueError("opening_fenced")
            self._save("arm_intent")
            self._guard()
            reply = self.clients["stepfunctions"].start_execution(
                stateMachineArn=self.machine, name=self.name, input='{"bounded_dev_probe":true}')
            self._guard()
            if reply.get("executionArn") != self.execution:
                raise ValueError("arm_outcome_unknown")
            run = self.clients["stepfunctions"].describe_execution(executionArn=self.execution)
            if (run.get("executionArn") != self.execution or run.get("stateMachineArn") != self.machine
                or run.get("status") != "RUNNING" or json.loads(run.get("input", "{}")) != {"bounded_dev_probe": True}):
                raise ValueError("independent_stop_unverified")
            self._guard()
            self._save("armed")
            self._save("lambda_intent")
            self._guard()
            self.clients["lambda"].delete_function_concurrency(FunctionName=FUNCTION)
            self._guard()
            if "ReservedConcurrentExecutions" in self.clients["lambda"].get_function_concurrency(FunctionName=FUNCTION):
                raise ValueError("shared_pool_unverified")
            self._save("lambda_open")
            self._guard()
            self._save("api_intent")
            self._guard()
            self.clients["apigatewayv2"].update_api(ApiId=self.api, DisableExecuteApiEndpoint=False)
            self._guard()
            api = self.clients["apigatewayv2"].get_api(ApiId=self.api)
            if api.get("ApiId") != self.api or api.get("DisableExecuteApiEndpoint") is not False:
                raise ValueError("opening_unverified")
            self._save("open")
            return {"success": True, "phase": "open", "independent_stop_armed": True}

    def close(self):
        # Expiration must never prohibit closure. Do not extend the window.
        with self.journal.locked():
            state = self._load()
            if state is None:
                raise ValueError("window_missing")
            if state["phase"] == "closed" or state["close_attempts"] >= 3:
                return {"success": self._closed(), "phase": "closed_readback"}
            self._save("close_intent", close_attempts=state["close_attempts"] + 1)
            errors = False
            try:
                self.clients["apigatewayv2"].update_api(ApiId=self.api, DisableExecuteApiEndpoint=True)
            except Exception:
                errors = True
            try:
                self.clients["lambda"].put_function_concurrency(FunctionName=FUNCTION, ReservedConcurrentExecutions=0)
            except Exception:
                errors = True
            closed = self._closed()
            if closed:
                self._save("closed")
            return {"success": closed, "phase": "closed" if closed else "closure_unverified", "ambiguous_response": errors}
