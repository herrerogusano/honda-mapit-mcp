"""Injected, one-intent CloudFormation updater for isolated retained DEV only.

The caller supplies independently reviewed exact template bytes and private
bindings. This core performs no discovery outside three fixed stacks, constructs
no SDK client, never opens an endpoint and never retries a write. An ambiguous
response is fenced; reconciliation is read-only, with the same request token.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time

REGION = "eu-west-1"
APP = "honda-mapit-mcp-dev-retained"
ROLES = "honda-mapit-mcp-dev-retained-cd-delivery"
CONTROLS = "honda-mapit-mcp-dev-retained-controls"


class ClosedUpdateError(ValueError):
    pass


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


class ClosedDevUpdate:
    def __init__(self, clients, journal, *, account, caller_arn, stack_arn,
                 prior_template, target_template, service_role_arn, source_sha,
                 start, end, token, clock=time.time):
        if (type(account) is not str or re.fullmatch(r"[0-9]{12}", account) is None
            or account == "0" * 12 or type(source_sha) is not str
            or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
            or type(token) is not str or re.fullmatch(r"dev-multiuser-[0-9a-f]{32}", token) is None
            or type(start) is not int or type(end) is not int or not 0 < end - start <= 7200):
            raise ClosedUpdateError("binding_invalid")
        match = re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/({APP}|{ROLES}|{CONTROLS})/"
                             r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", stack_arn)
        if match is None or caller_arn.endswith(":root") or not caller_arn.startswith(f"arn:aws:iam::{account}:user/"):
            raise ClosedUpdateError("binding_invalid")
        self.stack_name = match.group(1)
        expected_role = f"arn:aws:iam::{account}:role/honda-mapit-mcp-dev-retained-cfn-update"
        if (self.stack_name == APP and service_role_arn != expected_role
            or self.stack_name in {ROLES, CONTROLS} and service_role_arn is not None):
            raise ClosedUpdateError("service_role_invalid")
        for value in (prior_template, target_template):
            if type(value) is not dict or len(json.dumps(value).encode()) > 64 * 1024:
                raise ClosedUpdateError("template_invalid")
        if self.stack_name == APP:
            for value in (prior_template, target_template):
                resources = value.get("Resources", {})
                if (resources.get("McpApi", {}).get("Properties", {}).get("DisableExecuteApiEndpoint") is not True
                    or resources.get("McpHandler", {}).get("Properties", {}).get("ReservedConcurrentExecutions") != 0):
                    raise ClosedUpdateError("target_not_closed")
        self.clients, self.journal = dict(clients), journal
        self.account, self.caller, self.stack, self.role = account, caller_arn, stack_arn, service_role_arn
        self.prior = json.loads(json.dumps(prior_template))
        self.target = json.loads(json.dumps(target_template))
        self.clock, self.last = clock, None
        self.binding = {"schema": 1, "operation": "dev_multiuser_closed_update", "account": account,
                        "caller": caller_arn, "stack": stack_arn, "role": service_role_arn,
                        "source": source_sha, "start": start, "end": end, "token": token,
                        "prior": _digest(self.prior), "target": _digest(self.target)}

    def _window(self):
        now = self.clock()
        if (type(now) not in (int, float) or not math.isfinite(now)
            or not self.binding["start"] <= now < self.binding["end"]
            or self.last is not None and now < self.last):
            raise ClosedUpdateError("window_closed")
        self.last = now

    def _identity(self):
        self._window()
        value = self.clients["sts"].get_caller_identity()
        if value.get("Account") != self.account or value.get("Arn") != self.caller:
            raise ClosedUpdateError("identity_mismatch")

    def _stack_read(self):
        value = self.clients["cloudformation"].describe_stacks(StackName=self.stack)
        items = value.get("Stacks")
        if type(items) is not list or len(items) != 1:
            raise ClosedUpdateError("stack_invalid")
        item = items[0]
        tags = {row.get("Key"): row.get("Value") for row in item.get("Tags", [])}
        if (item.get("StackId") != self.stack or item.get("StackName") != self.stack_name
            or tags.get("Project") != "honda-mapit-mcp" or tags.get("Environment") != "dev"):
            raise ClosedUpdateError("ownership_invalid")
        return item

    def _closed(self):
        fn = "honda-mapit-mcp-dev-retained-handler"
        value = self.clients["lambda"].get_function_concurrency(FunctionName=fn)
        if value.get("ReservedConcurrentExecutions") != 0:
            raise ClosedUpdateError("runtime_not_closed")
        # API physical ID is read from the exact owned application, not a list.
        resources = self.clients["cloudformation"].describe_stack_resources(StackName=APP).get("StackResources", [])
        apis = [row for row in resources if row.get("LogicalResourceId") == "McpApi"
                and row.get("ResourceType") == "AWS::ApiGatewayV2::Api"]
        if len(apis) != 1:
            raise ClosedUpdateError("api_binding_invalid")
        api = self.clients["apigatewayv2"].get_api(ApiId=apis[0]["PhysicalResourceId"])
        if api.get("DisableExecuteApiEndpoint") is not True or api.get("ApiId") != apis[0]["PhysicalResourceId"]:
            raise ClosedUpdateError("runtime_not_closed")

    def _template(self):
        body = self.clients["cloudformation"].get_template(StackName=self.stack, TemplateStage="Original")["TemplateBody"]
        if isinstance(body, str):
            body = json.loads(body)
        if type(body) is not dict:
            raise ClosedUpdateError("template_invalid")
        return body

    def run(self, step):
        if step not in {"preflight", "update", "readback"}:
            raise ClosedUpdateError("step_invalid")
        with self.journal.locked():
            state = self.journal.load()
            if (_digest(self.prior) != self.binding["prior"] or _digest(self.target) != self.binding["target"]):
                raise ClosedUpdateError("template_binding_mismatch")
            if state is not None and (type(state) is not dict or set(state) != {"binding", "phase"} or state.get("binding") != self.binding or
                state.get("phase") not in {"ready", "intent", "acknowledged", "accepted"}):
                raise ClosedUpdateError("journal_mismatch")
            self._identity()
            stack = self._stack_read()
            self._closed()
            if step == "preflight":
                if state is not None:
                    raise ClosedUpdateError("journal_already_initialized")
                if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or _digest(self._template()) != self.binding["prior"]:
                    raise ClosedUpdateError("prior_mismatch")
                if stack.get("RoleARN") not in {None, self.role}:
                    raise ClosedUpdateError("service_role_invalid")
                self.journal.save({"binding": self.binding, "phase": "ready"})
                return {"ok": True, "phase": "ready"}
            if state is None:
                raise ClosedUpdateError("preflight_required")
            if step == "update":
                if state["phase"] != "ready":
                    raise ClosedUpdateError("write_fenced")
                if stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or _digest(self._template()) != self.binding["prior"]:
                    raise ClosedUpdateError("prior_mismatch")
                self._window()
                state["phase"] = "intent"
                self.journal.save(state)
                request = {"StackName": self.stack, "TemplateBody": json.dumps(self.target, separators=(",", ":")),
                           "Capabilities": ["CAPABILITY_NAMED_IAM"], "ClientRequestToken": self.binding["token"]}
                if self.role is not None:
                    request["RoleARN"] = self.role
                response = self.clients["cloudformation"].update_stack(**request)
                if response.get("StackId") != self.stack:
                    raise ClosedUpdateError("write_response_unknown")
                state["phase"] = "acknowledged"
                self.journal.save(state)
                return {"ok": True, "phase": "acknowledged"}
            if state["phase"] not in {"intent", "acknowledged", "accepted"}:
                raise ClosedUpdateError("write_required")
            if stack.get("StackStatus") == "UPDATE_IN_PROGRESS":
                return {"ok": True, "phase": "pending"}
            if (stack.get("StackStatus") != "UPDATE_COMPLETE" or stack.get("RoleARN") != self.role
                or _digest(self._template()) != self.binding["target"]):
                raise ClosedUpdateError("update_not_accepted")
            events = self.clients["cloudformation"].describe_stack_events(StackName=self.stack).get("StackEvents", [])
            matches = [event for event in events if event.get("PhysicalResourceId") == self.stack
                       and event.get("ResourceType") == "AWS::CloudFormation::Stack"
                       and event.get("ResourceStatus") == "UPDATE_COMPLETE"
                       and event.get("ClientRequestToken") == self.binding["token"]]
            if len(matches) != 1:
                raise ClosedUpdateError("completion_provenance_invalid")
            self._window()
            state["phase"] = "accepted"
            self.journal.save(state)
            return {"ok": True, "phase": "accepted"}
