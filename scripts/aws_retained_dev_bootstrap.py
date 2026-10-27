"""Closed, injected bootstrap coordinator for the retained dev scaffold.

This module deliberately contains no AWS SDK construction, credential lookup,
network setup, or default clients.  A caller supplies every client and a
private journal.  The only write is one CloudFormation ``CreateStack`` after a
fresh, bounded preflight; an uncertain write is never replayed.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from typing import Any, Callable

from scripts.build_aws_retained_dev import build_retained_dev_template

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained"
API_NAME = "honda-mapit-mcp-dev-retained-api"
FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
LOG_GROUP_NAME = "/aws/lambda/honda-mapit-mcp-dev-retained-handler"
ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
POLICY_NAME = "honda-mapit-mcp-dev-retained-owned-log-writes"
MAX_AUTHORITY_SECONDS = 60 * 60
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 32
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_SOURCE_RE = re.compile(r"^[0-9a-f]{40}$")
_STACK_RE = re.compile(
    rf"^arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/"
    rf"{re.escape(STACK_NAME)}/([0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}})$"
)
_RESOURCE_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
}
_CATEGORIES = {
    "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid",
    "window_expired", "step_invalid", "preflight_conflict", "stack_absence_unverified",
    "named_resource_conflict", "preflight_verified", "preflight_required",
    "create_intent_conflict", "create_outcome_unknown", "create_acknowledged",
    "create_in_progress", "stack_not_complete", "stack_readback_mismatch",
    "readback_clients_missing", "readback_verified", "aws_call_failed",
    "aws_response_invalid", "journal_failed", "coordinator_internal_error",
}


class RetainedDevBootstrapError(ValueError):
    """Fixed-category error that never includes input or provider text."""

    def __init__(self, category: str) -> None:
        self.category = category if category in _CATEGORIES else "coordinator_internal_error"
        super().__init__(self.category)


class _AwsCallFailure(Exception):
    def __init__(self, code: str, *, missing: bool = False) -> None:
        self.code = code
        self.missing = missing
        super().__init__(code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _strict_mapping(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value.encode("utf-8", "ignore")) > 64 * 1024:
        return None
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicates)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, child in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = child
    return result


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and type(error.get("Code")) is str:
            return error["Code"]
    return ""


class RetainedDevBootstrapCoordinator:
    """Bounded preflight/create/readback coordinator with injected clients."""

    STEPS = ("preflight", "create", "readback")

    def __init__(
        self,
        clients: Mapping[str, Any],
        journal: Any,
        *,
        account_id: str,
        source_sha: str,
        run_id: int,
        expected_caller_arn: str,
        authorized_from_epoch: int,
        authorized_until_epoch: int,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        required_clients = {"sts", "cloudformation", "lambda", "logs", "iam", "apigatewayv2"}
        if not isinstance(clients, Mapping) or not required_clients <= set(clients) or any(
            clients.get(name) is None for name in required_clients
        ):
            raise RetainedDevBootstrapError("clients_invalid")
        if any(not callable(getattr(clients[name], "__getattribute__", None)) for name in required_clients):
            raise RetainedDevBootstrapError("clients_invalid")
        if any(not callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            raise RetainedDevBootstrapError("journal_invalid")
        if type(account_id) is not str or _ACCOUNT_RE.fullmatch(account_id) is None:
            raise RetainedDevBootstrapError("binding_invalid")
        if type(source_sha) is not str or _SOURCE_RE.fullmatch(source_sha) is None or source_sha == "0" * 40:
            raise RetainedDevBootstrapError("binding_invalid")
        if type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0:
            raise RetainedDevBootstrapError("binding_invalid")
        if (
            type(expected_caller_arn) is not str
            or re.fullmatch(
                rf"(?:arn:aws:(?:iam|sts)::{account_id}:(?:user|role)/[^\s:/]+|"
                rf"arn:aws:sts::{account_id}:assumed-role/[^\s:/]+/[^\s:/]+)",
                expected_caller_arn,
            ) is None
        ):
            raise RetainedDevBootstrapError("binding_invalid")
        if (
            type(authorized_from_epoch) is not int
            or isinstance(authorized_from_epoch, bool)
            or type(authorized_until_epoch) is not int
            or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0
            or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS
        ):
            raise RetainedDevBootstrapError("window_invalid")
        try:
            template = build_retained_dev_template()
        except Exception:
            raise RetainedDevBootstrapError("binding_invalid") from None
        self.template = template
        self.template_bytes = _canonical(template)
        self.template_sha256 = hashlib.sha256(self.template_bytes).hexdigest()
        self.clients = dict(clients)
        for name, client in self.clients.items():
            try:
                meta = getattr(client, "meta", None)
                region_name = getattr(meta, "region_name", None)
                if region_name is None:
                    region_name = getattr(client, "region_name", None)
            except Exception:
                raise RetainedDevBootstrapError("binding_invalid") from None
            expected_region = "us-east-1" if name == "iam" else REGION
            endpoint_url = getattr(meta, "endpoint_url", None)
            # Minimal fakes may omit all metadata; once IAM metadata is
            # present, its signing region must be the global us-east-1 one.
            if region_name is not None and region_name != expected_region:
                raise RetainedDevBootstrapError("binding_invalid")
            if name == "iam":
                if endpoint_url is not None and endpoint_url != "https://iam.amazonaws.com":
                    raise RetainedDevBootstrapError("binding_invalid")
        self.journal = journal
        self.account_id = account_id
        self.source_sha = source_sha
        self.run_id = run_id
        self.expected_caller_arn = expected_caller_arn
        self.window_start = authorized_from_epoch
        self.window_end = authorized_until_epoch
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self._step_started = 0.0
        self._last_monotonic = 0.0
        self._calls = 0
        self._last_observed_epoch = 0

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                self._step_started = self._mono()
                self._last_monotonic = self._step_started
                self._calls = 0
                saved = self._load()
                if saved is not None:
                    observed = saved.get("last_observed_epoch")
                    if type(observed) is not int or observed <= 0:
                        raise RetainedDevBootstrapError("binding_invalid")
                    self._last_observed_epoch = max(self._last_observed_epoch, observed)
                self._check_identity()
                return getattr(self, f"_step_{step}")()
        except RetainedDevBootstrapError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "coordinator_internal_error")

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls}

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise RetainedDevBootstrapError("window_invalid")
        return int(value)

    def _mono(self) -> float:
        value = self.monotonic()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
            raise RetainedDevBootstrapError("window_invalid")
        return float(value)

    def _check_authority(self) -> None:
        now = self._now()
        if self._last_observed_epoch and now < self._last_observed_epoch:
            raise RetainedDevBootstrapError("window_expired")
        self._last_observed_epoch = now
        if not self.window_start <= now < self.window_end:
            raise RetainedDevBootstrapError("window_expired")

    def _check_identity(self) -> None:
        try:
            reply = self._call("sts", "get_caller_identity")
        except _AwsCallFailure:
            raise RetainedDevBootstrapError("aws_call_failed") from None
        if reply.get("Account") != self.account_id or reply.get("Arn") != self.expected_caller_arn:
            raise RetainedDevBootstrapError("binding_invalid")

    def _call(self, service: str, operation: str, **kwargs: Any) -> Mapping[str, Any]:
        if self._calls >= MAX_CALLS_PER_STEP or self._mono() - self._step_started > MAX_STEP_SECONDS:
            raise RetainedDevBootstrapError("aws_call_failed")
        self._check_authority()
        client = self.clients.get(service)
        if client is None or not callable(getattr(client, operation, None)):
            raise RetainedDevBootstrapError("clients_invalid")
        self._calls += 1
        try:
            result = getattr(client, operation)(**kwargs)
        except Exception as exc:
            code = _error_code(exc)
            response = getattr(exc, "response", None)
            error = response.get("Error") if isinstance(response, Mapping) else None
            message = error.get("Message") if isinstance(error, Mapping) else None
            missing = (
                (
                    service == "cloudformation"
                    and operation == "describe_stacks"
                    and code == "ValidationError"
                    and message == f"Stack with id {STACK_NAME} does not exist"
                )
                or (service in {"lambda", "logs"} and code == "ResourceNotFoundException")
                or (service == "iam" and code == "NoSuchEntity")
            )
            raise _AwsCallFailure(code, missing=missing) from None
        if not isinstance(result, Mapping):
            raise RetainedDevBootstrapError("aws_response_invalid")
        metadata = result.get("ResponseMetadata")
        if (
            not isinstance(metadata, Mapping)
            or type(metadata.get("HTTPStatusCode")) is not int
            or metadata["HTTPStatusCode"] != 200
        ):
            raise RetainedDevBootstrapError("aws_response_invalid")
        now_mono = self._mono()
        if now_mono < self._last_monotonic or now_mono - self._step_started > MAX_STEP_SECONDS:
            raise RetainedDevBootstrapError("aws_call_failed")
        self._last_monotonic = now_mono
        self._check_authority()
        return result

    def _load(self) -> dict[str, Any] | None:
        try:
            value = self.journal.load()
        except Exception:
            raise RetainedDevBootstrapError("journal_failed") from None
        if value is not None and not isinstance(value, dict):
            raise RetainedDevBootstrapError("journal_failed")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        try:
            self.journal.save(value)
        except Exception:
            raise RetainedDevBootstrapError("journal_failed") from None

    def _base_state(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "region": REGION,
            "stack_name": STACK_NAME,
            "account_id": self.account_id,
            "source_sha": self.source_sha,
            "template_sha256": self.template_sha256,
            "run_id": self.run_id,
            "expected_caller_arn": self.expected_caller_arn,
            "client_request_token": str(self.run_id),
            "authorized_from_epoch": self.window_start,
            "authorized_until_epoch": self.window_end,
            "last_observed_epoch": self._last_observed_epoch,
            "phase": "preflight_verified",
        }

    def _state(self, *, required: bool = True) -> dict[str, Any] | None:
        state = self._load()
        if state is None:
            if required:
                raise RetainedDevBootstrapError("preflight_required")
            return None
        expected = self._base_state()
        if type(state.get("schema")) is not int or state.get("schema") != 1:
            raise RetainedDevBootstrapError("binding_invalid")
        for key, value in expected.items():
            if key in {"phase", "last_observed_epoch"}:
                continue
            if state.get(key) != value:
                raise RetainedDevBootstrapError("binding_invalid")
        if type(state.get("run_id")) is not int or isinstance(state.get("run_id"), bool):
            raise RetainedDevBootstrapError("binding_invalid")
        if type(state.get("last_observed_epoch")) is not int or state["last_observed_epoch"] <= 0:
            raise RetainedDevBootstrapError("binding_invalid")
        self._last_observed_epoch = max(self._last_observed_epoch, state["last_observed_epoch"])
        if "create_intent" in state and state["create_intent"] != {
            "source_sha": self.source_sha,
            "template_sha256": self.template_sha256,
            "run_id": self.run_id,
            "client_request_token": str(self.run_id),
            "stack_name": STACK_NAME,
        }:
            raise RetainedDevBootstrapError("create_intent_conflict")
        stack_id = state.get("stack_id")
        if stack_id is not None and not self._stack_arn(stack_id):
            raise RetainedDevBootstrapError("binding_invalid")
        return state

    def _stack_arn(self, value: Any) -> bool:
        return type(value) is str and bool(_STACK_RE.fullmatch(value)) and value.split(":")[4] == self.account_id

    def _step_preflight(self) -> dict[str, Any]:
        if self._load() is not None:
            raise RetainedDevBootstrapError("preflight_conflict")
        self._check_authority()
        try:
            stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        except _AwsCallFailure as exc:
            if not exc.missing:
                raise RetainedDevBootstrapError("stack_absence_unverified") from None
            stack = None
        else:
            # A successful empty response is not proof that the fixed name is
            # absent; only the exact AWS ValidationError is admissible.
            raise RetainedDevBootstrapError("stack_absence_unverified")
        if stack is not None:
            raise RetainedDevBootstrapError("stack_absence_unverified")

        self._check_absent_name("lambda", "get_function", {"FunctionName": FUNCTION_NAME}, "lambda")
        self._check_absent_name("logs", "describe_log_groups", {"logGroupNamePrefix": LOG_GROUP_NAME}, "logs")
        self._check_absent_name("iam", "get_role", {"RoleName": ROLE_NAME}, "iam")
        api = self.clients.get("apigatewayv2")
        if api is not None:
            try:
                result = self._call("apigatewayv2", "get_apis", MaxResults="100")
            except _AwsCallFailure:
                raise RetainedDevBootstrapError("aws_call_failed") from None
            items = result.get("Items")
            if type(items) is not list or result.get("NextToken") not in (None, "") or any(isinstance(item, Mapping) and item.get("Name") == API_NAME for item in items):
                raise RetainedDevBootstrapError("named_resource_conflict")
        self._check_authority()
        self._save(self._base_state())
        return self._safe("preflight", True, "preflight_verified")

    def _check_absent_name(self, service: str, operation: str, kwargs: dict[str, Any], kind: str) -> None:
        try:
            result = self._call(service, operation, **kwargs)
        except _AwsCallFailure as exc:
            if exc.missing:
                return
            raise RetainedDevBootstrapError("aws_call_failed") from None
        if kind == "logs":
            groups = result.get("logGroups")
            if not isinstance(groups, list) or result.get("nextToken") not in (None, "") or any(isinstance(row, Mapping) and row.get("logGroupName") == LOG_GROUP_NAME for row in groups):
                raise RetainedDevBootstrapError("named_resource_conflict")
            return
        raise RetainedDevBootstrapError("named_resource_conflict")

    def _step_create(self) -> dict[str, Any]:
        state = self._state()
        assert state is not None
        if state.get("phase") != "preflight_verified" or "create_intent" in state:
            raise RetainedDevBootstrapError("create_intent_conflict")
        self._check_authority()
        intent = {
            "source_sha": self.source_sha,
            "template_sha256": self.template_sha256,
            "run_id": self.run_id,
            "client_request_token": str(self.run_id),
            "stack_name": STACK_NAME,
        }
        state["create_intent"] = intent
        self._check_authority()
        state["create_intent_saved_at"] = self._last_observed_epoch
        state["last_observed_epoch"] = self._last_observed_epoch
        state["phase"] = "create_intent_saved"
        self._save(state)
        self._check_authority()
        try:
            response = self._call(
                "cloudformation", "create_stack", StackName=STACK_NAME,
                TemplateBody=self.template_bytes.decode("ascii"),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                EnableTerminationProtection=True,
                ClientRequestToken=str(self.run_id),
                Tags=[
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "dev"},
                    {"Key": "Purpose", "Value": "retained-dev"},
                    {"Key": "OperatorRunId", "Value": str(self.run_id)},
                ],
            )
        except Exception:
            state["phase"] = "create_outcome_unknown"
            state["last_observed_epoch"] = self._last_observed_epoch
            self._save(state)
            raise RetainedDevBootstrapError("create_outcome_unknown") from None
        stack_id = response.get("StackId")
        if not self._stack_arn(stack_id):
            state["phase"] = "create_outcome_unknown"
            state["last_observed_epoch"] = self._last_observed_epoch
            self._save(state)
            raise RetainedDevBootstrapError("create_outcome_unknown")
        state["stack_id"] = stack_id
        state["phase"] = "create_acknowledged"
        state["last_observed_epoch"] = self._last_observed_epoch
        self._save(state)
        return self._safe("create", True, "create_acknowledged")

    def _step_readback(self) -> dict[str, Any]:
        state = self._state()
        assert state is not None
        if state.get("phase") in {"create_intent_saved", "create_outcome_unknown"}:
            if self._reconcile_ambiguous(state):
                return self._safe("readback", False, "create_in_progress")
            state = self._state()
            assert state is not None
        if state.get("phase") not in {"create_acknowledged", "create_reconciled", "readback_verified"}:
            raise RetainedDevBootstrapError("preflight_required")
        stack_id = state.get("stack_id")
        try:
            reply = self._call("cloudformation", "describe_stacks", StackName=stack_id)
        except _AwsCallFailure:
            raise RetainedDevBootstrapError("aws_call_failed") from None
        rows = reply.get("Stacks")
        if type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        stack = rows[0]
        if (
            stack.get("StackId") != stack_id
            or stack.get("StackName") != STACK_NAME
            or stack.get("EnableTerminationProtection") is not True
        ):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        status = stack.get("StackStatus")
        tags = stack.get("Tags")
        tagmap: dict[str, Any] = {}
        if isinstance(tags, list):
            for row in tags:
                if not isinstance(row, Mapping) or type(row.get("Key")) is not str or row["Key"] in tagmap:
                    raise RetainedDevBootstrapError("stack_readback_mismatch")
                tagmap[row["Key"]] = row.get("Value")
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": str(self.run_id)}
        if tagmap != expected_tags:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        if status == "CREATE_IN_PROGRESS":
            return self._safe("readback", False, "create_in_progress")
        if status != "CREATE_COMPLETE":
            raise RetainedDevBootstrapError("stack_not_complete")
        try:
            template_reply = self._call("cloudformation", "get_template", StackName=stack_id, TemplateStage="Original")
            resources_reply = self._call("cloudformation", "describe_stack_resources", StackName=stack_id)
        except _AwsCallFailure:
            raise RetainedDevBootstrapError("aws_call_failed") from None
        actual = _strict_mapping(template_reply.get("TemplateBody"))
        if actual is None or _canonical(actual) != self.template_bytes:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        resources = resources_reply.get("StackResources")
        if type(resources) is not list or len(resources) != len(_RESOURCE_TYPES):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        physical: dict[str, str] = {}
        for row in resources:
            if not isinstance(row, Mapping):
                raise RetainedDevBootstrapError("stack_readback_mismatch")
            logical = row.get("LogicalResourceId")
            if logical not in _RESOURCE_TYPES or logical in physical or row.get("ResourceType") != _RESOURCE_TYPES[logical] or row.get("ResourceStatus") != "CREATE_COMPLETE":
                raise RetainedDevBootstrapError("stack_readback_mismatch")
            if type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]:
                raise RetainedDevBootstrapError("stack_readback_mismatch")
            physical[logical] = row["PhysicalResourceId"]
        if set(physical) != set(_RESOURCE_TYPES) or physical["McpApiStage"] != "$default" or physical["McpHandler"] != FUNCTION_NAME or physical["McpHandlerRole"] != ROLE_NAME or physical["McpHandlerLogGroup"] != LOG_GROUP_NAME:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        self._verify_runtime(physical)
        state["phase"] = "readback_verified"
        state["readback_verified"] = True
        self._check_authority()
        state["last_observed_epoch"] = self._last_observed_epoch
        self._save(state)
        return self._safe("readback", True, "readback_verified")

    def _reconcile_ambiguous(self, state: dict[str, Any]) -> bool:
        """Adopt only the exact stack proven by its immutable run token."""
        try:
            reply = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        except _AwsCallFailure:
            raise RetainedDevBootstrapError("stack_absence_unverified") from None
        rows = reply.get("Stacks")
        if type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        stack = rows[0]
        stack_id = stack.get("StackId")
        if stack.get("StackName") != STACK_NAME or not self._stack_arn(stack_id):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        tags = stack.get("Tags")
        tagmap = {row.get("Key"): row.get("Value") for row in tags} if isinstance(tags, list) else {}
        expected = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": str(self.run_id)}
        if tagmap != expected or stack.get("ClientRequestToken") not in (None, str(self.run_id)):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        events_reply = self._call("cloudformation", "describe_stack_events", StackName=stack_id)
        events = events_reply.get("StackEvents")
        if (
            type(events) is not list
            or len(events) > 200
            or "NextToken" in events_reply
            or not any(
                isinstance(event, Mapping)
                and event.get("StackId") == stack_id
                and event.get("ClientRequestToken") == str(self.run_id)
                for event in events
            )
        ):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        state["stack_id"] = stack_id
        state["phase"] = "create_reconciled"
        self._check_authority()
        state["last_observed_epoch"] = self._last_observed_epoch
        self._save(state)
        if stack.get("StackStatus") == "CREATE_IN_PROGRESS":
            return True
        if stack.get("StackStatus") != "CREATE_COMPLETE":
            raise RetainedDevBootstrapError("stack_not_complete")
        return False

    def _verify_runtime(self, physical: Mapping[str, str]) -> None:
        for required in ("lambda", "logs", "iam", "apigatewayv2"):
            if self.clients.get(required) is None:
                raise RetainedDevBootstrapError("readback_clients_missing")
        try:
            api = self._call("apigatewayv2", "get_api", ApiId=physical["McpApi"])
            routes = self._call("apigatewayv2", "get_routes", ApiId=physical["McpApi"])
            stage = self._call("apigatewayv2", "get_stage", ApiId=physical["McpApi"], StageName="$default")
            function_config = self._call("lambda", "get_function_configuration", FunctionName=FUNCTION_NAME)
            concurrency = self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
            function_config_repeat = self._call("lambda", "get_function_configuration", FunctionName=FUNCTION_NAME)
            groups = self._call("logs", "describe_log_groups", logGroupNamePrefix=LOG_GROUP_NAME)
            role = self._call("iam", "get_role", RoleName=ROLE_NAME)
            attached = self._call("iam", "list_attached_role_policies", RoleName=ROLE_NAME)
            inline_list = self._call("iam", "list_role_policies", RoleName=ROLE_NAME)
            policy = self._call("iam", "get_role_policy", RoleName=ROLE_NAME, PolicyName=POLICY_NAME)
        except _AwsCallFailure:
            raise RetainedDevBootstrapError("aws_call_failed") from None
        if (
            api.get("ApiId") != physical["McpApi"]
            or api.get("Name") != API_NAME
            or api.get("ProtocolType") != "HTTP"
            or api.get("DisableExecuteApiEndpoint") is not True
        ):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        if routes.get("Items") != [] or "NextToken" in routes:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        stage_settings = stage.get("DefaultRouteSettings")
        if (
            stage.get("StageName") != "$default"
            or stage.get("AutoDeploy") is not True
            or stage_settings != {"DetailedMetricsEnabled": False, "ThrottlingBurstLimit": 1, "ThrottlingRateLimit": 1}
        ):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        runtime_fields = (
            "FunctionName", "FunctionArn", "Runtime", "Handler", "Role", "MemorySize",
            "Timeout", "Architectures", "State", "LastUpdateStatus", "Environment",
            "VpcConfig", "Layers", "DeadLetterConfig", "CodeSha256", "RevisionId",
        )
        snapshot = {key: function_config.get(key) for key in runtime_fields if key in function_config}
        repeat_snapshot = {key: function_config_repeat.get(key) for key in runtime_fields if key in function_config_repeat}
        if (
            snapshot != repeat_snapshot
            or
            function_config.get("FunctionName") != FUNCTION_NAME
            or function_config.get("Runtime") != "python3.13"
            or function_config.get("Handler") != "index.handler"
            or function_config.get("MemorySize") != 256
            or type(function_config.get("MemorySize")) is not int
            or function_config.get("Timeout") != 20
            or type(function_config.get("Timeout")) is not int
            or concurrency.get("ReservedConcurrentExecutions") != 0
            or type(concurrency.get("ReservedConcurrentExecutions")) is not int
            or function_config.get("Architectures") != ["arm64"]
            or function_config.get("Role") != f"arn:aws:iam::{self.account_id}:role/{ROLE_NAME}"
            or function_config.get("State") != "Active"
            or function_config.get("LastUpdateStatus") != "Successful"
            or function_config.get("FunctionArn") != f"arn:aws:lambda:{REGION}:{self.account_id}:function:{FUNCTION_NAME}"
            or ("Environment" in function_config and (not isinstance(function_config.get("Environment"), Mapping) or function_config["Environment"].get("Variables") not in (None, {})))
            or ("VpcConfig" in function_config and (not isinstance(function_config.get("VpcConfig"), Mapping) or function_config["VpcConfig"].get("VpcId") not in (None, "")))
            or function_config.get("Layers") not in (None, [])
            or function_config.get("DeadLetterConfig") not in (None, {})
        ):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        log_groups = groups.get("logGroups")
        if (
            "nextToken" in groups
            or type(log_groups) is not list
            or len(log_groups) != 1
            or not isinstance(log_groups[0], Mapping)
            or log_groups[0].get("logGroupName") != LOG_GROUP_NAME
            or type(log_groups[0].get("retentionInDays")) is not int
            or log_groups[0].get("retentionInDays") != 7
        ):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        role_row = role.get("Role")
        if not isinstance(role_row, Mapping) or role_row.get("RoleName") != ROLE_NAME or role_row.get("Arn") != f"arn:aws:iam::{self.account_id}:role/{ROLE_NAME}" or role_row.get("PermissionsBoundary") is not None:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        trust = _strict_mapping(role_row.get("AssumeRolePolicyDocument"))
        expected_trust = self.template["Resources"]["McpHandlerRole"]["Properties"]["AssumeRolePolicyDocument"]
        if trust is None or _canonical(trust) != _canonical(expected_trust):
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        if attached.get("AttachedPolicies") != [] or attached.get("IsTruncated") is not False:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        if inline_list.get("PolicyNames") != [POLICY_NAME] or inline_list.get("IsTruncated") is not False:
            raise RetainedDevBootstrapError("stack_readback_mismatch")
        policy_doc = _strict_mapping(policy.get("PolicyDocument"))
        expected_doc = json.loads(json.dumps(
            self.template["Resources"]["McpHandlerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        ))
        expected_doc["Statement"][0]["Resource"] = (
            f"arn:aws:logs:{REGION}:{self.account_id}:log-group:{LOG_GROUP_NAME}:*"
        )
        if policy.get("PolicyName") != POLICY_NAME or policy_doc is None or _canonical(policy_doc) != _canonical(expected_doc):
            raise RetainedDevBootstrapError("stack_readback_mismatch")


__all__ = [
    "API_NAME", "FUNCTION_NAME", "LOG_GROUP_NAME", "MAX_AUTHORITY_SECONDS",
    "POLICY_NAME", "REGION", "ROLE_NAME", "RetainedDevBootstrapCoordinator",
    "RetainedDevBootstrapError", "STACK_NAME",
]
