"""Injected, one-step coordinator for the closed Cognito OAuth setup update.

No SDK clients, credentials, CLI, or AWS operations are constructed here. The
operator supplies the existing private rehearsal journal and single-attempt
clients. Each update intent is saved before its one CloudFormation write; an
ambiguous update is never blindly replayed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle
from mapit.aws_dev_oauth_setup_control_bundle import build_dev_oauth_setup_control_bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from scripts.aws_dev_oauth_setup_readback import check_oauth_setup_readback
from scripts.build_aws_dev_oauth_template import build_dev_oauth_setup_template
from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template

REGION = "eu-west-1"
APP_STACK_NAME = "honda-mapit-mcp-dev"
CONTROL_STACK_NAME = "honda-mapit-mcp-dev-control"
RUN_TAG = "ClosedRehearsalRunId"
FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
HANDLER_ROLE = "honda-mapit-mcp-dev-handler-role"
LOG_GROUP = "/aws/lambda/honda-mapit-mcp-dev-handler"
API_NAME = "honda-mapit-mcp-dev-api"
DELETION_ROLE = "honda-mapit-mcp-dev-bootstrap-delete"
CLEANUP_ROLE = "honda-mapit-mcp-dev-bootstrap-cleanup-scheduler"
CLEANUP_GROUP = "honda-mapit-mcp-dev-bootstrap-cleanup"
CLEANUP_SCHEDULE = "honda-mapit-mcp-dev-bootstrap-delete-once"
CLEANUP_TARGET = "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
_MAX_STEP_SECONDS = 30.0
_CLEANUP_MARGIN_SECONDS = 300
_API_ID_RE = re.compile(r"^[a-z0-9]{10}$")
_POOL_ID_RE = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")
_APP_NAMES = frozenset({
    "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
})
_APP_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpUserPool": "AWS::Cognito::UserPool", "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup", "McpHandler": "AWS::Lambda::Function",
}
_CONTROL_NAMES = frozenset({
    "ShutdownStateMachine", "ShutdownWorkflowRole", "SchedulerGroup", "SchedulerInvokeRole",
    "ShutdownSchedule", "RequestTripwireAlarm", "RequestTripwireAlarmRule", "RequestTripwireEventRole",
    "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup", "BootstrapCleanupSchedulerRole",
    "BootstrapCleanupSchedule",
})
_CONTROL_TYPES = {
    "ShutdownStateMachine": "AWS::StepFunctions::StateMachine",
    "ShutdownWorkflowRole": "AWS::IAM::Role",
    "SchedulerGroup": "AWS::Scheduler::ScheduleGroup",
    "SchedulerInvokeRole": "AWS::IAM::Role",
    "ShutdownSchedule": "AWS::Scheduler::Schedule",
    "RequestTripwireAlarm": "AWS::CloudWatch::Alarm",
    "RequestTripwireAlarmRule": "AWS::Events::Rule",
    "RequestTripwireEventRole": "AWS::IAM::Role",
    "BootstrapDeletionRole": "AWS::IAM::Role",
    "BootstrapCleanupScheduleGroup": "AWS::Scheduler::ScheduleGroup",
    "BootstrapCleanupSchedulerRole": "AWS::IAM::Role",
    "BootstrapCleanupSchedule": "AWS::Scheduler::Schedule",
}


class OAuthSetupCoordinator:
    """Small injected coordinator; call one named step at a time."""

    STEPS = ("check-bootstrap", "update-controls", "check-controls", "update-oauth-setup", "check-oauth-setup")

    def __init__(
        self,
        clients: Mapping[str, Any],
        journal: Any,
        *,
        expected_account_id: str,
        callback_url: str,
        authorized_until_epoch: int,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        if type(expected_account_id) is not str or len(expected_account_id) != 12 or not expected_account_id.isdigit():
            raise ValueError("expected_account_invalid")
        if type(authorized_until_epoch) is not int or authorized_until_epoch <= 0:
            raise ValueError("authorization_window_invalid")
        required = {"cloudformation", "apigatewayv2", "lambda", "cognito", "iam", "scheduler"}
        if not isinstance(clients, Mapping) or not required <= clients.keys():
            raise ValueError("clients_invalid")
        for method in ("load", "save", "locked"):
            if not callable(getattr(journal, method, None)):
                raise ValueError("journal_invalid")
        # Reuse the reviewed callback validator without normalizing user input.
        from scripts.build_aws_dev_oauth_template import _validate_callback

        _validate_callback(callback_url)
        self.clients = clients
        self.journal = journal
        self.expected_account_id = expected_account_id
        self.callback_url = callback_url
        self.configured_authority = authorized_until_epoch
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self._step_started = 0.0
        self._calls = 0

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid", 0)
        try:
            with self.journal.locked():
                self._step_started = self.monotonic()
                self._calls = 0
                method = getattr(self, f"_step_{step.replace('-', '_')}")
                return method()
        except _FlowError as exc:
            return self._safe(step, False, exc.category, self._calls)
        except Exception:
            return self._safe(step, False, "coordinator_internal_error", self._calls)

    @staticmethod
    def _safe(step: str, ok: bool, category: str, calls: int, **facts: Any) -> dict[str, Any]:
        counts = {key: value for key, value in facts.items() if type(value) is int and value >= 0}
        return {"step": step, "ok": ok, "category": category, "calls": calls, **counts}

    def _call(self, service: str, method: str, **kwargs: Any) -> Any:
        if self.monotonic() - self._step_started >= _MAX_STEP_SECONDS:
            raise _FlowError("step_budget_exhausted")
        self._calls += 1
        try:
            value = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            raise _FlowError("aws_call_failed") from None
        if self.monotonic() - self._step_started >= _MAX_STEP_SECONDS:
            raise _FlowError("step_budget_exhausted")
        if not isinstance(value, Mapping):
            raise _FlowError("aws_response_invalid")
        metadata = value.get("ResponseMetadata")
        if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata["HTTPStatusCode"] != 200:
            raise _FlowError("aws_response_invalid")
        return value

    def _state(self) -> dict[str, Any]:
        state = self.journal.load()
        if not isinstance(state, dict) or type(state.get("schema")) is not int or state.get("schema") != 1 or state.get("region") != REGION:
            raise _FlowError("private_rehearsal_state_required")
        if state.get("account_id") != self.expected_account_id:
            raise _FlowError("account_binding_mismatch")
        if type(state.get("run_id")) is not str:
            raise _FlowError("run_binding_invalid")
        try:
            parsed = uuid.UUID(state["run_id"])
        except (ValueError, AttributeError):
            raise _FlowError("run_binding_invalid") from None
        if str(parsed) != state["run_id"] or parsed.int == 0:
            raise _FlowError("run_binding_invalid")
        if not self._stack_arn(state.get("app_stack_id"), self.expected_account_id, APP_STACK_NAME):
            raise _FlowError("app_stack_binding_invalid")
        if state.get("stack_uuid") != state["app_stack_id"].rsplit("/", 1)[-1]:
            raise _FlowError("app_stack_uuid_mismatch")
        if type(state.get("api_id")) is not str or not _API_ID_RE.fullmatch(state["api_id"]):
            raise _FlowError("api_binding_invalid")
        if type(state.get("user_pool_id")) is not str or not _POOL_ID_RE.fullmatch(state["user_pool_id"]):
            raise _FlowError("pool_binding_invalid")
        if not self._stack_arn(state.get("control_stack_id"), self.expected_account_id, CONTROL_STACK_NAME):
            raise _FlowError("control_stack_binding_invalid")
        return state

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise _FlowError("clock_invalid")
        try:
            return int(value)
        except (OverflowError, ValueError):
            raise _FlowError("clock_invalid") from None

    def _authority(self, state: Mapping[str, Any], *, require_cleanup_margin: bool = False) -> tuple[int, int]:
        saved = state.get("authorized_until_epoch")
        started = state.get("resource_started_epoch")
        if type(saved) is not int or saved <= 0 or type(started) is not int or started <= 0:
            raise _FlowError("immutable_time_binding_invalid")
        deadline = min(saved, self.configured_authority)
        now = self._now()
        cleanup = started + 2700
        resource_deadline = started + 3600
        if now < started or now >= deadline or now >= resource_deadline:
            raise _FlowError("authorization_or_resource_window_expired")
        if require_cleanup_margin and cleanup - now < _CLEANUP_MARGIN_SECONDS:
            raise _FlowError("cleanup_timer_margin_insufficient")
        return now, cleanup

    @staticmethod
    def _stack_arn(value: Any, account: str, name: str) -> bool:
        if type(value) is not str:
            return False
        prefix = f"arn:aws:cloudformation:{REGION}:{account}:stack/{name}/"
        if not value.startswith(prefix):
            return False
        suffix = value[len(prefix):]
        try:
            parsed = uuid.UUID(suffix)
        except (ValueError, AttributeError):
            return False
        return str(parsed) == suffix and parsed.int != 0

    @staticmethod
    def _run_tag(tags: Any, run_id: str) -> bool:
        return type(tags) is list and any(
            isinstance(item, Mapping) and item.get("Key") == RUN_TAG and item.get("Value") == run_id
            for item in tags
        )

    @staticmethod
    def _mapping(value: Any) -> Mapping[str, Any] | None:
        return value if isinstance(value, Mapping) else None

    def _describe_owned_stack(
        self, *, state: Mapping[str, Any], key: str, name: str, allowed_statuses: set[str], roleless: bool = False
    ) -> Mapping[str, Any]:
        stack_arn = state.get(key)
        if not self._stack_arn(stack_arn, self.expected_account_id, name):
            raise _FlowError("stack_binding_invalid")
        response = self._mapping(self._call("cloudformation", "describe_stacks", StackName=stack_arn))
        stacks = response.get("Stacks") if response is not None else None
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise _FlowError("stack_readback_invalid")
        stack = stacks[0]
        status = stack.get("StackStatus")
        if (
            stack.get("StackId") != stack_arn
            or stack.get("StackName") != name
            or type(status) is not str
            or status not in allowed_statuses
        ):
            raise _FlowError("stack_state_invalid")
        if not self._run_tag(stack.get("Tags"), str(state["run_id"])):
            raise _FlowError("stack_ownership_unverified")
        if roleless and stack.get("RoleARN") not in (None, ""):
            raise _FlowError("stack_role_binding_unexpected")
        return stack

    def _resource_map(self, stack_arn: str, expected: frozenset[str]) -> dict[str, Mapping[str, Any]]:
        response = self._mapping(self._call("cloudformation", "describe_stack_resources", StackName=stack_arn))
        rows = response.get("StackResources") if response is not None else None
        if type(rows) is not list or len(rows) != len(expected):
            raise _FlowError("stack_resources_invalid")
        found: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            if not isinstance(row, Mapping):
                raise _FlowError("stack_resources_invalid")
            logical = row.get("LogicalResourceId")
            if type(logical) is not str or logical not in expected or logical in found:
                raise _FlowError("stack_resources_invalid")
            status = row.get("ResourceStatus")
            if type(status) is not str or status not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
                raise _FlowError("stack_resources_incomplete")
            physical = row.get("PhysicalResourceId")
            if type(physical) is not str or not physical or len(physical) > 1024:
                raise _FlowError("stack_resources_invalid")
            expected_types = _APP_TYPES if expected == _APP_NAMES else _CONTROL_TYPES if expected == _CONTROL_NAMES else None
            if expected_types is None or row.get("ResourceType") != expected_types[logical]:
                raise _FlowError("stack_resources_invalid")
            found[logical] = row
        if set(found) != expected:
            raise _FlowError("stack_resources_invalid")
        return found

    def _verify_bootstrap(self, state: Mapping[str, Any]) -> dict[str, str]:
        stack_arn = state.get("app_stack_id")
        stack = self._describe_owned_stack(
            state=state, key="app_stack_id", name=APP_STACK_NAME,
            allowed_statuses={"CREATE_COMPLETE", "UPDATE_COMPLETE"},
            roleless=True,
        )
        outputs = stack.get("Outputs")
        if type(outputs) is not list:
            raise _FlowError("app_outputs_invalid")
        output_map: dict[str, Any] = {}
        for item in outputs:
            if not isinstance(item, Mapping) or type(item.get("OutputKey")) is not str or item["OutputKey"] in output_map:
                raise _FlowError("app_outputs_invalid")
            output_map[item["OutputKey"]] = item.get("OutputValue")
        api_id, pool_id = state.get("api_id"), state.get("user_pool_id")
        if output_map != {"ApiId": api_id, "UserPoolId": pool_id}:
            raise _FlowError("app_outputs_mismatch")
        template_response = self._mapping(self._call(
            "cloudformation", "get_template", StackName=stack_arn, TemplateStage="Original",
        ))
        body = template_response.get("TemplateBody") if template_response is not None else None
        if isinstance(body, str):
            if len(body) > 128 * 1024:
                raise _FlowError("app_template_readback_invalid")
            try:
                body = json.loads(body, object_pairs_hook=self._duplicate_keys)
            except (ValueError, RecursionError):
                raise _FlowError("app_template_readback_invalid") from None
        if not isinstance(body, Mapping) or self._json_bytes(body) != self._json_bytes(fixed_bootstrap_template()):
            raise _FlowError("app_template_readback_mismatch")
        resources = self._resource_map(stack_arn, _APP_NAMES)
        fixed = {
            "McpApi": api_id,
            "McpUserPool": pool_id,
            "McpHandler": FUNCTION_NAME,
            "McpHandlerRole": HANDLER_ROLE,
            "McpHandlerLogGroup": LOG_GROUP,
        }
        if any(resources[name].get("PhysicalResourceId") != value for name, value in fixed.items()):
            raise _FlowError("app_resource_identity_mismatch")
        api = self._mapping(self._call("apigatewayv2", "get_api", ApiId=api_id))
        if api is None or api.get("ApiId") != api_id or api.get("Name") != API_NAME or api.get("DisableExecuteApiEndpoint") is not True:
            raise _FlowError("app_api_not_closed")
        routes = self._mapping(self._call("apigatewayv2", "get_routes", ApiId=api_id, MaxResults="100"))
        if routes is None or type(routes.get("Items")) is not list or routes["Items"] or routes.get("NextToken") not in (None, ""):
            raise _FlowError("app_routes_unexpected")
        function = self._mapping(self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME))
        if function is None or type(function.get("ReservedConcurrentExecutions")) is not int or function["ReservedConcurrentExecutions"] != 0:
            raise _FlowError("app_function_not_reserved")
        users = self._mapping(self._call("cognito", "list_users", UserPoolId=pool_id, Limit=1))
        if users is None or type(users.get("Users")) is not list or users["Users"] or users.get("PaginationToken") not in (None, ""):
            raise _FlowError("app_users_unexpected")
        clients = self._mapping(self._call("cognito", "list_user_pool_clients", UserPoolId=pool_id, MaxResults=1))
        if clients is None or type(clients.get("UserPoolClients")) is not list or clients["UserPoolClients"] or clients.get("NextToken") not in (None, ""):
            raise _FlowError("app_clients_unexpected")
        if not self._stack_arn(stack_arn, self.expected_account_id, APP_STACK_NAME):
            raise _FlowError("stack_binding_invalid")
        if state.get("stack_uuid") != stack_arn.rsplit("/", 1)[-1]:
            raise _FlowError("app_stack_uuid_mismatch")
        return {"stack_arn": stack_arn, "api_id": api_id, "user_pool_id": pool_id}

    @staticmethod
    def _baseline_control_template(state: Mapping[str, Any]) -> dict[str, Any]:
        try:
            return build_dev_bootstrap_control_bundle(
                AwsDevShutdownPolicy(state.get("api_id")),
                user_pool_id=state.get("user_pool_id"),
                stack_uuid=state.get("stack_uuid"),
                resource_started_epoch=state.get("resource_started_epoch"),
                activation_start_epoch=state.get("activation_start_epoch"),
                now_epoch=state.get("controls_created_at_epoch"),
            )
        except Exception:
            raise _FlowError("control_template_binding_invalid") from None

    @staticmethod
    def _setup_control_template(state: Mapping[str, Any]) -> dict[str, Any]:
        try:
            template = build_dev_oauth_setup_control_bundle(
                AwsDevShutdownPolicy(state.get("api_id")),
                user_pool_id=state.get("user_pool_id"),
                stack_uuid=state.get("stack_uuid"),
                resource_started_epoch=state.get("resource_started_epoch"),
                activation_start_epoch=state.get("activation_start_epoch"),
                now_epoch=state.get("controls_created_at_epoch"),
            )
        except Exception:
            raise _FlowError("setup_control_template_invalid") from None
        schedule = template["Resources"]["BootstrapCleanupSchedule"]["Properties"]
        expected_epoch = state["resource_started_epoch"] + 2700
        try:
            expected_at = datetime.fromtimestamp(expected_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        except (OverflowError, OSError, ValueError):
            raise _FlowError("cleanup_schedule_time_invalid") from None
        if schedule.get("ScheduleExpression") != f"at({expected_at})" or schedule.get("State") != "DISABLED":
            raise _FlowError("cleanup_schedule_template_invalid")
        # The accepted factory remains disabled. Only this one controlled,
        # journaled CloudFormation update arms the exact first-resource+45m timer.
        schedule["State"] = "ENABLED"
        template["Metadata"]["CleanupScheduleEnabledByCoordinator"] = True
        return template

    @staticmethod
    def _json_bytes(value: Any) -> bytes:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")

    @staticmethod
    def _policy_document(response: Any) -> Mapping[str, Any] | None:
        if not isinstance(response, Mapping):
            return None
        value = response.get("PolicyDocument")
        if isinstance(value, Mapping):
            return value
        if type(value) is not str or len(value) > 65536:
            return None
        try:
            parsed = json.loads(value, object_pairs_hook=OAuthSetupCoordinator._duplicate_keys)
        except (ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, Mapping) else None

    @staticmethod
    def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate policy field")
            result[key] = value
        return result

    def _cleanup_schedule(self, state: Mapping[str, Any], now: int) -> Mapping[str, Any]:
        started = state.get("resource_started_epoch")
        if type(started) is not int:
            raise _FlowError("immutable_time_binding_invalid")
        scheduled = started + 2700
        if scheduled - now < _CLEANUP_MARGIN_SECONDS:
            raise _FlowError("cleanup_timer_margin_insufficient")
        try:
            at = datetime.fromtimestamp(scheduled, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        except (OverflowError, OSError, ValueError):
            raise _FlowError("cleanup_schedule_time_invalid") from None
        response = self._mapping(self._call(
            "scheduler", "get_schedule", Name=CLEANUP_SCHEDULE, GroupName=CLEANUP_GROUP,
        ))
        if response is None:
            raise _FlowError("cleanup_schedule_readback_invalid")
        expected_arn = f"arn:aws:scheduler:{REGION}:{self.expected_account_id}:schedule/{CLEANUP_GROUP}/{CLEANUP_SCHEDULE}"
        expected_role = f"arn:aws:iam::{self.expected_account_id}:role/{CLEANUP_ROLE}"
        expected_deletion_role = f"arn:aws:iam::{self.expected_account_id}:role/{DELETION_ROLE}"
        target = response.get("Target")
        if not isinstance(target, Mapping):
            raise _FlowError("cleanup_schedule_readback_invalid")
        try:
            parsed_input = json.loads(target.get("Input"), object_pairs_hook=self._duplicate_keys)
        except (TypeError, ValueError, RecursionError):
            raise _FlowError("cleanup_schedule_target_invalid") from None
        if (
            response.get("Arn") != expected_arn
            or response.get("Name") != CLEANUP_SCHEDULE
            or response.get("GroupName") != CLEANUP_GROUP
            or response.get("State") != "ENABLED"
            or response.get("ScheduleExpression") != f"at({at})"
            or response.get("ScheduleExpressionTimezone") != "UTC"
            or response.get("FlexibleTimeWindow") != {"Mode": "OFF"}
            or target.get("Arn") != CLEANUP_TARGET
            or target.get("RoleArn") != expected_role
            or parsed_input != {"StackName": state.get("app_stack_id"), "RoleARN": expected_deletion_role}
            or target.get("RetryPolicy") != {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
        ):
            raise _FlowError("cleanup_schedule_target_invalid")
        return response

    def _verify_disabled_cleanup_schedule(self, state: Mapping[str, Any], expected_expression: str) -> None:
        response = self._mapping(self._call(
            "scheduler", "get_schedule", Name=CLEANUP_SCHEDULE, GroupName=CLEANUP_GROUP,
        ))
        if response is None:
            raise _FlowError("cleanup_schedule_readback_invalid")
        expected_arn = f"arn:aws:scheduler:{REGION}:{self.expected_account_id}:schedule/{CLEANUP_GROUP}/{CLEANUP_SCHEDULE}"
        expected_role = f"arn:aws:iam::{self.expected_account_id}:role/{CLEANUP_ROLE}"
        expected_deletion_role = f"arn:aws:iam::{self.expected_account_id}:role/{DELETION_ROLE}"
        target = response.get("Target")
        if not isinstance(target, Mapping):
            raise _FlowError("cleanup_schedule_target_invalid")
        try:
            parsed_input = json.loads(target.get("Input"), object_pairs_hook=self._duplicate_keys)
        except (TypeError, ValueError, RecursionError):
            raise _FlowError("cleanup_schedule_target_invalid") from None
        if (
            response.get("Arn") != expected_arn or response.get("Name") != CLEANUP_SCHEDULE
            or response.get("GroupName") != CLEANUP_GROUP or response.get("State") != "DISABLED"
            or response.get("ScheduleExpression") != expected_expression
            or response.get("ScheduleExpressionTimezone") != "UTC"
            or response.get("FlexibleTimeWindow") != {"Mode": "OFF"}
            or target.get("Arn") != CLEANUP_TARGET or target.get("RoleArn") != expected_role
            or parsed_input != {"StackName": state.get("app_stack_id"), "RoleARN": expected_deletion_role}
            or target.get("RetryPolicy") != {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
        ):
            raise _FlowError("cleanup_schedule_target_invalid")

    def _verify_control_role_policy(self, state: Mapping[str, Any], *, expected_setup: bool) -> None:
        if expected_setup:
            expected = self._setup_control_template(state)
        else:
            expected = self._baseline_control_template(state)
        resources = expected.get("Resources")
        role = resources.get("BootstrapDeletionRole") if isinstance(resources, Mapping) else None
        properties = role.get("Properties") if isinstance(role, Mapping) else None
        policies = properties.get("Policies") if isinstance(properties, Mapping) else None
        if not isinstance(policies, list) or len(policies) != 1 or not isinstance(policies[0], Mapping):
            raise _FlowError("cleanup_policy_expected_invalid")
        policy_name = policies[0].get("PolicyName")
        expected_document = policies[0].get("PolicyDocument")
        if type(policy_name) is not str or not isinstance(expected_document, Mapping):
            raise _FlowError("cleanup_policy_expected_invalid")
        response = self._mapping(self._call(
            "iam", "get_role_policy", RoleName=DELETION_ROLE, PolicyName=policy_name,
        ))
        observed_document = self._policy_document(response)
        resolved_expected = self._resolve_iam_policy(expected_document)
        if observed_document is None or resolved_expected is None or self._json_bytes(observed_document) != self._json_bytes(resolved_expected):
            raise _FlowError("cleanup_policy_readback_mismatch")

    def _resolve_iam_policy(self, value: Any) -> Any | None:
        if isinstance(value, Mapping):
            if set(value) == {"Fn::Sub"} and type(value["Fn::Sub"]) is str:
                resolved = value["Fn::Sub"]
                for source, target in (
                    ("${AWS::Partition}", "aws"),
                    ("${AWS::Region}", REGION),
                    ("${AWS::AccountId}", self.expected_account_id),
                ):
                    resolved = resolved.replace(source, target)
                if "${" in resolved or "}" in resolved:
                    return None
                return resolved
            return {key: self._resolve_iam_policy(child) for key, child in value.items()}
        if isinstance(value, list):
            return [self._resolve_iam_policy(child) for child in value]
        if type(value) in (str, int, float, bool) or value is None:
            return value
        return None

    def _verify_control_resources(self, state: Mapping[str, Any], *, expected_statuses: set[str]) -> Mapping[str, Any]:
        stack = self._describe_owned_stack(
            state=state, key="control_stack_id", name=CONTROL_STACK_NAME,
            allowed_statuses=expected_statuses, roleless=True,
        )
        stack_arn = state["control_stack_id"]
        resources = self._resource_map(stack_arn, _CONTROL_NAMES)
        if resources["BootstrapDeletionRole"].get("PhysicalResourceId") != DELETION_ROLE:
            raise _FlowError("control_resource_identity_mismatch")
        if resources["BootstrapCleanupSchedulerRole"].get("PhysicalResourceId") != CLEANUP_ROLE:
            raise _FlowError("control_resource_identity_mismatch")
        if resources["BootstrapCleanupScheduleGroup"].get("PhysicalResourceId") != CLEANUP_GROUP:
            raise _FlowError("control_resource_identity_mismatch")
        if resources["BootstrapCleanupSchedule"].get("PhysicalResourceId") != CLEANUP_SCHEDULE:
            raise _FlowError("control_resource_identity_mismatch")
        return stack

    def _verify_setup_control_template(self, state: Mapping[str, Any]) -> None:
        template_response = self._mapping(self._call(
            "cloudformation", "get_template", StackName=state["control_stack_id"], TemplateStage="Original",
        ))
        body = template_response.get("TemplateBody") if template_response is not None else None
        if isinstance(body, str):
            if len(body) > 128 * 1024:
                raise _FlowError("control_template_readback_invalid")
            try:
                body = json.loads(body, object_pairs_hook=self._duplicate_keys)
            except (ValueError, RecursionError):
                raise _FlowError("control_template_readback_invalid") from None
        expected_template = self._setup_control_template(state)
        if not isinstance(body, Mapping):
            raise _FlowError("control_template_readback_mismatch")
        raw_body = self._json_bytes(body)
        if (
            raw_body != self._json_bytes(expected_template)
            or hashlib.sha256(raw_body).hexdigest() != state.get("oauth_setup_control_template_sha256")
        ):
            raise _FlowError("control_template_readback_mismatch")

    def _step_check_bootstrap(self) -> dict[str, Any]:
        state = self._state()
        self._authority(state)
        self._verify_bootstrap(state)
        state["oauth_setup_bootstrap_verified"] = True
        self.journal.save(state)
        return self._safe("check-bootstrap", True, "closed_bootstrap_verified", self._calls, resources_verified=6)

    def _step_update_controls(self) -> dict[str, Any]:
        state = self._state()
        if state.get("oauth_setup_controls_update_attempted"):
            raise _FlowError("controls_update_already_attempted")
        self._authority(state, require_cleanup_margin=True)
        # Recheck current app closure and owned baseline control template before write.
        self._verify_bootstrap(state)
        self._describe_owned_stack(
            state=state, key="control_stack_id", name=CONTROL_STACK_NAME,
            allowed_statuses={"CREATE_COMPLETE", "UPDATE_COMPLETE"},
            roleless=True,
        )
        control_arn = state["control_stack_id"]
        self._resource_map(control_arn, _CONTROL_NAMES)
        baseline = self._baseline_control_template(state)
        template_response = self._mapping(self._call(
            "cloudformation", "get_template", StackName=control_arn, TemplateStage="Original",
        ))
        body = template_response.get("TemplateBody") if template_response is not None else None
        if isinstance(body, str):
            if len(body) > 128 * 1024:
                raise _FlowError("control_template_readback_invalid")
            try:
                body = json.loads(body, object_pairs_hook=self._duplicate_keys)
            except (ValueError, RecursionError):
                raise _FlowError("control_template_readback_invalid") from None
        if not isinstance(body, Mapping) or self._json_bytes(body) != self._json_bytes(baseline):
            raise _FlowError("control_template_readback_mismatch")
        self._verify_control_role_policy(state, expected_setup=False)
        # Refuse a previously armed, possibly-now+120 timer. This update installs
        # the exact start+2700 schedule and expanded Cognito-only role together.
        now, cleanup_epoch = self._authority(state, require_cleanup_margin=True)
        old_schedule = baseline["Resources"]["BootstrapCleanupSchedule"]["Properties"]
        self._verify_disabled_cleanup_schedule(state, old_schedule.get("ScheduleExpression"))
        template = self._setup_control_template(state)
        schedule = template["Resources"]["BootstrapCleanupSchedule"]["Properties"]
        expected_epoch = state["resource_started_epoch"] + 2700
        try:
            expected_at = datetime.fromtimestamp(expected_epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        except (OverflowError, OSError, ValueError):
            raise _FlowError("cleanup_schedule_time_invalid") from None
        if cleanup_epoch != expected_epoch or schedule.get("ScheduleExpression") != f"at({expected_at})" or schedule.get("State") != "ENABLED":
            raise _FlowError("cleanup_schedule_template_invalid")
        raw_template = self._json_bytes(template)
        if len(raw_template) > 51200:
            raise _FlowError("control_template_size_invalid")
        token = uuid.uuid4().hex
        state.update({
            "oauth_setup_controls_update_attempted": True,
            "oauth_setup_controls_update_token": token,
            "oauth_setup_cleanup_schedule_expression": schedule["ScheduleExpression"],
            "oauth_setup_control_template_sha256": hashlib.sha256(raw_template).hexdigest(),
            "oauth_setup_control_update_requested_at_epoch": now,
        })
        self.journal.save(state)
        self._authority(state, require_cleanup_margin=True)
        try:
            response = self._mapping(self._call(
                "cloudformation", "update_stack",
                StackName=control_arn,
                TemplateBody=raw_template.decode("ascii"),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                ClientRequestToken=token,
            ))
        except _FlowError:
            state["oauth_setup_controls_update_ambiguous"] = True
            self.journal.save(state)
            raise _FlowError("controls_update_ambiguous") from None
        if response is None or response.get("StackId") != control_arn:
            state["oauth_setup_controls_update_ambiguous"] = True
            self.journal.save(state)
            raise _FlowError("controls_update_response_ambiguous")
        state["oauth_setup_controls_update_call_returned"] = True
        self.journal.save(state)
        return self._safe("update-controls", True, "controls_update_requested", self._calls, resources_requested=12)

    def _step_check_controls(self) -> dict[str, Any]:
        state = self._state()
        if not state.get("oauth_setup_controls_update_attempted"):
            raise _FlowError("controls_update_not_attempted")
        stack = self._verify_control_resources(state, expected_statuses={"UPDATE_COMPLETE"})
        if stack.get("StackStatus") != "UPDATE_COMPLETE":
            return self._safe("check-controls", False, "controls_update_pending", self._calls)
        self._verify_setup_control_template(state)
        self._verify_control_role_policy(state, expected_setup=True)
        self._authority(state, require_cleanup_margin=True)
        self._cleanup_schedule(state, self._now())
        self._authority(state, require_cleanup_margin=True)
        state["oauth_setup_controls_verified"] = True
        self.journal.save(state)
        return self._safe("check-controls", True, "controls_and_cleanup_verified", self._calls, resources_verified=12)

    def _step_update_oauth_setup(self) -> dict[str, Any]:
        state = self._state()
        if not state.get("oauth_setup_controls_verified") or not state.get("oauth_setup_controls_update_attempted"):
            raise _FlowError("cleanup_controls_not_verified")
        if state.get("oauth_setup_update_attempted"):
            raise _FlowError("oauth_setup_update_already_attempted")
        self._authority(state, require_cleanup_margin=True)
        self._verify_bootstrap(state)
        # Reconfirm the policy, complete control stack and timer immediately
        # before applying the app stack update; the timer must retain >=300s.
        stack = self._verify_control_resources(state, expected_statuses={"UPDATE_COMPLETE"})
        if stack.get("StackStatus") != "UPDATE_COMPLETE":
            raise _FlowError("cleanup_controls_not_complete")
        self._verify_setup_control_template(state)
        self._verify_control_role_policy(state, expected_setup=True)
        self._cleanup_schedule(state, self._now())
        now, _cleanup = self._authority(state, require_cleanup_margin=True)
        app_arn = state["app_stack_id"]
        try:
            template = build_dev_oauth_setup_template(state["api_id"], callback_url=self.callback_url)
        except Exception:
            raise _FlowError("oauth_setup_template_invalid") from None
        raw_template = self._json_bytes(template)
        if len(raw_template) > 51200:
            raise _FlowError("oauth_setup_template_size_invalid")
        token = uuid.uuid4().hex
        state.update({
            "oauth_setup_update_attempted": True,
            "oauth_setup_update_token": token,
            "oauth_setup_update_requested_at_epoch": now,
            "oauth_setup_callback_url": self.callback_url,
            "oauth_setup_template_sha256": hashlib.sha256(raw_template).hexdigest(),
        })
        self.journal.save(state)
        self._authority(state, require_cleanup_margin=True)
        try:
            response = self._mapping(self._call(
                "cloudformation", "update_stack",
                StackName=app_arn,
                TemplateBody=raw_template.decode("ascii"),
                Parameters=[
                    {"ParameterKey": "EnvironmentName", "ParameterValue": "dev"},
                    {"ParameterKey": "McpResourceUri", "ParameterValue": f"https://{state['api_id']}.execute-api.{REGION}.amazonaws.com/mcp"},
                    {"ParameterKey": "OAuthCallbackURL", "ParameterValue": self.callback_url},
                ],
                Capabilities=["CAPABILITY_NAMED_IAM"],
                ClientRequestToken=token,
            ))
        except _FlowError:
            state["oauth_setup_update_ambiguous"] = True
            self.journal.save(state)
            raise _FlowError("oauth_setup_update_ambiguous") from None
        if response is None or response.get("StackId") != app_arn:
            state["oauth_setup_update_ambiguous"] = True
            self.journal.save(state)
            raise _FlowError("oauth_setup_update_response_ambiguous")
        state["oauth_setup_update_call_returned"] = True
        self.journal.save(state)
        return self._safe("update-oauth-setup", True, "oauth_setup_update_requested", self._calls, resources_requested=10)

    def _step_check_oauth_setup(self) -> dict[str, Any]:
        state = self._state()
        self._authority(state, require_cleanup_margin=True)
        if not state.get("oauth_setup_update_attempted"):
            raise _FlowError("oauth_setup_update_not_attempted")
        if state.get("oauth_setup_update_ambiguous"):
            # A prior request with malformed response is reconciled by readback,
            # never replayed. The readback checker validates token-independent ownership.
            pass
        if state.get("oauth_setup_callback_url") != self.callback_url:
            raise _FlowError("oauth_setup_callback_binding_invalid")
        result = check_oauth_setup_readback(
            _ClientProxy(self, "cloudformation"),
            _ClientProxy(self, "apigatewayv2"),
            _ClientProxy(self, "lambda"),
            _ClientProxy(self, "cognito"),
            account_id=self.expected_account_id,
            stack_arn=state.get("app_stack_id"),
            run_id=state.get("run_id"),
            api_id=state.get("api_id"),
            user_pool_id=state.get("user_pool_id"),
            callback_url=state.get("oauth_setup_callback_url"),
        )
        if not result.verified or type(result.client_id) is not str:
            return self._safe("check-oauth-setup", False, result.category, self._calls)
        if self.monotonic() - self._step_started >= _MAX_STEP_SECONDS:
            return self._safe("check-oauth-setup", False, "step_budget_exhausted", self._calls)
        self._authority(state, require_cleanup_margin=True)
        state["oauth_setup_verified"] = True
        state["oauth_setup_client_id"] = result.client_id
        self.journal.save(state)
        return self._safe("check-oauth-setup", True, "oauth_setup_readback_verified", self._calls, resources_verified=10)


class _FlowError(Exception):
    def __init__(self, category: str):
        self.category = category


class _ClientProxy:
    """Route readback calls through the coordinator's bounded call guard."""

    def __init__(self, coordinator: OAuthSetupCoordinator, service: str):
        self._coordinator = coordinator
        self._service = service

    def __getattr__(self, method: str) -> Callable[..., Any]:
        if method.startswith("_"):
            raise AttributeError(method)

        def call(**kwargs: Any) -> Any:
            return self._coordinator._call(self._service, method, **kwargs)

        return call


__all__ = ["OAuthSetupCoordinator"]
