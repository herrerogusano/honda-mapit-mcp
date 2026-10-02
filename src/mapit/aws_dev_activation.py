"""Injected, single-attempt core for a bounded synthetic dev endpoint window.

This module does not construct SDK clients, authenticate Codex, or contact AWS
at import time. A caller supplies already-verified private-journal evidence,
single-attempt clients, and a cooperative synthetic smoke callback. API disable
and reserved-concurrency-zero are always attempted in ``finally``.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .aws_dev_shutdown import AwsDevShutdownPolicy, close_dev_runtime

_REGION = "eu-west-1"
_FUNCTION = "honda-mapit-mcp-dev-handler"
_APP_STACK = "honda-mapit-mcp-dev"
_STATE_MACHINE = "honda-mapit-mcp-dev-shutdown"
_WORKFLOW_ROLE = "honda-mapit-mcp-dev-shutdown-workflow"
_SCHEDULER_ROLE = "honda-mapit-mcp-dev-shutdown-scheduler"
_TRIPWIRE_ROLE = "honda-mapit-mcp-dev-request-tripwire"
_CLEANUP_ROLE = "honda-mapit-mcp-dev-bootstrap-cleanup-scheduler"
_DELETION_ROLE = "honda-mapit-mcp-dev-bootstrap-delete"
_SHUTDOWN_GROUP = "honda-mapit-mcp-dev-safety"
_SHUTDOWN_SCHEDULE = "honda-mapit-mcp-dev-close-once"
_CLEANUP_GROUP = "honda-mapit-mcp-dev-bootstrap-cleanup"
_CLEANUP_SCHEDULE = "honda-mapit-mcp-dev-bootstrap-delete-once"
_ALARM = "honda-mapit-mcp-dev-request-tripwire"
_RULE = "honda-mapit-mcp-dev-request-tripwire-alarm-rule"
_API_ID_RE = re.compile(r"^[a-z0-9]{10}$")
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_CATEGORIES = frozenset({
    "window_inputs_invalid", "window_not_open", "prerequisite_unverified", "client_unavailable",
    "readback_invalid", "runtime_not_closed", "capacity_not_10", "function_reservation_not_zero",
    "stage_throttle_mismatch", "shutdown_schedule_mismatch", "cleanup_schedule_mismatch",
    "tripwire_not_armed", "service_quota_not_10", "reservation_remove_failed",
    "reservation_remove_unverified", "api_enable_failed", "api_enable_unverified",
    "smoke_failed", "smoke_deadline_exceeded", "activation_failed", "closed_after_smoke",
    "activation_and_shutdown_verified", "shutdown_unverified",
})


class ActivationError(RuntimeError):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


@dataclass(frozen=True)
class ActivationResult:
    success: bool
    category: str
    calls: int
    reservation_removed: bool = False
    api_enabled: bool = False
    smoke_verified: bool = False
    endpoint_closed: bool = False
    function_reserved_zero: bool = False

    def safe_projection(self) -> dict[str, Any]:
        category = self.category if self.category in _CATEGORIES else "activation_failed"
        return {
            "success": self.success is True and category == "activation_and_shutdown_verified",
            "category": category,
            "calls": self.calls if type(self.calls) is int and self.calls >= 0 else 0,
            "reservation_removed": self.reservation_removed is True,
            "api_enabled": self.api_enabled is True,
            "smoke_verified": self.smoke_verified is True,
            "endpoint_closed": self.endpoint_closed is True,
            "function_reserved_zero": self.function_reserved_zero is True,
        }


def _http_ok(response: Any, allowed: tuple[int, ...] = (200,)) -> bool:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return type(status) is int and status in allowed


def _duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _json_object(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value) > 16 * 1024:
        return None
    try:
        parsed = json.loads(value, object_pairs_hook=_duplicate_keys)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _epoch(value: Any) -> datetime:
    if type(value) is not int or value <= 0:
        raise ActivationError("window_inputs_invalid")
    try:
        return datetime.fromtimestamp(value, timezone.utc)
    except (OverflowError, OSError, ValueError):
        raise ActivationError("window_inputs_invalid") from None


def _at(value: int) -> str:
    return _epoch(value).strftime("%Y-%m-%dT%H:%M:%S")


def _schedule_ok(
    response: Any,
    *,
    account: str,
    schedule_name: str,
    group_name: str,
    epoch: int,
    state_machine_arn: str | None = None,
    target_role: str | None = None,
    cleanup_stack_arn: str | None = None,
) -> bool:
    expected_arn = f"arn:aws:scheduler:{_REGION}:{account}:schedule/{group_name}/{schedule_name}"
    if not _http_ok(response) or not isinstance(response, Mapping):
        return False
    target = response.get("Target")
    if not isinstance(target, Mapping):
        return False
    expression = response.get("ScheduleExpression")
    if (
        response.get("Arn") != expected_arn
        or response.get("Name") != schedule_name
        or response.get("GroupName") != group_name
        or response.get("State") != "ENABLED"
        or expression != f"at({_at(epoch)})"
        or response.get("ScheduleExpressionTimezone") != "UTC"
        or response.get("FlexibleTimeWindow") != {"Mode": "OFF"}
        or target.get("RetryPolicy") != {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
    ):
        return False
    if state_machine_arn is not None:
        role = f"arn:aws:iam::{account}:role/{_SCHEDULER_ROLE}"
        return (
            set(target) == {"Arn", "RoleArn", "Input", "RetryPolicy"}
            and target.get("Arn") == state_machine_arn
            and target.get("RoleArn") == role
            and target.get("Input") == "{}"
        )
    if cleanup_stack_arn is not None:
        role = f"arn:aws:iam::{account}:role/{_CLEANUP_ROLE}"
        expected_input = {"StackName": cleanup_stack_arn, "RoleARN": f"arn:aws:iam::{account}:role/{_DELETION_ROLE}"}
        return (
            set(target) == {"Arn", "RoleArn", "Input", "RetryPolicy"}
            and target.get("Arn") == "arn:aws:scheduler:::aws-sdk:cloudformation:deleteStack"
            and target.get("RoleArn") == role
            and _json_object(target.get("Input")) == expected_input
        )
    return False


def _validate_evidence(evidence: Any, policy: AwsDevShutdownPolicy) -> tuple[str, int, int, int]:
    if not isinstance(evidence, Mapping):
        raise ActivationError("prerequisite_unverified")
    for key in ("private_journal_verified", "runtime_readback_verified", "control_readback_verified", "oauth_setup_verified"):
        if evidence.get(key) is not True:
            raise ActivationError("prerequisite_unverified")
    account = evidence.get("account_id")
    api_id = evidence.get("api_id")
    stack_arn = evidence.get("app_stack_arn")
    start = evidence.get("runtime_start_epoch")
    end = evidence.get("runtime_end_epoch")
    resource_started = evidence.get("resource_started_epoch")
    if (
        type(account) is not str or not _ACCOUNT_RE.fullmatch(account)
        or type(api_id) is not str or not _API_ID_RE.fullmatch(api_id) or api_id != policy.api_id
        or type(stack_arn) is not str
        or not re.fullmatch(
            rf"arn:aws:cloudformation:{_REGION}:{account}:stack/{re.escape(_APP_STACK)}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}",
            stack_arn,
        )
        or type(start) is not int or type(end) is not int or type(resource_started) is not int
    ):
        raise ActivationError("prerequisite_unverified")
    if not 1 <= end - start <= 300:
        raise ActivationError("window_inputs_invalid")
    _epoch(start)
    _epoch(end)
    _epoch(resource_started)
    return account, start, end, resource_started


def _capacity_is_ten(response: Any) -> bool:
    if not _http_ok(response) or not isinstance(response, Mapping):
        return False
    limit = response.get("AccountLimit")
    return (
        isinstance(limit, Mapping)
        and type(limit.get("ConcurrentExecutions")) is int
        and limit.get("ConcurrentExecutions") == 10
        and type(limit.get("UnreservedConcurrentExecutions")) is int
        and limit.get("UnreservedConcurrentExecutions") == 10
    )


def _stage_is_throttled(response: Any) -> bool:
    if not _http_ok(response) or not isinstance(response, Mapping) or response.get("StageName") != "$default":
        return False
    default = response.get("DefaultRouteSettings")
    routes = response.get("RouteSettings", {})
    if not isinstance(default, Mapping) or not isinstance(routes, Mapping) or routes:
        return False
    return (
        type(default.get("ThrottlingBurstLimit")) is int and default["ThrottlingBurstLimit"] == 1
        and type(default.get("ThrottlingRateLimit")) in (int, float)
        and not isinstance(default.get("ThrottlingRateLimit"), bool)
        and default["ThrottlingRateLimit"] == 1
    )


def _alarm_is_tripwire(response: Any, *, api_id: str) -> bool:
    if not _http_ok(response) or not isinstance(response, Mapping):
        return False
    alarms = response.get("MetricAlarms")
    if type(alarms) is not list or len(alarms) != 1 or not isinstance(alarms[0], Mapping):
        return False
    alarm = alarms[0]
    dims = alarm.get("Dimensions")
    expected_dims = [{"Name": "ApiId", "Value": api_id}, {"Name": "Stage", "Value": "$default"}]
    return (
        alarm.get("AlarmName") == _ALARM
        and alarm.get("Namespace") == "AWS/ApiGateway"
        and alarm.get("MetricName") == "Count"
        and dims == expected_dims
        and type(alarm.get("Period")) is int and alarm["Period"] == 60
        and alarm.get("Statistic") == "SampleCount"
        and type(alarm.get("Threshold")) in (int, float) and not isinstance(alarm.get("Threshold"), bool) and alarm["Threshold"] == 100
        and alarm.get("ComparisonOperator") == "GreaterThanOrEqualToThreshold"
        and type(alarm.get("EvaluationPeriods")) is int and alarm["EvaluationPeriods"] == 1
        and type(alarm.get("DatapointsToAlarm")) is int and alarm["DatapointsToAlarm"] == 1
        and alarm.get("TreatMissingData") == "notBreaching"
        and alarm.get("ActionsEnabled") is False
    )


def _rule_pattern_ok(value: Any, *, account: str, state_machine_arn: str) -> bool:
    pattern = _json_object(value)
    alarm_arn = f"arn:aws:cloudwatch:eu-west-1:{account}:alarm:{_ALARM}"
    expected = {
        "source": ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        "account": [account],
        "region": [_REGION],
        "resources": [alarm_arn],
        "detail": {"alarmName": [_ALARM], "state": {"value": ["ALARM"]}},
    }
    return pattern == expected


def _tripwire_is_armed(
    clients: Mapping[str, Any],
    *,
    account: str,
    state_machine_arn: str,
    api_id: str,
    call: Callable[..., Any],
    expected_state: str = "ENABLED",
) -> bool:
    if type(expected_state) is not str or expected_state not in {"ENABLED", "DISABLED"}:
        return False
    alarm_result = call("cloudwatch", "describe_alarms", AlarmNames=[_ALARM])
    if not _alarm_is_tripwire(alarm_result, api_id=api_id):
        return False
    rule = call("events", "describe_rule", Name=_RULE, EventBusName="default")
    expected_rule_arn = f"arn:aws:events:{_REGION}:{account}:rule/{_RULE}"
    if (
        not _http_ok(rule) or not isinstance(rule, Mapping)
        or rule.get("Name") != _RULE or rule.get("Arn") != expected_rule_arn
        or rule.get("State") != expected_state
        or not _rule_pattern_ok(rule.get("EventPattern"), account=account, state_machine_arn=state_machine_arn)
    ):
        return False
    targets = call("events", "list_targets_by_rule", Rule=_RULE, EventBusName="default")
    rows = targets.get("Targets") if isinstance(targets, Mapping) else None
    if not _http_ok(targets) or type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping):
        return False
    target = rows[0]
    return (
        not targets.get("NextToken")
        and set(target) == {"Id", "Arn", "RoleArn", "Input", "RetryPolicy"}
        and target.get("Id") == "StartFixedDevShutdownWorkflow"
        and target.get("Arn") == state_machine_arn
        and target.get("RoleArn") == f"arn:aws:iam::{account}:role/{_TRIPWIRE_ROLE}"
        and target.get("Input") == "{}"
        and target.get("RetryPolicy") == {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
    )


def activate_synthetic_dev_window(
    clients: Mapping[str, Any],
    *,
    policy: AwsDevShutdownPolicy,
    evidence: Mapping[str, Any],
    smoke_callback: Callable[[float], Any],
    record_intent: Callable[[str], None],
    wall_clock: Callable[[], float] = time.time,
    monotonic: Callable[[], float] = time.monotonic,
) -> ActivationResult:
    """Open one already-prepared five-minute synthetic window, smoke, then close.

    Clients must be preconfigured for one-attempt SDK calls. The callback is
    given an absolute monotonic deadline and must cooperate with it. This is
    not a hard process-kill or billing-cap guarantee.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        return ActivationResult(False, "prerequisite_unverified", 0)
    try:
        policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    except Exception:
        return ActivationResult(False, "prerequisite_unverified", 0)

    calls = 0
    reservation_removed = False
    api_enabled = False
    smoke_verified = False
    category = "activation_failed"
    start_mono = 0.0
    deadline = 0.0
    shutdown_result = None
    try:
        # Keep even clock failures inside the cleanup-protected region.
        start_mono = monotonic()
        deadline = start_mono
        account, start, end, resource_started = _validate_evidence(evidence, policy)
        now_value = wall_clock()
        if isinstance(now_value, bool) or not isinstance(now_value, (int, float)) or not math.isfinite(now_value):
            raise ActivationError("window_inputs_invalid")
        now = int(now_value)
        if now < start or now >= end:
            raise ActivationError("window_not_open")
        if not isinstance(start_mono, (int, float)) or isinstance(start_mono, bool) or not math.isfinite(start_mono):
            raise ActivationError("window_inputs_invalid")
        # The whole externally authorized window is at most five minutes.
        # The injected smoke/portal layer owns any narrower per-request cap.
        deadline = start_mono + (end - now)

        required = {"apigatewayv2", "lambda", "scheduler", "stepfunctions", "cloudwatch", "events"}
        if not isinstance(clients, Mapping) or not required <= clients.keys():
            raise ActivationError("client_unavailable")
        if not callable(smoke_callback) or not callable(record_intent):
            raise ActivationError("client_unavailable")

        def guard() -> None:
            mono_now = monotonic()
            wall_now = wall_clock()
            if (
                isinstance(mono_now, bool) or not isinstance(mono_now, (int, float)) or not math.isfinite(mono_now)
                or isinstance(wall_now, bool) or not isinstance(wall_now, (int, float)) or not math.isfinite(wall_now)
                or mono_now >= deadline or wall_now < start or wall_now >= end
            ):
                raise ActivationError("smoke_deadline_exceeded")

        def call(service: str, method: str, **kwargs: Any) -> Any:
            nonlocal calls
            guard()
            try:
                operation = getattr(clients[service], method)
                if not callable(operation):
                    raise AttributeError
                response = operation(**kwargs)
            except ActivationError:
                raise
            except Exception:
                raise ActivationError("readback_invalid") from None
            calls += 1
            guard()
            return response

        # One initial check catches a wall-clock rollback before any read/write.
        guard()
        api_id = evidence["api_id"]
        api = call("apigatewayv2", "get_api", ApiId=api_id)
        if not _http_ok(api) or not isinstance(api, Mapping) or api.get("ApiId") != api_id:
            raise ActivationError("readback_invalid")
        if api.get("DisableExecuteApiEndpoint") is not True:
            raise ActivationError("runtime_not_closed")
        stage = call("apigatewayv2", "get_stage", ApiId=api_id, StageName="$default")
        if not _stage_is_throttled(stage):
            raise ActivationError("stage_throttle_mismatch")

        function = call("lambda", "get_function_concurrency", FunctionName=_FUNCTION)
        if (
            not _http_ok(function) or not isinstance(function, Mapping)
            or type(function.get("ReservedConcurrentExecutions")) is not int
            or function.get("ReservedConcurrentExecutions") != 0
        ):
            raise ActivationError("function_reservation_not_zero")
        capacity = call("lambda", "get_account_settings")
        if not _capacity_is_ten(capacity):
            raise ActivationError("capacity_not_10")
        servicequotas = clients.get("servicequotas")
        if servicequotas is not None:
            quota = call("servicequotas", "get_service_quota", ServiceCode="lambda", QuotaCode="L-B99A9384")
            detail = quota.get("Quota") if isinstance(quota, Mapping) else None
            if not _http_ok(quota) or not isinstance(detail, Mapping) or type(detail.get("Value")) not in (int, float) or detail.get("Value") != 10:
                raise ActivationError("service_quota_not_10")

        sm_arn = f"arn:aws:states:{_REGION}:{account}:stateMachine:{_STATE_MACHINE}"
        machine = call("stepfunctions", "describe_state_machine", stateMachineArn=sm_arn)
        if (
            not _http_ok(machine) or not isinstance(machine, Mapping)
            or machine.get("stateMachineArn") != sm_arn
            or machine.get("name") != _STATE_MACHINE
            or machine.get("roleArn") != f"arn:aws:iam::{account}:role/{_WORKFLOW_ROLE}"
            or machine.get("status") != "ACTIVE"
        ):
            raise ActivationError("readback_invalid")

        shutdown_epoch = end - 120
        cleanup_epoch = resource_started + 2700
        if shutdown_epoch <= now or cleanup_epoch - now < 300:
            raise ActivationError("window_not_open")
        shutdown = call("scheduler", "get_schedule", Name=_SHUTDOWN_SCHEDULE, GroupName=_SHUTDOWN_GROUP)
        if not _schedule_ok(
            shutdown, account=account, schedule_name=_SHUTDOWN_SCHEDULE, group_name=_SHUTDOWN_GROUP,
            epoch=shutdown_epoch, state_machine_arn=sm_arn,
        ):
            raise ActivationError("shutdown_schedule_mismatch")
        cleanup = call("scheduler", "get_schedule", Name=_CLEANUP_SCHEDULE, GroupName=_CLEANUP_GROUP)
        if not _schedule_ok(
            cleanup, account=account, schedule_name=_CLEANUP_SCHEDULE, group_name=_CLEANUP_GROUP,
            epoch=cleanup_epoch, cleanup_stack_arn=evidence["app_stack_arn"],
        ):
            raise ActivationError("cleanup_schedule_mismatch")
        if not _tripwire_is_armed(clients, account=account, state_machine_arn=sm_arn, api_id=api_id, call=call):
            raise ActivationError("tripwire_not_armed")

        guard()
        record_intent("remove_reserved_concurrency")
        guard()
        removed = call("lambda", "delete_function_concurrency", FunctionName=_FUNCTION)
        if not _http_ok(removed, (200, 204)):
            raise ActivationError("reservation_remove_failed")
        reservation_removed = True
        function_after = call("lambda", "get_function_concurrency", FunctionName=_FUNCTION)
        capacity_after = call("lambda", "get_account_settings")
        reservation = function_after.get("ReservedConcurrentExecutions") if isinstance(function_after, Mapping) else "invalid"
        if not _http_ok(function_after) or reservation not in (None,) or not _capacity_is_ten(capacity_after):
            raise ActivationError("reservation_remove_unverified")

        guard()
        record_intent("enable_api_endpoint")
        guard()
        enabled = call("apigatewayv2", "update_api", ApiId=api_id, DisableExecuteApiEndpoint=False)
        if not _http_ok(enabled) or not isinstance(enabled, Mapping) or enabled.get("ApiId") != api_id:
            raise ActivationError("api_enable_failed")
        api_enabled = True
        api_after = call("apigatewayv2", "get_api", ApiId=api_id)
        if (
            not _http_ok(api_after) or not isinstance(api_after, Mapping)
            or api_after.get("ApiId") != api_id or api_after.get("DisableExecuteApiEndpoint") is not False
        ):
            raise ActivationError("api_enable_unverified")

        guard()
        smoke_result = smoke_callback(deadline)
        guard()
        if (
            not isinstance(smoke_result, Mapping)
            or smoke_result.get("success") is not True
            or smoke_result.get("category") != "success"
            or type(smoke_result.get("tool_call_count")) is not int
            or smoke_result.get("tool_call_count") != 2
        ):
            raise ActivationError("smoke_failed")
        smoke_verified = True
        category = "activation_and_shutdown_verified"
    except ActivationError as exc:
        category = exc.category if exc.category in _CATEGORIES else "activation_failed"
    except Exception:
        category = "activation_failed"
    finally:
        try:
            shutdown_result = close_dev_runtime(policy, clients.get("apigatewayv2"), clients.get("lambda"))
        except Exception:
            shutdown_result = None

    endpoint_closed = bool(shutdown_result is not None and shutdown_result.api_closed is True)
    function_reserved = bool(shutdown_result is not None and shutdown_result.function_reserved is True)
    if not (endpoint_closed and function_reserved):
        category = "shutdown_unverified"
    elif category == "activation_and_shutdown_verified":
        category = "activation_and_shutdown_verified"
    elif category not in _CATEGORIES:
        category = "activation_failed"
    if category == "activation_and_shutdown_verified":
        return ActivationResult(True, category, calls + (4 if shutdown_result is not None else 0), reservation_removed, api_enabled, smoke_verified, endpoint_closed, function_reserved)
    if category == "shutdown_unverified" and endpoint_closed and function_reserved:
        category = "activation_failed"
    return ActivationResult(False, category, calls + (4 if shutdown_result is not None else 0), reservation_removed, api_enabled, smoke_verified, endpoint_closed, function_reserved)


__all__ = ["ActivationError", "ActivationResult", "activate_synthetic_dev_window"]
