"""Injected, one-step coordinator for the bounded production geography upgrade.

This module constructs no AWS clients and performs no SDK/network work on
import. The caller supplies the private journal and single-attempt clients.
Each mutating request is journaled before dispatch and is never blindly replayed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
import uuid
from collections.abc import Mapping
from typing import Any, Callable

from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts.build_aws_prod_oauth_template import build_prod_runtime_template

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-prod"
FUNCTION_NAME = "honda-mapit-mcp-prod-handler"
SHUTDOWN_NAME = "honda-mapit-mcp-prod-shutdown"
RUN_TAG = "ProductionRunId"
AUTHORIZATION_CUTOFF_EPOCH = 1_791_042_120  # 2026-10-03 15:42 UTC
AUTHORIZATION_START_EPOCH = 1_791_042_717  # 2026-10-03 15:51:57 UTC
AUTHORIZATION_NEW_CUTOFF_EPOCH = 1_791_049_917  # 2026-10-03 17:51:57 UTC
_MAX_STEP_SECONDS = 30.0
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_STACK_ARN = re.compile(
    r"^arn:aws:cloudformation:eu-west-1:(?P<account>[0-9]{12}):stack/honda-mapit-mcp-prod/"
    r"(?P<uuid>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_STEP_ARN = re.compile(
    r"^arn:aws:states:eu-west-1:(?P<account>[0-9]{12}):stateMachine:honda-mapit-mcp-prod-shutdown$"
)
_REQUIRED_CLIENTS = frozenset(
    {"sts", "cloudformation", "apigatewayv2", "lambda", "stepfunctions", "cloudwatch", "events"}
)
_CATEGORIES = frozenset(
    {
        "inputs_invalid", "journal_invalid", "journal_not_fresh", "authorization_not_started", "authorization_expired",
        "clock_invalid", "clock_rollback", "step_budget_exhausted", "client_unavailable",
        "aws_call_failed", "aws_response_invalid", "identity_mismatch", "stack_unverified",
        "stack_not_owned", "stack_not_terminated", "template_mismatch", "resources_mismatch",
        "api_state_mismatch", "function_state_mismatch", "function_code_mismatch",
        "capacity_mismatch", "shutdown_machine_mismatch", "tripwire_unverified",
        "close_intent_exists", "close_ack_invalid", "close_not_verified", "close_pending",
        "update_intent_exists", "update_ack_invalid", "update_not_requested", "update_pending",
        "update_not_verified", "concurrency_intent_exists", "concurrency_restore_ambiguous",
        "concurrency_restore_unverified", "api_open_intent_exists", "api_open_ambiguous",
        "api_open_ack_invalid", "api_open_unverified", "production_open_verified",
        "upgrade_internal_error", "preflight_verified",
    }
)


class ProdGeographyUpgradeError(ValueError):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category if category in _CATEGORIES else "upgrade_internal_error"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _json_mapping(value: Any, *, limit: int = 128 * 1024) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value) > limit:
        return None
    try:
        parsed = json.loads(value, object_pairs_hook=_duplicate_reject)
    except Exception:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _ok(response: Any, statuses: tuple[int, ...] = (200,)) -> bool:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return type(status) is int and status in statuses


def _only_two_template_changes(old: Mapping[str, Any], new: Mapping[str, Any]) -> bool:
    try:
        old_copy = json.loads(_canonical(old))
        new_copy = json.loads(_canonical(new))
        old_fn = old_copy["Resources"]["McpHandler"]["Properties"]
        new_fn = new_copy["Resources"]["McpHandler"]["Properties"]
        if set(old_fn["Code"]) != {"S3Bucket", "S3Key"} or set(new_fn["Code"]) != {"S3Bucket", "S3Key"}:
            return False
        old_vars = old_fn["Environment"]["Variables"]
        new_vars = new_fn["Environment"]["Variables"]
        if set(old_vars) != {"MAPIT_MCP_ENV", "MAPIT_PROD_MANIFEST_SHA256"}:
            return False
        if set(new_vars) != set(old_vars) or old_vars["MAPIT_MCP_ENV"] != new_vars["MAPIT_MCP_ENV"]:
            return False
        old_fn["Code"].pop("S3Key")
        new_fn["Code"].pop("S3Key")
        old_vars.pop("MAPIT_PROD_MANIFEST_SHA256")
        new_vars.pop("MAPIT_PROD_MANIFEST_SHA256")
        return _canonical(old_copy) == _canonical(new_copy)
    except Exception:
        return False


class ProdGeographyUpgrade:
    """Manual single-step state machine; no polling, retries, or client creation."""

    STEPS = ("preflight", "close", "check-close", "request-update", "check-update", "open")

    def __init__(
        self,
        clients: Mapping[str, Any],
        journal: Any,
        *,
        policy: CognitoProdPolicy,
        account_id: str,
        stack_arn: str,
        prod_run_id: str,
        api_id: str,
        function_name: str,
        shutdown_state_machine_arn: str,
        bucket: str,
        old_zip_sha256: str,
        old_manifest_sha256: str,
        new_zip_sha256: str,
        new_manifest_sha256: str,
        authorized_until_epoch: int,
        authorized_from_epoch: int | None = None,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            type(policy) is not CognitoProdPolicy
            or type(account_id) is not str or not _ACCOUNT.fullmatch(account_id) or account_id == "000000000000"
            or type(stack_arn) is not str or not (match := _STACK_ARN.fullmatch(stack_arn))
            or match.group("account") != account_id
            or type(prod_run_id) is not str or not _UUID.fullmatch(prod_run_id) or uuid.UUID(prod_run_id).int == 0
            or type(api_id) is not str or not _API_ID.fullmatch(api_id) or api_id != policy.api_id
            or type(function_name) is not str or function_name != FUNCTION_NAME
            or type(shutdown_state_machine_arn) is not str
            or not (sm_match := _STEP_ARN.fullmatch(shutdown_state_machine_arn))
            or sm_match.group("account") != account_id
            or type(authorized_until_epoch) is not int
            or not (
                (authorized_until_epoch == AUTHORIZATION_CUTOFF_EPOCH and authorized_from_epoch is None)
                or (
                    authorized_until_epoch == AUTHORIZATION_NEW_CUTOFF_EPOCH
                    and type(authorized_from_epoch) is int
                    and authorized_from_epoch == AUTHORIZATION_START_EPOCH
                )
            )
            or not callable(wall_clock) or not callable(monotonic)
        ):
            raise ProdGeographyUpgradeError("inputs_invalid")
        for digest in (old_zip_sha256, old_manifest_sha256, new_zip_sha256, new_manifest_sha256):
            if type(digest) is not str or not _SHA.fullmatch(digest):
                raise ProdGeographyUpgradeError("inputs_invalid")
        # A code/public-asset-only revision retains the exact runtime identity
        # manifest. The ZIP must change; manifest changes remain optional and
        # are still the sole permitted environment-variable difference.
        if old_zip_sha256 == new_zip_sha256:
            raise ProdGeographyUpgradeError("inputs_invalid")
        if type(bucket) is not str or len(bucket) > 63:
            raise ProdGeographyUpgradeError("inputs_invalid")
        try:
            from scripts.build_aws_prod_oauth_template import _validate_bucket_name
            _validate_bucket_name(bucket)
        except Exception:
            raise ProdGeographyUpgradeError("inputs_invalid") from None
        if not isinstance(clients, Mapping) or not _REQUIRED_CLIENTS <= set(clients):
            raise ProdGeographyUpgradeError("client_unavailable")
        if any(not callable(getattr(journal, method, None)) for method in ("load", "save", "locked")):
            raise ProdGeographyUpgradeError("journal_invalid")
        self.clients = clients
        self.journal = journal
        self.policy = policy
        self.account_id = account_id
        self.stack_arn = stack_arn
        self.prod_run_id = prod_run_id
        self.api_id = api_id
        self.function_name = function_name
        self.shutdown_arn = shutdown_state_machine_arn
        self.bucket = bucket
        self.old_zip = old_zip_sha256
        self.old_manifest = old_manifest_sha256
        self.new_zip = new_zip_sha256
        self.new_manifest = new_manifest_sha256
        self.authorized_until = authorized_until_epoch
        self.authorized_from = authorized_from_epoch
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self._step_started = 0.0
        self._last_wall: float | None = None
        self._calls = 0
        try:
            self.old_template = build_prod_runtime_template(
                policy, bucket=bucket, zip_sha256=old_zip_sha256, manifest_sha256=old_manifest_sha256
            )
            self.new_template = build_prod_runtime_template(
                policy, bucket=bucket, zip_sha256=new_zip_sha256, manifest_sha256=new_manifest_sha256
            )
        except Exception:
            raise ProdGeographyUpgradeError("inputs_invalid") from None
        if not _only_two_template_changes(self.old_template, self.new_template):
            raise ProdGeographyUpgradeError("inputs_invalid")

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", "inputs_invalid")
        try:
            with self.journal.locked():
                self._step_started = self.monotonic()
                self._calls = 0
                return getattr(self, f"_step_{step.replace('-', '_')}")()
        except ProdGeographyUpgradeError as exc:
            return self._safe(step, exc.category)
        except Exception:
            return self._safe(step, "upgrade_internal_error")

    def _safe(self, step: str, category: str, **facts: Any) -> dict[str, Any]:
        clean = {key: value for key, value in facts.items() if type(value) is bool or (type(value) is int and value >= 0)}
        return {"step": step, "category": category if category in _CATEGORIES else "upgrade_internal_error", "calls": self._calls, **clean}

    def _state(self, *, fresh: bool = False) -> dict[str, Any] | None:
        value = self.journal.load()
        if fresh:
            if value is not None:
                raise ProdGeographyUpgradeError("journal_not_fresh")
            return None
        if (
            type(value) is not dict or type(value.get("schema")) is not int or value.get("schema") != 1
            or value.get("kind") != "prod_geography_upgrade"
            or value.get("account_id") != self.account_id or value.get("stack_arn") != self.stack_arn
            or value.get("prod_run_id") != self.prod_run_id or value.get("api_id") != self.api_id
            or value.get("shutdown_state_machine_arn") != self.shutdown_arn
            or value.get("old_zip_sha256") != self.old_zip or value.get("old_manifest_sha256") != self.old_manifest
            or value.get("new_zip_sha256") != self.new_zip or value.get("new_manifest_sha256") != self.new_manifest
            or value.get("bucket") != self.bucket
            or value.get("function_name") != self.function_name
            or type(value.get("authorization_cutoff_epoch")) is not int
            or value.get("authorization_cutoff_epoch") != self.authorized_until
            or value.get("authorization_start_epoch") != self.authorized_from
            or value.get("old_template_sha256") != hashlib.sha256(_canonical(self.old_template)).hexdigest()
            or value.get("new_template_sha256") != hashlib.sha256(_canonical(self.new_template)).hexdigest()
        ):
            raise ProdGeographyUpgradeError("journal_invalid")
        return value

    def _save(self, state: dict[str, Any]) -> None:
        try:
            self.journal.save(state)
        except Exception:
            raise ProdGeographyUpgradeError("journal_invalid") from None

    def _guard(self, *, allow_expired_close: bool = False) -> float:
        mono = self.monotonic()
        wall = self.wall_clock()
        if (
            type(mono) not in (int, float) or isinstance(mono, bool) or not math.isfinite(mono)
            or type(wall) not in (int, float) or isinstance(wall, bool) or not math.isfinite(wall)
        ):
            raise ProdGeographyUpgradeError("clock_invalid")
        if self._last_wall is not None and wall < self._last_wall:
            raise ProdGeographyUpgradeError("clock_rollback")
        self._last_wall = float(wall)
        if mono - self._step_started >= _MAX_STEP_SECONDS:
            raise ProdGeographyUpgradeError("step_budget_exhausted")
        if self.authorized_from is not None and wall < self.authorized_from:
            raise ProdGeographyUpgradeError("authorization_not_started")
        if not allow_expired_close and wall >= self.authorized_until:
            raise ProdGeographyUpgradeError("authorization_expired")
        return float(wall)

    def _call(
        self,
        service: str,
        method: str,
        *,
        allow_expired_close: bool = False,
        statuses: tuple[int, ...] = (200,),
        **kwargs: Any,
    ) -> Mapping[str, Any]:
        self._guard(allow_expired_close=allow_expired_close)
        self._calls += 1
        try:
            response = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            raise ProdGeographyUpgradeError("aws_call_failed") from None
        self._guard(allow_expired_close=allow_expired_close)
        if not isinstance(response, Mapping) or not _ok(response, statuses):
            raise ProdGeographyUpgradeError("aws_response_invalid")
        return response

    def _save_new_state(self) -> dict[str, Any]:
        self._guard()
        self._state(fresh=True)
        upgrade_id = str(uuid.uuid4())
        state = {
            "schema": 1, "kind": "prod_geography_upgrade", "upgrade_id": upgrade_id,
            "account_id": self.account_id, "stack_arn": self.stack_arn, "prod_run_id": self.prod_run_id,
            "api_id": self.api_id, "function_name": self.function_name,
            "shutdown_state_machine_arn": self.shutdown_arn, "bucket": self.bucket,
            "old_zip_sha256": self.old_zip, "old_manifest_sha256": self.old_manifest,
            "new_zip_sha256": self.new_zip, "new_manifest_sha256": self.new_manifest,
            "authorization_cutoff_epoch": self.authorized_until,
            "authorization_start_epoch": self.authorized_from,
            "old_template_sha256": hashlib.sha256(_canonical(self.old_template)).hexdigest(),
            "new_template_sha256": hashlib.sha256(_canonical(self.new_template)).hexdigest(),
            "preflight_verified": False,
        }
        self._save(state)
        return state

    def _require_state(self) -> dict[str, Any]:
        state = self._state()
        assert state is not None
        return state

    @staticmethod
    def _has_run_tag(tags: Any, run_id: str) -> bool:
        return type(tags) is list and any(
            isinstance(item, Mapping) and item.get("Key") == RUN_TAG and item.get("Value") == run_id for item in tags
        )

    def _owned_stack(
        self,
        state: Mapping[str, Any],
        expected_template: Mapping[str, Any],
        *,
        allow_in_progress: bool = False,
    ) -> Mapping[str, Any]:
        reply = self._call("cloudformation", "describe_stacks", StackName=self.stack_arn)
        rows = reply.get("Stacks")
        if type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise ProdGeographyUpgradeError("stack_unverified")
        stack = rows[0]
        if (
            stack.get("StackId") != self.stack_arn or stack.get("StackName") != STACK_NAME
            or stack.get("RoleARN") not in (None, "")
            or not self._has_run_tag(stack.get("Tags"), self.prod_run_id)
            or stack.get("EnableTerminationProtection") is not True
        ):
            raise ProdGeographyUpgradeError("stack_not_owned")
        status = stack.get("StackStatus")
        if status == "UPDATE_IN_PROGRESS" and allow_in_progress:
            return stack
        if status != "UPDATE_COMPLETE":
            raise ProdGeographyUpgradeError("stack_not_owned")
        template_reply = self._call("cloudformation", "get_template", StackName=self.stack_arn, TemplateStage="Original")
        actual = _json_mapping(template_reply.get("TemplateBody"))
        if actual is None or _canonical(actual) != _canonical(expected_template):
            raise ProdGeographyUpgradeError("template_mismatch")
        resources_reply = self._call("cloudformation", "describe_stack_resources", StackName=self.stack_arn)
        expected = expected_template.get("Resources")
        rows = resources_reply.get("StackResources")
        if not isinstance(expected, Mapping) or type(rows) is not list or len(rows) != len(expected):
            raise ProdGeographyUpgradeError("resources_mismatch")
        found: dict[str, Mapping[str, Any]] = {}
        for row in rows:
            logical = row.get("LogicalResourceId") if isinstance(row, Mapping) else None
            if type(logical) is not str or logical not in expected or logical in found:
                raise ProdGeographyUpgradeError("resources_mismatch")
            item = expected[logical]
            if (
                not isinstance(item, Mapping) or row.get("ResourceType") != item.get("Type")
                or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]
            ):
                raise ProdGeographyUpgradeError("resources_mismatch")
            found[logical] = row
        if set(found) != set(expected):
            raise ProdGeographyUpgradeError("resources_mismatch")
        if found.get("McpApi", {}).get("PhysicalResourceId") != self.api_id or found.get("McpHandler", {}).get("PhysicalResourceId") != self.function_name:
            raise ProdGeographyUpgradeError("resources_mismatch")
        return stack

    def _api(self, *, closed: bool) -> None:
        reply = self._call("apigatewayv2", "get_api", ApiId=self.api_id)
        expected_closed = closed
        if reply.get("ApiId") != self.api_id or reply.get("Name") != "honda-mapit-mcp-prod-api" or reply.get("DisableExecuteApiEndpoint") is not expected_closed:
            raise ProdGeographyUpgradeError("api_state_mismatch")

    def _function(self, *, zip_digest: str, manifest_digest: str, reserve_zero: bool | None) -> int | None:
        reply = self._call("lambda", "get_function", FunctionName=self.function_name)
        cfg = reply.get("Configuration")
        expected_arn = f"arn:aws:lambda:{REGION}:{self.account_id}:function:{self.function_name}"
        expected_code = base64.b64encode(bytes.fromhex(zip_digest)).decode("ascii")
        expected_vars = {"MAPIT_MCP_ENV": "prod", "MAPIT_PROD_MANIFEST_SHA256": manifest_digest}
        if (
            not isinstance(cfg, Mapping) or cfg.get("FunctionArn") != expected_arn
            or cfg.get("Handler") != "mapit.aws_prod_entrypoint.handler"
            or cfg.get("CodeSha256") != expected_code
            or not isinstance(cfg.get("Environment"), Mapping)
            or cfg["Environment"].get("Variables") != expected_vars
            or cfg.get("Runtime") != "python3.13" or cfg.get("Architectures") != ["arm64"]
            or cfg.get("MemorySize") != 256 or cfg.get("Timeout") != 15
        ):
            raise ProdGeographyUpgradeError("function_code_mismatch")
        conc = self._call("lambda", "get_function_concurrency", FunctionName=self.function_name)
        configured = conc.get("ReservedConcurrentExecutions")
        if reserve_zero is True:
            if type(configured) is not int or configured != 0:
                raise ProdGeographyUpgradeError("function_state_mismatch")
        elif reserve_zero is False:
            if configured is not None:
                raise ProdGeographyUpgradeError("function_state_mismatch")
        elif configured is not None and (type(configured) is not int or configured < 0):
            raise ProdGeographyUpgradeError("function_state_mismatch")
        return configured

    def _capacity(self) -> None:
        reply = self._call("lambda", "get_account_settings")
        limits = reply.get("AccountLimit")
        usage = reply.get("AccountUsage")
        if (
            not isinstance(limits, Mapping) or type(limits.get("ConcurrentExecutions")) is not int
            or limits.get("ConcurrentExecutions") != 10
            or type(limits.get("UnreservedConcurrentExecutions")) is not int
            or limits.get("UnreservedConcurrentExecutions") != 10
            or not isinstance(usage, Mapping)
            or type(usage.get("FunctionCount")) is not int
        ):
            raise ProdGeographyUpgradeError("capacity_mismatch")

    def _tripwire(self, *, check_machine: bool = True) -> dict[str, Any]:
        # Read the reviewed fixed production control definition as the source
        # of metric/threshold/event semantics; runtime readbacks below compare
        # only stable, security-relevant fields (not AWS request metadata or
        # alarm-state timestamps/reasons).
        from scripts.build_aws_prod_controls import fixed_prod_controls_template

        control_resources = fixed_prod_controls_template(self.api_id)["Resources"]
        alarm_template = control_resources["RequestTripwireAlarm"]["Properties"]
        rule_template = control_resources["RequestTripwireAlarmRule"]["Properties"]
        alarm_name = "honda-mapit-mcp-prod-request-tripwire"
        rule_name = "honda-mapit-mcp-prod-request-tripwire-alarm-rule"
        role = f"arn:aws:iam::{self.account_id}:role/honda-mapit-mcp-prod-request-tripwire"
        alarm_reply = self._call("cloudwatch", "describe_alarms", AlarmNames=[alarm_name])
        alarms = alarm_reply.get("MetricAlarms")
        if type(alarms) is not list or len(alarms) != 1 or not isinstance(alarms[0], Mapping):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        alarm = alarms[0]
        dimensions = [{"Name": "ApiId", "Value": self.api_id}, {"Name": "Stage", "Value": "$default"}]
        stable_alarm = {
            "AlarmName": alarm_name,
            "Namespace": alarm_template["Namespace"],
            "MetricName": alarm_template["MetricName"],
            "Dimensions": dimensions,
            "Period": alarm_template["Period"],
            "Statistic": alarm_template["Statistic"],
            "Threshold": alarm_template["Threshold"],
            "ComparisonOperator": alarm_template["ComparisonOperator"],
            "EvaluationPeriods": alarm_template["EvaluationPeriods"],
            "DatapointsToAlarm": alarm_template["DatapointsToAlarm"],
            "TreatMissingData": alarm_template["TreatMissingData"],
            # Production trigger is intentionally armed; the actual alarm has
            # no direct actions because the exact EventBridge rule owns stop.
            "ActionsEnabled": True,
            "AlarmActions": [],
            "OKActions": [],
            "InsufficientDataActions": [],
        }
        threshold = alarm.get("Threshold")
        if (type(threshold) not in (int, float) or not math.isfinite(threshold)
            or threshold != stable_alarm["Threshold"]):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        if any(alarm.get(key) != value or type(alarm.get(key)) is not type(value)
               for key, value in stable_alarm.items() if key != "Threshold"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        rule_reply = self._call("events", "describe_rule", Name=rule_name, EventBusName="default")
        expected_rule_arn = f"arn:aws:events:{REGION}:{self.account_id}:rule/{rule_name}"
        expected_alarm_arn = f"arn:aws:cloudwatch:{REGION}:{self.account_id}:alarm:{alarm_name}"
        pattern = {
            "source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"],
            "account": [self.account_id], "region": [REGION], "resources": [expected_alarm_arn],
            "detail": {"alarmName": [alarm_name], "state": {"value": ["ALARM"]}},
        }
        if (
            rule_reply.get("Name") != rule_name or rule_reply.get("Arn") != expected_rule_arn
            or rule_reply.get("State") != "ENABLED"
            or _json_mapping(rule_reply.get("EventPattern")) != pattern
            or rule_template.get("Name") != rule_name
            or _json_mapping(rule_template.get("EventPattern")) is None
        ):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        target_reply = self._call("events", "list_targets_by_rule", Rule=rule_name, EventBusName="default")
        targets = target_reply.get("Targets")
        if type(targets) is not list or len(targets) != 1 or not isinstance(targets[0], Mapping) or target_reply.get("NextToken"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        target = targets[0]
        expected_target_arn = self.shutdown_arn
        if (
            set(target) != {"Id", "Arn", "RoleArn", "Input", "RetryPolicy"}
            or target.get("Id") != "StartFixedProdShutdownWorkflow" or target.get("Arn") != expected_target_arn
            or target.get("RoleArn") != role or target.get("Input") != "{}"
            or target.get("RetryPolicy") != {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60}
        ):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        if check_machine:
            machine = self._call("stepfunctions", "describe_state_machine", stateMachineArn=self.shutdown_arn)
            expected_role = f"arn:aws:iam::{self.account_id}:role/honda-mapit-mcp-prod-shutdown-workflow"
            expected_definition = _json_mapping(
                control_resources["ShutdownStateMachine"]["Properties"].get("DefinitionString"),
                limit=128 * 1024,
            )
            actual_definition = _json_mapping(machine.get("definition"), limit=128 * 1024)
            if (
                machine.get("stateMachineArn") != self.shutdown_arn or machine.get("name") != SHUTDOWN_NAME
                or machine.get("roleArn") != expected_role or machine.get("status") != "ACTIVE"
                or machine.get("type") != "STANDARD"
                or expected_definition is None or actual_definition is None
                or _canonical(expected_definition) != _canonical(actual_definition)
            ):
                raise ProdGeographyUpgradeError("shutdown_machine_mismatch")
        stable_rule = {
            "Name": rule_name,
            "Arn": expected_rule_arn,
            "State": "ENABLED",
            "EventPattern": pattern,
        }
        return {"alarm": stable_alarm, "rule": stable_rule, "target": dict(target)}

    def _step_preflight(self) -> dict[str, Any]:
        self._guard()
        state = self._save_new_state()
        identity = self._call("sts", "get_caller_identity")
        arn = identity.get("Arn")
        if (
            identity.get("Account") != self.account_id or type(arn) is not str
            or ":root" in arn or not re.fullmatch(rf"arn:aws:(?:iam|sts)::{self.account_id}:(?:user|role|assumed-role)/[A-Za-z0-9+=,.@_/-]{{1,512}}", arn)
        ):
            raise ProdGeographyUpgradeError("identity_mismatch")
        stack = self._owned_stack(state, self.old_template)
        self._function(zip_digest=self.old_zip, manifest_digest=self.old_manifest, reserve_zero=False)
        self._api(closed=False)
        self._capacity()
        tripwire = self._tripwire()
        state["tripwire_fingerprint"] = hashlib.sha256(_canonical(tripwire)).hexdigest()
        state["original_api_enabled"] = True
        state["original_function_unreserved"] = True
        state["preflight_verified"] = True
        state["preflight_time_epoch"] = int(self._guard())
        self._save(state)
        return self._safe("preflight", "preflight_verified", verified=True, calls=self._calls)

    def _require_preflight(self) -> dict[str, Any]:
        state = self._require_state()
        if state.get("preflight_verified") is not True:
            raise ProdGeographyUpgradeError("journal_invalid")
        return state

    def _step_close(self) -> dict[str, Any]:
        state = self._require_preflight()
        self._guard(allow_expired_close=True)
        if state.get("close_intent") is not None:
            raise ProdGeographyUpgradeError("close_intent_exists")
        execution_name = state["upgrade_id"]
        execution_arn = f"arn:aws:states:{REGION}:{self.account_id}:execution:{SHUTDOWN_NAME}:{execution_name}"
        state["close_intent"] = {"execution_name": execution_name, "execution_arn": execution_arn}
        self._save(state)
        response = self._call(
            "stepfunctions", "start_execution", allow_expired_close=True,
            stateMachineArn=self.shutdown_arn, name=execution_name, input="{}",
        )
        if not _ok(response, (200,)) or response.get("executionArn") != execution_arn:
            raise ProdGeographyUpgradeError("close_ack_invalid")
        state["close_acknowledged"] = True
        self._save(state)
        return self._safe("close", "close_pending", attempted=True, acknowledged=True, calls=self._calls)

    @staticmethod
    def _close_output(value: Any) -> bool:
        output = _json_mapping(value, limit=16 * 1024)
        return bool(
            output is not None and output.get("verified") is True
            and output.get("category") == "shutdown_verified"
            and output.get("api_closed") is True and output.get("function_reserved") is True
            and output.get("api_write_call_returned") is True
            and output.get("function_write_call_returned") is True
        )

    def _step_check_close(self) -> dict[str, Any]:
        state = self._require_preflight()
        self._guard(allow_expired_close=True)
        intent = state.get("close_intent")
        if not isinstance(intent, Mapping) or type(intent.get("execution_arn")) is not str:
            raise ProdGeographyUpgradeError("close_not_verified")
        response = self._call("stepfunctions", "describe_execution", allow_expired_close=True, executionArn=intent["execution_arn"])
        if response.get("executionArn") != intent["execution_arn"]:
            raise ProdGeographyUpgradeError("close_not_verified")
        if response.get("status") in {"RUNNING", "TIMED_OUT"}:
            return self._safe("check-close", "close_pending", calls=self._calls)
        if response.get("status") != "SUCCEEDED" or not self._close_output(response.get("output")):
            raise ProdGeographyUpgradeError("close_not_verified")
        self._api(closed=True)
        self._function(zip_digest=self.old_zip, manifest_digest=self.old_manifest, reserve_zero=True)
        self._capacity()
        tripwire = self._tripwire()
        if hashlib.sha256(_canonical(tripwire)).hexdigest() != state.get("tripwire_fingerprint"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        state["close_verified"] = True
        self._save(state)
        return self._safe("check-close", "close_not_verified", verified=True, calls=self._calls)

    def _step_request_update(self) -> dict[str, Any]:
        state = self._require_preflight()
        self._guard()
        if state.get("close_verified") is not True:
            raise ProdGeographyUpgradeError("close_not_verified")
        if state.get("update_intent") is not None:
            raise ProdGeographyUpgradeError("update_intent_exists")
        self._owned_stack(state, self.old_template)
        self._api(closed=True)
        self._function(zip_digest=self.old_zip, manifest_digest=self.old_manifest, reserve_zero=True)
        self._capacity()
        tripwire = self._tripwire()
        if hashlib.sha256(_canonical(tripwire)).hexdigest() != state.get("tripwire_fingerprint"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        body = _canonical(self.new_template).decode("ascii")
        if len(body.encode("ascii")) > 50 * 1024:
            raise ProdGeographyUpgradeError("inputs_invalid")
        token = str(uuid.uuid4())
        state["update_intent"] = {"client_request_token": token}
        self._save(state)
        self._guard()
        response = self._call(
            "cloudformation", "update_stack", StackName=self.stack_arn, TemplateBody=body,
            Parameters=[{"ParameterKey": "EnvironmentName", "ParameterValue": "prod"}],
            Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=token,
        )
        if response.get("StackId") != self.stack_arn:
            raise ProdGeographyUpgradeError("update_ack_invalid")
        state["update_acknowledged"] = True
        self._save(state)
        return self._safe("request-update", "update_pending", attempted=True, acknowledged=True, calls=self._calls)

    def _step_check_update(self) -> dict[str, Any]:
        state = self._require_preflight()
        self._guard()
        if not isinstance(state.get("update_intent"), Mapping):
            raise ProdGeographyUpgradeError("update_not_requested")
        if state.get("update_acknowledged") is not True:
            # An ambiguous SDK result is never replayed; this readback can still reconcile it.
            pass
        stack = self._owned_stack(state, self.new_template, allow_in_progress=True)
        if stack.get("StackStatus") != "UPDATE_COMPLETE":
            raise ProdGeographyUpgradeError("update_pending")
        self._api(closed=True)
        self._function(zip_digest=self.new_zip, manifest_digest=self.new_manifest, reserve_zero=True)
        self._capacity()
        tripwire = self._tripwire()
        if hashlib.sha256(_canonical(tripwire)).hexdigest() != state.get("tripwire_fingerprint"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        state["update_verified"] = True
        self._save(state)
        return self._safe("check-update", "update_not_verified", verified=True, calls=self._calls)

    def _step_open(self) -> dict[str, Any]:
        state = self._require_preflight()
        self._guard()
        if state.get("close_verified") is not True or state.get("update_verified") is not True:
            raise ProdGeographyUpgradeError("update_not_verified")
        if state.get("production_open_verified") is True:
            return self._safe("open", "production_open_verified", verified=True, calls=0)
        function_reservation = self._function(
            zip_digest=self.new_zip, manifest_digest=self.new_manifest,
            reserve_zero=None if state.get("concurrency_restore_intent") is not None else True,
        )
        self._capacity()
        tripwire = self._tripwire()
        if hashlib.sha256(_canonical(tripwire)).hexdigest() != state.get("tripwire_fingerprint"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        # Restore the original unreserved state once. Ambiguous writes are
        # reconciled only by readback and are never retried.
        if state.get("concurrency_restore_intent") is None:
            state["concurrency_restore_intent"] = True
            self._save(state)
            self._guard()
            response = self._call(
                "lambda", "delete_function_concurrency", statuses=(204,), FunctionName=self.function_name
            )
            if not _ok(response, (204,)):
                raise ProdGeographyUpgradeError("concurrency_restore_ambiguous")
            state["concurrency_restore_acknowledged"] = True
            self._save(state)
        elif state.get("concurrency_restore_acknowledged") is not True:
            if function_reservation is None:
                # The one-shot write may have succeeded before the process
                # stopped. Reconcile by readback; never issue it again.
                state["concurrency_restore_acknowledged"] = True
                self._save(state)
            else:
                raise ProdGeographyUpgradeError("concurrency_restore_ambiguous")
        self._function(zip_digest=self.new_zip, manifest_digest=self.new_manifest, reserve_zero=False)
        self._capacity()
        tripwire = self._tripwire()
        if hashlib.sha256(_canonical(tripwire)).hexdigest() != state.get("tripwire_fingerprint"):
            raise ProdGeographyUpgradeError("tripwire_unverified")
        if state.get("api_open_intent") is None:
            self._api(closed=True)
            state["api_open_intent"] = True
            self._save(state)
            self._guard()
            response = self._call(
                "apigatewayv2", "update_api", statuses=(200, 201),
                ApiId=self.api_id, DisableExecuteApiEndpoint=False,
            )
            if (
                not _ok(response, (200, 201)) or ("ApiId" in response and response.get("ApiId") != self.api_id)
            ):
                raise ProdGeographyUpgradeError("api_open_ack_invalid")
            state["api_open_acknowledged"] = True
            self._save(state)
        elif state.get("api_open_acknowledged") is not True:
            # A previous call may have succeeded but its acknowledgement was
            # lost. Exact enabled-state readback is the only reconciliation;
            # a still-closed API is ambiguous and is never retried.
            pass
        api = self._call("apigatewayv2", "get_api", ApiId=self.api_id)
        if api.get("ApiId") != self.api_id or api.get("DisableExecuteApiEndpoint") is not False:
            raise ProdGeographyUpgradeError("api_open_unverified")
        state["production_open_verified"] = True
        self._save(state)
        return self._safe("open", "production_open_verified", verified=True, calls=self._calls)


__all__ = ["ProdGeographyUpgrade", "ProdGeographyUpgradeError"]
