"""Injected bootstrap coordinator for the retained-dev control stack.

The coordinator is intentionally SDK-free.  Callers inject direct, bounded
clients and a private journal.  It creates exactly the disabled five-resource
control stack once, then performs strict readbacks without ever opening the
API endpoint or changing Lambda concurrency.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from typing import Any, Callable
from urllib.parse import unquote_to_bytes

from scripts.aws_retained_dev_bootstrap import _canonical, _strict_mapping
from scripts.aws_retained_dev_bootstrap import build_retained_dev_template
from scripts.build_aws_retained_dev_support import build_retained_dev_controls

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained-controls"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 32
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_STACK = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_APP_STACK = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/honda-mapit-mcp-dev-retained/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_RESOURCE_TYPES = {
    "ShutdownWorkflowRole": "AWS::IAM::Role",
    "ShutdownStateMachine": "AWS::StepFunctions::StateMachine",
    "RequestTripwireAlarm": "AWS::CloudWatch::Alarm",
    "RequestTripwireEventRole": "AWS::IAM::Role",
    "RequestTripwireAlarmRule": "AWS::Events::Rule",
}
_TAGS = [
    {"Key": "Project", "Value": "honda-mapit-mcp"},
    {"Key": "Environment", "Value": "dev"},
    {"Key": "Purpose", "Value": "retained-dev-controls"},
]
_CFN_TAG_KEYS = {"OperatorRunId", "aws:cloudformation:stack-id", "aws:cloudformation:stack-name", "aws:cloudformation:logical-id"}
_ALLOWED_RESOURCE_KEYS = {
    "LogicalResourceId", "ResourceType", "PhysicalResourceId", "ResourceStatus",
    "StackId", "StackName", "Timestamp", "ResourceStatusReason", "DriftInformation",
}
_CATEGORIES = {
    "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid", "window_expired",
    "step_invalid", "preflight_verified", "preflight_required", "preflight_conflict",
    "named_resource_conflict", "create_intent_saved", "create_intent_present", "create_outcome_unknown",
    "create_acknowledged", "stack_in_progress", "stack_not_complete", "stack_readback_mismatch",
    "readback_verified", "aws_call_failed", "aws_response_invalid", "journal_failed",
    "operator_internal_error",
}


class RetainedDevControlsError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category if category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _error(exc: Exception) -> tuple[str, int | None, str]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    meta = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else ""
    message = error.get("Message") if isinstance(error, Mapping) else ""
    status = meta.get("HTTPStatusCode") if isinstance(meta, Mapping) else None
    return (
        code if type(code) is str else "",
        status if type(status) is int and not isinstance(status, bool) else None,
        message if type(message) is str else "",
    )


def _token(account: str, source_sha: str, run_id: int) -> str:
    digest = hashlib.sha256(f"{account}:{source_sha}:{run_id}".encode("ascii")).hexdigest()
    return "retained-dev-controls-" + digest


def _expected_physical(account: str) -> dict[str, str]:
    prefix = "honda-mapit-mcp-dev-retained"
    return {
        # CloudFormation physical IDs are names for IAM/EventBridge/Alarm;
        # Step Functions exposes its state-machine ARN as the physical ID.
        "ShutdownWorkflowRole": f"{prefix}-shutdown-workflow",
        "ShutdownStateMachine": f"arn:aws:states:{REGION}:{account}:stateMachine:{prefix}-shutdown",
        "RequestTripwireAlarm": f"{prefix}-request-tripwire",
        "RequestTripwireEventRole": f"{prefix}-request-tripwire",
        "RequestTripwireAlarmRule": f"{prefix}-request-tripwire-alarm-rule",
    }


def _expected_service_arns(account: str) -> dict[str, str]:
    prefix = "honda-mapit-mcp-dev-retained"
    return {
        "ShutdownWorkflowRole": f"arn:aws:iam::{account}:role/{prefix}-shutdown-workflow",
        "ShutdownStateMachine": f"arn:aws:states:{REGION}:{account}:stateMachine:{prefix}-shutdown",
        "RequestTripwireAlarm": f"arn:aws:cloudwatch:{REGION}:{account}:alarm:{prefix}-request-tripwire",
        "RequestTripwireEventRole": f"arn:aws:iam::{account}:role/{prefix}-request-tripwire",
        "RequestTripwireAlarmRule": f"arn:aws:events:{REGION}:{account}:rule/{prefix}-request-tripwire-alarm-rule",
    }


def _resolve_internal_template(value: Any, account: str) -> Any:
    """Resolve only the fixed intrinsics emitted by the controls factory.

    CloudFormation returns resolved IAM documents and EventBridge patterns.
    This resolver is deliberately not a general template interpreter: every
    pseudo-parameter, Ref, GetAtt, and Sub token must belong to this fixed
    five-resource template or the readback fails closed.
    """
    service_arns = _expected_service_arns(account)
    physical = _expected_physical(account)
    refs = {
        "AWS::AccountId": account,
        "AWS::Region": REGION,
        "AWS::Partition": "aws",
        "AWS::StackName": STACK_NAME,
        "ShutdownWorkflowRole": physical["ShutdownWorkflowRole"],
        "ShutdownStateMachine": service_arns["ShutdownStateMachine"],
        "RequestTripwireAlarm": physical["RequestTripwireAlarm"],
        "RequestTripwireEventRole": physical["RequestTripwireEventRole"],
        "RequestTripwireAlarmRule": physical["RequestTripwireAlarmRule"],
    }
    attrs = {
        (logical, "Arn"): arn
        for logical, arn in service_arns.items()
        if logical in {"ShutdownWorkflowRole", "ShutdownStateMachine", "RequestTripwireEventRole", "RequestTripwireAlarmRule"}
    }
    token_values = {
        "AWS::AccountId": account,
        "AWS::Region": REGION,
        "AWS::Partition": "aws",
        "AWS::StackName": STACK_NAME,
    }
    token_pattern = re.compile(r"\$\{([^}]+)\}")

    def resolve(node: Any) -> Any:
        if isinstance(node, list):
            return [resolve(item) for item in node]
        if not isinstance(node, Mapping):
            return node
        intrinsic_keys = [key for key in node if isinstance(key, str) and (key == "Ref" or key.startswith("Fn::"))]
        if intrinsic_keys:
            if len(node) != 1 or len(intrinsic_keys) != 1:
                raise RetainedDevControlsError("stack_readback_mismatch")
            key = intrinsic_keys[0]
            operand = node[key]
            if key == "Ref":
                if not isinstance(operand, str) or operand not in refs:
                    raise RetainedDevControlsError("stack_readback_mismatch")
                return refs[operand]
            if key == "Fn::GetAtt":
                if not isinstance(operand, list) or len(operand) != 2 or type(operand[0]) is not str or operand[1] != "Arn":
                    raise RetainedDevControlsError("stack_readback_mismatch")
                try:
                    return attrs[(operand[0], operand[1])]
                except KeyError:
                    raise RetainedDevControlsError("stack_readback_mismatch") from None
            if key == "Fn::Sub":
                if type(operand) is not str:
                    raise RetainedDevControlsError("stack_readback_mismatch")
                def replace(match: re.Match[str]) -> str:
                    token = match.group(1)
                    if token not in token_values:
                        raise RetainedDevControlsError("stack_readback_mismatch")
                    return token_values[token]
                resolved = token_pattern.sub(replace, operand)
                # Do not silently accept an unmatched `${...` fragment.
                if "${" in resolved:
                    raise RetainedDevControlsError("stack_readback_mismatch")
                return resolved
            raise RetainedDevControlsError("stack_readback_mismatch")
        return {key: resolve(child) for key, child in node.items()}

    return resolve(value)


def _tags_match(value: Any, required: Any, *, stack_id: str, logical_id: str, run_id: int) -> bool:
    """Compare AWS tag lists as unique maps, allowing only exact CFN tags."""
    if not isinstance(required, list) or not isinstance(value, list):
        return False
    required_map: dict[str, str] = {}
    for item in required:
        if not isinstance(item, Mapping) or set(item) != {"Key", "Value"} or type(item.get("Key")) is not str or type(item.get("Value")) is not str or item["Key"] in required_map:
            return False
        required_map[item["Key"]] = item["Value"]
    actual: dict[str, str] = {}
    for item in value:
        if not isinstance(item, Mapping) or set(item) != {"Key", "Value"} or type(item.get("Key")) is not str or type(item.get("Value")) is not str or item["Key"] in actual:
            return False
        actual[item["Key"]] = item["Value"]
    optional = {
        "OperatorRunId": str(run_id),
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:stack-name": STACK_NAME,
        "aws:cloudformation:logical-id": logical_id,
    }
    if set(actual) - (set(required_map) | _CFN_TAG_KEYS) or any(actual.get(key) != value for key, value in required_map.items()):
        return False
    return all(key not in actual or actual[key] == value for key, value in optional.items())


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


class RetainedDevControlsCoordinator:
    STEPS = ("preflight", "create", "readback")

    def __init__(
        self, clients: Mapping[str, Any], journal: Any, *, account_id: str, api_id: str,
        app_stack_id: str,
        source_sha: str, run_id: int, expected_caller_arn: str,
        authorized_from_epoch: int, authorized_until_epoch: int,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        required = {"sts", "cloudformation", "iam", "sfn", "events", "cloudwatch", "apigatewayv2", "lambda"}
        if not isinstance(clients, Mapping) or set(clients) != required or any(clients.get(k) is None for k in required):
            raise RetainedDevControlsError("clients_invalid")
        if not all(callable(getattr(journal, n, None)) for n in ("load", "save", "locked")):
            raise RetainedDevControlsError("journal_invalid")
        if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000":
            raise RetainedDevControlsError("binding_invalid")
        if type(api_id) is not str or _API.fullmatch(api_id) is None:
            raise RetainedDevControlsError("binding_invalid")
        if type(app_stack_id) is not str or _APP_STACK.fullmatch(app_stack_id) is None or app_stack_id.split(":")[4] != account_id:
            raise RetainedDevControlsError("binding_invalid")
        if type(source_sha) is not str or _SOURCE.fullmatch(source_sha) is None or source_sha == "0" * 40:
            raise RetainedDevControlsError("binding_invalid")
        if type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0:
            raise RetainedDevControlsError("binding_invalid")
        if type(expected_caller_arn) is not str or re.fullmatch(
            rf"(?:arn:aws:(?:iam|sts)::{account_id}:(?:user|role)/[^\s:/]+|arn:aws:sts::{account_id}:assumed-role/[^\s:/]+/[^\s:/]+)",
            expected_caller_arn,
        ) is None:
            raise RetainedDevControlsError("binding_invalid")
        if (
            type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
            or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS
        ):
            raise RetainedDevControlsError("window_invalid")
        try:
            template = build_retained_dev_controls(api_id)
        except Exception:
            raise RetainedDevControlsError("binding_invalid") from None
        resources = template.get("Resources")
        if (
            not isinstance(resources, Mapping) or set(resources) != set(_RESOURCE_TYPES)
            or any(not isinstance(resources[k], Mapping) or resources[k].get("Type") != v for k, v in _RESOURCE_TYPES.items())
        ):
            raise RetainedDevControlsError("binding_invalid")
        metadata = template.get("Metadata")
        if not isinstance(metadata, Mapping) or metadata.get("NoActivation") is not True or metadata.get("NoControlLambda") is not True:
            raise RetainedDevControlsError("binding_invalid")
        self.template = template
        self.template_bytes = _canonical(template)
        self.template_sha256 = hashlib.sha256(self.template_bytes).hexdigest()
        self.clients = dict(clients)
        self.journal = journal
        self.account_id, self.api_id, self.app_stack_id = account_id, api_id, app_stack_id
        self.source_sha, self.run_id = source_sha, run_id
        self.expected_caller_arn = expected_caller_arn
        self.window_start, self.window_end = authorized_from_epoch, authorized_until_epoch
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started: float | None = None
        self._last_mono = 0.0
        self._last_epoch = 0
        self._calls = 0
        endpoints = {
            "sts": "https://sts.eu-west-1.amazonaws.com",
            "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com",
            "iam": "https://iam.amazonaws.com",
            "sfn": "https://states.eu-west-1.amazonaws.com",
            "events": "https://events.eu-west-1.amazonaws.com",
            "cloudwatch": "https://monitoring.eu-west-1.amazonaws.com",
            "apigatewayv2": "https://apigateway.eu-west-1.amazonaws.com",
            "lambda": "https://lambda.eu-west-1.amazonaws.com",
        }
        for name, client in self.clients.items():
            meta = getattr(client, "meta", None)
            region = getattr(meta, "region_name", None)
            endpoint = getattr(meta, "endpoint_url", None)
            if region is not None and region != ("us-east-1" if name == "iam" else REGION):
                raise RetainedDevControlsError("clients_invalid")
            if endpoint is not None and endpoint != endpoints[name]:
                raise RetainedDevControlsError("clients_invalid")

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls}

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise RetainedDevControlsError("window_invalid")
        epoch = int(value)
        if epoch < self._last_epoch:
            raise RetainedDevControlsError("window_invalid")
        self._last_epoch = epoch
        if epoch < self.window_start or epoch >= self.window_end:
            raise RetainedDevControlsError("window_expired")
        return epoch

    def _budget(self) -> None:
        current = self.monotonic()
        if type(current) not in (int, float) or isinstance(current, bool) or not math.isfinite(current) or current < self._last_mono:
            raise RetainedDevControlsError("window_invalid")
        self._last_mono = float(current)
        if self._started is None or self._last_mono - self._started >= MAX_STEP_SECONDS:
            raise RetainedDevControlsError("window_expired")
        if self._calls >= MAX_CALLS_PER_STEP:
            raise RetainedDevControlsError("aws_call_failed")

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._budget(); self._now(); self._calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            self._now(); raise RetainedDevControlsError("aws_call_failed") from None
        if not isinstance(result, Mapping):
            raise RetainedDevControlsError("aws_response_invalid")
        metadata = result.get("ResponseMetadata")
        if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata["HTTPStatusCode"] != 200:
            raise RetainedDevControlsError("aws_response_invalid")
        if any(key in result for key in ("NextToken", "NextMarker", "Marker")) or result.get("IsTruncated") not in (None, False):
            raise RetainedDevControlsError("aws_response_invalid")
        self._now(); self._budget()
        return result

    def _call_absent(self, method: str, **kwargs: Any) -> None:
        self._budget(); self._now(); self._calls += 1
        try:
            result = self.clients["cloudformation"].__getattribute__(method)(**kwargs)
        except Exception as exc:
            code, status, message = _error(exc)
            if code == "ValidationError" and status in {400, 404} and message == f"Stack with id {STACK_NAME} does not exist":
                self._now(); self._budget(); return
            self._now(); raise RetainedDevControlsError("aws_call_failed") from None
        if isinstance(result, Mapping) and isinstance(result.get("ResponseMetadata"), Mapping) and type(result["ResponseMetadata"].get("HTTPStatusCode")) is int and result["ResponseMetadata"].get("HTTPStatusCode") == 200:
            self._now(); raise RetainedDevControlsError("named_resource_conflict")
        self._now(); raise RetainedDevControlsError("aws_response_invalid")

    def _identity(self) -> None:
        result = self._call("sts", "get_caller_identity")
        if result.get("Account") != self.account_id or result.get("Arn") != self.expected_caller_arn:
            raise RetainedDevControlsError("binding_invalid")

    def _load(self) -> dict[str, Any] | None:
        try:
            state = self.journal.load()
        except Exception:
            raise RetainedDevControlsError("journal_failed") from None
        if state is None:
            return None
        if not isinstance(state, Mapping):
            raise RetainedDevControlsError("journal_invalid")
        expected = {"schema", "kind", "account", "api_id", "app_stack_id", "source_sha", "run_id", "template_sha256", "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch", "last_observed_epoch", "preflight", "intent", "acknowledged", "acknowledged_stack_id", "readback", "readback_receipt"}
        if set(state) != expected or state.get("schema") != 1 or state.get("kind") != "retained-dev-controls" or state.get("account") != self.account_id or state.get("api_id") != self.api_id or state.get("app_stack_id") != self.app_stack_id or state.get("source_sha") != self.source_sha or state.get("run_id") != self.run_id or state.get("template_sha256") != self.template_sha256 or state.get("expected_caller_arn") != self.expected_caller_arn or state.get("authorized_from_epoch") != self.window_start or state.get("authorized_until_epoch") != self.window_end:
            raise RetainedDevControlsError("journal_invalid")
        if any(type(state.get(k)) is not bool for k in ("preflight", "acknowledged", "readback")) or type(state.get("last_observed_epoch")) is not int or state["last_observed_epoch"] <= 0:
            raise RetainedDevControlsError("journal_invalid")
        intent = state.get("intent")
        expected_intent = {"token": _token(self.account_id, self.source_sha, self.run_id), "stack_name": STACK_NAME}
        if intent is not None and (not isinstance(intent, Mapping) or dict(intent) != expected_intent):
            raise RetainedDevControlsError("journal_invalid")
        if not state["preflight"] or (state["acknowledged"] and intent is None) or (state["readback"] and intent is None):
            raise RetainedDevControlsError("journal_invalid")
        ack = state.get("acknowledged_stack_id")
        if state["acknowledged"] and (type(ack) is not str or _STACK.fullmatch(ack) is None or ack.split(":")[4] != self.account_id):
            raise RetainedDevControlsError("journal_invalid")
        if not state["acknowledged"] and ack is not None:
            raise RetainedDevControlsError("journal_invalid")
        receipt = state.get("readback_receipt")
        if state["readback"]:
            if not isinstance(receipt, Mapping) or set(receipt) != {"token", "stack_id", "template_sha256", "api_id"} or receipt.get("token") != expected_intent["token"] or receipt.get("template_sha256") != self.template_sha256 or receipt.get("api_id") != self.api_id or type(receipt.get("stack_id")) is not str or _STACK.fullmatch(receipt["stack_id"]) is None or receipt["stack_id"].split(":")[4] != self.account_id or (ack is not None and receipt["stack_id"] != ack):
                raise RetainedDevControlsError("journal_invalid")
        if not state["readback"] and receipt is not None:
            raise RetainedDevControlsError("journal_invalid")
        return dict(state)

    def _save(self, *, preflight: bool, intent: Mapping[str, Any] | None, acknowledged: bool, acknowledged_stack_id: str | None, readback: bool, readback_receipt: Mapping[str, Any] | None = None) -> None:
        self._now(); self._budget()
        state = {"schema": 1, "kind": "retained-dev-controls", "account": self.account_id, "api_id": self.api_id, "app_stack_id": self.app_stack_id, "source_sha": self.source_sha, "run_id": self.run_id, "template_sha256": self.template_sha256, "expected_caller_arn": self.expected_caller_arn, "authorized_from_epoch": self.window_start, "authorized_until_epoch": self.window_end, "last_observed_epoch": self._last_epoch, "preflight": preflight, "intent": dict(intent) if intent is not None else None, "acknowledged": acknowledged, "acknowledged_stack_id": acknowledged_stack_id, "readback": readback, "readback_receipt": dict(readback_receipt) if readback_receipt is not None else None}
        try:
            self.journal.save(state)
        except Exception:
            raise RetainedDevControlsError("journal_failed") from None
        self._now(); self._budget()

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                initial = self.monotonic()
                if type(initial) not in (int, float) or isinstance(initial, bool) or not math.isfinite(initial) or initial < 0:
                    raise RetainedDevControlsError("window_invalid")
                self._started = float(initial); self._last_mono = self._started; self._calls = 0
                state = self._load(); self._last_epoch = state.get("last_observed_epoch", 0) if state is not None else 0
                self._now(); self._identity()
                if step == "preflight":
                    return self._preflight(state)
                if step == "create":
                    return self._create(state)
                return self._readback(state)
        except RetainedDevControlsError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "operator_internal_error")

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None and (state.get("intent") is not None or state.get("acknowledged")):
            raise RetainedDevControlsError("preflight_conflict")
        self._verify_app_binding()
        self._call_absent("describe_stacks", StackName=STACK_NAME)
        self._save(preflight=True, intent=None, acknowledged=False, acknowledged_stack_id=None, readback=False)
        return self._safe("preflight", True, "preflight_verified")

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise RetainedDevControlsError("preflight_required")
        if state.get("intent") is not None or state.get("acknowledged"):
            raise RetainedDevControlsError("create_intent_present")
        intent = {"token": _token(self.account_id, self.source_sha, self.run_id), "stack_name": STACK_NAME}
        self._save(preflight=True, intent=intent, acknowledged=False, acknowledged_stack_id=None, readback=False)
        # The preflight proof can become stale while the intent is being
        # durably saved. Re-prove the exact app binding immediately before the
        # only write, leaving the intent intact if this check fails.
        self._verify_app_binding()
        self._budget(); self._now(); self._calls += 1
        try:
            response = self.clients["cloudformation"].create_stack(
                StackName=STACK_NAME, TemplateBody=self.template_bytes.decode("ascii"),
                Tags=[*_TAGS, {"Key": "OperatorRunId", "Value": str(self.run_id)}],
                ClientRequestToken=intent["token"], EnableTerminationProtection=True,
                Capabilities=["CAPABILITY_NAMED_IAM"],
            )
        except Exception:
            self._now(); self._budget(); raise RetainedDevControlsError("create_outcome_unknown") from None
        self._now(); self._budget()
        stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        if not isinstance(response, Mapping) or not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata.get("HTTPStatusCode") != 200 or type(stack_id) is not str or _STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != self.account_id:
            raise RetainedDevControlsError("create_outcome_unknown")
        self._save(preflight=True, intent=intent, acknowledged=True, acknowledged_stack_id=stack_id, readback=False)
        return self._safe("create", True, "create_acknowledged")

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None:
            raise RetainedDevControlsError("preflight_required")
        stack_reply = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        stacks = stack_reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RetainedDevControlsError("stack_readback_mismatch")
        row = stacks[0]; stack_id = row.get("StackId")
        tags = row.get("Tags")
        if type(stack_id) is not str or _STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != self.account_id or row.get("StackName") != STACK_NAME or row.get("StackStatus") == "CREATE_IN_PROGRESS" or row.get("StackStatus") != "CREATE_COMPLETE" or row.get("EnableTerminationProtection") is not True:
            if row.get("StackStatus") == "CREATE_IN_PROGRESS":
                raise RetainedDevControlsError("stack_in_progress")
            if row.get("StackStatus") != "CREATE_COMPLETE":
                raise RetainedDevControlsError("stack_not_complete")
            raise RetainedDevControlsError("stack_readback_mismatch")
        if state.get("acknowledged") and state.get("acknowledged_stack_id") != stack_id:
            raise RetainedDevControlsError("stack_readback_mismatch")
        if not _tags_match(tags, [*_TAGS, {"Key": "OperatorRunId", "Value": str(self.run_id)}], stack_id=stack_id, logical_id="", run_id=self.run_id):
            raise RetainedDevControlsError("stack_readback_mismatch")
        template_reply = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
        body = _strict_mapping(template_reply.get("TemplateBody"))
        if body is None or _canonical(body) != self.template_bytes:
            raise RetainedDevControlsError("stack_readback_mismatch")
        events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME)
        rows = events.get("StackEvents")
        if not isinstance(rows, list) or not rows or len(rows) > 64 or not any(isinstance(x, Mapping) and x.get("StackId") == stack_id and x.get("ClientRequestToken") == state["intent"]["token"] for x in rows):
            raise RetainedDevControlsError("stack_readback_mismatch")
        resource_reply = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME)
        resources = resource_reply.get("StackResources")
        if type(resources) is not list or len(resources) != len(_RESOURCE_TYPES):
            raise RetainedDevControlsError("stack_readback_mismatch")
        by_id = {x.get("LogicalResourceId"): x for x in resources if isinstance(x, Mapping)}
        if set(by_id) != set(_RESOURCE_TYPES):
            raise RetainedDevControlsError("stack_readback_mismatch")
        for logical, kind in _RESOURCE_TYPES.items():
            item = by_id[logical]
            if set(item) - _ALLOWED_RESOURCE_KEYS or ("DriftInformation" in item and item["DriftInformation"] != {"StackResourceDriftStatus": "NOT_CHECKED"}) or item.get("ResourceType") != kind or item.get("ResourceStatus") != "CREATE_COMPLETE" or item.get("StackId") != stack_id or item.get("StackName") != STACK_NAME or item.get("PhysicalResourceId") != _expected_physical(self.account_id)[logical]:
                raise RetainedDevControlsError("stack_readback_mismatch")
        self._verify_iam("ShutdownWorkflowRole", "honda-mapit-mcp-dev-retained-shutdown-workflow", stack_id=stack_id)
        self._verify_iam("RequestTripwireEventRole", "honda-mapit-mcp-dev-retained-request-tripwire", stack_id=stack_id)
        service_arns = _expected_service_arns(self.account_id)
        machine = self._call("sfn", "describe_state_machine", stateMachineArn=service_arns["ShutdownStateMachine"])
        # Step Functions returns the state-machine fields at the response top
        # level (unlike CloudFormation's nested resource envelopes).
        machine_data = machine
        expected_machine = _resolve_internal_template(self.template["Resources"]["ShutdownStateMachine"]["Properties"], self.account_id)
        expected_definition = _strict_mapping(expected_machine.get("DefinitionString"))
        actual_definition = _strict_mapping(machine_data.get("definition")) if isinstance(machine_data, Mapping) else None
        if (
            not isinstance(machine_data, Mapping)
            or machine_data.get("stateMachineArn") != service_arns["ShutdownStateMachine"]
            or machine_data.get("name") != "honda-mapit-mcp-dev-retained-shutdown"
            or machine_data.get("status") != "ACTIVE"
            or machine_data.get("type") != "STANDARD"
            or machine_data.get("roleArn") != service_arns["ShutdownWorkflowRole"]
            or expected_definition is None or actual_definition is None
            or _canonical(actual_definition) != _canonical(expected_definition)
            or not isinstance(machine_data.get("loggingConfiguration"), Mapping)
            or machine_data["loggingConfiguration"].get("level") != "OFF"
            or machine_data["loggingConfiguration"].get("includeExecutionData") not in (None, False)
            or not isinstance(machine_data.get("tracingConfiguration"), Mapping)
            or machine_data["tracingConfiguration"].get("enabled") is not False
        ):
            raise RetainedDevControlsError("stack_readback_mismatch")
        rule = self._call("events", "describe_rule", Name="honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule")
        expected_rule = _resolve_internal_template(self.template["Resources"]["RequestTripwireAlarmRule"]["Properties"], self.account_id)
        expected_pattern = expected_rule.get("EventPattern")
        actual_pattern = _strict_mapping(rule.get("EventPattern"))
        if (
            rule.get("Name") != "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"
            or rule.get("Arn") != service_arns["RequestTripwireAlarmRule"]
            or rule.get("State") != "DISABLED"
            or actual_pattern is None or _canonical(actual_pattern) != _canonical(expected_pattern)
        ):
            raise RetainedDevControlsError("stack_readback_mismatch")
        machine_tags = self._call("sfn", "list_tags_for_resource", resourceArn=service_arns["ShutdownStateMachine"])
        if not _tags_match(machine_tags.get("tags"), expected_machine.get("Tags"), stack_id=stack_id, logical_id="ShutdownStateMachine", run_id=self.run_id):
            raise RetainedDevControlsError("stack_readback_mismatch")
        rule_tags = self._call("events", "list_tags_for_resource", ResourceARN=service_arns["RequestTripwireAlarmRule"])
        if not _tags_match(rule_tags.get("Tags"), expected_rule.get("Tags"), stack_id=stack_id, logical_id="RequestTripwireAlarmRule", run_id=self.run_id):
            raise RetainedDevControlsError("stack_readback_mismatch")
        targets = self._call("events", "list_targets_by_rule", Rule="honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule")
        target_rows = targets.get("Targets")
        expected_target = expected_rule["Targets"][0]
        if (
            type(target_rows) is not list or len(target_rows) != 1
            or target_rows[0].get("Id") != expected_target.get("Id")
            or target_rows[0].get("Arn") != service_arns["ShutdownStateMachine"]
            or target_rows[0].get("RoleArn") != service_arns["RequestTripwireEventRole"]
            or target_rows[0].get("Input") != "{}"
            or target_rows[0].get("RetryPolicy") != expected_target.get("RetryPolicy")
        ):
            raise RetainedDevControlsError("stack_readback_mismatch")
        alarm_reply = self._call("cloudwatch", "describe_alarms", AlarmNames=["honda-mapit-mcp-dev-retained-request-tripwire"])
        alarms = alarm_reply.get("MetricAlarms")
        if type(alarms) is not list or len(alarms) != 1:
            raise RetainedDevControlsError("stack_readback_mismatch")
        alarm = alarms[0]
        dims = alarm.get("Dimensions")
        expected_alarm = self.template["Resources"]["RequestTripwireAlarm"]["Properties"]
        if (
            not isinstance(dims, list)
            or alarm.get("AlarmName") != "honda-mapit-mcp-dev-retained-request-tripwire"
            or alarm.get("Namespace") != expected_alarm.get("Namespace")
            or alarm.get("MetricName") != expected_alarm.get("MetricName")
            or alarm.get("ActionsEnabled") is not False
            or alarm.get("Period") != expected_alarm.get("Period")
            or alarm.get("Statistic") != expected_alarm.get("Statistic")
            or alarm.get("Threshold") != expected_alarm.get("Threshold")
            or alarm.get("ComparisonOperator") != expected_alarm.get("ComparisonOperator")
            or alarm.get("EvaluationPeriods") != expected_alarm.get("EvaluationPeriods")
            or alarm.get("DatapointsToAlarm") != expected_alarm.get("DatapointsToAlarm")
            or alarm.get("TreatMissingData") != expected_alarm.get("TreatMissingData")
            or [{"Name": x.get("Name"), "Value": x.get("Value")} for x in dims] != expected_alarm.get("Dimensions")
        ):
            raise RetainedDevControlsError("stack_readback_mismatch")
        alarm_tags = self._call("cloudwatch", "list_tags_for_resource", ResourceARN=alarm.get("AlarmArn"))
        if not _tags_match(alarm_tags.get("Tags"), expected_alarm.get("Tags"), stack_id=stack_id, logical_id="RequestTripwireAlarm", run_id=self.run_id):
            raise RetainedDevControlsError("stack_readback_mismatch")
        self._verify_app_binding()
        self._save(preflight=True, intent=state["intent"], acknowledged=bool(state.get("acknowledged")), acknowledged_stack_id=state.get("acknowledged_stack_id"), readback=True, readback_receipt={"token": state["intent"]["token"], "stack_id": stack_id, "template_sha256": self.template_sha256, "api_id": self.api_id})
        return self._safe("readback", True, "readback_verified")

    def _verify_iam(self, logical: str, role_name: str, *, stack_id: str) -> None:
        expected = _expected_service_arns(self.account_id)[logical]
        reply = self._call("iam", "get_role", RoleName=role_name)
        role = reply.get("Role")
        if not isinstance(role, Mapping) or role.get("RoleName") != role_name or role.get("Arn") != expected or "PermissionsBoundary" in role:
            raise RetainedDevControlsError("stack_readback_mismatch")
        expected_props = _resolve_internal_template(self.template["Resources"][logical]["Properties"], self.account_id)
        trust = self._document(role.get("AssumeRolePolicyDocument"))
        if trust is None or _canonical(trust) != _canonical(expected_props["AssumeRolePolicyDocument"]):
            raise RetainedDevControlsError("stack_readback_mismatch")
        if not _tags_match(role.get("Tags"), expected_props.get("Tags"), stack_id=stack_id, logical_id=logical, run_id=self.run_id):
            raise RetainedDevControlsError("stack_readback_mismatch")
        policies = expected_props.get("Policies")
        if not isinstance(policies, list) or len(policies) != 1:
            raise RetainedDevControlsError("stack_readback_mismatch")
        policy_name = policies[0].get("PolicyName")
        listed = self._call("iam", "list_role_policies", RoleName=role_name)
        if listed.get("PolicyNames") != [policy_name]:
            raise RetainedDevControlsError("stack_readback_mismatch")
        inline = self._call("iam", "get_role_policy", RoleName=role_name, PolicyName=policy_name)
        document = self._document(inline.get("PolicyDocument"))
        if document is None or _canonical(document) != _canonical(policies[0].get("PolicyDocument")):
            raise RetainedDevControlsError("stack_readback_mismatch")
        attached = self._call("iam", "list_attached_role_policies", RoleName=role_name)
        if attached.get("AttachedPolicies") != []:
            raise RetainedDevControlsError("stack_readback_mismatch")

    @staticmethod
    def _document(value: Any) -> Mapping[str, Any] | None:
        if isinstance(value, Mapping):
            return value
        if type(value) is not str or len(value) > 64 * 1024 or re.search(r"%(?![0-9A-Fa-f]{2})", value):
            return None
        try:
            parsed = json.loads(unquote_to_bytes(value).decode("utf-8", "strict"), object_pairs_hook=_strict_pairs)
        except Exception:
            return None
        return parsed if isinstance(parsed, Mapping) else None

    def _verify_app_binding(self) -> None:
        """Re-prove the exact existing app stack before/after control creation."""
        stack_reply = self._call("cloudformation", "describe_stacks", StackName=self.app_stack_id)
        stacks = stack_reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RetainedDevControlsError("binding_invalid")
        row = stacks[0]
        if (
            row.get("StackId") != self.app_stack_id
            or row.get("StackName") != "honda-mapit-mcp-dev-retained"
            or row.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or row.get("EnableTerminationProtection") is not True
        ):
            raise RetainedDevControlsError("binding_invalid")
        template_reply = self._call("cloudformation", "get_template", StackName=self.app_stack_id)
        actual = _strict_mapping(template_reply.get("TemplateBody"))
        expected = build_retained_dev_template()
        if actual is None or actual.get("Conditions") != expected.get("Conditions"):
            raise RetainedDevControlsError("binding_invalid")
        actual_resources = actual.get("Resources")
        expected_resources = expected.get("Resources")
        if not isinstance(actual_resources, Mapping) or not isinstance(expected_resources, Mapping) or set(actual_resources) != set(expected_resources):
            raise RetainedDevControlsError("binding_invalid")
        for logical in ("McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup"):
            if actual_resources.get(logical) != expected_resources.get(logical):
                raise RetainedDevControlsError("binding_invalid")
        handler = actual_resources.get("McpHandler")
        expected_handler = expected_resources.get("McpHandler")
        if not isinstance(handler, Mapping) or not isinstance(expected_handler, Mapping) or handler.get("Type") != expected_handler.get("Type"):
            raise RetainedDevControlsError("binding_invalid")
        handler_props = handler.get("Properties")
        expected_props = expected_handler.get("Properties")
        if not isinstance(handler_props, Mapping) or not isinstance(expected_props, Mapping):
            raise RetainedDevControlsError("binding_invalid")
        for key in ("Architectures", "FunctionName", "MemorySize", "ReservedConcurrentExecutions", "Role", "Runtime", "Tags", "Timeout"):
            if handler_props.get(key) != expected_props.get(key):
                raise RetainedDevControlsError("binding_invalid")
        if handler_props.get("ReservedConcurrentExecutions") != 0:
            raise RetainedDevControlsError("binding_invalid")
        resource_reply = self._call("cloudformation", "describe_stack_resources", StackName=self.app_stack_id)
        resources = resource_reply.get("StackResources")
        if type(resources) is not list or len(resources) != 5:
            raise RetainedDevControlsError("binding_invalid")
        expected_types = {
            "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
            "McpHandlerRole": "AWS::IAM::Role", "McpHandlerLogGroup": "AWS::Logs::LogGroup",
            "McpHandler": "AWS::Lambda::Function",
        }
        expected_physical = {
            "McpApi": self.api_id,
            "McpApiStage": "$default",
            "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
            "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
            "McpHandler": "honda-mapit-mcp-dev-retained-handler",
        }
        by_logical = {item.get("LogicalResourceId"): item for item in resources if isinstance(item, Mapping)}
        if set(by_logical) != set(expected_types):
            raise RetainedDevControlsError("binding_invalid")
        for logical, kind in expected_types.items():
            item = by_logical[logical]
            if (
                set(item) - _ALLOWED_RESOURCE_KEYS
                or ("DriftInformation" in item and item["DriftInformation"] != {"StackResourceDriftStatus": "NOT_CHECKED"})
                or item.get("ResourceType") != kind
                or item.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                or item.get("StackId") != self.app_stack_id
                or item.get("StackName") != "honda-mapit-mcp-dev-retained"
                or item.get("PhysicalResourceId") != expected_physical[logical]
            ):
                raise RetainedDevControlsError("binding_invalid")
        api = self._call("apigatewayv2", "get_api", ApiId=self.api_id)
        if api.get("ApiId") != self.api_id or api.get("Name") != "honda-mapit-mcp-dev-retained-api" or api.get("ProtocolType") != "HTTP" or api.get("DisableExecuteApiEndpoint") is not True:
            raise RetainedDevControlsError("binding_invalid")
        routes = self._call("apigatewayv2", "get_routes", ApiId=self.api_id, MaxResults="100")
        if routes.get("Items") != []:
            raise RetainedDevControlsError("binding_invalid")
        function = self._call("lambda", "get_function_configuration", FunctionName="honda-mapit-mcp-dev-retained-handler")
        expected_role = f"arn:aws:iam::{self.account_id}:role/honda-mapit-mcp-dev-retained-handler-role"
        if (
            function.get("FunctionName") != "honda-mapit-mcp-dev-retained-handler"
            or function.get("Role") != expected_role
            or function.get("Runtime") != "python3.13"
            or function.get("Architectures") != ["arm64"]
            or function.get("MemorySize") != 256
            or function.get("Timeout") != 20
            or ("State" in function and function.get("State") != "Active")
        ):
            raise RetainedDevControlsError("binding_invalid")
        concurrency = self._call("lambda", "get_function_concurrency", FunctionName="honda-mapit-mcp-dev-retained-handler")
        if concurrency.get("ReservedConcurrentExecutions") != 0:
            raise RetainedDevControlsError("binding_invalid")


__all__ = ["RetainedDevControlsCoordinator", "RetainedDevControlsError"]
