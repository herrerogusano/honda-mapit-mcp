"""Injected closed retained-dev rollback coordinator.

This SDK-free core changes only CloudFormation's closed template.  It never
calls ``UpdateFunctionCode`` and accepts neither arbitrary templates nor
untyped artifact mappings.  A durable intent precedes the one UpdateStack;
unknown writes are reconciled by exact stack/event/readback checks and never
replayed.
"""

from __future__ import annotations

import base64
import copy
from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from typing import Any, Callable

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.aws_retained_dev_journal import MAX_REVISION
from scripts.aws_retained_dev_delivery_update import RetainedDevCreationTagBinding, _lambda_tags_equal, _resource_rows
from scripts.aws_retained_dev_recovery_artifact import RetainedDevRecoveryArtifactReceipt
from scripts.build_aws_retained_dev_archive import RetainedDevBuildReceipt
from scripts.build_aws_retained_dev_recovery import (
    CFN_ROLE_NAME,
    FUNCTION_NAME,
    HANDLER_ROLE_NAME,
    RetainedDevRecoveryTemplate,
    materialize_recovery_template,
)
from scripts.build_aws_retained_dev_runtime import build_retained_dev_runtime_template

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS = 32
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{STACK_NAME}/[0-9a-f-]{{36}}\Z")
_CALLER = re.compile(r"arn:aws:(?:iam::[0-9]{12}:(?:user|role)/[^\s:]+|sts::[0-9]{12}:assumed-role/[^\s:/]+/[^\s:/]+)\Z")
_RESOURCE_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role", "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
}


class RetainedDevRecoveryError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _status(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _template_body(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value.encode("utf-8", "ignore")) > 64 * 1024:
        return None
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in items:
            if key in result:
                raise ValueError
            result[key] = item
        return result
    try:
        parsed = json.loads(value, object_pairs_hook=pairs)
    except Exception:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _state(*, coordinator: "RetainedDevRecoveryCoordinator", status: str, revision: int, intent: Mapping[str, Any] | None = None, acknowledged: bool = False, event: bool = False, verified: bool = False, stack_id: str | None = None, last_epoch: float | int | None = None) -> dict[str, Any]:
    return {
        "schema": 1, "kind": "retained-dev-recovery-update", "revision": revision,
        "binding_sha256": coordinator.binding_sha256, "account_id": coordinator.account_id,
        "stack_arn": coordinator.stack_arn, "api_id": coordinator.api_id,
        "source_sha": coordinator.source_sha, "run_id": coordinator.run_id,
        "current_zip_sha256": coordinator.current_build_receipt.zip_sha256,
        "current_template_sha256": coordinator.current_template_sha256,
        "prior_zip_sha256": coordinator.recovery_template.code_sha256,
        "prior_template_sha256": coordinator.recovery_template.recovery_template_sha256,
        "prior_artifact_key": coordinator.recovery_artifact.key,
        "authorized_from_epoch": coordinator.authorized_from,
        "authorized_until_epoch": coordinator.authorized_until,
        "expected_caller_arn": coordinator.expected_caller_arn,
        "status": status, "preflight": status in {"preflight", "intent", "acknowledged", "verified"},
        "update_intent": dict(intent) if intent is not None else None,
        "update_acknowledged": acknowledged, "update_event_observed": event,
        "update_verified": verified, "stack_id": stack_id,
        "last_observed_epoch": coordinator._last_epoch if last_epoch is None else last_epoch,
    }


class RetainedDevRecoveryCoordinator:
    STEPS = ("preflight", "request-update", "check-update")

    def __init__(
        self, clients: Mapping[str, Any], journal: Any, *, account_id: str, stack_arn: str,
        api_id: str, run_id: str, source_sha: str, current_build_receipt: RetainedDevBuildReceipt,
        recovery_template: RetainedDevRecoveryTemplate, recovery_artifact: RetainedDevRecoveryArtifactReceipt,
        expected_caller_arn: str, authorized_from_epoch: int, authorized_until_epoch: int,
        creation_tag_binding: RetainedDevCreationTagBinding | None = None,
        wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "lambda", "apigatewayv2", "s3"} or any(clients.get(k) is None for k in clients):
            raise RetainedDevRecoveryError("clients_invalid")
        if not all(callable(getattr(journal, k, None)) for k in ("load", "compare_and_set", "locked")):
            raise RetainedDevRecoveryError("journal_invalid")
        if (
            type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000"
            or type(stack_arn) is not str or _STACK.fullmatch(stack_arn) is None or f":{account_id}:" not in stack_arn
            or type(api_id) is not str or not re.fullmatch(r"[a-z0-9]{10}", api_id)
            or type(run_id) is not str or _UUID.fullmatch(run_id) is None
            or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40
            or not isinstance(current_build_receipt, RetainedDevBuildReceipt) or not current_build_receipt.validate()
            or current_build_receipt.source_sha != source_sha or current_build_receipt.api_id != api_id
            or not isinstance(recovery_template, RetainedDevRecoveryTemplate) or recovery_template.account_id != account_id
            or recovery_template.cfn_role_arn != f"arn:aws:iam::{account_id}:role/{CFN_ROLE_NAME}"
            or not isinstance(recovery_artifact, RetainedDevRecoveryArtifactReceipt)
            or recovery_artifact.bucket != recovery_template.bucket or recovery_artifact.key != recovery_template.key
            or recovery_artifact.sha256 != recovery_template.code_sha256 or recovery_artifact.server_side_encryption != "AES256"
            or type(recovery_artifact.size_bytes) is not int or recovery_artifact.size_bytes <= 0
            or type(expected_caller_arn) is not str or _CALLER.fullmatch(expected_caller_arn) is None or f"::{account_id}:" not in expected_caller_arn
            or type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int
            or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS
            or not callable(wall_clock) or not callable(monotonic)
            or (creation_tag_binding is not None and (not isinstance(creation_tag_binding, RetainedDevCreationTagBinding) or not creation_tag_binding.validate_for(stack_arn=stack_arn)))
        ):
            raise RetainedDevRecoveryError("binding_invalid")
        try:
            self.current_template = build_retained_dev_runtime_template(
                account_id, api_id, current_build_receipt.zip_sha256, current_build_receipt.jwks_sha256,
                execution_start_epoch=current_build_receipt.execution_start_epoch,
                execution_end_epoch=current_build_receipt.execution_end_epoch,
            )
            self.recovery_template_body = materialize_recovery_template(recovery_template)
        except Exception:
            raise RetainedDevRecoveryError("binding_invalid") from None
        self.clients = dict(clients); self.journal = journal
        self.account_id, self.stack_arn, self.api_id, self.run_id, self.source_sha = account_id, stack_arn, api_id, run_id, source_sha
        self.current_build_receipt, self.recovery_template, self.recovery_artifact = current_build_receipt, recovery_template, recovery_artifact
        self.creation_tag_binding = creation_tag_binding
        self.expected_caller_arn = expected_caller_arn; self.authorized_from = authorized_from_epoch; self.authorized_until = authorized_until_epoch
        self.current_template_sha256 = hashlib.sha256(_canonical(self.current_template)).hexdigest()
        self.recovery_template_sha256 = hashlib.sha256(_canonical(self.recovery_template_body)).hexdigest()
        if self.recovery_template_sha256 != recovery_template.recovery_template_sha256:
            raise RetainedDevRecoveryError("binding_invalid")
        self.binding_sha256 = hashlib.sha256(_canonical({"account": account_id, "stack": stack_arn, "api": api_id, "run": run_id, "source": source_sha, "current": current_build_receipt.zip_sha256, "prior": recovery_template.code_sha256, "prior_template": self.recovery_template_sha256, "caller": expected_caller_arn, "from": authorized_from_epoch, "until": authorized_until_epoch, "creation_tag_binding": creation_tag_binding.payload() if creation_tag_binding is not None else None})).hexdigest()
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started = 0.0; self._last_mono = 0.0; self._last_epoch = 0.0; self._calls = 0

    def _clock(self, fn: Callable[[], float]) -> float:
        value = fn()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
            raise RetainedDevRecoveryError("window_invalid")
        return float(value)

    def _guard(self) -> None:
        epoch, mono = self._clock(self.wall_clock), self._clock(self.monotonic)
        if epoch < self.authorized_from or epoch >= self.authorized_until or mono < self._last_mono or mono - self._started >= MAX_STEP_SECONDS or epoch < self._last_epoch:
            raise RetainedDevRecoveryError("window_expired")
        self._last_epoch, self._last_mono = epoch, mono

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._guard()
        if self._calls >= MAX_CALLS:
            raise RetainedDevRecoveryError("call_budget_exhausted")
        self._calls += 1
        try:
            try:
                response = getattr(self.clients[service], method)(**kwargs)
            finally:
                self._guard()
        except RetainedDevRecoveryError:
            raise
        except Exception:
            raise RetainedDevRecoveryError("aws_call_failed") from None
        if not _status(response) or any(key in response for key in ("NextToken", "NextMarker", "Marker")) or response.get("IsTruncated") not in (None, False):
            raise RetainedDevRecoveryError("response_invalid")
        return response

    def _verify_caller(self) -> None:
        identity = self._call("sts", "get_caller_identity")
        if identity.get("Account") != self.account_id or identity.get("Arn") != self.expected_caller_arn:
            raise RetainedDevRecoveryError("caller_mismatch")

    def _artifact_head(self) -> None:
        head = self._call("s3", "head_object", Bucket=self.recovery_artifact.bucket, Key=self.recovery_artifact.key, ChecksumMode="ENABLED", ExpectedBucketOwner=self.account_id)
        checksum = base64.b64encode(bytes.fromhex(self.recovery_artifact.sha256)).decode("ascii")
        if (head.get("ContentLength") != self.recovery_artifact.size_bytes or head.get("ChecksumSHA256") != checksum or head.get("ServerSideEncryption") != "AES256" or head.get("ContentType") != "application/zip"):
            raise RetainedDevRecoveryError("artifact_readback_mismatch")

    def _read_closed(self, expected: Mapping[str, Any], expected_code_sha: str) -> None:
        row = self._call("cloudformation", "describe_stacks", StackName=self.stack_arn).get("Stacks")
        if type(row) is not list or len(row) != 1 or not isinstance(row[0], Mapping) or row[0].get("StackId") != self.stack_arn or row[0].get("StackName") != STACK_NAME or row[0].get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or row[0].get("RoleARN") != f"arn:aws:iam::{self.account_id}:role/{CFN_ROLE_NAME}":
            raise RetainedDevRecoveryError("preflight_mismatch")
        actual = _template_body(self._call("cloudformation", "get_template", StackName=self.stack_arn, TemplateStage="Original").get("TemplateBody"))
        if actual is None or hashlib.sha256(_canonical(actual)).hexdigest() != hashlib.sha256(_canonical(expected)).hexdigest():
            raise RetainedDevRecoveryError("preflight_mismatch")
        resources = self._call("cloudformation", "describe_stack_resources", StackName=self.stack_arn).get("StackResources")
        if not _resource_rows(resources, self.stack_arn, self.api_id):
            raise RetainedDevRecoveryError("preflight_mismatch")
        api = self._call("apigatewayv2", "get_api", ApiId=self.api_id); routes = self._call("apigatewayv2", "get_routes", ApiId=self.api_id)
        if api.get("ApiId") != self.api_id or api.get("ProtocolType") != "HTTP" or api.get("DisableExecuteApiEndpoint") is not True or routes.get("Items") != []:
            raise RetainedDevRecoveryError("preflight_mismatch")
        config = self._call("lambda", "get_function_configuration", FunctionName=FUNCTION_NAME)
        concurrency = self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
        tags = self._call("lambda", "list_tags", Resource=f"arn:aws:lambda:{REGION}:{self.account_id}:function:{FUNCTION_NAME}")
        function = self._call("lambda", "get_function", FunctionName=FUNCTION_NAME)
        props = expected.get("Resources", {}).get("McpHandler", {}).get("Properties", {})
        expected_b64 = base64.b64encode(bytes.fromhex(expected_code_sha)).decode("ascii")
        actual_config = function.get("Configuration") if isinstance(function.get("Configuration"), Mapping) else None
        expected_env = props.get("Environment") if isinstance(props, Mapping) else None
        if (config.get("FunctionName") != FUNCTION_NAME or config.get("Role") != f"arn:aws:iam::{self.account_id}:role/{HANDLER_ROLE_NAME}" or config.get("Runtime") != props.get("Runtime") or config.get("Handler") != props.get("Handler") or config.get("Architectures") != props.get("Architectures") or config.get("MemorySize") != props.get("MemorySize") or config.get("Timeout") != props.get("Timeout") or config.get("Environment") != expected_env or config.get("State") != "Active" or config.get("LastUpdateStatus") != "Successful" or concurrency.get("ReservedConcurrentExecutions") != 0 or not _lambda_tags_equal(tags.get("Tags"), props.get("Tags"), stack_arn=self.stack_arn, creation_tag_binding=self.creation_tag_binding) or not isinstance(actual_config, Mapping) or actual_config.get("CodeSha256") != expected_b64):
            raise RetainedDevRecoveryError("preflight_mismatch")

    def _event(self) -> None:
        events = self._call("cloudformation", "describe_stack_events", StackName=self.stack_arn).get("StackEvents")
        if type(events) is not list or len(events) > 64 or sum(1 for row in events if isinstance(row, Mapping)
            and row.get("StackId") == self.stack_arn and row.get("StackName") == STACK_NAME
            and row.get("ResourceType") == "AWS::CloudFormation::Stack"
            and row.get("LogicalResourceId") == STACK_NAME and row.get("PhysicalResourceId") == self.stack_arn
            and row.get("ClientRequestToken") == self.run_id and row.get("ResourceStatus") == "UPDATE_COMPLETE") != 1:
            raise RetainedDevRecoveryError("update_outcome_unknown")

    def _state(self) -> dict[str, Any] | None:
        self._guard()
        try:
            try:
                value = self.journal.load()
            finally:
                self._guard()
        except RetainedDevRecoveryError:
            raise
        except Exception:
            raise RetainedDevRecoveryError("journal_failed") from None
        if value is None:
            return None
        expected = _state(coordinator=self, status="preflight", revision=1)
        if not isinstance(value, Mapping) or set(value) != set(expected):
            raise RetainedDevRecoveryError("journal_invalid")
        static_fields = (
            "schema", "kind", "binding_sha256", "account_id", "stack_arn", "api_id", "source_sha", "run_id",
            "current_zip_sha256", "current_template_sha256", "prior_zip_sha256", "prior_template_sha256",
            "prior_artifact_key", "authorized_from_epoch", "authorized_until_epoch", "expected_caller_arn",
        )
        if any(value.get(key) != expected[key] for key in static_fields):
            raise RetainedDevRecoveryError("journal_invalid")
        if type(value.get("schema")) is not int or type(value.get("revision")) is not int or isinstance(value.get("revision"), bool) or not 1 <= value["revision"] <= MAX_REVISION:
            raise RetainedDevRecoveryError("journal_invalid")
        if type(value.get("preflight")) is not bool or any(type(value.get(k)) is not bool for k in ("update_acknowledged", "update_event_observed", "update_verified")) or value.get("preflight") is not True:
            raise RetainedDevRecoveryError("journal_invalid")
        intent = value.get("update_intent")
        if value["revision"] == 1:
            if value.get("status") != "preflight" or intent is not None or any(value[k] for k in ("update_acknowledged", "update_event_observed", "update_verified")):
                raise RetainedDevRecoveryError("journal_invalid")
        elif not isinstance(intent, Mapping) or set(intent) != {"client_request_token"} or intent.get("client_request_token") != self.run_id:
            raise RetainedDevRecoveryError("journal_invalid")
        expected_status = {
            (1, False, False, False): "preflight",
            (2, False, False, False): "intent",
            (3, True, False, False): "acknowledged",
            (3, False, True, False): "reconciled",
            (4, True, True, True): "verified",
        }
        status_key = (value["revision"], value["update_acknowledged"], value["update_event_observed"], value["update_verified"])
        if value.get("status") != expected_status.get(status_key):
            raise RetainedDevRecoveryError("journal_invalid")
        stack_id = value.get("stack_id")
        if (value["update_acknowledged"] or value["update_event_observed"]) and stack_id != self.stack_arn:
            raise RetainedDevRecoveryError("journal_invalid")
        if stack_id is not None and (type(stack_id) is not str or stack_id != self.stack_arn):
            raise RetainedDevRecoveryError("journal_invalid")
        observed = value.get("last_observed_epoch")
        try:
            observed_valid = type(observed) in (int, float) and not isinstance(observed, bool) and math.isfinite(float(observed)) and self.authorized_from <= observed < self.authorized_until
        except (OverflowError, TypeError, ValueError):
            observed_valid = False
        if not observed_valid:
            raise RetainedDevRecoveryError("journal_invalid")
        return dict(value)

    def _save(self, value: dict[str, Any], expected_revision: int | None) -> None:
        self._guard()
        try:
            try:
                ok = self.journal.compare_and_set(expected_revision, value)
            finally:
                self._guard()
        except RetainedDevRecoveryError:
            raise
        except Exception:
            raise RetainedDevRecoveryError("journal_failed") from None
        if ok is not True:
            raise RetainedDevRecoveryError("journal_conflict")

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None:
            raise RetainedDevRecoveryError("preflight_conflict")
        self._verify_caller(); self._artifact_head(); self._read_closed(self.current_template, self.current_build_receipt.zip_sha256); self._verify_caller()
        value = _state(coordinator=self, status="preflight", revision=1); self._save(value, None)
        return {"success": True, "category": "preflight_verified", "calls": self._calls}

    def _request_update(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise RetainedDevRecoveryError("preflight_required")
        if state.get("update_intent") is not None:
            raise RetainedDevRecoveryError("update_intent_present")
        intent = dict(state); intent["status"] = "intent"; intent["revision"] = state["revision"] + 1; intent["update_intent"] = {"client_request_token": self.run_id}; intent["last_observed_epoch"] = self._last_epoch
        self._save(intent, state["revision"])
        self._artifact_head(); self._read_closed(self.current_template, self.current_build_receipt.zip_sha256); self._verify_caller(); self._guard()
        body = _canonical(self.recovery_template_body).decode("ascii")
        if self._calls >= MAX_CALLS:
            raise RetainedDevRecoveryError("call_budget_exhausted")
        self._calls += 1
        self._guard()
        reply = None
        call_error: Exception | None = None
        try:
            reply = self.clients["cloudformation"].update_stack(StackName=self.stack_arn, TemplateBody=body, RoleARN=self.recovery_template.cfn_role_arn, Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=self.run_id)
        except Exception as exc:
            call_error = exc
        try:
            self._guard()
        except RetainedDevRecoveryError:
            raise RetainedDevRecoveryError("update_outcome_unknown") from None
        if call_error is not None or not _status(reply) or reply.get("StackId") != self.stack_arn:
            raise RetainedDevRecoveryError("update_outcome_unknown")
        acknowledged = dict(intent); acknowledged["status"] = "acknowledged"; acknowledged["revision"] = intent["revision"] + 1; acknowledged["update_acknowledged"] = True; acknowledged["stack_id"] = self.stack_arn
        self._save(acknowledged, intent["revision"])
        return {"success": True, "category": "update_acknowledged", "calls": self._calls}

    def _check_update(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("update_intent") is None:
            raise RetainedDevRecoveryError("update_required")
        row = self._call("cloudformation", "describe_stacks", StackName=self.stack_arn).get("Stacks")
        if type(row) is not list or len(row) != 1 or not isinstance(row[0], Mapping):
            raise RetainedDevRecoveryError("update_failed")
        if row[0].get("StackStatus") in {"UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"}:
            return {"success": True, "category": "update_pending", "calls": self._calls}
        if row[0].get("StackStatus") != "UPDATE_COMPLETE" or row[0].get("RoleARN") != self.recovery_template.cfn_role_arn:
            raise RetainedDevRecoveryError("update_failed")
        self._read_closed(self.recovery_template_body, self.recovery_artifact.sha256); self._artifact_head(); self._event()
        value = dict(state); value["status"] = "verified" if state.get("update_acknowledged") else "reconciled"; value["revision"] = state["revision"] + 1; value["update_event_observed"] = True; value["stack_id"] = self.stack_arn
        if state.get("update_acknowledged"):
            value["update_verified"] = True
        self._save(value, state["revision"])
        return {"success": bool(state.get("update_acknowledged")), "category": "readback_verified" if state.get("update_acknowledged") else "update_reconciled_without_ack", "calls": self._calls}

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return {"success": False, "category": "step_invalid", "calls": 0}
        try:
            with self.journal.locked():
                self._started = self._last_mono = self._clock(self.monotonic); self._last_epoch = self._clock(self.wall_clock); self._calls = 0; self._guard()
                state = self._state()
                if state is not None and self._last_epoch < float(state["last_observed_epoch"]):
                    raise RetainedDevRecoveryError("window_expired")
                if step == "preflight": return self._preflight(state)
                if step == "request-update": return self._request_update(state)
                return self._check_update(state)
        except RetainedDevRecoveryError as exc:
            return {"success": False, "category": exc.category, "calls": self._calls}
        except Exception:
            return {"success": False, "category": "coordinator_internal_error", "calls": self._calls}


__all__ = ["RetainedDevRecoveryCoordinator", "RetainedDevRecoveryError"]
