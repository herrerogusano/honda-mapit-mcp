"""Injected closed retained-dev UpdateStack coordinator.

This core is offline-testable and SDK-free.  It accepts only sealed private
bindings, constructs the candidate through the retained-dev template factory,
and uses a CAS journal.  It performs one UpdateStack at most; ambiguous write
results are reconciled read-only and never replayed.
"""

from __future__ import annotations

import base64
import copy
from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import json
import math
import re
import time
from typing import Any, Callable

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.aws_retained_dev_journal import MAX_REVISION
from scripts.aws_retained_dev_delivery_artifact import RetainedDevArtifactReceipt
from scripts.aws_retained_dev_prior_code import PriorCodeSnapshot
from scripts.build_aws_retained_dev_archive import RetainedDevBuildReceipt
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest, build_retained_dev_runtime_template, retained_dev_artifact_bucket

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained"
FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
HANDLER_ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
CFN_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS = 32
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{STACK_NAME}/[0-9a-f-]{{36}}\Z")
_RESOURCE_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
}


class RetainedDevUpdateError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


@dataclass(frozen=True)
class RetainedDevCreationTagBinding:
    """Immutable proof of the original app-stack creation tag.

    ``OperatorRunId`` is not the UUID of a later update.  It is accepted only
    when reconstructed from a complete, freshly read CloudFormation stack tag
    list with the fixed retained-dev base tags and exact stack identity.
    """

    stack_arn: str
    operator_run_id: int
    stack_name: str = STACK_NAME
    logical_id: str = "McpHandler"

    def __post_init__(self) -> None:
        if (
            type(self.stack_arn) is not str or _STACK.fullmatch(self.stack_arn) is None
            or type(self.operator_run_id) is not int or isinstance(self.operator_run_id, bool) or self.operator_run_id <= 0
            or type(self.stack_name) is not str or self.stack_name != STACK_NAME
            or type(self.logical_id) is not str or self.logical_id != "McpHandler"
        ):
            raise RetainedDevUpdateError("creation_tag_binding_invalid")

    @classmethod
    def from_stack_tags(cls, *, stack_arn: str, stack_name: str, tags: Any) -> "RetainedDevCreationTagBinding":
        if type(stack_name) is not str or stack_name != STACK_NAME or not isinstance(tags, (list, tuple)):
            raise RetainedDevUpdateError("creation_tag_binding_invalid")
        values: dict[str, str] = {}
        for row in tags:
            if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or type(row["Key"]) is not str or type(row["Value"]) is not str or row["Key"] in values:
                raise RetainedDevUpdateError("creation_tag_binding_invalid")
            values[row["Key"]] = row["Value"]
        if values.get("Project") != "honda-mapit-mcp" or values.get("Environment") != "dev" or values.get("Purpose") != "retained-dev" or set(values) != {"Project", "Environment", "Purpose", "OperatorRunId"}:
            raise RetainedDevUpdateError("creation_tag_binding_invalid")
        raw_run_id = values["OperatorRunId"]
        if not re.fullmatch(r"[1-9][0-9]*", raw_run_id):
            raise RetainedDevUpdateError("creation_tag_binding_invalid")
        try:
            run_id = int(raw_run_id)
        except Exception:
            raise RetainedDevUpdateError("creation_tag_binding_invalid") from None
        return cls(stack_arn=stack_arn, operator_run_id=run_id, stack_name=stack_name)

    @classmethod
    def from_verified_bootstrap_binding(cls, binding: Any) -> "RetainedDevCreationTagBinding":
        """Derive the tag binding only from the exact read-only bootstrap receipt.

        ``RetainedDevBinding`` is produced by the bounded four-read verifier;
        callers must not replace it with a hand-authored run id or tag map.
        The local import avoids coupling the SDK-free delivery core at module
        import time.
        """
        try:
            from scripts.aws_retained_dev_binding import RetainedDevBinding
            if not isinstance(binding, RetainedDevBinding):
                raise RetainedDevUpdateError("creation_tag_binding_invalid")
            return cls(stack_arn=binding.stack_id, operator_run_id=binding.creation_run_id)
        except RetainedDevUpdateError:
            raise
        except Exception:
            raise RetainedDevUpdateError("creation_tag_binding_invalid") from None

    def validate_for(self, *, stack_arn: str, stack_name: str = STACK_NAME, logical_id: str = "McpHandler") -> bool:
        return self.stack_arn == stack_arn and self.stack_name == stack_name and self.logical_id == logical_id

    def extra_tags(self) -> dict[str, str]:
        return {"OperatorRunId": str(self.operator_run_id)}

    def payload(self) -> dict[str, Any]:
        return {"stack_arn": self.stack_arn, "stack_name": self.stack_name, "logical_id": self.logical_id, "operator_run_id": self.operator_run_id}


def build_retained_dev_manifest_from_receipt(receipt: RetainedDevBuildReceipt) -> Mapping[str, Any]:
    return build_retained_dev_manifest(
        receipt.source_sha, receipt.api_id, receipt.jwks_sha256,
        receipt.execution_start_epoch, receipt.execution_end_epoch,
    )


def _digest(value: Any) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def _status(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _clock(clock: Callable[[], float]) -> float:
    value = clock()
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise RetainedDevUpdateError("window_invalid")
    return float(value)


def _template_body(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value.encode("utf-8", "ignore")) > 64 * 1024:
        return None
    def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = item
        return result
    try:
        parsed = json.loads(value, object_pairs_hook=_pairs)
    except Exception:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _resource_rows(value: Any, stack_id: str, api_id: str) -> bool:
    if type(value) is not list or len(value) != len(_RESOURCE_TYPES):
        return False
    by_id = {row.get("LogicalResourceId"): row for row in value if isinstance(row, Mapping)}
    if set(by_id) != set(_RESOURCE_TYPES):
        return False
    expected_physical = {
        "McpApi": api_id,
        "McpApiStage": "$default",
        "McpHandlerRole": HANDLER_ROLE_NAME,
        "McpHandlerLogGroup": f"/aws/lambda/{FUNCTION_NAME}",
        "McpHandler": FUNCTION_NAME,
    }
    return all(
        set(row) >= {"LogicalResourceId", "PhysicalResourceId", "ResourceType", "ResourceStatus", "StackId", "StackName"}
        and row.get("ResourceType") == _RESOURCE_TYPES[logical]
        and row.get("PhysicalResourceId") == expected_physical[logical]
        and row.get("ResourceStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
        and row.get("StackId") == stack_id
        and row.get("StackName") == STACK_NAME
        for logical, row in by_id.items()
    )


def _lambda_tags_equal(actual: Any, expected: Any, *, stack_arn: str, stack_name: str = STACK_NAME, logical_id: str = "McpHandler", creation_tag_binding: RetainedDevCreationTagBinding | None = None) -> bool:
    """Compare the Lambda ``list_tags`` map with exact owned CFN tags."""
    if not isinstance(expected, list) or not isinstance(actual, Mapping):
        return False
    expected_map: dict[str, str] = {}
    for row in expected:
        if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or type(row.get("Key")) is not str or type(row.get("Value")) is not str or row["Key"] in expected_map:
            return False
        expected_map[row["Key"]] = row["Value"]
    allowed = dict(expected_map)
    allowed.update({
        "aws:cloudformation:stack-id": stack_arn,
        "aws:cloudformation:stack-name": stack_name,
        "aws:cloudformation:logical-id": logical_id,
    })
    if creation_tag_binding is not None:
        if not isinstance(creation_tag_binding, RetainedDevCreationTagBinding) or not creation_tag_binding.validate_for(stack_arn=stack_arn, stack_name=stack_name, logical_id=logical_id):
            return False
        allowed.update(creation_tag_binding.extra_tags())
    if set(actual) - set(allowed):
        return False
    return all(type(key) is str and type(value) is str and allowed.get(key) == value for key, value in actual.items()) and all(actual.get(key) == value for key, value in expected_map.items())


def _tags_equal(actual: Any, expected: Any) -> bool:
    """Backward-compatible strict row comparison for stack tag readbacks."""
    if type(actual) is not list or type(expected) is not list:
        return False
    def normalize(value: Any) -> dict[str, str] | None:
        rows: dict[str, str] = {}
        for row in value:
            if not isinstance(row, Mapping) or set(row) != {"Key", "Value"}:
                return None
            key, item = row.get("Key"), row.get("Value")
            if type(key) is not str or type(item) is not str or key in rows:
                return None
            rows[key] = item
        return rows
    left, right = normalize(actual), normalize(expected)
    return left is not None and right is not None and left == right


class RetainedDevUpdateCoordinator:
    STEPS = ("preflight", "request-update", "check-update")

    def __init__(
        self,
        clients: Mapping[str, Any],
        journal: Any,
        *,
        account_id: str,
        stack_arn: str,
        api_id: str,
        source_sha: str,
        run_id: str,
        prior_template_body: Mapping[str, Any],
        prior_template_sha256: str,
        prior_zip_sha256: str,
        build_receipt: RetainedDevBuildReceipt,
        prior_code_snapshot: PriorCodeSnapshot | None = None,
        prior_artifact_receipt: RetainedDevArtifactReceipt | None = None,
        candidate_artifact_receipt: RetainedDevArtifactReceipt | None = None,
        execution_start_epoch: int,
        execution_end_epoch: int,
        expected_caller_arn: str,
        authorized_from_epoch: int,
        authorized_until_epoch: int,
        creation_tag_binding: RetainedDevCreationTagBinding | None = None,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "lambda", "apigatewayv2", "s3"} or any(clients.get(key) is None for key in clients):
            raise RetainedDevUpdateError("clients_invalid")
        if not all(callable(getattr(journal, key, None)) for key in ("load", "compare_and_set", "locked")):
            raise RetainedDevUpdateError("journal_invalid")
        if (
            type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000"
            or type(stack_arn) is not str or _STACK.fullmatch(stack_arn) is None or stack_arn.split(":")[4] != account_id
            or type(api_id) is not str or _API.fullmatch(api_id) is None
            or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40
            or type(run_id) is not str or _UUID.fullmatch(run_id) is None
            or not _digest(prior_template_sha256) or not _digest(prior_zip_sha256)
            or not isinstance(build_receipt, RetainedDevBuildReceipt) or not build_receipt.validate()
            or not isinstance(candidate_artifact_receipt, RetainedDevArtifactReceipt)
            or not isinstance(prior_template_body, Mapping)
            or type(execution_start_epoch) is not int or type(execution_end_epoch) is not int
            or isinstance(execution_start_epoch, bool) or isinstance(execution_end_epoch, bool)
            or execution_start_epoch <= 0 or execution_end_epoch <= execution_start_epoch
            or execution_end_epoch - execution_start_epoch > 300
            or type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int
            or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS
            or type(expected_caller_arn) is not str
            or re.fullmatch(rf"arn:aws:(?:iam::{account_id}:(?:user|role)/[^\s:]+|sts::{account_id}:assumed-role/[^\s:/]+/[^\s:/]+)", expected_caller_arn) is None
            or expected_caller_arn.endswith(":root")
            or (creation_tag_binding is not None and (not isinstance(creation_tag_binding, RetainedDevCreationTagBinding) or not creation_tag_binding.validate_for(stack_arn=stack_arn)))
        ):
            raise RetainedDevUpdateError("binding_invalid")
        if not self._accepted_prior_template(prior_template_body, prior_zip_sha256, account_id, prior_code_snapshot, api_id=api_id):
            raise RetainedDevUpdateError("prior_recovery_unavailable")
        if prior_code_snapshot is None and not isinstance(prior_artifact_receipt, RetainedDevArtifactReceipt):
            raise RetainedDevUpdateError("prior_recovery_unavailable")
        if prior_code_snapshot is not None and prior_artifact_receipt is not None:
            raise RetainedDevUpdateError("binding_invalid")
        if prior_artifact_receipt is not None and (
            prior_artifact_receipt.key != f"runtime/{prior_zip_sha256}.zip"
            or prior_artifact_receipt.sha256 != prior_zip_sha256
            or prior_artifact_receipt.server_side_encryption != "AES256"
            or type(prior_artifact_receipt.size_bytes) is not int or prior_artifact_receipt.size_bytes <= 0
        ):
            raise RetainedDevUpdateError("prior_recovery_unavailable")
        if (
            candidate_artifact_receipt.key != f"runtime/{build_receipt.zip_sha256}.zip"
            or candidate_artifact_receipt.sha256 != build_receipt.zip_sha256
            or candidate_artifact_receipt.manifest_sha256 != build_receipt.manifest_sha256
            or candidate_artifact_receipt.server_side_encryption != "AES256"
            or type(candidate_artifact_receipt.size_bytes) is not int or candidate_artifact_receipt.size_bytes <= 0
        ):
            raise RetainedDevUpdateError("build_receipt_invalid")
        if hashlib.sha256(_canonical(prior_template_body)).hexdigest() != prior_template_sha256:
            raise RetainedDevUpdateError("prior_recovery_unavailable")
        if (
            build_receipt.source_sha != source_sha or build_receipt.api_id != api_id
            or build_receipt.zip_sha256 == prior_zip_sha256
            or build_receipt.execution_start_epoch != execution_start_epoch
            or build_receipt.execution_end_epoch != execution_end_epoch
            or hashlib.sha256(_canonical(build_retained_dev_manifest_from_receipt(build_receipt))).hexdigest() != build_receipt.manifest_sha256
        ):
            raise RetainedDevUpdateError("build_receipt_invalid")
        try:
            candidate = build_retained_dev_runtime_template(
                account_id, api_id, build_receipt.zip_sha256, build_receipt.jwks_sha256,
                execution_start_epoch=execution_start_epoch, execution_end_epoch=execution_end_epoch,
            )
        except Exception:
            raise RetainedDevUpdateError("candidate_invalid") from None
        self.clients = dict(clients); self.journal = journal
        self.account_id, self.stack_arn, self.api_id = account_id, stack_arn, api_id
        self.source_sha, self.run_id = source_sha, run_id
        self.prior_template = copy.deepcopy(dict(prior_template_body))
        self.prior_template_sha256, self.prior_zip_sha256 = prior_template_sha256, prior_zip_sha256
        self.build_receipt = build_receipt
        self.candidate_zip_sha256, self.candidate_manifest_sha256 = build_receipt.zip_sha256, build_receipt.manifest_sha256
        self.jwks_sha256, self.execution_start, self.execution_end = build_receipt.jwks_sha256, execution_start_epoch, execution_end_epoch
        self.prior_code_snapshot = prior_code_snapshot
        self.prior_artifact_receipt = prior_artifact_receipt
        self.candidate_artifact_receipt = candidate_artifact_receipt
        self.candidate_template = copy.deepcopy(candidate)
        self.candidate_template_sha256 = hashlib.sha256(_canonical(candidate)).hexdigest()
        self.expected_caller_arn = expected_caller_arn
        self.creation_tag_binding = creation_tag_binding
        self.authorized_from, self.authorized_until = authorized_from_epoch, authorized_until_epoch
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._calls = 0; self._started = 0.0; self._last_mono = 0.0; self._last_epoch = 0.0
        self.binding_sha256 = hashlib.sha256(_canonical({
            "account_id": account_id, "stack_arn": stack_arn, "api_id": api_id, "source_sha": source_sha,
            "run_id": run_id, "prior_template_sha256": prior_template_sha256, "prior_zip_sha256": prior_zip_sha256,
            "candidate_zip_sha256": build_receipt.zip_sha256, "candidate_manifest_sha256": build_receipt.manifest_sha256,
            "candidate_template_sha256": self.candidate_template_sha256, "jwks_sha256": build_receipt.jwks_sha256,
            "execution_start_epoch": execution_start_epoch, "execution_end_epoch": execution_end_epoch,
            "expected_caller_arn": expected_caller_arn, "authorized_from_epoch": authorized_from_epoch,
            "authorized_until_epoch": authorized_until_epoch,
            "creation_tag_binding": creation_tag_binding.payload() if creation_tag_binding is not None else None,
        })).hexdigest()

    @staticmethod
    def _accepted_prior_template(template: Mapping[str, Any], prior_zip: str, account: str, snapshot: PriorCodeSnapshot | None, *, api_id: str | None = None) -> bool:
        resources = template.get("Resources")
        if not isinstance(resources, Mapping) or set(resources) != set(_RESOURCE_TYPES):
            return False
        handler = resources.get("McpHandler", {}).get("Properties") if isinstance(resources.get("McpHandler"), Mapping) else None
        if not isinstance(handler, Mapping) or handler.get("ReservedConcurrentExecutions") != 0:
            return False
        code = handler.get("Code")
        if isinstance(code, Mapping) and set(code) == {"S3Bucket", "S3Key"}:
            if code.get("S3Bucket") != retained_dev_artifact_bucket(account) or code.get("S3Key") != f"runtime/{prior_zip}.zip":
                return False
            if api_id is None:
                return True
            try:
                variables = handler["Environment"]["Variables"]
                if not isinstance(variables, Mapping):
                    return False
                jwks = variables["MAPIT_COGNITO_JWKS_SHA256"]
                start = variables["MAPIT_DEV_EXECUTION_START_EPOCH"]
                end = variables["MAPIT_DEV_EXECUTION_END_EPOCH"]
                if type(start) is not str or type(end) is not str:
                    return False
                expected = build_retained_dev_runtime_template(
                    account, api_id, prior_zip, jwks,
                    execution_start_epoch=int(start), execution_end_epoch=int(end),
                )
            except (KeyError, TypeError, ValueError, RetainedDevUpdateError):
                return False
            except Exception:
                return False
            return _canonical(template) == _canonical(expected)
        if snapshot is None or not isinstance(snapshot, PriorCodeSnapshot):
            return False
        return (
            isinstance(code, Mapping) and set(code) == {"ZipFile"}
            and type(snapshot.template_bytes) is bytes and type(snapshot.archive_bytes) is bytes
            and snapshot.zip_sha256 == prior_zip
            and snapshot.template_sha256 == hashlib.sha256(snapshot.template_bytes).hexdigest()
            and _canonical(template) == snapshot.template_bytes
            and hashlib.sha256(snapshot.archive_bytes).hexdigest() == snapshot.zip_sha256
        )

    def _safe(self, step: str, ok: bool, category: str, **facts: Any) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls, **{key: value for key, value in facts.items() if type(value) is bool or (type(value) is int and value >= 0)}}

    def _guard(self) -> None:
        now = _clock(self.wall_clock); mono = _clock(self.monotonic)
        if (
            now < self.authorized_from or now >= self.authorized_until
            or now < self._last_epoch or mono < self._last_mono
            or mono - self._started >= MAX_STEP_SECONDS
        ):
            raise RetainedDevUpdateError("window_expired")
        self._last_epoch = now; self._last_mono = mono

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._guard()
        if self._calls >= MAX_CALLS:
            raise RetainedDevUpdateError("call_budget_exhausted")
        self._calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            raise RetainedDevUpdateError("aws_call_failed") from None
        if not _status(result) or any(key in result for key in ("NextToken", "NextMarker", "Marker")):
            raise RetainedDevUpdateError("aws_response_invalid")
        self._guard()
        return result

    def _verify_caller(self) -> None:
        identity = self._call("sts", "get_caller_identity")
        if identity.get("Account") != self.account_id or identity.get("Arn") != self.expected_caller_arn:
            raise RetainedDevUpdateError("caller_mismatch")

    def _matching_update_event(self) -> Mapping[str, Any]:
        events = self._call("cloudformation", "describe_stack_events", StackName=self.stack_arn).get("StackEvents")
        if type(events) is not list or len(events) > 64:
            raise RetainedDevUpdateError("update_outcome_unknown")
        matches = [
            row for row in events
            if isinstance(row, Mapping)
            and row.get("StackId") == self.stack_arn
            and row.get("StackName") == STACK_NAME
            and row.get("ResourceType") == "AWS::CloudFormation::Stack"
            and row.get("LogicalResourceId") == STACK_NAME
            and row.get("PhysicalResourceId") == self.stack_arn
            and row.get("ClientRequestToken") == self.run_id
            and row.get("ResourceStatus") == "UPDATE_COMPLETE"
        ]
        if len(matches) != 1:
            raise RetainedDevUpdateError("update_outcome_unknown")
        return matches[0]

    def _state(self) -> dict[str, Any] | None:
        value = self.journal.load()
        if value is None:
            return None
        fields = {"schema", "kind", "revision", "binding_sha256", "source_sha", "run_id", "prior_template_sha256", "prior_zip_sha256", "candidate_zip_sha256", "candidate_manifest_sha256", "candidate_template_sha256", "authorized_from_epoch", "authorized_until_epoch", "preflight", "update_intent", "update_acknowledged", "update_event_observed", "update_verified", "stack_id", "last_observed_epoch"}
        expected = self._base_state()
        if not isinstance(value, Mapping) or set(value) != fields:
            raise RetainedDevUpdateError("journal_invalid")
        static_fields = ("schema", "kind", "binding_sha256", "source_sha", "run_id", "prior_template_sha256", "prior_zip_sha256", "candidate_zip_sha256", "candidate_manifest_sha256", "candidate_template_sha256", "authorized_from_epoch", "authorized_until_epoch")
        if any(value.get(key) != expected[key] for key in static_fields):
            raise RetainedDevUpdateError("journal_invalid")
        if type(value.get("schema")) is not int or type(value.get("revision")) is not int or isinstance(value.get("revision"), bool) or not 1 <= value["revision"] <= MAX_REVISION or any(type(value.get(key)) is not bool for key in ("preflight", "update_acknowledged", "update_event_observed", "update_verified")) or value.get("preflight") is not True:
            raise RetainedDevUpdateError("journal_invalid")
        intent = value.get("update_intent")
        if value["revision"] == 1:
            if intent is not None or any(value[key] for key in ("update_acknowledged", "update_event_observed", "update_verified")):
                raise RetainedDevUpdateError("journal_invalid")
        elif not isinstance(intent, Mapping) or set(intent) != {"client_request_token"} or intent.get("client_request_token") != self.run_id:
            raise RetainedDevUpdateError("journal_invalid")
        if (value["revision"], value["update_acknowledged"], value["update_event_observed"], value["update_verified"]) not in {
            (1, False, False, False), (2, False, False, False), (3, True, False, False),
            (3, False, True, False), (4, True, True, True),
        }:
            raise RetainedDevUpdateError("journal_invalid")
        observed = value.get("last_observed_epoch")
        try:
            observed_valid = type(observed) in (int, float) and not isinstance(observed, bool) and math.isfinite(float(observed)) and self.authorized_from <= observed < self.authorized_until
        except (OverflowError, TypeError, ValueError):
            observed_valid = False
        if not observed_valid:
            raise RetainedDevUpdateError("journal_invalid")
        stack_id = value.get("stack_id")
        if (value["update_acknowledged"] or value["update_event_observed"]) and stack_id != self.stack_arn:
            raise RetainedDevUpdateError("journal_invalid")
        if stack_id is not None and (type(stack_id) is not str or not _STACK.fullmatch(stack_id) or stack_id != self.stack_arn):
            raise RetainedDevUpdateError("journal_invalid")
        if value.get("update_acknowledged") and stack_id != self.stack_arn:
            raise RetainedDevUpdateError("journal_invalid")
        return dict(value)

    def _save(self, state: dict[str, Any], expected_revision: int | None) -> None:
        self._guard()
        candidate = dict(state); candidate["revision"] = 1 if expected_revision is None else expected_revision + 1
        candidate["last_observed_epoch"] = self._last_epoch
        try:
            if self.journal.compare_and_set(expected_revision, candidate) is not True:
                raise RetainedDevUpdateError("journal_conflict")
            # Keep the caller's in-memory state aligned with the durable
            # revision.  This is required when the next receipt is based on
            # the state just written (intent -> acknowledgement -> verified).
            state.clear()
            state.update(candidate)
        except RetainedDevUpdateError:
            raise
        except Exception:
            raise RetainedDevUpdateError("journal_failed") from None
        self._guard()

    def _base_state(self) -> dict[str, Any]:
        return {"schema": 1, "kind": "retained-dev-update", "revision": 0, "binding_sha256": self.binding_sha256, "source_sha": self.source_sha, "run_id": self.run_id, "prior_template_sha256": self.prior_template_sha256, "prior_zip_sha256": self.prior_zip_sha256, "candidate_zip_sha256": self.candidate_zip_sha256, "candidate_manifest_sha256": self.candidate_manifest_sha256, "candidate_template_sha256": self.candidate_template_sha256, "authorized_from_epoch": self.authorized_from, "authorized_until_epoch": self.authorized_until, "preflight": False, "update_intent": None, "update_acknowledged": False, "update_event_observed": False, "update_verified": False, "stack_id": None, "last_observed_epoch": self._last_epoch}

    def _read_artifact_receipt(self, receipt: RetainedDevArtifactReceipt) -> None:
        head = self._call(
            "s3", "head_object", Bucket=retained_dev_artifact_bucket(self.account_id),
            Key=receipt.key, ChecksumMode="ENABLED", ExpectedBucketOwner=self.account_id,
        )
        expected_checksum = base64.b64encode(bytes.fromhex(receipt.sha256)).decode("ascii")
        if (
            type(head.get("ContentLength")) is not int or head["ContentLength"] != receipt.size_bytes
            or head.get("ChecksumSHA256") != expected_checksum
            or head.get("ServerSideEncryption") != receipt.server_side_encryption
            or head.get("ContentType") != "application/zip"
        ):
            raise RetainedDevUpdateError("artifact_readback_mismatch")

    def _read_closed_current(self, *, expected_template: Mapping[str, Any], expected_code_sha: str) -> str:
        stacks = self._call("cloudformation", "describe_stacks", StackName=self.stack_arn).get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RetainedDevUpdateError("preflight_mismatch")
        row = stacks[0]
        expected_role = f"arn:aws:iam::{self.account_id}:role/{CFN_ROLE_NAME}"
        role_arn = row.get("RoleARN")
        sealed_inline = expected_template is self.prior_template and self.prior_code_snapshot is not None
        if row.get("StackId") != self.stack_arn or row.get("StackName") != STACK_NAME or row.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or (role_arn != expected_role and not (sealed_inline and role_arn is None)):
            raise RetainedDevUpdateError("preflight_mismatch")
        if expected_template is self.prior_template and self.prior_artifact_receipt is not None:
            self._read_artifact_receipt(self.prior_artifact_receipt)
        template_reply = self._call("cloudformation", "get_template", StackName=self.stack_arn, TemplateStage="Original")
        actual = _template_body(template_reply.get("TemplateBody"))
        if actual is None or hashlib.sha256(_canonical(actual)).hexdigest() != hashlib.sha256(_canonical(expected_template)).hexdigest():
            raise RetainedDevUpdateError("preflight_mismatch")
        resources = self._call("cloudformation", "describe_stack_resources", StackName=self.stack_arn).get("StackResources")
        if not _resource_rows(resources, self.stack_arn, self.api_id):
            raise RetainedDevUpdateError("preflight_mismatch")
        api = self._call("apigatewayv2", "get_api", ApiId=self.api_id)
        routes = self._call("apigatewayv2", "get_routes", ApiId=self.api_id)
        if api.get("ApiId") != self.api_id or api.get("ProtocolType") != "HTTP" or api.get("DisableExecuteApiEndpoint") is not True or routes.get("Items") != []:
            raise RetainedDevUpdateError("preflight_mismatch")
        config = self._call("lambda", "get_function_configuration", FunctionName=FUNCTION_NAME)
        concurrency = self._call("lambda", "get_function_concurrency", FunctionName=FUNCTION_NAME)
        tags_reply = self._call("lambda", "list_tags", Resource=f"arn:aws:lambda:{REGION}:{self.account_id}:function:{FUNCTION_NAME}")
        function = self._call("lambda", "get_function", FunctionName=FUNCTION_NAME)
        function_config = function.get("Configuration") if isinstance(function.get("Configuration"), Mapping) else None
        code_sha = function_config.get("CodeSha256") if isinstance(function_config, Mapping) else None
        expected_props = expected_template.get("Resources", {}).get("McpHandler", {}).get("Properties")
        expected_environment = expected_props.get("Environment") if isinstance(expected_props, Mapping) else None
        expected_tags = expected_props.get("Tags") if isinstance(expected_props, Mapping) else None
        actual_environment = config.get("Environment")
        expected_role = f"arn:aws:iam::{self.account_id}:role/{HANDLER_ROLE_NAME}"
        expected_b64 = base64.b64encode(bytes.fromhex(expected_code_sha)).decode("ascii")
        if (
            config.get("FunctionName") != FUNCTION_NAME
            or config.get("Role") != expected_role
            or config.get("Runtime") != (expected_props or {}).get("Runtime")
            or config.get("Handler") != (expected_props or {}).get("Handler")
            or config.get("Architectures") != (expected_props or {}).get("Architectures")
            or config.get("MemorySize") != (expected_props or {}).get("MemorySize")
            or config.get("Timeout") != (expected_props or {}).get("Timeout")
            or actual_environment != expected_environment
            or config.get("State") != "Active"
            or config.get("LastUpdateStatus") != "Successful"
            or concurrency.get("ReservedConcurrentExecutions") != 0
            or not _lambda_tags_equal(tags_reply.get("Tags"), expected_tags, stack_arn=self.stack_arn, creation_tag_binding=self.creation_tag_binding)
            or code_sha != expected_b64
        ):
            raise RetainedDevUpdateError("preflight_mismatch")
        return self.stack_arn

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None:
            raise RetainedDevUpdateError("preflight_conflict")
        self._verify_caller()
        self._read_artifact_receipt(self.candidate_artifact_receipt)
        self._read_closed_current(expected_template=self.prior_template, expected_code_sha=self.prior_zip_sha256)
        self._verify_caller()
        new = self._base_state(); new["preflight"] = True
        self._save(new, None)
        return self._safe("preflight", True, "preflight_verified")

    def _request_update(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise RetainedDevUpdateError("preflight_required")
        if state.get("update_intent") is not None:
            raise RetainedDevUpdateError("update_intent_present")
        intent = dict(state); intent["update_intent"] = {"client_request_token": self.run_id}
        self._save(intent, state["revision"])
        # Reconfirm the closed prior state after the durable fence and before
        # the only write. A changed API, route, Lambda reservation, role,
        # template, or code digest leaves the intent for read-only review.
        self._read_closed_current(expected_template=self.prior_template, expected_code_sha=self.prior_zip_sha256)
        self._verify_caller()
        body = _canonical(self.candidate_template).decode("ascii")
        self._guard()
        if self._calls >= MAX_CALLS:
            raise RetainedDevUpdateError("call_budget_exhausted")
        self._calls += 1
        try:
            reply = self.clients["cloudformation"].update_stack(
                StackName=self.stack_arn, TemplateBody=body, RoleARN=f"arn:aws:iam::{self.account_id}:role/{CFN_ROLE_NAME}",
                Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=self.run_id,
            )
        except Exception:
            raise RetainedDevUpdateError("update_outcome_unknown") from None
        self._guard()
        if not _status(reply) or reply.get("StackId") != self.stack_arn:
            raise RetainedDevUpdateError("update_outcome_unknown")
        acknowledged = dict(intent); acknowledged["update_acknowledged"] = True; acknowledged["stack_id"] = self.stack_arn
        self._save(acknowledged, intent["revision"])
        return self._safe("request-update", True, "update_acknowledged")

    def _check_update(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("update_intent") is None:
            raise RetainedDevUpdateError("update_required")
        stacks = self._call("cloudformation", "describe_stacks", StackName=self.stack_arn).get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RetainedDevUpdateError("update_failed")
        row = stacks[0]
        if row.get("StackStatus") in {"UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"}:
            return self._safe("check-update", True, "update_pending")
        if row.get("StackStatus") != "UPDATE_COMPLETE" or row.get("RoleARN") != f"arn:aws:iam::{self.account_id}:role/{CFN_ROLE_NAME}":
            raise RetainedDevUpdateError("update_failed")
        self._read_closed_current(expected_template=self.candidate_template, expected_code_sha=self.candidate_zip_sha256)
        self._read_artifact_receipt(self.candidate_artifact_receipt)
        self._matching_update_event()
        verified = dict(state); verified["update_event_observed"] = True; verified["stack_id"] = self.stack_arn
        if not verified.get("update_acknowledged"):
            self._save(verified, state["revision"])
            return self._safe("check-update", False, "update_reconciled_without_ack", observed=True)
        verified["update_verified"] = True
        self._save(verified, state["revision"])
        return self._safe("check-update", True, "readback_verified", verified=True)

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                self._started = _clock(self.monotonic); self._last_mono = self._started; self._calls = 0; self._guard()
                state = self._state()
                if state is not None:
                    if self._last_epoch < float(state["last_observed_epoch"]):
                        raise RetainedDevUpdateError("window_expired")
                if step == "preflight":
                    return self._preflight(state)
                if step == "request-update":
                    return self._request_update(state)
                return self._check_update(state)
        except RetainedDevUpdateError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "coordinator_internal_error")


__all__ = [
    "RetainedDevCreationTagBinding",
    "RetainedDevUpdateCoordinator",
    "RetainedDevUpdateError",
]
