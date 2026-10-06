"""Injected, read-before-write operator for the retained-dev artifact stack.

This module has no SDK construction, credential lookup, network default, or
live side effect.  Every AWS client and journal is injected by the caller.
The only write it can issue is one CloudFormation CreateStack after a private
authorization, exact absence preflight, and durable create intent.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from typing import Any, Callable

from scripts.aws_retained_dev_bootstrap import _canonical, _strict_mapping
from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained-runtime-artifacts"
BUCKET_NAME = "honda-mapit-mcp-dev-retained-{account}-{region}"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 32
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_STACK = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\Z"
)
_CATEGORIES = {
    "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid", "window_expired",
    "step_invalid", "preflight_verified", "preflight_required", "preflight_conflict",
    "stack_absent_unverified", "bucket_absent_unverified", "named_resource_conflict",
    "create_intent_saved", "create_intent_present", "create_outcome_unknown", "create_acknowledged",
    "stack_in_progress", "stack_not_complete", "stack_readback_mismatch", "readback_verified",
    "aws_call_failed", "aws_response_invalid", "journal_failed", "operator_internal_error",
}
_RESOURCE_TYPES = {
    "RuntimeArtifactBucket": "AWS::S3::Bucket",
    "RuntimeArtifactBucketPolicy": "AWS::S3::BucketPolicy",
}
_MAX_EVENT_ROWS = 64
_TAGS = [
    {"Key": "Project", "Value": "honda-mapit-mcp"},
    {"Key": "Environment", "Value": "dev"},
    {"Key": "Purpose", "Value": "retained-dev-artifacts"},
]


class RetainedDevArtifactError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category if category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _error_code(exc: Exception) -> tuple[str, int | None, str]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else ""
    message = error.get("Message") if isinstance(error, Mapping) else ""
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    return (code if type(code) is str else "", status if type(status) is int and not isinstance(status, bool) else None,
            message if type(message) is str else "")


def _expected_bucket(account_id: str) -> str:
    return BUCKET_NAME.format(account=account_id, region=REGION)


def _create_token(account_id: str, source_sha: str, run_id: int) -> str:
    return "retained-dev-artifacts-" + hashlib.sha256(f"{account_id}:{source_sha}:{run_id}".encode("ascii")).hexdigest()


def _exact_absence_error(exc: Exception, *, kind: str) -> bool:
    code, status, message = _error_code(exc)
    if kind == "cloudformation":
        return code == "ValidationError" and status in {400, 404} and message == f"Stack with id {STACK_NAME} does not exist"
    if kind == "s3":
        return status == 404 and code in {"404", "NotFound", "NoSuchBucket"}
    return False


class RetainedDevArtifactCoordinator:
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
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "s3"} or any(clients.get(k) is None for k in clients):
            raise RetainedDevArtifactError("clients_invalid")
        if any(not callable(getattr(clients[name], "__getattribute__", None)) for name in clients):
            raise RetainedDevArtifactError("clients_invalid")
        endpoints = {
            "sts": "https://sts.eu-west-1.amazonaws.com",
            "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com",
            "s3": "https://s3.eu-west-1.amazonaws.com",
        }
        for name, client in clients.items():
            meta = getattr(client, "meta", None)
            if meta is not None:
                if getattr(meta, "region_name", None) != REGION or getattr(meta, "endpoint_url", None) != endpoints[name]:
                    raise RetainedDevArtifactError("clients_invalid")
        if not all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            raise RetainedDevArtifactError("journal_invalid")
        if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000":
            raise RetainedDevArtifactError("binding_invalid")
        if type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None or source_sha == "0" * 40:
            raise RetainedDevArtifactError("binding_invalid")
        if type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0:
            raise RetainedDevArtifactError("binding_invalid")
        if type(expected_caller_arn) is not str or not re.fullmatch(
            rf"(?:arn:aws:(?:iam|sts)::{account_id}:(?:user|role)/[^\s:/]+|arn:aws:sts::{account_id}:assumed-role/[^\s:/]+/[^\s:/]+)", expected_caller_arn
        ):
            raise RetainedDevArtifactError("binding_invalid")
        if type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool) or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool) or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS:
            raise RetainedDevArtifactError("window_invalid")
        try:
            template = build_retained_dev_artifacts()
        except Exception:
            raise RetainedDevArtifactError("binding_invalid") from None
        resources = template.get("Resources")
        if not isinstance(resources, Mapping) or set(resources) != set(_RESOURCE_TYPES) or any(resources[k].get("Type") != v for k, v in _RESOURCE_TYPES.items()):
            raise RetainedDevArtifactError("binding_invalid")
        self.template = template
        self.template_bytes = _canonical(template)
        self.template_sha256 = hashlib.sha256(self.template_bytes).hexdigest()
        self.clients = dict(clients)
        self.journal = journal
        self.account_id = account_id
        self.source_sha = source_sha
        self.run_id = run_id
        self.expected_caller_arn = expected_caller_arn
        self.window_start = authorized_from_epoch
        self.window_end = authorized_until_epoch
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self._started: float | None = None
        self._last_mono = 0.0
        self._last_epoch = 0
        self._calls = 0

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls}

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise RetainedDevArtifactError("window_invalid")
        epoch = int(value)
        if epoch < self._last_epoch:
            raise RetainedDevArtifactError("window_invalid")
        self._last_epoch = epoch
        if epoch < self.window_start or epoch >= self.window_end:
            raise RetainedDevArtifactError("window_expired")
        return epoch

    def _budget(self) -> None:
        current = self.monotonic()
        if type(current) not in (int, float) or isinstance(current, bool) or not math.isfinite(current) or current < self._last_mono:
            raise RetainedDevArtifactError("window_invalid")
        self._last_mono = float(current)
        if self._started is None or self._last_mono - self._started >= MAX_STEP_SECONDS:
            raise RetainedDevArtifactError("window_expired")
        if self._calls >= MAX_CALLS_PER_STEP:
            raise RetainedDevArtifactError("aws_call_failed")

    def _call(self, client_name: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._budget()
        self._now()
        self._calls += 1
        try:
            result = getattr(self.clients[client_name], method)(**kwargs)
        except Exception:
            self._now()
            raise RetainedDevArtifactError("aws_call_failed") from None
        if not isinstance(result, Mapping):
            raise RetainedDevArtifactError("aws_response_invalid")
        metadata = result.get("ResponseMetadata")
        if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata.get("HTTPStatusCode") != 200:
            raise RetainedDevArtifactError("aws_response_invalid")
        self._now()
        self._budget()
        if "NextToken" in result:
            raise RetainedDevArtifactError("aws_response_invalid")
        return result

    def _call_absent(self, client_name: str, method: str, *, kind: str, **kwargs: Any) -> None:
        self._budget()
        self._now()
        self._calls += 1
        try:
            result = getattr(self.clients[client_name], method)(**kwargs)
        except Exception as exc:
            if _exact_absence_error(exc, kind=kind):
                self._now()
                self._budget()
                return
            self._now()
            raise RetainedDevArtifactError("aws_call_failed") from None
        metadata = result.get("ResponseMetadata") if isinstance(result, Mapping) else None
        if isinstance(result, Mapping) and isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata.get("HTTPStatusCode") == 200:
            if "NextToken" in result:
                self._now()
                raise RetainedDevArtifactError("aws_response_invalid")
            self._now()
            raise RetainedDevArtifactError("named_resource_conflict")
        self._now()
        raise RetainedDevArtifactError("aws_response_invalid")

    def _identity(self) -> None:
        result = self._call("sts", "get_caller_identity")
        if result.get("Account") != self.account_id or result.get("Arn") != self.expected_caller_arn:
            raise RetainedDevArtifactError("binding_invalid")

    def _load(self) -> dict[str, Any] | None:
        state = self.journal.load()
        if state is None:
            return None
        if not isinstance(state, Mapping) or set(state) != {"schema", "kind", "account", "source_sha", "run_id", "template_sha256", "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch", "last_observed_epoch", "preflight", "intent", "acknowledged", "acknowledged_stack_id", "readback", "readback_receipt"}:
            raise RetainedDevArtifactError("journal_invalid")
        if state.get("schema") != 1 or state.get("kind") != "retained-dev-artifact" or state.get("account") != self.account_id or state.get("source_sha") != self.source_sha or state.get("run_id") != self.run_id or state.get("template_sha256") != self.template_sha256:
            raise RetainedDevArtifactError("journal_invalid")
        if type(state.get("preflight")) is not bool or type(state.get("acknowledged")) is not bool or type(state.get("readback")) is not bool:
            raise RetainedDevArtifactError("journal_invalid")
        if state["preflight"] is not True or (
            state["intent"] is None and (state["acknowledged"] or state["readback"])
        ):
            raise RetainedDevArtifactError("journal_invalid")
        ack_id = state.get("acknowledged_stack_id")
        if state.get("acknowledged"):
            if type(ack_id) is not str or _STACK.fullmatch(ack_id) is None or ack_id.split(":")[4] != self.account_id:
                raise RetainedDevArtifactError("journal_invalid")
        elif ack_id is not None:
            raise RetainedDevArtifactError("journal_invalid")
        if state.get("expected_caller_arn") != self.expected_caller_arn or state.get("authorized_from_epoch") != self.window_start or state.get("authorized_until_epoch") != self.window_end:
            raise RetainedDevArtifactError("journal_invalid")
        if type(state.get("last_observed_epoch")) is not int or state.get("last_observed_epoch") <= 0:
            raise RetainedDevArtifactError("journal_invalid")
        intent = state.get("intent")
        if intent is not None:
            if not isinstance(intent, Mapping) or set(intent) != {"token", "stack_name"} or intent.get("token") != _create_token(self.account_id, self.source_sha, self.run_id) or intent.get("stack_name") != STACK_NAME:
                raise RetainedDevArtifactError("journal_invalid")
        receipt = state.get("readback_receipt")
        if state.get("readback"):
            if not isinstance(receipt, Mapping) or set(receipt) != {"stack_id", "template_sha256", "bucket"} or receipt.get("template_sha256") != self.template_sha256 or receipt.get("bucket") != _expected_bucket(self.account_id) or type(receipt.get("stack_id")) is not str or _STACK.fullmatch(receipt["stack_id"]) is None or (ack_id is not None and receipt.get("stack_id") != ack_id):
                raise RetainedDevArtifactError("journal_invalid")
        elif receipt is not None:
            raise RetainedDevArtifactError("journal_invalid")
        if state.get("readback") and (
            receipt["stack_id"].split(":")[4] != self.account_id
            or (state.get("acknowledged") and receipt["stack_id"] != ack_id)
        ):
            raise RetainedDevArtifactError("journal_invalid")
        return dict(state)

    def _save(self, *, preflight: bool, intent: Mapping[str, Any] | None, acknowledged: bool, acknowledged_stack_id: str | None = None, readback: bool, readback_receipt: Mapping[str, Any] | None = None) -> None:
        self._now()
        self._budget()
        try:
            self.journal.save({"schema": 1, "kind": "retained-dev-artifact", "account": self.account_id,
                               "source_sha": self.source_sha, "run_id": self.run_id, "template_sha256": self.template_sha256,
                               "expected_caller_arn": self.expected_caller_arn, "authorized_from_epoch": self.window_start,
                               "authorized_until_epoch": self.window_end, "last_observed_epoch": self._last_epoch,
                               "preflight": preflight, "intent": dict(intent) if intent is not None else None,
                               "acknowledged": acknowledged, "acknowledged_stack_id": acknowledged_stack_id, "readback": readback,
                               "readback_receipt": dict(readback_receipt) if readback_receipt is not None else None})
        except Exception:
            raise RetainedDevArtifactError("journal_failed") from None
        self._now()
        self._budget()

    def run_step(self, step: str) -> dict[str, Any]:
        if step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                initial_mono = self.monotonic()
                if type(initial_mono) not in (int, float) or isinstance(initial_mono, bool) or not math.isfinite(initial_mono) or initial_mono < 0:
                    raise RetainedDevArtifactError("window_invalid")
                self._started = float(initial_mono)
                self._last_mono = self._started
                self._calls = 0
                state = self._load()
                self._last_epoch = state.get("last_observed_epoch", 0) if state is not None else 0
                self._now()
                self._identity()
                if step == "preflight":
                    return self._preflight(state)
                if step == "create":
                    return self._create(state)
                return self._readback(state)
        except RetainedDevArtifactError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "operator_internal_error")

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None and (state.get("intent") is not None or state.get("acknowledged")):
            raise RetainedDevArtifactError("preflight_conflict")
        # HeadBucket cannot distinguish an absent bucket from an inaccessible
        # bucket.  Ownership/adoption is established only by the closed
        # CreateStack plus the subsequent expected-owner readbacks.
        self._call_absent("cloudformation", "describe_stacks", kind="cloudformation", StackName=STACK_NAME)
        self._save(preflight=True, intent=None, acknowledged=False, acknowledged_stack_id=None, readback=False)
        return self._safe("preflight", True, "preflight_verified")

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise RetainedDevArtifactError("preflight_required")
        if state.get("intent") is not None or state.get("acknowledged"):
            raise RetainedDevArtifactError("create_intent_present")
        token = _create_token(self.account_id, self.source_sha, self.run_id)
        intent = {"token": token, "stack_name": STACK_NAME}
        stack_tags = [*_TAGS, {"Key": "OperatorRunId", "Value": str(self.run_id)}]
        self._save(preflight=True, intent=intent, acknowledged=False, acknowledged_stack_id=None, readback=False)
        self._budget()
        self._now()
        self._calls += 1
        try:
            response = self.clients["cloudformation"].create_stack(
                StackName=STACK_NAME, TemplateBody=self.template_bytes.decode("ascii"),
                Tags=stack_tags, ClientRequestToken=token, EnableTerminationProtection=True,
            )
        except Exception:
            self._now()
            self._budget()
            raise RetainedDevArtifactError("create_outcome_unknown") from None
        self._now()
        self._budget()
        response_stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        if not isinstance(response, Mapping) or type(metadata) is not dict or type(metadata.get("HTTPStatusCode")) is not int or metadata.get("HTTPStatusCode") != 200 or type(response_stack_id) is not str or _STACK.fullmatch(response_stack_id) is None or response_stack_id.split(":")[4] != self.account_id:
            self._now()
            raise RetainedDevArtifactError("create_outcome_unknown")
        self._now()
        self._save(preflight=True, intent=intent, acknowledged=True, acknowledged_stack_id=response_stack_id, readback=False)
        return self._safe("create", True, "create_acknowledged")

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None:
            raise RetainedDevArtifactError("preflight_required")
        stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        stacks = stack.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        row = stacks[0]
        stack_id = row.get("StackId")
        if type(stack_id) is not str or _STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != self.account_id or row.get("StackName") != STACK_NAME:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        if state.get("acknowledged") and state.get("acknowledged_stack_id") != stack_id:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        if row.get("StackStatus") == "CREATE_IN_PROGRESS":
            raise RetainedDevArtifactError("stack_in_progress")
        if row.get("StackStatus") != "CREATE_COMPLETE":
            raise RetainedDevArtifactError("stack_not_complete")
        if row.get("EnableTerminationProtection") is not True:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        tags = row.get("Tags")
        if not isinstance(tags, list) or len(tags) != 4 or any(not isinstance(x, Mapping) or set(x) != {"Key", "Value"} for x in tags):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        if {x["Key"]: x["Value"] for x in tags} != {**{x["Key"]: x["Value"] for x in _TAGS}, "OperatorRunId": str(self.run_id)}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        outputs = row.get("Outputs")
        if type(outputs) is not list or len(outputs) != 1 or outputs[0].get("OutputKey") != "RuntimeArtifactBucketName" or outputs[0].get("OutputValue") != _expected_bucket(self.account_id):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        template = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
        body = _strict_mapping(template.get("TemplateBody"))
        if body is None or _canonical(body) != self.template_bytes:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME)
        if set(events) - {"ResponseMetadata", "StackEvents"}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        event_rows = events.get("StackEvents")
        if not isinstance(event_rows, list) or not event_rows or len(event_rows) > _MAX_EVENT_ROWS:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        matching_events = [event for event in event_rows if isinstance(event, Mapping) and event.get("ClientRequestToken") == state["intent"]["token"] and event.get("StackId") == stack_id]
        if not matching_events:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        resources_response = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME)
        if set(resources_response) - {"ResponseMetadata", "StackResources"}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        resources = resources_response.get("StackResources")
        if type(resources) is not list or len(resources) != 2:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        by_logical = {item.get("LogicalResourceId"): item for item in resources if isinstance(item, Mapping)}
        if set(by_logical) != set(_RESOURCE_TYPES) or any(
            set(by_logical[k]) - {"LogicalResourceId", "ResourceType", "PhysicalResourceId", "ResourceStatus", "StackId", "StackName", "Timestamp", "ResourceStatusReason", "DriftInformation"}
            or ("DriftInformation" in by_logical[k] and by_logical[k]["DriftInformation"] != {"StackResourceDriftStatus": "NOT_CHECKED"})
            or by_logical[k].get("ResourceType") != v
            or by_logical[k].get("ResourceStatus") != "CREATE_COMPLETE"
            or by_logical[k].get("StackId") != stack_id
            or by_logical[k].get("StackName") != STACK_NAME
            for k, v in _RESOURCE_TYPES.items()
        ):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        bucket = _expected_bucket(self.account_id)
        if by_logical["RuntimeArtifactBucket"].get("PhysicalResourceId") != bucket or by_logical["RuntimeArtifactBucketPolicy"].get("PhysicalResourceId") != bucket:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        self._verify_bucket(bucket, stack_id)
        self._save(preflight=True, intent=state["intent"], acknowledged=bool(state.get("acknowledged")),
                   acknowledged_stack_id=state.get("acknowledged_stack_id"), readback=True,
                   readback_receipt={"stack_id": stack_id, "template_sha256": self.template_sha256, "bucket": bucket})
        return self._safe("readback", True, "readback_verified")

    def _verify_bucket(self, bucket: str, stack_id: str) -> None:
        public = self._call("s3", "get_public_access_block", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        if public.get("PublicAccessBlockConfiguration") != {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        encryption = self._call("s3", "get_bucket_encryption", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        encryption_config = encryption.get("ServerSideEncryptionConfiguration")
        if not isinstance(encryption_config, Mapping) or set(encryption_config) != {"Rules"}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        encryption_rows = encryption_config["Rules"]
        if type(encryption_rows) is not list or len(encryption_rows) != 1 or not isinstance(encryption_rows[0], Mapping):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        encryption_row = encryption_rows[0]
        if set(encryption_row) - {"ApplyServerSideEncryptionByDefault", "BucketKeyEnabled"} or encryption_row.get("ApplyServerSideEncryptionByDefault") != {"SSEAlgorithm": "AES256"} or ("BucketKeyEnabled" in encryption_row and encryption_row["BucketKeyEnabled"] is not False):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        ownership = self._call("s3", "get_bucket_ownership_controls", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        if ownership.get("OwnershipControls") != {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        versioning = self._call("s3", "get_bucket_versioning", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        if set(versioning) - {"ResponseMetadata", "Status"} or versioning.get("Status") not in (None, ""):
            raise RetainedDevArtifactError("stack_readback_mismatch")
        location = self._call("s3", "get_bucket_location", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        if location.get("LocationConstraint") != REGION:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        policy_status = self._call("s3", "get_bucket_policy_status", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        policy_value = policy_status.get("PolicyStatus", {}).get("IsPublic") if isinstance(policy_status.get("PolicyStatus"), Mapping) else None
        if type(policy_value) is not bool or policy_value is not False:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        tags = self._call("s3", "get_bucket_tagging", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        expected_tags = [*_TAGS, {"Key": "OperatorRunId", "Value": str(self.run_id)},
                         {"Key": "aws:cloudformation:stack-id", "Value": stack_id},
                         {"Key": "aws:cloudformation:stack-name", "Value": STACK_NAME},
                         {"Key": "aws:cloudformation:logical-id", "Value": "RuntimeArtifactBucket"}]
        actual_tags = tags.get("TagSet")
        if type(actual_tags) is not list or len(actual_tags) != len(expected_tags) or any(not isinstance(item, Mapping) or set(item) != {"Key", "Value"} for item in actual_tags) or {item["Key"]: item["Value"] for item in actual_tags} != {item["Key"]: item["Value"] for item in expected_tags}:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        lifecycle = self._call("s3", "get_bucket_lifecycle_configuration", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        expected_rule = {"ID": "DevTerminalJournalRetention", "Status": "Enabled", "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}}, "Expiration": {"Days": 30}}
        if lifecycle.get("Rules") != [expected_rule]:
            raise RetainedDevArtifactError("stack_readback_mismatch")
        policy = self._call("s3", "get_bucket_policy", Bucket=bucket, ExpectedBucketOwner=self.account_id)
        document = _strict_mapping(policy.get("Policy"))
        expected_policy = {"Version": "2012-10-17", "Statement": [{"Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        if document is None or _canonical(document) != _canonical(expected_policy):
            raise RetainedDevArtifactError("stack_readback_mismatch")


__all__ = ["RetainedDevArtifactCoordinator", "RetainedDevArtifactError"]
