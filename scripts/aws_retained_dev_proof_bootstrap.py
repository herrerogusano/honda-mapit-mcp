"""Injected, SDK-free bootstrap for the two-resource retained-dev proof role.

This is a separate offline core.  It creates no clients and performs no work
at import time.  A caller supplies the reviewed private factory bindings,
clients, and a CAS journal.  At most one CreateStack is attempted after a
read-only absence/provider preflight; an uncertain result is fenced and never
replayed.
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

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.build_cd_retained_dev_proof_role import (
    BOUNDARY_NAME, ROLE_NAME, STACK_NAME, build_cd_retained_dev_proof_role,
)
from scripts.build_cd_identity_bootstrap import AUDIENCE, ISSUER_HOST, OWNER, REPOSITORY

REGION = "eu-west-1"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS = 32
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/[0-9a-f-]{{36}}\Z")


class RetainedDevProofBootstrapError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _document(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        try:
            return json.loads(_canonical(value).decode("ascii"), object_pairs_hook=_strict_pairs)
        except Exception:
            return None
    if type(value) is not str or len(value.encode("utf-8", "strict")) > 192 * 1024:
        return None
    if re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return None
    try:
        raw = unquote_to_bytes(value)
        if len(raw) > 64 * 1024:
            return None
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_strict_pairs)
    except Exception:
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _error(exc: Exception) -> tuple[str, int | None, str]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (
        error.get("Code", "") if isinstance(error, Mapping) and type(error.get("Code", "")) is str else "",
        metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int else None,
        error.get("Message", "") if isinstance(error, Mapping) and type(error.get("Message", "")) is str else "",
    )


def _absent(exc: Exception, method: str) -> bool:
    code, status, message = _error(exc)
    if method == "describe_stacks":
        return code == "ValidationError" and status in {400, 404} and message == f"Stack with id {STACK_NAME} does not exist"
    return code in {"NoSuchEntity", "NoSuchEntityException"} and status in {400, 404}


def _tags(value: Any, expected: Mapping[str, str]) -> bool:
    if type(value) is not list or len(value) != len(expected):
        return False
    found: dict[str, str] = {}
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or type(row["Key"]) is not str or type(row["Value"]) is not str or row["Key"] in found:
            return False
        found[row["Key"]] = row["Value"]
    return found == dict(expected)


class RetainedDevProofBootstrapCoordinator:
    STEPS = ("preflight", "create", "readback")

    def __init__(self, clients: Mapping[str, Any], journal: Any, *, bindings: Mapping[str, Any], expected_caller_arn: str, authorized_from_epoch: int, authorized_until_epoch: int, source_sha: str, run_id: str, wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "iam"} or any(clients.get(k) is None for k in clients):
            raise RetainedDevProofBootstrapError("clients_invalid")
        if not all(callable(getattr(journal, key, None)) for key in ("load", "compare_and_set", "locked")):
            raise RetainedDevProofBootstrapError("journal_invalid")
        required = {"account_id", "provider_arn", "owner_id", "repository_id", "observed_dev_subject_sha256", "app_stack_arn", "artifact_stack_arn", "controls_stack_arn", "artifact_bucket_arn", "api_arn", "handler_arn", "cfn_role_arn", "execution_role_arn", "cfn_boundary_arn", "executor_boundary_arn", "shutdown_state_machine_arn", "tripwire_alarm_arn", "tripwire_rule_arn"}
        if not isinstance(bindings, Mapping) or set(bindings) != required:
            raise RetainedDevProofBootstrapError("binding_invalid")
        account = bindings["account_id"]
        if type(account) is not str or _ACCOUNT.fullmatch(account) is None or account == "000000000000":
            raise RetainedDevProofBootstrapError("binding_invalid")
        if type(expected_caller_arn) is not str or re.fullmatch(rf"arn:aws:(?:iam::{account}:(?:user|role)/[^\s:]+|sts::{account}:assumed-role/[^\s:/]+/[^\s:/]+)", expected_caller_arn) is None:
            raise RetainedDevProofBootstrapError("binding_invalid")
        if type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40 or type(run_id) is not str or _UUID.fullmatch(run_id) is None:
            raise RetainedDevProofBootstrapError("binding_invalid")
        if type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool) or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS:
            raise RetainedDevProofBootstrapError("window_invalid")
        try:
            factory = dict(bindings)
            template = build_cd_retained_dev_proof_role(**factory)
        except Exception:
            raise RetainedDevProofBootstrapError("binding_invalid") from None
        resources = template.get("Resources") if isinstance(template, Mapping) else None
        if not isinstance(resources, Mapping) or set(resources) != {"RetainedDevReadOnlyProofBoundary", "RetainedDevReadOnlyProofRole"}:
            raise RetainedDevProofBootstrapError("binding_invalid")
        self.clients, self.journal, self.bindings = dict(clients), journal, dict(bindings)
        self.account, self.template, self.template_bytes = account, template, _canonical(template)
        self.template_sha256 = hashlib.sha256(self.template_bytes).hexdigest()
        self.expected_caller_arn, self.source_sha, self.run_id = expected_caller_arn, source_sha, run_id
        self.start, self.end = authorized_from_epoch, authorized_until_epoch
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started = 0.0; self._last_mono = 0.0; self._last_epoch = 0.0; self._calls = 0
        self.binding_sha256 = hashlib.sha256(_canonical({"account_id": account, "provider_arn": bindings["provider_arn"], "app_stack_arn": bindings["app_stack_arn"], "template_sha256": self.template_sha256, "source_sha": source_sha, "run_id": run_id, "expected_caller_arn": expected_caller_arn, "authorized_from_epoch": authorized_from_epoch, "authorized_until_epoch": authorized_until_epoch})).hexdigest()

    def _guard(self) -> None:
        wall, mono = self.wall_clock(), self.monotonic()
        if type(wall) not in (int, float) or type(mono) not in (int, float) or isinstance(wall, bool) or isinstance(mono, bool) or not math.isfinite(wall) or not math.isfinite(mono) or wall < self._last_epoch or mono < self._last_mono or wall < self.start or wall >= self.end or mono - self._started >= MAX_STEP_SECONDS:
            raise RetainedDevProofBootstrapError("window_expired")
        self._last_epoch, self._last_mono = float(wall), float(mono)

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._guard()
        if self._calls >= MAX_CALLS:
            raise RetainedDevProofBootstrapError("call_budget_exhausted")
        self._calls += 1
        try:
            value = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            raise RetainedDevProofBootstrapError("aws_call_failed") from None
        self._guard()
        if not _ok(value) or any(key in value for key in ("NextToken", "NextMarker", "Marker")):
            raise RetainedDevProofBootstrapError("aws_response_invalid")
        return value

    def _call_absent(self, service: str, method: str, **kwargs: Any) -> None:
        self._guard()
        if self._calls >= MAX_CALLS:
            raise RetainedDevProofBootstrapError("call_budget_exhausted")
        self._calls += 1
        try:
            value = getattr(self.clients[service], method)(**kwargs)
        except Exception as exc:
            self._guard()
            if _absent(exc, method):
                return
            raise RetainedDevProofBootstrapError("absence_check_failed") from None
        self._guard()
        if not _ok(value):
            raise RetainedDevProofBootstrapError("aws_response_invalid")
        raise RetainedDevProofBootstrapError("named_resource_conflict")

    def _state(self) -> dict[str, Any] | None:
        value = self.journal.load()
        if value is None:
            return None
        fields = {"schema", "kind", "revision", "binding_sha256", "source_sha", "run_id", "template_sha256", "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch", "last_observed_epoch", "preflight", "intent", "acknowledged", "acknowledged_stack_id", "readback", "readback_receipt"}
        if not isinstance(value, Mapping) or set(value) != fields or value.get("schema") != 1 or value.get("kind") != "retained-dev-proof-role" or value.get("binding_sha256") != self.binding_sha256 or value.get("source_sha") != self.source_sha or value.get("run_id") != self.run_id or value.get("template_sha256") != self.template_sha256 or value.get("expected_caller_arn") != self.expected_caller_arn or value.get("authorized_from_epoch") != self.start or value.get("authorized_until_epoch") != self.end:
            raise RetainedDevProofBootstrapError("journal_invalid")
        if type(value.get("revision")) is not int or value["revision"] < 1 or any(type(value.get(key)) is not bool for key in ("preflight", "acknowledged", "readback")):
            raise RetainedDevProofBootstrapError("journal_invalid")
        intent = value.get("intent")
        if intent is not None and (not isinstance(intent, Mapping) or set(intent) != {"client_request_token"} or intent.get("client_request_token") != self.run_id):
            raise RetainedDevProofBootstrapError("journal_invalid")
        if type(value.get("last_observed_epoch")) is not int or value["last_observed_epoch"] <= 0 or value["last_observed_epoch"] < self.start or value["last_observed_epoch"] >= self.end:
            raise RetainedDevProofBootstrapError("journal_invalid")
        stack_id = value.get("acknowledged_stack_id")
        if stack_id is not None and (type(stack_id) is not str or _STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != self.account):
            raise RetainedDevProofBootstrapError("journal_invalid")
        receipt = value.get("readback_receipt")
        if receipt is not None and (not isinstance(receipt, Mapping) or set(receipt) != {"stack_id", "template_sha256", "client_request_token", "acknowledged"} or receipt.get("stack_id") != stack_id or receipt.get("template_sha256") != self.template_sha256 or receipt.get("client_request_token") != self.run_id or type(receipt.get("acknowledged")) is not bool):
            raise RetainedDevProofBootstrapError("journal_invalid")
        if value.get("readback") is True and receipt is None:
            raise RetainedDevProofBootstrapError("journal_invalid")
        if (intent is not None and value["preflight"] is not True
                or stack_id is not None and intent is None
                or receipt is not None and (value["readback"] is not True
                                            or receipt["acknowledged"] != value["acknowledged"])
                or value["readback"] and intent is None):
            raise RetainedDevProofBootstrapError("journal_invalid")
        if value.get("acknowledged") is True and (intent is None or stack_id is None):
            raise RetainedDevProofBootstrapError("journal_invalid")
        self._last_epoch = max(self._last_epoch, float(value["last_observed_epoch"]))
        return dict(value)

    def _save(self, state: dict[str, Any], expected: int | None) -> None:
        self._guard()
        candidate = dict(state); candidate["revision"] = 1 if expected is None else expected + 1; candidate["last_observed_epoch"] = int(self._last_epoch)
        try:
            if self.journal.compare_and_set(expected, candidate) is not True:
                raise RetainedDevProofBootstrapError("journal_conflict")
        except RetainedDevProofBootstrapError:
            raise
        except Exception:
            raise RetainedDevProofBootstrapError("journal_failed") from None
        state.clear(); state.update(candidate); self._guard()

    def _base(self) -> dict[str, Any]:
        return {"schema": 1, "kind": "retained-dev-proof-role", "revision": 0, "binding_sha256": self.binding_sha256, "source_sha": self.source_sha, "run_id": self.run_id, "template_sha256": self.template_sha256, "expected_caller_arn": self.expected_caller_arn, "authorized_from_epoch": self.start, "authorized_until_epoch": self.end, "last_observed_epoch": int(self._last_epoch), "preflight": False, "intent": None, "acknowledged": False, "acknowledged_stack_id": None, "readback": False, "readback_receipt": None}

    def _identity(self) -> None:
        value = self._call("sts", "get_caller_identity")
        if value.get("Account") != self.account or value.get("Arn") != self.expected_caller_arn:
            raise RetainedDevProofBootstrapError("caller_mismatch")

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None and (state.get("intent") is not None or state.get("acknowledged")):
            raise RetainedDevProofBootstrapError("preflight_conflict")
        self._call_absent("cloudformation", "describe_stacks", StackName=STACK_NAME)
        self._call_absent("iam", "get_role", RoleName=ROLE_NAME)
        self._call_absent("iam", "get_policy", PolicyArn=f"arn:aws:iam::{self.account}:policy/{BOUNDARY_NAME}")
        provider = self._call("iam", "get_open_id_connect_provider", OpenIDConnectProviderArn=self.bindings["provider_arn"])
        if provider.get("Url") != ISSUER_HOST or provider.get("ClientIDList") != [AUDIENCE]:
            raise RetainedDevProofBootstrapError("provider_mismatch")
        new = self._base(); new["preflight"] = True; self._save(new, None)
        return {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": self._calls}

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise RetainedDevProofBootstrapError("preflight_required")
        if state.get("intent") is not None or state.get("acknowledged"):
            raise RetainedDevProofBootstrapError("create_intent_present")
        intent = dict(state); intent["intent"] = {"client_request_token": self.run_id}; self._save(intent, state["revision"])
        self._guard();
        if self._calls >= MAX_CALLS:
            raise RetainedDevProofBootstrapError("call_budget_exhausted")
        self._calls += 1
        try:
            response = self.clients["cloudformation"].create_stack(StackName=STACK_NAME, TemplateBody=self.template_bytes.decode("ascii"), Tags=[{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "CDReadOnlyProof"}, {"Key": "OperatorRunId", "Value": self.run_id}], ClientRequestToken=self.run_id, Capabilities=["CAPABILITY_NAMED_IAM"], EnableTerminationProtection=True)
        except Exception:
            raise RetainedDevProofBootstrapError("create_outcome_unknown") from None
        self._guard()
        stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        if not _ok(response) or type(stack_id) is not str or _STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != self.account:
            raise RetainedDevProofBootstrapError("create_outcome_unknown")
        acknowledged = dict(intent); acknowledged["acknowledged"] = True; acknowledged["acknowledged_stack_id"] = stack_id; self._save(acknowledged, intent["revision"])
        return {"step": "create", "ok": True, "category": "create_acknowledged", "calls": self._calls}

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None:
            raise RetainedDevProofBootstrapError("preflight_required")
        stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME).get("Stacks")
        if type(stack) is not list or len(stack) != 1 or not isinstance(stack[0], Mapping):
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        row, stack_id = stack[0], stack[0].get("StackId")
        if type(stack_id) is not str or _STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != self.account or row.get("StackName") != STACK_NAME or row.get("StackStatus") == "CREATE_IN_PROGRESS" or row.get("StackStatus") != "CREATE_COMPLETE" or row.get("EnableTerminationProtection") is not True:
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        if state.get("acknowledged_stack_id") not in (None, stack_id):
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME).get("StackEvents")
        if type(events) is not list or not any(isinstance(event, Mapping) and event.get("ClientRequestToken") == self.run_id and event.get("StackId") == stack_id for event in events):
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        expected_stack_tags = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "CDReadOnlyProof", "OperatorRunId": self.run_id}
        if not _tags(row.get("Tags"), expected_stack_tags):
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        template = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
        if _canonical(template.get("TemplateBody")) != self.template_bytes:
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        resources = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME).get("StackResources")
        by = {r.get("LogicalResourceId"): r for r in resources if isinstance(r, Mapping)} if isinstance(resources, list) else {}
        if set(by) != {"RetainedDevReadOnlyProofBoundary", "RetainedDevReadOnlyProofRole"} or len(resources) != 2:
            raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        expected_physical = {"RetainedDevReadOnlyProofBoundary": f"arn:aws:iam::{self.account}:policy/{BOUNDARY_NAME}", "RetainedDevReadOnlyProofRole": ROLE_NAME}
        for logical, resource in by.items():
            if resource.get("PhysicalResourceId") != expected_physical[logical] or resource.get("ResourceStatus") != "CREATE_COMPLETE" or resource.get("StackId") != stack_id or resource.get("StackName") != STACK_NAME:
                raise RetainedDevProofBootstrapError("stack_readback_mismatch")
        self._verify_role(stack_id); self._verify_boundary()
        verified = dict(state); verified["acknowledged"] = bool(state.get("acknowledged")); verified["acknowledged_stack_id"] = stack_id; verified["readback"] = True; verified["readback_receipt"] = {"stack_id": stack_id, "template_sha256": self.template_sha256, "client_request_token": self.run_id, "acknowledged": bool(state.get("acknowledged"))}; self._save(verified, state["revision"])
        return {"step": "readback", "ok": True, "category": "readback_verified", "calls": self._calls}

    def _verify_role(self, stack_id: str) -> None:
        response = self._call("iam", "get_role", RoleName=ROLE_NAME); role = response.get("Role")
        expected = self.template["Resources"]["RetainedDevReadOnlyProofRole"]["Properties"]
        if not isinstance(role, Mapping) or role.get("RoleName") != ROLE_NAME or role.get("Path") != "/" or role.get("Arn") != f"arn:aws:iam::{self.account}:role/{ROLE_NAME}" or role.get("MaxSessionDuration") != 3600 or _document(role.get("AssumeRolePolicyDocument")) != expected["AssumeRolePolicyDocument"] or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") != f"arn:aws:iam::{self.account}:policy/{BOUNDARY_NAME}" or role.get("PermissionsBoundary", {}).get("PermissionsBoundaryType") not in {"Policy", "PermissionsBoundaryPolicy"}:
            raise RetainedDevProofBootstrapError("role_readback_mismatch")
        expected_tags = {item["Key"]: item["Value"] for item in expected["Tags"]} | {"OperatorRunId": self.run_id}
        optional_tags = {"aws:cloudformation:stack-id": stack_id, "aws:cloudformation:stack-name": STACK_NAME, "aws:cloudformation:logical-id": "RetainedDevReadOnlyProofRole"}
        tags = role.get("Tags")
        if type(tags) is not list:
            raise RetainedDevProofBootstrapError("role_readback_mismatch")
        for tag in tags:
            if isinstance(tag, Mapping) and tag.get("Key") in optional_tags:
                expected_tags[tag["Key"]] = optional_tags[tag["Key"]]
        if not _tags(tags, expected_tags):
            raise RetainedDevProofBootstrapError("role_readback_mismatch")
        policy_list = self._call("iam", "list_role_policies", RoleName=ROLE_NAME)
        if policy_list.get("IsTruncated") is not False:
            raise RetainedDevProofBootstrapError("role_readback_mismatch")
        names = policy_list.get("PolicyNames")
        if names != [ROLE_NAME + "-policy"]:
            raise RetainedDevProofBootstrapError("role_readback_mismatch")
        inline = self._call("iam", "get_role_policy", RoleName=ROLE_NAME, PolicyName=names[0])
        if inline.get("RoleName") != ROLE_NAME or inline.get("PolicyName") != names[0] or _document(inline.get("PolicyDocument")) != expected["Policies"][0]["PolicyDocument"]:
            raise RetainedDevProofBootstrapError("role_readback_mismatch")
        attached = self._call("iam", "list_attached_role_policies", RoleName=ROLE_NAME)
        if attached.get("AttachedPolicies") != [] or attached.get("IsTruncated") is not False:
            raise RetainedDevProofBootstrapError("role_readback_mismatch")

    def _verify_boundary(self) -> None:
        arn = f"arn:aws:iam::{self.account}:policy/{BOUNDARY_NAME}"; response = self._call("iam", "get_policy", PolicyArn=arn); policy = response.get("Policy")
        expected = self.template["Resources"]["RetainedDevReadOnlyProofBoundary"]["Properties"]["PolicyDocument"]
        if not isinstance(policy, Mapping) or policy.get("PolicyName") != BOUNDARY_NAME or policy.get("Path") != "/" or policy.get("Arn") != arn or policy.get("IsAttachable") is not True or policy.get("AttachmentCount") != 0 or policy.get("PermissionsBoundaryUsageCount") != 1 or policy.get("DefaultVersionId") != "v1":
            raise RetainedDevProofBootstrapError("boundary_readback_mismatch")
        version = self._call("iam", "get_policy_version", PolicyArn=arn, VersionId="v1").get("PolicyVersion")
        if not isinstance(version, Mapping) or version.get("VersionId") != "v1" or version.get("IsDefaultVersion") is not True or _document(version.get("Document")) != expected:
            raise RetainedDevProofBootstrapError("boundary_readback_mismatch")

    def run_step(self, step: str) -> dict[str, Any]:
        if step not in self.STEPS:
            return {"step": "unknown", "ok": False, "category": "step_invalid", "calls": 0}
        try:
            with self.journal.locked():
                self._started = float(self.monotonic()); self._last_mono = self._started; self._last_epoch = 0.0; self._calls = 0; self._guard(); state = self._state()
                if state is not None:
                    self._last_epoch = max(self._last_epoch, float(state["last_observed_epoch"]))
                    self._guard()
                self._identity()
                result = self._preflight(state) if step == "preflight" else self._create(state) if step == "create" else self._readback(state)
                return result
        except RetainedDevProofBootstrapError as exc:
            return {"step": step, "ok": False, "category": exc.category, "calls": self._calls}
        except Exception:
            return {"step": step, "ok": False, "category": "operator_internal_error", "calls": self._calls}


__all__ = ["RetainedDevProofBootstrapCoordinator", "RetainedDevProofBootstrapError"]
