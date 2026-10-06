"""Offline/injected retained-dev IAM role bootstrap coordinator.

The coordinator deliberately constructs no SDK clients and performs no work at
import time.  A caller supplies the reviewed private bindings, clients and
journal; the only possible write is one CloudFormation CreateStack after all
absence and ownership checks pass.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from urllib.parse import unquote_to_bytes
from typing import Any, Callable

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained-cd-delivery"
EXECUTOR_ROLE_NAME = "honda-mapit-mcp-dev-retained-cd-executor"
CFN_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
EXECUTOR_BOUNDARY_NAME = f"{EXECUTOR_ROLE_NAME}-boundary"
CFN_BOUNDARY_NAME = f"{CFN_ROLE_NAME}-boundary"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 32
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}\Z")
_APP_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/honda-mapit-mcp-dev-retained/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}\Z")
_CATEGORIES = {"clients_invalid", "journal_invalid", "binding_invalid", "window_invalid", "window_expired", "preflight_verified", "preflight_required", "preflight_conflict", "named_resource_conflict", "create_intent_saved", "create_intent_present", "create_outcome_unknown", "create_acknowledged", "stack_in_progress", "stack_not_complete", "stack_readback_mismatch", "readback_verified", "aws_call_failed", "aws_response_invalid", "journal_failed", "operator_internal_error"}
_RESOURCES = {
    "RetainedDevCdExecutorBoundary": "AWS::IAM::ManagedPolicy",
    "RetainedDevCdExecutorRole": "AWS::IAM::Role",
    "RetainedDevCdCloudFormationBoundary": "AWS::IAM::ManagedPolicy",
    "RetainedDevCdCloudFormationRole": "AWS::IAM::Role",
}
_TAGS = [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-cd-roles"}]
MAX_IAM_DOCUMENT_BYTES = 64 * 1024


class RetainedDevRoleBootstrapError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category if category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _status_ok(response: Any) -> bool:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata.get("HTTPStatusCode") == 200


def _aws_error(exc: Exception) -> tuple[str, int | None, str]:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    meta = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (error.get("Code", "") if isinstance(error, Mapping) and type(error.get("Code", "")) is str else "", meta.get("HTTPStatusCode") if isinstance(meta, Mapping) and type(meta.get("HTTPStatusCode")) is int else None, error.get("Message", "") if isinstance(error, Mapping) and type(error.get("Message", "")) is str else "")


def _absence(exc: Exception, method: str) -> bool:
    code, status, message = _aws_error(exc)
    if method == "describe_stacks":
        return code == "ValidationError" and status in {400, 404} and message == f"Stack with id {STACK_NAME} does not exist"
    return code in {"NoSuchEntity", "NoSuchEntityException"} and status in {400, 404}


def _document(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        try:
            if len(_canonical(value)) > MAX_IAM_DOCUMENT_BYTES:
                return None
        except Exception:
            return None
        return value
    if type(value) is str:
        try:
            if len(value) > MAX_IAM_DOCUMENT_BYTES * 3 or re.search(r"%(?![0-9A-Fa-f]{2})", value):
                return None
            raw = unquote_to_bytes(value)
            if len(raw) > MAX_IAM_DOCUMENT_BYTES:
                return None
            decoded = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_strict_pairs)
        except Exception:
            return None
        return decoded if isinstance(decoded, Mapping) else None
    return None


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _token(account: str, source_sha: str, run_id: int) -> str:
    return "retained-dev-roles-" + hashlib.sha256(f"{account}:{source_sha}:{run_id}".encode("ascii")).hexdigest()


class RetainedDevRoleBootstrapCoordinator:
    STEPS = ("preflight", "create", "readback")

    def __init__(self, clients: Mapping[str, Any], journal: Any, *, bindings: Mapping[str, Any], expected_caller_arn: str, authorized_from_epoch: int, authorized_until_epoch: int, source_sha: str, run_id: int, wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(clients, Mapping) or set(clients) != {"sts", "cloudformation", "iam"} or any(clients.get(k) is None for k in clients):
            raise RetainedDevRoleBootstrapError("clients_invalid")
        if not all(callable(getattr(journal, n, None)) for n in ("load", "save", "locked")):
            raise RetainedDevRoleBootstrapError("journal_invalid")
        required = {"account", "provider_arn", "owner_id", "repository_id", "observed_dev_subject_format", "observed_dev_subject_sha256", "stack_arn", "artifact_stack_arn", "handler_arn", "api_arn", "shutdown_state_machine_arn", "artifact_bucket_arn", "execution_role_arn"}
        if not isinstance(bindings, Mapping) or set(bindings) != required:
            raise RetainedDevRoleBootstrapError("binding_invalid")
        self.bindings = dict(bindings)
        account = self.bindings["account"]
        if type(account) is not str or _ACCOUNT.fullmatch(account) is None or account == "000000000000" or type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None or source_sha == "0" * 40 or type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0:
            raise RetainedDevRoleBootstrapError("binding_invalid")
        if type(authorized_from_epoch) is not int or type(authorized_until_epoch) is not int or isinstance(authorized_from_epoch, bool) or isinstance(authorized_until_epoch, bool) or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS:
            raise RetainedDevRoleBootstrapError("window_invalid")
        if type(self.bindings["stack_arn"]) is not str or _APP_STACK.fullmatch(self.bindings["stack_arn"]) is None or self.bindings["stack_arn"].split(":")[4] != account:
            raise RetainedDevRoleBootstrapError("binding_invalid")
        try:
            factory_bindings = dict(self.bindings)
            factory_bindings["account_id"] = factory_bindings.pop("account")
            template = build_cd_retained_dev_roles(**factory_bindings)
        except Exception:
            raise RetainedDevRoleBootstrapError("binding_invalid") from None
        if not isinstance(template, Mapping) or not isinstance(template.get("Resources"), Mapping) or set(template["Resources"]) != set(_RESOURCES) or any(not isinstance(template["Resources"][k], Mapping) or template["Resources"][k].get("Type") != v for k, v in _RESOURCES.items()):
            raise RetainedDevRoleBootstrapError("binding_invalid")
        self.template = dict(template)
        self.template_bytes = _canonical(self.template)
        self.template_sha = hashlib.sha256(self.template_bytes).hexdigest()
        self.clients, self.journal = dict(clients), journal
        self.account, self.source_sha, self.run_id = account, source_sha, run_id
        if type(expected_caller_arn) is not str or not re.fullmatch(rf"arn:aws:(?:iam|sts)::{account}:(?:user|role)/[^\s:/]+|arn:aws:sts::{account}:assumed-role/[^\s:/]+/[^\s:/]+", expected_caller_arn):
            raise RetainedDevRoleBootstrapError("binding_invalid")
        self.expected_caller_arn = expected_caller_arn
        self.start, self.end = authorized_from_epoch, authorized_until_epoch
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started: float | None = None
        self._last_mono, self._last_epoch, self._calls = 0.0, 0, 0

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
            raise RetainedDevRoleBootstrapError("window_invalid")
        epoch = int(value)
        if epoch < self._last_epoch:
            raise RetainedDevRoleBootstrapError("window_invalid")
        self._last_epoch = epoch
        if epoch < self.start or epoch >= self.end:
            raise RetainedDevRoleBootstrapError("window_expired")
        return epoch

    def _budget(self) -> None:
        value = self.monotonic()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value < self._last_mono:
            raise RetainedDevRoleBootstrapError("window_invalid")
        self._last_mono = float(value)
        if self._started is None or self._last_mono - self._started >= MAX_STEP_SECONDS:
            raise RetainedDevRoleBootstrapError("window_expired")
        if self._calls >= MAX_CALLS_PER_STEP:
            raise RetainedDevRoleBootstrapError("aws_call_failed")

    def _call(self, client: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._budget(); self._now(); self._calls += 1
        try:
            response = getattr(self.clients[client], method)(**kwargs)
        except Exception:
            self._now(); raise RetainedDevRoleBootstrapError("aws_call_failed") from None
        if not _status_ok(response) or not isinstance(response, Mapping) or "NextToken" in response or "Marker" in response or response.get("IsTruncated") is True:
            raise RetainedDevRoleBootstrapError("aws_response_invalid")
        self._now(); self._budget(); return response

    def _call_absent(self, client: str, method: str, **kwargs: Any) -> None:
        self._budget(); self._now(); self._calls += 1
        try:
            response = getattr(self.clients[client], method)(**kwargs)
        except Exception as exc:
            if _absence(exc, method):
                self._now(); self._budget(); return
            self._now(); raise RetainedDevRoleBootstrapError("aws_call_failed") from None
        if _status_ok(response):
            self._now(); raise RetainedDevRoleBootstrapError("named_resource_conflict")
        self._now(); raise RetainedDevRoleBootstrapError("aws_response_invalid")

    def _identity(self) -> None:
        result = self._call("sts", "get_caller_identity")
        if result.get("Account") != self.account or result.get("Arn") != self.expected_caller_arn:
            raise RetainedDevRoleBootstrapError("binding_invalid")

    def _load(self) -> dict[str, Any] | None:
        state = self.journal.load()
        if state is None: return None
        if not isinstance(state, Mapping) or set(state) != {"schema", "kind", "account", "source_sha", "run_id", "template_sha256", "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch", "last_observed_epoch", "preflight", "intent", "acknowledged", "acknowledged_stack_id", "readback", "readback_receipt"}:
            raise RetainedDevRoleBootstrapError("journal_invalid")
        if state.get("schema") != 1 or state.get("kind") != "retained-dev-roles" or state.get("account") != self.account or state.get("source_sha") != self.source_sha or state.get("run_id") != self.run_id or state.get("template_sha256") != self.template_sha or state.get("expected_caller_arn") != self.expected_caller_arn or state.get("authorized_from_epoch") != self.start or state.get("authorized_until_epoch") != self.end:
            raise RetainedDevRoleBootstrapError("journal_invalid")
        if not all(type(state.get(key)) is bool for key in ("preflight", "acknowledged", "readback")) or type(state.get("last_observed_epoch")) is not int or state["last_observed_epoch"] <= 0:
            raise RetainedDevRoleBootstrapError("journal_invalid")
        if (not state["preflight"]) or (state["acknowledged"] and state["intent"] is None) or (state["readback"] and state["intent"] is None):
            raise RetainedDevRoleBootstrapError("journal_invalid")
        intent = state.get("intent")
        if intent is not None and (not isinstance(intent, Mapping) or set(intent) != {"token", "stack_name"} or intent.get("token") != _token(self.account, self.source_sha, self.run_id) or intent.get("stack_name") != STACK_NAME):
            raise RetainedDevRoleBootstrapError("journal_invalid")
        ack_id = state.get("acknowledged_stack_id")
        if (not state.get("acknowledged") and ack_id is not None) or (state.get("acknowledged") and (type(ack_id) is not str or _STACK.fullmatch(ack_id) is None or ack_id.split(":")[4] != self.account)):
            raise RetainedDevRoleBootstrapError("journal_invalid")
        receipt = state.get("readback_receipt")
        if (not state.get("readback") and receipt is not None) or (state.get("readback") and (not isinstance(receipt, Mapping) or set(receipt) != {"stack_id", "template_sha256"} or receipt.get("template_sha256") != self.template_sha or type(receipt.get("stack_id")) is not str or _STACK.fullmatch(receipt["stack_id"]) is None or receipt["stack_id"].split(":")[4] != self.account or (ack_id is not None and receipt["stack_id"] != ack_id))):
            raise RetainedDevRoleBootstrapError("journal_invalid")
        return dict(state)

    def _save(self, *, preflight: bool, intent: Mapping[str, Any] | None, acknowledged: bool, acknowledged_stack_id: str | None, readback: bool, readback_receipt: Mapping[str, Any] | None = None) -> None:
        self._budget(); self._now()
        try:
            self.journal.save({"schema": 1, "kind": "retained-dev-roles", "account": self.account, "source_sha": self.source_sha, "run_id": self.run_id, "template_sha256": self.template_sha, "expected_caller_arn": self.expected_caller_arn, "authorized_from_epoch": self.start, "authorized_until_epoch": self.end, "last_observed_epoch": self._last_epoch, "preflight": preflight, "intent": dict(intent) if intent else None, "acknowledged": acknowledged, "acknowledged_stack_id": acknowledged_stack_id, "readback": readback, "readback_receipt": dict(readback_receipt) if readback_receipt else None})
        except RetainedDevRoleBootstrapError:
            raise
        except Exception:
            raise RetainedDevRoleBootstrapError("journal_failed") from None
        self._now(); self._budget()

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": self._calls}

    def run_step(self, step: str) -> dict[str, Any]:
        if step not in self.STEPS: return self._safe("unknown", False, "operator_internal_error")
        try:
            with self.journal.locked():
                initial = self.monotonic()
                if type(initial) not in (int, float) or isinstance(initial, bool) or not math.isfinite(initial) or initial < 0: raise RetainedDevRoleBootstrapError("window_invalid")
                self._started, self._last_mono, self._calls = float(initial), float(initial), 0
                state = self._load(); self._last_epoch = state.get("last_observed_epoch", 0) if state else 0
                self._now(); self._identity()
                return self._preflight(state) if step == "preflight" else self._create(state) if step == "create" else self._readback(state)
        except RetainedDevRoleBootstrapError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "operator_internal_error")

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state and (state.get("intent") is not None or state.get("acknowledged")): raise RetainedDevRoleBootstrapError("preflight_conflict")
        self._call_absent("cloudformation", "describe_stacks", StackName=STACK_NAME)
        for name in (EXECUTOR_ROLE_NAME, CFN_ROLE_NAME): self._call_absent("iam", "get_role", RoleName=name)
        for name in (EXECUTOR_BOUNDARY_NAME, CFN_BOUNDARY_NAME): self._call_absent("iam", "get_policy", PolicyArn=f"arn:aws:iam::{self.account}:policy/{name}")
        provider = self._call("iam", "get_open_id_connect_provider", OpenIDConnectProviderArn=self.bindings["provider_arn"])
        if provider.get("Url") != "token.actions.githubusercontent.com" or provider.get("ClientIDList") != ["sts.amazonaws.com"]: raise RetainedDevRoleBootstrapError("binding_invalid")
        self._save(preflight=True, intent=None, acknowledged=False, acknowledged_stack_id=None, readback=False)
        return self._safe("preflight", True, "preflight_verified")

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True: raise RetainedDevRoleBootstrapError("preflight_required")
        if state.get("intent") is not None or state.get("acknowledged"): raise RetainedDevRoleBootstrapError("create_intent_present")
        token = _token(self.account, self.source_sha, self.run_id); intent = {"token": token, "stack_name": STACK_NAME}
        self._save(preflight=True, intent=intent, acknowledged=False, acknowledged_stack_id=None, readback=False)
        self._budget(); self._now(); self._calls += 1
        try: response = self.clients["cloudformation"].create_stack(StackName=STACK_NAME, TemplateBody=self.template_bytes.decode("ascii"), Tags=[*_TAGS, {"Key": "OperatorRunId", "Value": str(self.run_id)}], ClientRequestToken=token, Capabilities=["CAPABILITY_NAMED_IAM"], EnableTerminationProtection=True)
        except Exception:
            self._now(); raise RetainedDevRoleBootstrapError("create_outcome_unknown") from None
        sid = response.get("StackId") if isinstance(response, Mapping) else None
        if not _status_ok(response) or type(sid) is not str or _STACK.fullmatch(sid) is None or sid.split(":")[4] != self.account:
            self._now(); raise RetainedDevRoleBootstrapError("create_outcome_unknown")
        self._now(); self._save(preflight=True, intent=intent, acknowledged=True, acknowledged_stack_id=sid, readback=False)
        return self._safe("create", True, "create_acknowledged")

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None: raise RetainedDevRoleBootstrapError("preflight_required")
        stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME); rows = stack.get("Stacks")
        if type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping): raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        row = rows[0]; sid = row.get("StackId")
        if type(sid) is not str or _STACK.fullmatch(sid) is None or sid.split(":")[4] != self.account or row.get("StackName") != STACK_NAME: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        if state.get("acknowledged") and state.get("acknowledged_stack_id") != sid: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME).get("StackEvents")
        token = state["intent"]["token"]
        if type(events) is not list or not any(isinstance(event, Mapping) and event.get("ClientRequestToken") == token and event.get("StackId") == sid for event in events): raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        if row.get("StackStatus") == "CREATE_IN_PROGRESS": raise RetainedDevRoleBootstrapError("stack_in_progress")
        if row.get("StackStatus") != "CREATE_COMPLETE" or row.get("EnableTerminationProtection") is not True: raise RetainedDevRoleBootstrapError("stack_not_complete")
        stack_tags = row.get("Tags")
        expected_stack_tags = {item["Key"]: item["Value"] for item in [*_TAGS, {"Key": "OperatorRunId", "Value": str(self.run_id)}]}
        if type(stack_tags) is not list or len(stack_tags) != len(expected_stack_tags) or {item.get("Key"): item.get("Value") for item in stack_tags if isinstance(item, Mapping)} != expected_stack_tags:
            raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        template = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
        if _canonical(template.get("TemplateBody")) != self.template_bytes: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        resources = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME).get("StackResources")
        if type(resources) is not list or len(resources) != 4: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        by = {r.get("LogicalResourceId"): r for r in resources if isinstance(r, Mapping)}
        expected_physical = {"RetainedDevCdExecutorRole": EXECUTOR_ROLE_NAME, "RetainedDevCdCloudFormationRole": CFN_ROLE_NAME, "RetainedDevCdExecutorBoundary": f"arn:aws:iam::{self.account}:policy/{EXECUTOR_BOUNDARY_NAME}", "RetainedDevCdCloudFormationBoundary": f"arn:aws:iam::{self.account}:policy/{CFN_BOUNDARY_NAME}"}
        if set(by) != set(_RESOURCES) or any(by[k].get("ResourceType") != typ or by[k].get("ResourceStatus") != "CREATE_COMPLETE" or by[k].get("StackId") != sid or by[k].get("StackName") != STACK_NAME or by[k].get("PhysicalResourceId") != expected_physical[k] for k, typ in _RESOURCES.items()): raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        for logical in ("RetainedDevCdExecutorRole", "RetainedDevCdCloudFormationRole"): self._verify_role(by[logical].get("PhysicalResourceId"), logical, sid)
        for logical in ("RetainedDevCdExecutorBoundary", "RetainedDevCdCloudFormationBoundary"): self._verify_boundary(by[logical].get("PhysicalResourceId"), logical)
        self._save(preflight=True, intent=state["intent"], acknowledged=bool(state.get("acknowledged")), acknowledged_stack_id=state.get("acknowledged_stack_id"), readback=True, readback_receipt={"stack_id": sid, "template_sha256": self.template_sha})
        return self._safe("readback", True, "readback_verified")

    def _verify_role(self, physical: Any, logical: str, stack_id: str | None = None) -> None:
        expected = EXECUTOR_ROLE_NAME if logical.endswith("ExecutorRole") else CFN_ROLE_NAME
        if physical != expected: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        response = self._call("iam", "get_role", RoleName=expected); role = response.get("Role")
        expected_props = self.template["Resources"][logical]["Properties"]
        permissions = role.get("PermissionsBoundary") if isinstance(role, Mapping) else None
        expected_boundary = f"arn:aws:iam::{self.account}:policy/" + (EXECUTOR_BOUNDARY_NAME if logical.endswith("ExecutorRole") else CFN_BOUNDARY_NAME)
        expected_tags = expected_props.get("Tags", [])
        role_tags = role.get("Tags") if isinstance(role, Mapping) else None
        if not isinstance(role_tags, list) or any(not isinstance(item, Mapping) or set(item) != {"Key", "Value"} or type(item.get("Key")) is not str or type(item.get("Value")) is not str for item in role_tags): raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        tag_map = {item["Key"]: item["Value"] for item in role_tags}
        required_tags = {item["Key"]: item["Value"] for item in expected_tags}
        optional_tags = {"OperatorRunId": str(self.run_id)}
        if stack_id is not None:
            optional_tags.update({"aws:cloudformation:stack-id": stack_id, "aws:cloudformation:stack-name": STACK_NAME, "aws:cloudformation:logical-id": logical})
        if len(tag_map) != len(role_tags) or set(tag_map) - (set(required_tags) | set(optional_tags)) or any(tag_map.get(key) != value for key, value in required_tags.items()) or any(key in tag_map and tag_map[key] != value for key, value in optional_tags.items()): raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        if not isinstance(role, Mapping) or role.get("RoleName") != expected or role.get("Path") != "/" or role.get("Arn") != f"arn:aws:iam::{self.account}:role/{expected}" or role.get("MaxSessionDuration") != 3600 or _document(role.get("AssumeRolePolicyDocument")) != expected_props.get("AssumeRolePolicyDocument") or not isinstance(permissions, Mapping) or permissions.get("PermissionsBoundaryArn") != expected_boundary or permissions.get("PermissionsBoundaryType") not in {"Policy", "PermissionsBoundaryPolicy"}: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        policies = self._call("iam", "list_role_policies", RoleName=expected).get("PolicyNames")
        if type(policies) is not list or policies != [f"{expected}-policy"]: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        inline = self._call("iam", "get_role_policy", RoleName=expected, PolicyName=policies[0])
        inline_doc = _document(inline.get("PolicyDocument"))
        expected_doc = expected_props.get("Policies", [{}])[0].get("PolicyDocument")
        if inline.get("RoleName") != expected or inline.get("PolicyName") != policies[0] or inline_doc != expected_doc: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        attached = self._call("iam", "list_attached_role_policies", RoleName=expected)
        if attached.get("AttachedPolicies") != [] or attached.get("IsTruncated") is not False: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")

    def _verify_boundary(self, physical: Any, logical: str) -> None:
        expected = EXECUTOR_BOUNDARY_NAME if logical.endswith("ExecutorBoundary") else CFN_BOUNDARY_NAME
        if physical != f"arn:aws:iam::{self.account}:policy/{expected}": raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        policy_response = self._call("iam", "get_policy", PolicyArn=physical); policy = policy_response.get("Policy")
        expected_doc = self.template["Resources"][logical]["Properties"].get("PolicyDocument")
        if not isinstance(policy, Mapping) or policy.get("PolicyName") != expected or policy.get("Path") != "/" or policy.get("Arn") != physical or policy.get("IsAttachable") is not True or type(policy.get("AttachmentCount")) is not int or isinstance(policy.get("AttachmentCount"), bool) or policy.get("AttachmentCount") != 0 or type(policy.get("PermissionsBoundaryUsageCount")) is not int or isinstance(policy.get("PermissionsBoundaryUsageCount"), bool) or policy.get("PermissionsBoundaryUsageCount") != 1 or policy.get("DefaultVersionId") != "v1": raise RetainedDevRoleBootstrapError("stack_readback_mismatch")
        version = self._call("iam", "get_policy_version", PolicyArn=physical, VersionId="v1")
        version_row = version.get("PolicyVersion")
        if not isinstance(version_row, Mapping) or version_row.get("IsDefaultVersion") is not True or _document(version_row.get("Document")) != expected_doc: raise RetainedDevRoleBootstrapError("stack_readback_mismatch")


__all__ = ["RetainedDevRoleBootstrapCoordinator", "RetainedDevRoleBootstrapError"]
