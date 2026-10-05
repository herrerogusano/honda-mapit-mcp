"""Injected, single-step coordinator for the closed CD identity bootstrap.

No AWS SDK clients, credentials, networking, or deployment are constructed
here. Callers supply a private journal and single-attempt clients. The sole
write is a fresh CloudFormation CreateStack after a complete read-only
preflight; ambiguous writes are never replayed.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import hmac
import json
import math
import re
import time
import uuid
from typing import Any, Callable

from scripts.build_cd_identity_bootstrap import build_cd_identity_bootstrap


REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-cd-identity"
RUN_TAG = "UniqueCdIdentityRunId"
PROJECT_TAG = "Project"
_MAX_WINDOW_SECONDS = 2 * 60 * 60
_MAX_STEP_SECONDS = 30.0
_MAX_CALLS_PER_STEP = 24
_MAX_TEMPLATE_BYTES = 50 * 1024
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_STACK_ARN_RE = re.compile(
    rf"^arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)
_ROLE_NAMES = {"dev": "honda-mapit-mcp-dev-cd", "prod": "honda-mapit-mcp-prod-cd"}
_BOUNDARY_NAMES = {
    "dev": "honda-mapit-mcp-dev-cd-boundary",
    "prod": "honda-mapit-mcp-prod-cd-boundary",
}
_RESOURCE_TYPES = {
    "DevCdPermissionsBoundary": "AWS::IAM::ManagedPolicy",
    "DevCdIdentityRole": "AWS::IAM::Role",
    "ProdCdPermissionsBoundary": "AWS::IAM::ManagedPolicy",
    "ProdCdIdentityRole": "AWS::IAM::Role",
}


class CdIdentityBootstrapError(ValueError):
    """Fixed-category failure; no input or AWS response is interpolated."""

    def __init__(self, category: str) -> None:
        if category not in {
            "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid",
            "step_invalid", "preflight_required", "preflight_conflict", "identity_unverified",
            "provider_unverified", "stack_absence_unverified", "iam_name_conflict",
            "window_expired", "step_budget_exhausted", "aws_call_failed", "aws_response_invalid",
            "create_intent_conflict", "create_outcome_unknown", "stack_not_complete",
            "stack_readback_mismatch", "identity_readback_mismatch", "journal_failed",
            "coordinator_internal_error",
        }:
            category = "coordinator_internal_error"
        self.category = category
        super().__init__(category)


class _AwsCallFailure(Exception):
    def __init__(self, code: str, *, missing_stack: bool = False):
        self.code = code
        self.missing_stack = missing_stack
        super().__init__(code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _strict_json_mapping(value: Any, *, max_bytes: int = 64 * 1024) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value.encode("utf-8", "ignore")) > max_bytes:
        return None
    try:
        parsed = json.loads(value, object_pairs_hook=_reject_duplicates)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _aws_error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, Mapping):
        error = response.get("Error")
        if isinstance(error, Mapping) and type(error.get("Code")) is str:
            return error["Code"]
    return ""


class CdIdentityBootstrapCoordinator:
    """Bounded preflight/create/readback coordinator with injected clients."""

    STEPS = ("preflight", "create", "check-create", "final-readback")

    def __init__(
        self,
        clients: Mapping[str, Any],
        journal: Any,
        *,
        account_id: str,
        provider_arn: str,
        owner_id: str,
        repository_id: str,
        observed_subjects: Mapping[str, Mapping[str, str]],
        source_sha: str,
        authorized_from_epoch: int,
        authorized_until_epoch: int,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(clients, Mapping) or not {"sts", "iam", "cloudformation"} <= clients.keys():
            raise CdIdentityBootstrapError("clients_invalid")
        if any(not callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            raise CdIdentityBootstrapError("journal_invalid")
        if type(account_id) is not str or _ACCOUNT_RE.fullmatch(account_id) is None:
            raise CdIdentityBootstrapError("binding_invalid")
        if type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
            raise CdIdentityBootstrapError("binding_invalid")
        try:
            template = build_cd_identity_bootstrap(
                account_id=account_id,
                provider_arn=provider_arn,
                owner_id=owner_id,
                repository_id=repository_id,
                observed_subjects=observed_subjects,
            )
        except Exception:
            raise CdIdentityBootstrapError("binding_invalid") from None
        if (
            type(authorized_from_epoch) is not int
            or authorized_from_epoch <= 0
            or type(authorized_until_epoch) is not int
            or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > _MAX_WINDOW_SECONDS
        ):
            raise CdIdentityBootstrapError("window_invalid")
        self.clients = clients
        self.journal = journal
        self.account_id = account_id
        self.provider_arn = provider_arn
        self.owner_id = owner_id
        self.repository_id = repository_id
        self.observed_subjects = json.loads(_canonical(observed_subjects))
        self.source_sha = source_sha
        self.window_start = authorized_from_epoch
        self.window_end = authorized_until_epoch
        self.wall_clock = wall_clock
        self.monotonic = monotonic
        self.template = template
        self.template_bytes = _canonical(template)
        if len(self.template_bytes) > _MAX_TEMPLATE_BYTES:
            raise CdIdentityBootstrapError("binding_invalid")
        self.template_sha256 = hashlib.sha256(self.template_bytes).hexdigest()
        self._input_fingerprint = self._fingerprint_inputs()
        self._step_started = 0.0
        self._last_monotonic = 0.0
        self._calls = 0
        self._run_id = str(uuid.uuid4())

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid", 0)
        try:
            with self.journal.locked():
                self._assert_input_binding()
                self._step_started = self._monotonic()
                self._last_monotonic = self._step_started
                self._calls = 0
                method = getattr(self, f"_step_{step.replace('-', '_')}")
                return method()
        except CdIdentityBootstrapError as exc:
            return self._safe(step, False, exc.category, self._calls)
        except Exception:
            return self._safe(step, False, "coordinator_internal_error", self._calls)

    @staticmethod
    def _safe(step: str, ok: bool, category: str, calls: int, **facts: Any) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category, "calls": calls, **facts}

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise CdIdentityBootstrapError("window_invalid")
        try:
            return int(value)
        except (OverflowError, ValueError):
            raise CdIdentityBootstrapError("window_invalid") from None

    def _check_window(self) -> None:
        now = self._now()
        if now < self.window_start or now >= self.window_end:
            raise CdIdentityBootstrapError("window_expired")

    def _monotonic(self) -> float:
        value = self.monotonic()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
            raise CdIdentityBootstrapError("step_budget_exhausted")
        return float(value)

    def _elapsed(self) -> float:
        now = self._monotonic()
        if now < self._last_monotonic:
            raise CdIdentityBootstrapError("step_budget_exhausted")
        self._last_monotonic = now
        return now - self._step_started

    def _call(self, service: str, operation: str, **kwargs: Any) -> Mapping[str, Any]:
        if self._calls >= _MAX_CALLS_PER_STEP or self._elapsed() >= _MAX_STEP_SECONDS:
            raise CdIdentityBootstrapError("step_budget_exhausted")
        self._check_window()
        self._calls += 1
        try:
            result = getattr(self.clients[service], operation)(**kwargs)
        except Exception as exc:
            code = _aws_error_code(exc)
            error_response = getattr(exc, "response", None)
            error_data = error_response.get("Error") if isinstance(error_response, Mapping) else None
            message = error_data.get("Message") if isinstance(error_data, Mapping) else None
            missing_stack = (
                service == "cloudformation"
                and operation == "describe_stacks"
                and kwargs.get("StackName") == STACK_NAME
                and code == "ValidationError"
                and type(message) is str
                and message == f"Stack with id {STACK_NAME} does not exist"
            )
            raise _AwsCallFailure(code, missing_stack=missing_stack) from None
        if self._elapsed() >= _MAX_STEP_SECONDS:
            raise CdIdentityBootstrapError("step_budget_exhausted")
        if not isinstance(result, Mapping):
            raise CdIdentityBootstrapError("aws_response_invalid")
        metadata = result.get("ResponseMetadata")
        if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int or metadata["HTTPStatusCode"] != 200:
            raise CdIdentityBootstrapError("aws_response_invalid")
        return result

    def _save(self, state: dict[str, Any]) -> None:
        try:
            self.journal.save(state)
        except Exception:
            raise CdIdentityBootstrapError("journal_failed") from None

    def _load(self) -> dict[str, Any] | None:
        try:
            value = self.journal.load()
        except Exception:
            raise CdIdentityBootstrapError("journal_failed") from None
        if value is not None and not isinstance(value, dict):
            raise CdIdentityBootstrapError("journal_failed")
        return value

    def _subject_binding(self) -> dict[str, dict[str, str]]:
        return json.loads(_canonical(self.observed_subjects))

    def _fingerprint_inputs(self) -> str:
        inputs = {
            "account_id": self.account_id,
            "provider_arn": self.provider_arn,
            "owner_id": self.owner_id,
            "repository_id": self.repository_id,
            "observed_subjects": self._subject_binding(),
            "source_sha": self.source_sha,
            "authorized_from_epoch": self.window_start,
            "authorized_until_epoch": self.window_end,
            "template_sha256": self.template_sha256,
        }
        return hashlib.sha256(_canonical(inputs)).hexdigest()

    def _assert_input_binding(self) -> None:
        try:
            rebuilt = build_cd_identity_bootstrap(
                account_id=self.account_id,
                provider_arn=self.provider_arn,
                owner_id=self.owner_id,
                repository_id=self.repository_id,
                observed_subjects=self._subject_binding(),
            )
            rebuilt_bytes = _canonical(rebuilt)
        except Exception:
            raise CdIdentityBootstrapError("binding_invalid") from None
        if (
            rebuilt_bytes != self.template_bytes
            or _canonical(self.template) != self.template_bytes
            or hashlib.sha256(rebuilt_bytes).hexdigest() != self.template_sha256
            or not hmac.compare_digest(self._fingerprint_inputs(), self._input_fingerprint)
        ):
            raise CdIdentityBootstrapError("binding_invalid")

    def _new_state(self) -> dict[str, Any]:
        return {
            "schema": 1,
            "region": REGION,
            "phase": "preflight_verified",
            "account_id": self.account_id,
            "provider_arn": self.provider_arn,
            "owner_id": self.owner_id,
            "repository_id": self.repository_id,
            "observed_subjects": self._subject_binding(),
            "source_sha": self.source_sha,
            "template_sha256": self.template_sha256,
            "run_id": self._run_id,
            "client_request_token": self._run_id,
            "authorized_from_epoch": self.window_start,
            "authorized_until_epoch": self.window_end,
        }

    def _state(self, *, required: bool = True) -> dict[str, Any] | None:
        state = self._load()
        if state is None:
            if required:
                raise CdIdentityBootstrapError("preflight_required")
            return None
        if (
            state.get("schema") != 1
            or type(state.get("schema")) is not int
            or state.get("region") != REGION
            or state.get("account_id") != self.account_id
            or state.get("provider_arn") != self.provider_arn
            or state.get("owner_id") != self.owner_id
            or state.get("repository_id") != self.repository_id
            or state.get("observed_subjects") != self._subject_binding()
            or state.get("source_sha") != self.source_sha
            or state.get("template_sha256") != self.template_sha256
            or state.get("authorized_from_epoch") != self.window_start
            or state.get("authorized_until_epoch") != self.window_end
            or not self._valid_uuid(state.get("run_id"))
            or state.get("client_request_token") != state.get("run_id")
        ):
            raise CdIdentityBootstrapError("binding_invalid")
        if "create_intent" in state and state["create_intent"] != {
            "stack_name": STACK_NAME,
            "client_request_token": state["client_request_token"],
            "template_sha256": self.template_sha256,
            "run_id": state["run_id"],
        }:
            raise CdIdentityBootstrapError("create_intent_conflict")
        stack_arn = state.get("stack_arn")
        if stack_arn is not None and not self._stack_arn(stack_arn):
            raise CdIdentityBootstrapError("binding_invalid")
        return state

    @staticmethod
    def _valid_uuid(value: Any) -> bool:
        if type(value) is not str:
            return False
        try:
            parsed = uuid.UUID(value)
        except (ValueError, AttributeError):
            return False
        return str(parsed) == value and parsed.int != 0

    def _stack_arn(self, value: Any) -> bool:
        if type(value) is not str:
            return False
        match = _STACK_ARN_RE.fullmatch(value)
        return bool(match and match.group(1) == self.account_id)

    @staticmethod
    def _response_code(result: Mapping[str, Any]) -> int:
        metadata = result.get("ResponseMetadata")
        if isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int:
            return metadata["HTTPStatusCode"]
        return 0

    def _step_preflight(self) -> dict[str, Any]:
        if self._load() is not None:
            raise CdIdentityBootstrapError("preflight_conflict")
        self._check_window()
        try:
            identity = self._call("sts", "get_caller_identity")
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("identity_unverified") from None
        if (
            identity.get("Account") != self.account_id
            or type(identity.get("Arn")) is not str
            or identity["Arn"].endswith(":root")
            or not re.fullmatch(
                rf"arn:aws:(?:iam|sts)::{self.account_id}:(?:user|assumed-role)/[^\s]+",
                identity["Arn"],
            )
        ):
            raise CdIdentityBootstrapError("identity_unverified")
        try:
            provider = self._call(
                "iam", "get_open_id_connect_provider", OpenIDConnectProviderArn=self.provider_arn
            )
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("provider_unverified") from None
        audiences = provider.get("ClientIDList")
        if (
            provider.get("Url") != "token.actions.githubusercontent.com"
            or type(audiences) is not list
            or not audiences
            or any(type(value) is not str for value in audiences)
            or "sts.amazonaws.com" not in audiences
        ):
            raise CdIdentityBootstrapError("provider_unverified")
        try:
            stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        except _AwsCallFailure as exc:
            if not exc.missing_stack:
                raise CdIdentityBootstrapError("stack_absence_unverified") from None
            # AWS CloudFormation reports an exact missing stack with a
            # ValidationError; because the request name is fixed, no message
            # parsing or user-controlled text is required.
            stack = None
        if stack is not None:
            stacks = stack.get("Stacks")
            if type(stacks) is not list or stacks:
                raise CdIdentityBootstrapError("preflight_conflict")
        for name in (*_ROLE_NAMES.values(), *_BOUNDARY_NAMES.values()):
            operation = "get_role" if name in _ROLE_NAMES.values() else "get_policy"
            kwargs = {"RoleName": name} if operation == "get_role" else {"PolicyArn": f"arn:aws:iam::{self.account_id}:policy/{name}"}
            try:
                result = self._call("iam", operation, **kwargs)
            except _AwsCallFailure as exc:
                if exc.code == "NoSuchEntity":
                    continue
                raise CdIdentityBootstrapError("aws_call_failed") from None
            if isinstance(result, Mapping):
                raise CdIdentityBootstrapError("iam_name_conflict")
            raise CdIdentityBootstrapError("aws_response_invalid")
        self._check_window()
        state = self._new_state()
        self._save(state)
        return self._safe("preflight", True, "preflight_verified", self._calls)

    def _step_create(self) -> dict[str, Any]:
        state = self._state()
        assert state is not None
        if state.get("phase") != "preflight_verified" or "create_intent" in state:
            raise CdIdentityBootstrapError("create_intent_conflict")
        self._check_window()
        state["create_intent"] = {
            "stack_name": STACK_NAME,
            "client_request_token": state["client_request_token"],
            "template_sha256": self.template_sha256,
            "run_id": state["run_id"],
        }
        state["phase"] = "create_intent_saved"
        self._save(state)
        self._check_window()
        try:
            response = self._call(
                "cloudformation",
                "create_stack",
                StackName=STACK_NAME,
                TemplateBody=self.template_bytes.decode("ascii"),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                EnableTerminationProtection=True,
                Tags=[
                    {"Key": PROJECT_TAG, "Value": "honda-mapit-mcp"},
                    {"Key": RUN_TAG, "Value": state["run_id"]},
                ],
                ClientRequestToken=state["client_request_token"],
            )
            self._check_window()
        except Exception:
            state["phase"] = "create_outcome_unknown"
            self._save(state)
            raise CdIdentityBootstrapError("create_outcome_unknown") from None
        stack_arn = response.get("StackId")
        if not self._stack_arn(stack_arn):
            state["phase"] = "create_outcome_unknown"
            self._save(state)
            raise CdIdentityBootstrapError("create_outcome_unknown")
        state["stack_arn"] = stack_arn
        state["phase"] = "create_acknowledged"
        self._save(state)
        return self._safe("create", True, "create_acknowledged", self._calls)

    def _parse_template_body(self, value: Any) -> Mapping[str, Any] | None:
        if isinstance(value, Mapping):
            return value
        if type(value) is not str or len(value.encode("utf-8", "ignore")) > _MAX_TEMPLATE_BYTES:
            return None
        try:
            parsed = json.loads(value, object_pairs_hook=_reject_duplicates)
        except (ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, Mapping) else None

    def _verify_stack_and_iam(self, state: Mapping[str, Any]) -> None:
        stack_arn = state.get("stack_arn")
        if not self._stack_arn(stack_arn):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        try:
            stack_reply = self._call("cloudformation", "describe_stacks", StackName=stack_arn)
            template_reply = self._call("cloudformation", "get_template", StackName=stack_arn, TemplateStage="Original")
            resources_reply = self._call("cloudformation", "describe_stack_resources", StackName=stack_arn)
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("aws_call_failed") from None
        rows = stack_reply.get("Stacks")
        if type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        stack = rows[0]
        if (
            stack.get("StackId") != stack_arn
            or stack.get("StackName") != STACK_NAME
            or stack.get("StackStatus") != "CREATE_COMPLETE"
            or type(stack.get("StackStatus")) is not str
            or stack.get("EnableTerminationProtection") is not True
        ):
            raise CdIdentityBootstrapError("stack_not_complete")
        tags = stack.get("Tags")
        if type(tags) is not list:
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        tagmap = {row.get("Key"): row.get("Value") for row in tags if isinstance(row, Mapping)}
        if tagmap.get(PROJECT_TAG) != "honda-mapit-mcp" or tagmap.get(RUN_TAG) != state.get("run_id"):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        actual_template = self._parse_template_body(template_reply.get("TemplateBody"))
        if actual_template is None or _canonical(actual_template) != self.template_bytes:
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        resources = resources_reply.get("StackResources")
        expected = self.template["Resources"]
        if type(resources) is not list or len(resources) != 4:
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        resource_map: dict[str, Mapping[str, Any]] = {}
        for row in resources:
            if not isinstance(row, Mapping):
                raise CdIdentityBootstrapError("stack_readback_mismatch")
            logical = row.get("LogicalResourceId")
            if type(logical) is not str or logical not in expected or logical in resource_map:
                raise CdIdentityBootstrapError("stack_readback_mismatch")
            if row.get("ResourceType") != _RESOURCE_TYPES[logical] or row.get("ResourceStatus") != "CREATE_COMPLETE":
                raise CdIdentityBootstrapError("stack_not_complete")
            if type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]:
                raise CdIdentityBootstrapError("stack_readback_mismatch")
            resource_map[logical] = row
        if set(resource_map) != set(expected):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        boundary_arns: dict[str, str] = {}
        for target in ("dev", "prod"):
            prefix = target.title()
            role_logical = f"{prefix}CdIdentityRole"
            boundary_logical = f"{prefix}CdPermissionsBoundary"
            role_name = _ROLE_NAMES[target]
            boundary_name = _BOUNDARY_NAMES[target]
            role_arn = f"arn:aws:iam::{self.account_id}:role/{role_name}"
            boundary_arn = resource_map[boundary_logical]["PhysicalResourceId"]
            if resource_map[role_logical]["PhysicalResourceId"] != role_name:
                raise CdIdentityBootstrapError("identity_readback_mismatch")
            if boundary_arn != f"arn:aws:iam::{self.account_id}:policy/{boundary_name}":
                raise CdIdentityBootstrapError("identity_readback_mismatch")
            boundary_arns[target] = boundary_arn
            self._verify_role(target, role_name, role_arn, boundary_arn, str(state["run_id"]))
            self._verify_boundary(target, boundary_name, boundary_arn)
        self._verify_provider()

    def _verify_provider(self) -> None:
        try:
            provider = self._call(
                "iam", "get_open_id_connect_provider", OpenIDConnectProviderArn=self.provider_arn
            )
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("provider_unverified") from None
        audiences = provider.get("ClientIDList")
        if (
            provider.get("Url") != "token.actions.githubusercontent.com"
            or type(audiences) is not list
            or not audiences
            or any(type(value) is not str for value in audiences)
            or "sts.amazonaws.com" not in audiences
        ):
            raise CdIdentityBootstrapError("provider_unverified")

    def _reconcile_stack_after_ambiguous_create(self, state: dict[str, Any]) -> None:
        """Adopt only an exact-name stack tied to both this run tag and token."""
        try:
            reply = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("stack_absence_unverified") from None
        stacks = reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        stack = stacks[0]
        arn = stack.get("StackId")
        if stack.get("StackName") != STACK_NAME or not self._stack_arn(arn):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        tags = stack.get("Tags")
        if type(tags) is not list:
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        tagmap = {row.get("Key"): row.get("Value") for row in tags if isinstance(row, Mapping)}
        if tagmap.get(PROJECT_TAG) != "honda-mapit-mcp" or tagmap.get(RUN_TAG) != state.get("run_id"):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        try:
            event_reply = self._call("cloudformation", "describe_stack_events", StackName=arn)
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("stack_readback_mismatch") from None
        events = event_reply.get("StackEvents")
        if (
            type(events) is not list
            or len(events) > 200
            or event_reply.get("NextToken") not in (None, "")
            or not any(
                isinstance(event, Mapping)
                and event.get("StackId") == arn
                and event.get("ClientRequestToken") == state.get("client_request_token")
                for event in events
            )
        ):
            raise CdIdentityBootstrapError("stack_readback_mismatch")
        state["stack_arn"] = arn
        state["phase"] = "create_reconciled"
        self._save(state)

    def _verify_role(
        self, target: str, role_name: str, role_arn: str, boundary_arn: str, run_id: str
    ) -> None:
        try:
            role_reply = self._call("iam", "get_role", RoleName=role_name)
            attached = self._call("iam", "list_attached_role_policies", RoleName=role_name)
            inline_list = self._call("iam", "list_role_policies", RoleName=role_name)
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("identity_readback_mismatch") from None
        role = role_reply.get("Role")
        if not isinstance(role, Mapping):
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        template_role = self.template["Resources"][f"{target.title()}CdIdentityRole"]["Properties"]
        tag_rows = role.get("Tags")
        expected_tags = {
            row["Key"]: row["Value"] for row in template_role.get("Tags", [])
        }
        tagmap: dict[str, str] = {}
        tags_valid = type(tag_rows) is list
        if tags_valid:
            for row in tag_rows:
                if (
                    not isinstance(row, Mapping)
                    or type(row.get("Key")) is not str
                    or type(row.get("Value")) is not str
                    or row["Key"] in tagmap
                ):
                    tags_valid = False
                    break
                tagmap[row["Key"]] = row["Value"]
        if tags_valid and RUN_TAG in tagmap and tagmap[RUN_TAG] != run_id:
            tags_valid = False
        trust = _strict_json_mapping(role.get("AssumeRolePolicyDocument"))
        if (
            role.get("RoleName") != role_name
            or role.get("Arn") != role_arn
            or role.get("MaxSessionDuration") != 3600
            or type(role.get("MaxSessionDuration")) is not int
            or role.get("Path") != "/"
            or not isinstance(role.get("PermissionsBoundary"), Mapping)
            or role["PermissionsBoundary"].get("PermissionsBoundaryArn") != boundary_arn
            or role["PermissionsBoundary"].get("PermissionsBoundaryType") != "PermissionsBoundaryPolicy"
            or not tags_valid
            or any(tagmap.get(key) != value for key, value in expected_tags.items())
            or trust is None
            or _canonical(trust) != _canonical(template_role["AssumeRolePolicyDocument"])
        ):
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        attached_rows = attached.get("AttachedPolicies")
        if (
            type(attached_rows) is not list
            or attached_rows
            or attached.get("Marker") not in (None, "")
            or type(attached.get("IsTruncated")) is not bool
            or attached["IsTruncated"] is not False
        ):
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        policy_names = inline_list.get("PolicyNames")
        if (
            type(policy_names) is not list
            or policy_names != [f"{role_name}-identity-only"]
            or inline_list.get("Marker") not in (None, "")
            or type(inline_list.get("IsTruncated")) is not bool
            or inline_list["IsTruncated"] is not False
        ):
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        try:
            inline = self._call(
                "iam", "get_role_policy", RoleName=role_name, PolicyName=f"{role_name}-identity-only"
            )
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("identity_readback_mismatch") from None
        if inline.get("RoleName") != role_name or inline.get("PolicyName") != f"{role_name}-identity-only":
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        doc = _strict_json_mapping(inline.get("PolicyDocument"))
        expected_doc = template_role["Policies"][0]["PolicyDocument"]
        if doc is None or _canonical(doc) != _canonical(expected_doc):
            raise CdIdentityBootstrapError("identity_readback_mismatch")

    def _verify_boundary(self, target: str, name: str, arn: str) -> None:
        try:
            policy_reply = self._call("iam", "get_policy", PolicyArn=arn)
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("identity_readback_mismatch") from None
        policy = policy_reply.get("Policy")
        if (
            not isinstance(policy, Mapping)
            or policy.get("Arn") != arn
            or policy.get("PolicyName") != name
            or policy.get("Path") != "/"
        ):
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        version = policy.get("DefaultVersionId")
        if type(version) is not str or re.fullmatch(r"v[1-9][0-9]{0,2}", version) is None:
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        try:
            version_reply = self._call("iam", "get_policy_version", PolicyArn=arn, VersionId=version)
        except _AwsCallFailure:
            raise CdIdentityBootstrapError("identity_readback_mismatch") from None
        version_row = version_reply.get("PolicyVersion")
        if not isinstance(version_row, Mapping) or version_row.get("VersionId") != version or version_row.get("IsDefaultVersion") is not True:
            raise CdIdentityBootstrapError("identity_readback_mismatch")
        doc = _strict_json_mapping(version_row.get("Document"))
        expected = self.template["Resources"][f"{target.title()}CdPermissionsBoundary"]["Properties"]["PolicyDocument"]
        if doc is None or _canonical(doc) != _canonical(expected):
            raise CdIdentityBootstrapError("identity_readback_mismatch")

    def _step_check_create(self) -> dict[str, Any]:
        state = self._state()
        assert state is not None
        if state.get("phase") in {"create_intent_saved", "create_outcome_unknown"}:
            self._check_window()
            self._reconcile_stack_after_ambiguous_create(state)
        elif state.get("phase") not in {"create_acknowledged", "create_reconciled", "create_readback_verified"}:
            raise CdIdentityBootstrapError("create_intent_conflict")
        self._check_window()
        self._verify_stack_and_iam(state)
        self._check_window()
        state["phase"] = "create_readback_verified"
        state["create_readback_verified"] = True
        self._save(state)
        return self._safe("check-create", True, "stack_and_identity_verified", self._calls)

    def _step_final_readback(self) -> dict[str, Any]:
        state = self._state()
        assert state is not None
        if state.get("phase") != "create_readback_verified" or state.get("create_readback_verified") is not True:
            raise CdIdentityBootstrapError("preflight_required")
        self._check_window()
        self._verify_stack_and_iam(state)
        self._check_window()
        state["phase"] = "final_readback_verified"
        state["final_readback_verified"] = True
        self._save(state)
        return self._safe("final-readback", True, "final_readback_verified", self._calls)
