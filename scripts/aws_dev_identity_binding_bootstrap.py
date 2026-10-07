"""Injected one-shot coordinator for the dedicated synthetic DEV binding stack.

This module constructs no SDK clients and performs no work at import. It only
creates a new fixed CloudFormation stack after current closed-app evidence,
exact account identity, fresh-key absence, and a durable one-use intent.
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

from scripts.build_aws_dev_identity_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_BOUNDARY_NAME, OPERATOR_ROLE_NAME,
    RUNTIME_ROLE_NAME, STACK_NAME, build_dev_identity_binding_bootstrap,
)

REGION = "eu-west-1"
MAX_AUTHORITY_SECONDS = 3600
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 48
APP_STACK_NAME = "honda-mapit-mcp-dev-retained"
HANDLER_POLICY_NAMES = frozenset({
    "honda-mapit-mcp-dev-retained-owned-log-writes",
    "honda-mapit-mcp-dev-retained-tenant-read",
})
RUNTIME_POLICY_NAME = "honda-mapit-mcp-dev-identity-bindings-runtime-read"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CALLER = re.compile(r"arn:aws:iam::([0-9]{12}):user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+\Z")
_APP_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:([0-9]{12}):stack/honda-mapit-mcp-dev-retained/[0-9a-f-]{36}\Z")
_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/[0-9a-f-]{{36}}\Z")
_CATEGORIES = frozenset({
    "clients_invalid", "journal_invalid", "binding_invalid", "window_invalid", "window_expired",
    "step_invalid", "preflight_verified", "preflight_required", "preflight_conflict",
    "app_runtime_unverified", "named_resource_conflict", "create_intent_saved",
    "create_intent_present", "create_outcome_unknown", "create_acknowledged",
    "stack_in_progress", "stack_not_complete", "stack_readback_mismatch", "readback_verified",
    "aws_call_failed", "aws_response_invalid", "journal_failed", "operator_internal_error",
})


class IdentityBindingBootstrapError(ValueError):
    def __init__(self, category: str) -> None:
        self.category = category if type(category) is str and category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _document(value: Any) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value) > 256 * 1024 or re.search(r"%(?![0-9A-Fa-f]{2})", value):
        return None
    try:
        raw = unquote_to_bytes(value)
        if len(raw) > 64 * 1024:
            return None
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique)
        return parsed if isinstance(parsed, Mapping) else None
    except Exception:
        return None


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _exact_boundary(value: Any, expected_arn: str) -> bool:
    return (
        isinstance(value, Mapping)
        and set(value) == {"PermissionsBoundaryArn", "PermissionsBoundaryType"}
        and type(value.get("PermissionsBoundaryArn")) is str
        and value.get("PermissionsBoundaryArn") == expected_arn
        and type(value.get("PermissionsBoundaryType")) is str
        and value.get("PermissionsBoundaryType") in {"Policy", "PermissionsBoundaryPolicy"}
    )


def _aws_error(exc: Exception) -> tuple[str, int | None, str]:
    try:
        response = getattr(exc, "response", None)
        error = response.get("Error") if isinstance(response, Mapping) else None
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        code = error.get("Code") if isinstance(error, Mapping) else None
        status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
        message = error.get("Message") if isinstance(error, Mapping) else None
        return (code if type(code) is str else "",
                status if type(status) is int and not isinstance(status, bool) else None,
                message if type(message) is str else "")
    except Exception:
        return "", None, ""


def _valid_evidence(value: Any, *, binding: Mapping[str, Any]) -> bool:
    expected = {
        "app_stack_arn": binding["app_stack_arn"], "app_run_id": binding["app_run_id"],
        "api_id": binding["api_id"], "template_sha256": binding["template_sha256"],
        "code_sha256": binding["code_sha256"], "handler_role_arn": binding["handler_role_arn"],
        "handler_trust_sha256": binding["handler_trust_sha256"],
        "handler_policies_sha256": binding["handler_policies_sha256"],
        "resource_count": 19, "api_closed": True, "reserve_zero": True,
    }
    if not isinstance(value, Mapping) or set(value) != {"verified", "calls", *expected}:
        return False
    if value.get("verified") is not True or type(value.get("calls")) is not int or not 1 <= value["calls"] <= 32:
        return False
    for key, expected_value in expected.items():
        actual = value.get(key)
        if type(expected_value) is bool:
            if actual is not expected_value:
                return False
        elif type(expected_value) is int:
            if type(actual) is not int or actual != expected_value:
                return False
        elif type(actual) is not type(expected_value) or actual != expected_value:
            return False
    return True


class DevIdentityBindingBootstrapCoordinator:
    """Fresh, injected preflight/create/readback steps for DEV only."""
    STEPS = ("preflight", "create", "readback")

    def __init__(self, clients: Mapping[str, Any], journal: Any, *, binding: Mapping[str, Any],
                 source_sha: str, run_id: int, expected_caller_arn: str,
                 authorized_from_epoch: int, authorized_until_epoch: int,
                 accepted_runtime_verifier: Callable[[Mapping[str, Any], Mapping[str, Any]], Mapping[str, Any]],
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        required_clients = {"sts", "cloudformation", "iam", "dynamodb", "ssm",
                            "cognito", "apigatewayv2", "lambda", "kms"}
        if not isinstance(clients, Mapping) or set(clients) != required_clients or any(clients[k] is None for k in required_clients):
            raise IdentityBindingBootstrapError("clients_invalid")
        endpoints = {
            "sts": ("sts", REGION, f"https://sts.{REGION}.amazonaws.com"),
            "cloudformation": ("cloudformation", REGION, f"https://cloudformation.{REGION}.amazonaws.com"),
            "iam": ("iam", "us-east-1", "https://iam.amazonaws.com"),
            "dynamodb": ("dynamodb", REGION, f"https://dynamodb.{REGION}.amazonaws.com"),
            "ssm": ("ssm", REGION, f"https://ssm.{REGION}.amazonaws.com"),
            "cognito": ("cognito-idp", REGION, f"https://cognito-idp.{REGION}.amazonaws.com"),
            "apigatewayv2": ("apigatewayv2", REGION, f"https://apigateway.{REGION}.amazonaws.com"),
            "lambda": ("lambda", REGION, f"https://lambda.{REGION}.amazonaws.com"),
            "kms": ("kms", REGION, f"https://kms.{REGION}.amazonaws.com"),
        }
        try:
            for name, client in clients.items():
                meta = client.meta
                cfg = meta.config
                expected_service, expected_region, expected_endpoint = endpoints[name]
                if (meta.service_model.service_name != expected_service
                    or meta.region_name != expected_region
                    or meta.endpoint_url != expected_endpoint
                    or type(cfg.retries.get("total_max_attempts")) is not int
                    or cfg.retries.get("total_max_attempts") != 1
                    or any(type(x) not in (int, float) or not math.isfinite(x) or not 0 < x <= 3
                           for x in (cfg.connect_timeout, cfg.read_timeout))):
                    raise ValueError
        except Exception:
            raise IdentityBindingBootstrapError("clients_invalid") from None
        if not all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked")):
            raise IdentityBindingBootstrapError("journal_invalid")
        if not callable(accepted_runtime_verifier) or not callable(wall_clock) or not callable(monotonic):
            raise IdentityBindingBootstrapError("binding_invalid")
        if not isinstance(binding, Mapping) or set(binding) != {
            "account_id", "operator_user_arn", "tenant_keys", "accepted_runtime_journal_path",
            "app_stack_arn", "app_run_id", "api_id", "user_pool_id", "client_id",
            "template_sha256", "code_sha256", "handler_role_arn",
            "handler_trust_sha256", "handler_policies_sha256", "ssm_key_arn",
        }:
            raise IdentityBindingBootstrapError("binding_invalid")
        account = binding.get("account_id")
        caller_match = _CALLER.fullmatch(expected_caller_arn) if type(expected_caller_arn) is str else None
        operator_match = _CALLER.fullmatch(binding.get("operator_user_arn")) if type(binding.get("operator_user_arn")) is str else None
        app_match = _APP_STACK.fullmatch(binding.get("app_stack_arn")) if type(binding.get("app_stack_arn")) is str else None
        tenant_keys = binding.get("tenant_keys")
        if (type(account) is not str or _ACCOUNT.fullmatch(account) is None or account == "000000000000"
            or caller_match is None or operator_match is None or caller_match.group(1) != account
            or operator_match.group(1) != account or expected_caller_arn != binding.get("operator_user_arn")
            or app_match is None or app_match.group(1) != account
            or type(binding.get("app_run_id")) is not int or isinstance(binding.get("app_run_id"), bool) or binding["app_run_id"] <= 0
            or type(binding.get("api_id")) is not str or re.fullmatch(r"[a-z0-9]{10}", binding["api_id"]) is None
            or type(tenant_keys) is not tuple or len(tenant_keys) != 2
            or any(type(key) is not str or _TENANT_KEY.fullmatch(key) is None for key in tenant_keys)
            or len(set(tenant_keys)) != 2
            or any(type(binding.get(name)) is not str or _SHA.fullmatch(binding[name]) is None
                   for name in ("template_sha256", "code_sha256", "handler_trust_sha256", "handler_policies_sha256"))
            or type(binding.get("accepted_runtime_journal_path")) is not str
            or not binding["accepted_runtime_journal_path"]
            or type(binding.get("user_pool_id")) is not str
            or re.fullmatch(r"eu-west-1_[0-9A-Za-z]+", binding["user_pool_id"]) is None
            or type(binding.get("client_id")) is not str
            or re.fullmatch(r"[0-9A-Za-z]{8,128}", binding["client_id"]) is None
            or binding.get("handler_role_arn") != f"arn:aws:iam::{account}:role/{RUNTIME_ROLE_NAME}"):
            raise IdentityBindingBootstrapError("binding_invalid")
        if (type(source_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None or source_sha == "0" * 40
            or type(run_id) is not int or isinstance(run_id, bool) or run_id <= 0
            or type(expected_caller_arn) is not str
            or type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
            or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
            or authorized_from_epoch <= 0 or authorized_until_epoch <= authorized_from_epoch
            or authorized_until_epoch - authorized_from_epoch > MAX_AUTHORITY_SECONDS):
            raise IdentityBindingBootstrapError("window_invalid")
        try:
            template = build_dev_identity_binding_bootstrap(
                account_id=account, operator_user_arn=binding["operator_user_arn"],
                tenant_keys=tenant_keys,
                ssm_key_arn=binding["ssm_key_arn"],
            )
            template_bytes = _canonical(template)
        except Exception:
            raise IdentityBindingBootstrapError("binding_invalid") from None
        self.clients = dict(clients)
        self.journal = journal
        self.binding = dict(binding)
        self.binding_sha256 = _digest({key: value for key, value in self.binding.items() if key != "tenant_keys"})
        self.account = account
        self.source_sha = source_sha
        self.run_id = run_id
        self.caller = expected_caller_arn
        self.window_start, self.window_end = authorized_from_epoch, authorized_until_epoch
        self.template = template
        self.template_bytes = template_bytes
        self.template_sha256 = hashlib.sha256(template_bytes).hexdigest()
        self.accepted_runtime_verifier = accepted_runtime_verifier
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started: float | None = None
        self._last_mono = 0.0
        self._last_epoch = 0
        self._calls = 0
        self._accepted_calls = 0

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category,
                "calls": self._calls + self._accepted_calls}

    def _now(self) -> int:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
            raise IdentityBindingBootstrapError("window_invalid")
        epoch = int(value)
        if epoch < self._last_epoch:
            raise IdentityBindingBootstrapError("window_invalid")
        self._last_epoch = epoch
        if not self.window_start <= epoch < self.window_end:
            raise IdentityBindingBootstrapError("window_expired")
        return epoch

    def _budget(self) -> None:
        current = self.monotonic()
        if (type(current) not in (int, float) or isinstance(current, bool)
            or not math.isfinite(current) or current < self._last_mono):
            raise IdentityBindingBootstrapError("window_invalid")
        self._last_mono = float(current)
        if self._started is None or self._last_mono - self._started >= MAX_STEP_SECONDS:
            raise IdentityBindingBootstrapError("window_expired")
        if self._calls + self._accepted_calls >= MAX_CALLS_PER_STEP:
            raise IdentityBindingBootstrapError("aws_call_failed")

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._budget()
        self._now()
        self._calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            self._now()
            self._budget()
            raise IdentityBindingBootstrapError("aws_call_failed") from None
        if (not isinstance(result, Mapping) or not isinstance(result.get("ResponseMetadata"), Mapping)
            or type(result["ResponseMetadata"].get("HTTPStatusCode")) is not int
            or result["ResponseMetadata"]["HTTPStatusCode"] != 200):
            raise IdentityBindingBootstrapError("aws_response_invalid")
        self._now()
        self._budget()
        return result

    def _call_absent(self, service: str, method: str, *, absence: str, **kwargs: Any) -> None:
        self._budget()
        self._now()
        self._calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception as exc:
            code, status, message = _aws_error(exc)
            exact = (
                (absence == "stack" and code == "ValidationError" and status in {400, 404}
                 and message == f"Stack with id {STACK_NAME} does not exist")
                or (absence == "table" and code == "ResourceNotFoundException" and status == 400)
                or (absence in {"role", "policy", "role_policy"} and code == "NoSuchEntity" and status == 404)
                or (absence == "parameter" and code == "ParameterNotFound" and status == 400)
            )
            self._now()
            self._budget()
            if exact:
                return
            raise IdentityBindingBootstrapError("aws_call_failed") from None
        if (not isinstance(result, Mapping) or not isinstance(result.get("ResponseMetadata"), Mapping)
            or type(result["ResponseMetadata"].get("HTTPStatusCode")) is not int
            or result["ResponseMetadata"]["HTTPStatusCode"] != 200):
            raise IdentityBindingBootstrapError("aws_response_invalid")
        self._now()
        self._budget()
        raise IdentityBindingBootstrapError("named_resource_conflict")

    def _identity(self) -> None:
        result = self._call("sts", "get_caller_identity")
        if result.get("Account") != self.account or result.get("Arn") != self.caller:
            raise IdentityBindingBootstrapError("binding_invalid")

    def _verify_current_app(self, *, include_runtime_policy: bool = False) -> None:
        self._now()
        self._budget()
        try:
            evidence_binding = dict(self.binding)
            if include_runtime_policy:
                runtime = self.template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
                evidence_binding["added_runtime_policy"] = {
                    "policy_name": runtime["PolicyName"],
                    "policy_document": runtime["PolicyDocument"],
                }
            result = self.accepted_runtime_verifier(self.clients, evidence_binding)
        except Exception:
            self._now()
            self._budget()
            raise IdentityBindingBootstrapError("app_runtime_unverified") from None
        self._now()
        self._budget()
        if (isinstance(result, Mapping) and type(result.get("calls")) is int
            and 0 <= result["calls"] <= 32):
            self._accepted_calls += result["calls"]
        if not _valid_evidence(result, binding=self.binding):
            raise IdentityBindingBootstrapError("app_runtime_unverified")
        if self._calls + self._accepted_calls > MAX_CALLS_PER_STEP:
            raise IdentityBindingBootstrapError("aws_call_failed")

    def _handler_role(self) -> None:
        role = self._call("iam", "get_role", RoleName=RUNTIME_ROLE_NAME).get("Role")
        expected_arn = self.binding["handler_role_arn"]
        if (not isinstance(role, Mapping) or role.get("RoleName") != RUNTIME_ROLE_NAME
            or role.get("Arn") != expected_arn or role.get("Path") != "/"
            or role.get("PermissionsBoundary") not in (None, {})):
            raise IdentityBindingBootstrapError("app_runtime_unverified")
        trust = role.get("AssumeRolePolicyDocument")
        if not isinstance(trust, Mapping) or _digest(trust) != self.binding["handler_trust_sha256"]:
            raise IdentityBindingBootstrapError("app_runtime_unverified")
        listed = self._call("iam", "list_role_policies", RoleName=RUNTIME_ROLE_NAME)
        names = listed.get("PolicyNames")
        if (type(names) is not list or set(names) != HANDLER_POLICY_NAMES
            or len(names) != len(HANDLER_POLICY_NAMES) or listed.get("IsTruncated", False) is not False
            or listed.get("Marker") not in (None, "")):
            raise IdentityBindingBootstrapError("app_runtime_unverified")
        policies = {}
        for name in sorted(HANDLER_POLICY_NAMES):
            response = self._call("iam", "get_role_policy", RoleName=RUNTIME_ROLE_NAME, PolicyName=name)
            doc = _document(response.get("PolicyDocument"))
            if doc is None:
                raise IdentityBindingBootstrapError("app_runtime_unverified")
            policies[name] = doc
        if _digest(policies) != self.binding["handler_policies_sha256"]:
            raise IdentityBindingBootstrapError("app_runtime_unverified")

    def _parameter_arns(self) -> tuple[str, ...]:
        return tuple(
            f"arn:aws:ssm:{REGION}:{self.account}:parameter/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
            for key in self.binding["tenant_keys"]
        ) + (f"arn:aws:ssm:{REGION}:{self.account}:parameter/honda-mapit-mcp/dev/identity-binding-config",)

    def _preflight_reads(self) -> None:
        self._identity()
        self._verify_ssm_key()
        self._verify_current_app()
        self._handler_role()
        self._call_absent("cloudformation", "describe_stacks", absence="stack", StackName=STACK_NAME)
        self._call_absent("dynamodb", "describe_table", absence="table", TableName="honda-mapit-mcp-dev-identity-bindings")
        self._call_absent("iam", "get_role", absence="role", RoleName=OPERATOR_ROLE_NAME)
        self._call_absent("iam", "get_policy", absence="policy",
                          PolicyArn=f"arn:aws:iam::{self.account}:policy/{OPERATOR_BOUNDARY_NAME}")
        self._call_absent("iam", "get_role_policy", absence="role_policy",
                          RoleName=RUNTIME_ROLE_NAME, PolicyName=RUNTIME_POLICY_NAME)
        for path in (f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token" for key in self.binding["tenant_keys"]):
            self._call_absent("ssm", "get_parameter", absence="parameter", Name=path, WithDecryption=False)
        self._call_absent("ssm", "get_parameter", absence="parameter", Name=CONFIG_PARAMETER, WithDecryption=False)

    def _base_state(self, *, last_epoch: int, preflight: bool, intent: Mapping[str, Any] | None,
                    acknowledged: bool, stack_id: str | None, readback: bool,
                    receipt: Mapping[str, Any] | None) -> dict[str, Any]:
        return {"schema": 1, "kind": "dev-identity-binding-bootstrap", "account": self.account,
                "source_sha": self.source_sha, "run_id": self.run_id,
                "binding_sha256": self.binding_sha256,
                "template_sha256": self.template_sha256, "expected_caller_arn": self.caller,
                "authorized_from_epoch": self.window_start, "authorized_until_epoch": self.window_end,
                "last_observed_epoch": last_epoch, "preflight": preflight,
                "intent": dict(intent) if intent is not None else None,
                "acknowledged": acknowledged, "acknowledged_stack_id": stack_id,
                "readback": readback, "readback_receipt": dict(receipt) if receipt is not None else None}

    def _load(self) -> dict[str, Any] | None:
        state = self.journal.load()
        if state is None:
            return None
        expected = {"schema", "kind", "account", "source_sha", "run_id", "template_sha256",
                    "binding_sha256",
                    "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch",
                    "last_observed_epoch", "preflight", "intent", "acknowledged",
                    "acknowledged_stack_id", "readback", "readback_receipt"}
        if not isinstance(state, Mapping) or set(state) != expected:
            raise IdentityBindingBootstrapError("journal_invalid")
        if (state.get("schema") != 1 or state.get("kind") != "dev-identity-binding-bootstrap"
            or state.get("account") != self.account or state.get("source_sha") != self.source_sha
            or state.get("run_id") != self.run_id or state.get("template_sha256") != self.template_sha256
            or state.get("binding_sha256") != self.binding_sha256
            or state.get("expected_caller_arn") != self.caller
            or state.get("authorized_from_epoch") != self.window_start
            or state.get("authorized_until_epoch") != self.window_end):
            raise IdentityBindingBootstrapError("journal_invalid")
        for key in ("schema", "run_id", "authorized_from_epoch", "authorized_until_epoch", "last_observed_epoch"):
            if type(state.get(key)) is not int or isinstance(state.get(key), bool):
                raise IdentityBindingBootstrapError("journal_invalid")
        for key in ("preflight", "acknowledged", "readback"):
            if type(state.get(key)) is not bool:
                raise IdentityBindingBootstrapError("journal_invalid")
        intent = state.get("intent")
        token = self._create_token()
        if intent is not None and (not isinstance(intent, Mapping) or set(intent) != {"token", "stack_name"}
                                   or intent.get("token") != token or intent.get("stack_name") != STACK_NAME):
            raise IdentityBindingBootstrapError("journal_invalid")
        stack_id = state.get("acknowledged_stack_id")
        if stack_id is not None:
            match = _STACK.fullmatch(stack_id) if type(stack_id) is str else None
            if match is None or match.group(1) != self.account:
                raise IdentityBindingBootstrapError("journal_invalid")
        receipt = state.get("readback_receipt")
        if state["readback"]:
            if (not isinstance(receipt, Mapping) or set(receipt) != {"stack_id", "template_sha256"}
                or receipt.get("stack_id") != stack_id or receipt.get("template_sha256") != self.template_sha256):
                raise IdentityBindingBootstrapError("journal_invalid")
        elif receipt is not None:
            raise IdentityBindingBootstrapError("journal_invalid")
        if (state["acknowledged"] and (intent is None or stack_id is None)
            or stack_id is not None and intent is None
            or state["readback"] and (not state["acknowledged"] or not state["preflight"])
            or intent is not None and not state["preflight"]):
            raise IdentityBindingBootstrapError("journal_invalid")
        return dict(state)

    def _save(self, *, preflight: bool, intent: Mapping[str, Any] | None, acknowledged: bool,
              stack_id: str | None, readback: bool, receipt: Mapping[str, Any] | None) -> None:
        self._now()
        self._budget()
        state = self._base_state(last_epoch=self._last_epoch, preflight=preflight, intent=intent,
                                 acknowledged=acknowledged, stack_id=stack_id,
                                 readback=readback, receipt=receipt)
        try:
            self.journal.save(state)
        except Exception:
            raise IdentityBindingBootstrapError("journal_failed") from None
        self._now()
        self._budget()

    def _create_token(self) -> str:
        return "dev-identity-bindings-" + hashlib.sha256(
            f"{self.account}:{self.source_sha}:{self.run_id}".encode("ascii")
        ).hexdigest()

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None and (state.get("intent") is not None or state.get("acknowledged")):
            raise IdentityBindingBootstrapError("preflight_conflict")
        self._preflight_reads()
        self._save(preflight=True, intent=None, acknowledged=False, stack_id=None,
                   readback=False, receipt=None)
        return self._safe("preflight", True, "preflight_verified")

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise IdentityBindingBootstrapError("preflight_required")
        if state.get("intent") is not None or state.get("acknowledged"):
            raise IdentityBindingBootstrapError("create_intent_present")
        # The earlier preflight is not a durable substitute for a fresh app,
        # caller, resource-absence and parameter-absence check at write time.
        self._preflight_reads()
        intent = {"token": self._create_token(), "stack_name": STACK_NAME}
        self._save(preflight=True, intent=intent, acknowledged=False, stack_id=None,
                   readback=False, receipt=None)
        self._budget()
        self._now()
        self._calls += 1
        try:
            response = self.clients["cloudformation"].create_stack(
                StackName=STACK_NAME, TemplateBody=self.template_bytes.decode("ascii"),
                Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=intent["token"],
                EnableTerminationProtection=True,
                Tags=[{"Key": "Project", "Value": "honda-mapit-mcp"},
                      {"Key": "Environment", "Value": "dev"},
                      {"Key": "Purpose", "Value": "mapit-identity-bindings"},
                      {"Key": "OperatorRunId", "Value": str(self.run_id)}],
            )
        except Exception:
            self._now()
            self._budget()
            raise IdentityBindingBootstrapError("create_outcome_unknown") from None
        self._now()
        self._budget()
        stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        match = _STACK.fullmatch(stack_id) if type(stack_id) is str else None
        if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
            or metadata["HTTPStatusCode"] != 200 or match is None or match.group(1) != self.account):
            raise IdentityBindingBootstrapError("create_outcome_unknown")
        self._save(preflight=True, intent=intent, acknowledged=True, stack_id=stack_id,
                   readback=False, receipt=None)
        return self._safe("create", True, "create_acknowledged")

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None:
            raise IdentityBindingBootstrapError("preflight_required")
        self._identity()
        stack_reply = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        stacks = stack_reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        stack = stacks[0]
        stack_id = stack.get("StackId")
        match = _STACK.fullmatch(stack_id) if type(stack_id) is str else None
        if match is None or match.group(1) != self.account or stack.get("StackName") != STACK_NAME:
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        if state.get("acknowledged") and state.get("acknowledged_stack_id") != stack_id:
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        if stack.get("StackStatus") == "CREATE_IN_PROGRESS":
            raise IdentityBindingBootstrapError("stack_in_progress")
        if stack.get("StackStatus") != "CREATE_COMPLETE":
            raise IdentityBindingBootstrapError("stack_not_complete")
        self._verify_current_app(include_runtime_policy=True)
        if stack.get("EnableTerminationProtection") is not True or stack.get("RoleARN") not in (None, ""):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev",
                         "Purpose": "mapit-identity-bindings", "OperatorRunId": str(self.run_id)}
        tags = stack.get("Tags")
        if (type(tags) is not list or any(not isinstance(tag, Mapping) or set(tag) != {"Key", "Value"} for tag in tags)
            or len(tags) != len(expected_tags)
            or {tag["Key"]: tag["Value"] for tag in tags} != expected_tags):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        template_reply = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original")
        actual_template = _document(template_reply.get("TemplateBody"))
        if actual_template is None or _canonical(actual_template) != self.template_bytes:
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME)
        event_rows = events.get("StackEvents")
        if (type(event_rows) is not list or not 1 <= len(event_rows) <= 100
            or not any(isinstance(event, Mapping) and event.get("ClientRequestToken") == state["intent"]["token"]
                       and event.get("StackId") == stack_id and event.get("StackName") == STACK_NAME
                       for event in event_rows)):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        resources_response = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME)
        rows = resources_response.get("StackResources")
        expected_types = {
            "MapitIdentityBindings": "AWS::DynamoDB::Table",
            "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
            "IdentityEnrollerRole": "AWS::IAM::Role",
            "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy",
        }
        if type(rows) is not list or len(rows) != len(expected_types):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        by_name = {}
        for row in rows:
            if (not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str
                or row["LogicalResourceId"] in by_name
                or row.get("ResourceType") != expected_types.get(row["LogicalResourceId"])
                or row.get("ResourceStatus") != "CREATE_COMPLETE"
                or row.get("StackId") != stack_id or row.get("StackName") != STACK_NAME
                or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
                raise IdentityBindingBootstrapError("stack_readback_mismatch")
            by_name[row["LogicalResourceId"]] = row
        if set(by_name) != set(expected_types):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        table_arn = f"arn:aws:dynamodb:{REGION}:{self.account}:table/honda-mapit-mcp-dev-identity-bindings"
        boundary_arn = f"arn:aws:iam::{self.account}:policy/{OPERATOR_BOUNDARY_NAME}"
        if (by_name["MapitIdentityBindings"].get("PhysicalResourceId") != "honda-mapit-mcp-dev-identity-bindings"
            or by_name["IdentityEnrollerRole"].get("PhysicalResourceId") != OPERATOR_ROLE_NAME
            or by_name["IdentityEnrollerBoundary"].get("PhysicalResourceId") != boundary_arn):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        self._verify_table(table_arn, stack_id)
        self._verify_iam(boundary_arn)
        self._verify_ssm_key()
        self._verify_parameters_absent()
        receipt = {"stack_id": stack_id, "template_sha256": self.template_sha256}
        self._save(preflight=True, intent=state["intent"], acknowledged=True, stack_id=stack_id,
                   readback=True, receipt=receipt)
        return self._safe("readback", True, "readback_verified")

    def _verify_ssm_key(self) -> None:
        metadata = self._call("kms", "describe_key", KeyId="alias/aws/ssm").get("KeyMetadata")
        if (not isinstance(metadata, Mapping)
            or metadata.get("Arn") != self.binding["ssm_key_arn"]
            or metadata.get("AWSAccountId") != self.account
            or metadata.get("KeyManager") != "AWS"
            or metadata.get("Enabled") is not True
            or metadata.get("KeyState") != "Enabled"
            or metadata.get("KeyUsage") != "ENCRYPT_DECRYPT"):
            raise IdentityBindingBootstrapError("app_runtime_unverified")

    def _verify_table(self, table_arn: str, stack_id: str) -> None:
        reply = self._call("dynamodb", "describe_table", TableName="honda-mapit-mcp-dev-identity-bindings")
        table = reply.get("Table")
        if (not isinstance(table, Mapping) or table.get("TableName") != "honda-mapit-mcp-dev-identity-bindings"
            or table.get("TableArn") != table_arn or table.get("TableStatus") != "ACTIVE"
            or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
            or table.get("OnDemandThroughput") != {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100}
            or table.get("KeySchema") != [{"AttributeName": "key", "KeyType": "HASH"}]
            or table.get("AttributeDefinitions") != [{"AttributeName": "key", "AttributeType": "S"}]
            or table.get("DeletionProtectionEnabled") is not True
            or table.get("SSEDescription", {}).get("Status") not in {"ENABLED", "ENABLING"}
            or table.get("GlobalSecondaryIndexes") not in (None, [])
            or table.get("LocalSecondaryIndexes") not in (None, [])):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        tags = self._call("dynamodb", "list_tags_of_resource", ResourceArn=table_arn).get("Tags")
        expected = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "mapit-identity-bindings"}
        actual = {row.get("Key"): row.get("Value") for row in tags if isinstance(row, Mapping)} if type(tags) is list else {}
        if not all(actual.get(key) == value for key, value in expected.items()):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        item = self._call("dynamodb", "get_item", TableName=table_arn,
                          Key={"key": {"S": "identity-bindings-v1"}},
                          ConsistentRead=True, ReturnConsumedCapacity="NONE")
        if set(item) - {"ResponseMetadata"}:
            raise IdentityBindingBootstrapError("stack_readback_mismatch")

    def _verify_iam(self, boundary_arn: str) -> None:
        role_reply = self._call("iam", "get_role", RoleName=OPERATOR_ROLE_NAME)
        role = role_reply.get("Role")
        expected_trust = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"AWS": self.binding["operator_user_arn"]},
            "Action": "sts:AssumeRole",
        }]}
        if (not isinstance(role, Mapping) or role.get("RoleName") != OPERATOR_ROLE_NAME
            or role.get("Arn") != f"arn:aws:iam::{self.account}:role/{OPERATOR_ROLE_NAME}"
            or role.get("Path") != "/" or role.get("MaxSessionDuration") != 3600
            or not _exact_boundary(role.get("PermissionsBoundary"), boundary_arn)
            or _document(role.get("AssumeRolePolicyDocument")) is None
            or _canonical(_document(role["AssumeRolePolicyDocument"])) != _canonical(expected_trust)):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        inline = self._call("iam", "get_role_policy", RoleName=OPERATOR_ROLE_NAME,
                            PolicyName=OPERATOR_ROLE_NAME + "-policy")
        expected_operator = self.template["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        actual_operator = _document(inline.get("PolicyDocument"))
        if actual_operator is None or _canonical(actual_operator) != _canonical(expected_operator):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        policy_reply = self._call("iam", "get_policy", PolicyArn=boundary_arn)
        policy = policy_reply.get("Policy")
        if (not isinstance(policy, Mapping) or policy.get("Arn") != boundary_arn
            or policy.get("PolicyName") != OPERATOR_BOUNDARY_NAME or policy.get("Path") != "/"
            or policy.get("DefaultVersionId") != "v1"):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        version_reply = self._call("iam", "get_policy_version", PolicyArn=boundary_arn, VersionId="v1")
        actual_boundary = _document(version_reply.get("PolicyVersion", {}).get("Document")
                                    if isinstance(version_reply.get("PolicyVersion"), Mapping) else None)
        expected_boundary = self.template["Resources"]["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
        if actual_boundary is None or _canonical(actual_boundary) != _canonical(expected_boundary):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")

        runtime = self._call("iam", "get_role_policy", RoleName=RUNTIME_ROLE_NAME, PolicyName=RUNTIME_POLICY_NAME)
        actual_runtime = _document(runtime.get("PolicyDocument"))
        expected_runtime = self.template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyDocument"]
        if actual_runtime is None or _canonical(actual_runtime) != _canonical(expected_runtime):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")
        names_reply = self._call("iam", "list_role_policies", RoleName=RUNTIME_ROLE_NAME)
        names = names_reply.get("PolicyNames")
        if (type(names) is not list or len(names) != 3
            or set(names) != HANDLER_POLICY_NAMES | {RUNTIME_POLICY_NAME}
            or names_reply.get("IsTruncated", False) is not False or names_reply.get("Marker") not in (None, "")):
            raise IdentityBindingBootstrapError("stack_readback_mismatch")

    def _verify_parameters_absent(self) -> None:
        for name in (f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token" for key in self.binding["tenant_keys"]):
            self._call_absent("ssm", "get_parameter", absence="parameter", Name=name, WithDecryption=False)
        self._call_absent("ssm", "get_parameter", absence="parameter", Name=CONFIG_PARAMETER, WithDecryption=False)

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                current = self.monotonic()
                if type(current) not in (int, float) or isinstance(current, bool) or not math.isfinite(current) or current < 0:
                    raise IdentityBindingBootstrapError("window_invalid")
                self._started = self._last_mono = float(current)
                self._calls = self._accepted_calls = 0
                state = self._load()
                self._last_epoch = state.get("last_observed_epoch", 0) if state is not None else 0
                self._now()
                if step == "preflight":
                    return self._preflight(state)
                if step == "create":
                    return self._create(state)
                return self._readback(state)
        except IdentityBindingBootstrapError as exc:
            return self._safe(step, False, exc.category)
        except Exception:
            return self._safe(step, False, "operator_internal_error")


__all__ = ["DevIdentityBindingBootstrapCoordinator", "IdentityBindingBootstrapError"]
