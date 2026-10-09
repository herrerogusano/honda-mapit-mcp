"""Injected one-shot coordinator for the distinct DEV MAPIT namespace.

No SDK clients are constructed here. A caller supplies explicitly validated
clients, a durable journal and trusted fresh-evidence callbacks. In particular,
the production/current-runtime verifier is intentionally only an interface:
the accepted runtime currently has a different policy inventory, so this module
does not implement or claim a deploy-ready closed-runtime validator.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import unquote_to_bytes

from scripts.build_aws_dev_mapit_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_BOUNDARY_NAME, OPERATOR_ROLE_NAME,
    RUNTIME_ROLE_NAME, STACK_NAME, build_dev_mapit_binding_bootstrap,
)
from scripts.dev_mapit_bootstrap_contract import (
    ENVIRONMENT, KIND, NAMESPACE, OPERATION, ExclusiveWindow,
    MapitBootstrapAuthority, MapitBootstrapContractError, build_plan,
    create_only_intent, validate_intent,
)

REGION = "eu-west-1"
MAX_STEP_SECONDS = 30.0
MAX_CALLS_PER_STEP = 128
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_STACK_ARN = re.compile(rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/{re.escape(STACK_NAME)}/[0-9a-f-]{{36}}\Z")
_TABLE_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_CATEGORIES = frozenset({
    "clients_invalid", "journal_invalid", "authority_invalid", "window_invalid",
    "window_expired", "step_invalid", "source_unverified", "protections_unverified",
    "runtime_unverified", "preflight_required", "preflight_conflict", "resource_conflict",
    "create_intent_saved", "create_intent_present", "create_outcome_unknown",
    "create_acknowledged", "stack_in_progress", "stack_not_complete",
    "stack_readback_mismatch", "readback_verified", "aws_call_failed",
    "aws_response_invalid", "journal_failed", "operator_internal_error",
})
_EXPECTED_TYPES = {
    "MapitIdentityBindings": "AWS::DynamoDB::Table",
    "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
    "IdentityEnrollerRole": "AWS::IAM::Role",
    "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy",
}


class MapitBootstrapCoordinatorError(ValueError):
    def __init__(self, category: str):
        self.category = category if type(category) is str and category in _CATEGORIES else "operator_internal_error"
        super().__init__(self.category)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _error(exc: Exception) -> tuple[str, int | None, str]:
    try:
        response = getattr(exc, "response", None)
        e = response.get("Error") if isinstance(response, Mapping) else None
        meta = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        code = e.get("Code") if isinstance(e, Mapping) else None
        status = meta.get("HTTPStatusCode") if isinstance(meta, Mapping) else None
        message = e.get("Message") if isinstance(e, Mapping) else None
        return (code if type(code) is str else "",
                status if type(status) is int and not isinstance(status, bool) else None,
                message if type(message) is str else "")
    except Exception:
        return "", None, ""


def _exact_keys(value: Any, fields: set[str]) -> bool:
    return isinstance(value, Mapping) and set(value) == fields


def _valid_source_evidence(value: Any, authority: MapitBootstrapAuthority) -> bool:
    fields = {"verified", "calls", "account_id", "source_sha", "run_id", "caller_arn",
              "branch", "evidence_sha256"}
    return (
        _exact_keys(value, fields) and value.get("verified") is True
        and type(value.get("calls")) is int and 1 <= value["calls"] <= 8
        and type(value.get("account_id")) is str and value["account_id"] == authority.account_id
        and type(value.get("source_sha")) is str and value["source_sha"] == authority.source_sha
        and type(value.get("run_id")) is int and value["run_id"] == authority.run_id
        and type(value.get("caller_arn")) is str and value["caller_arn"] == authority.expected_caller_arn
        and type(value.get("branch")) is str and value["branch"] == "develop"
        and type(value.get("evidence_sha256")) is str
        and value["evidence_sha256"] == authority.ci_evidence_sha256
    )


def _valid_protection_evidence(value: Any, authority: MapitBootstrapAuthority) -> bool:
    fields = {"verified", "calls", "account_id", "source_sha", "run_id", "caller_arn",
              "environment", "protections_verified", "evidence_sha256"}
    return (
        _exact_keys(value, fields) and value.get("verified") is True
        and type(value.get("calls")) is int and 1 <= value["calls"] <= 8
        and type(value.get("account_id")) is str and value["account_id"] == authority.account_id
        and type(value.get("source_sha")) is str and value["source_sha"] == authority.source_sha
        and type(value.get("run_id")) is int and value["run_id"] == authority.run_id
        and type(value.get("caller_arn")) is str and value["caller_arn"] == authority.expected_caller_arn
        and type(value.get("environment")) is str and value["environment"] == ENVIRONMENT
        and value.get("protections_verified") is True
        and type(value.get("evidence_sha256")) is str
        and value["evidence_sha256"] == authority.ci_evidence_sha256
    )


def _valid_runtime_evidence(value: Any, authority: MapitBootstrapAuthority, phase: str) -> bool:
    fields = {"verified", "calls", "phase", "account_id", "source_sha", "run_id",
              "caller_arn", "evidence_sha256", "resource_count", "api_closed",
              "reserve_zero", "mapit_policy_attached"}
    expected_attached = phase == "readback"
    return (
        _exact_keys(value, fields) and value.get("verified") is True
        and type(value.get("calls")) is int and 1 <= value["calls"] <= 64
        and type(value.get("phase")) is str and value["phase"] == phase
        and type(value.get("account_id")) is str and value["account_id"] == authority.account_id
        and type(value.get("source_sha")) is str and value["source_sha"] == authority.source_sha
        and type(value.get("run_id")) is int and value["run_id"] == authority.run_id
        and type(value.get("caller_arn")) is str and value["caller_arn"] == authority.expected_caller_arn
        and type(value.get("evidence_sha256")) is str
        and value["evidence_sha256"] == authority.runtime_evidence_sha256
        and type(value.get("resource_count")) is int and value["resource_count"] == 19
        and value.get("api_closed") is True and value.get("reserve_zero") is True
        and value.get("mapit_policy_attached") is expected_attached
    )


class MapitBootstrapCoordinator:
    """Fresh injected preflight/create/readback for the distinct MAPIT stack.

    Evidence callbacks are trusted adapters and must themselves read and validate
    current source/protection/runtime state. Digests bind those callback results
    to this authority but do not prove the underlying evidence. No callback here
    implements the currently missing four-policy runtime baseline validator.
    """

    STEPS = ("preflight", "create", "readback")
    _CLIENTS = frozenset({"sts", "cloudformation", "iam", "dynamodb", "ssm",
                          "cognito", "apigatewayv2", "lambda", "kms"})
    _ENDPOINTS = {
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

    def __init__(self, clients: Mapping[str, Any], journal: Any, *,
                 authority: MapitBootstrapAuthority,
                 fresh_source: Callable[[MapitBootstrapAuthority], Mapping[str, Any]],
                 fresh_protections: Callable[[MapitBootstrapAuthority], Mapping[str, Any]],
                 closed_runtime_verifier: Callable[..., Mapping[str, Any]],
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(clients, Mapping) or set(clients) != self._CLIENTS or any(clients.get(k) is None for k in self._CLIENTS):
            raise MapitBootstrapCoordinatorError("clients_invalid")
        try:
            for name, client in clients.items():
                meta, cfg = client.meta, client.meta.config
                svc, region, endpoint = self._ENDPOINTS[name]
                verify = getattr(getattr(getattr(client, "_endpoint", None), "http_session", None), "_verify", None)
                if (meta.service_model.service_name != svc or meta.region_name != region
                    or meta.endpoint_url != endpoint
                    or type(cfg.retries.get("total_max_attempts")) is not int
                    or cfg.retries.get("total_max_attempts") != 1
                    or not isinstance(cfg.signature_version, str) or cfg.signature_version != "v4"
                    or type(cfg.proxies) is not dict or cfg.proxies != {}
                    or verify is not True
                    or any(type(v) not in (int, float) or isinstance(v, bool)
                           or not math.isfinite(v) or not 0 < v <= 3
                           for v in (cfg.connect_timeout, cfg.read_timeout))):
                    raise ValueError
        except Exception:
            raise MapitBootstrapCoordinatorError("clients_invalid") from None
        if not all(callable(getattr(journal, k, None)) for k in ("load", "save", "locked")):
            raise MapitBootstrapCoordinatorError("journal_invalid")
        if (not callable(fresh_source) or not callable(fresh_protections)
                or not callable(closed_runtime_verifier) or not callable(wall_clock)
                or not callable(monotonic)):
            raise MapitBootstrapCoordinatorError("authority_invalid")
        if type(authority) is not MapitBootstrapAuthority:
            raise MapitBootstrapCoordinatorError("authority_invalid")
        try:
            self.plan = build_plan(authority)
        except MapitBootstrapContractError:
            raise MapitBootstrapCoordinatorError("authority_invalid") from None
        self.authority, self.clients, self.journal = authority, dict(clients), journal
        self.fresh_source, self.fresh_protections = fresh_source, fresh_protections
        self.closed_runtime_verifier = closed_runtime_verifier
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self.window = ExclusiveWindow(authority, wall_clock=wall_clock, monotonic=monotonic)
        self._calls = self._accepted_calls = 0
        self._started: float | None = None
        self._last_mono = 0.0
        self._last_epoch = 0
        self._invalid = False

    def _safe(self, step: str, ok: bool, category: str) -> dict[str, Any]:
        return {"step": step, "ok": ok, "category": category,
                "calls": self._calls + self._accepted_calls}

    def _now(self) -> int:
        if self._invalid:
            raise MapitBootstrapCoordinatorError("window_invalid")
        try:
            wall, _ = self.window.check(self.authority)
        except MapitBootstrapContractError:
            self._invalid = True
            raise MapitBootstrapCoordinatorError("window_expired") from None
        epoch = int(wall)
        if epoch < self._last_epoch:
            self._invalid = True
            raise MapitBootstrapCoordinatorError("window_invalid")
        self._last_epoch = epoch
        return epoch

    def _budget(self) -> None:
        if self._invalid:
            raise MapitBootstrapCoordinatorError("window_invalid")
        try:
            current = self.monotonic()
        except Exception:
            self._invalid = True
            raise MapitBootstrapCoordinatorError("window_invalid") from None
        if (type(current) not in (int, float) or isinstance(current, bool)
                or not math.isfinite(current) or current < self._last_mono):
            self._invalid = True
            raise MapitBootstrapCoordinatorError("window_invalid")
        self._last_mono = float(current)
        if self._started is None or self._last_mono - self._started >= MAX_STEP_SECONDS:
            self._invalid = True
            raise MapitBootstrapCoordinatorError("window_expired")
        if self._calls + self._accepted_calls > MAX_CALLS_PER_STEP:
            raise MapitBootstrapCoordinatorError("aws_call_failed")

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._budget()
        self._now()
        if self._calls + self._accepted_calls >= MAX_CALLS_PER_STEP:
            raise MapitBootstrapCoordinatorError("aws_call_failed")
        self._calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception:
            self._now()
            self._budget()
            raise MapitBootstrapCoordinatorError("aws_call_failed") from None
        if (not isinstance(result, Mapping) or not isinstance(result.get("ResponseMetadata"), Mapping)
                or type(result["ResponseMetadata"].get("HTTPStatusCode")) is not int
                or result["ResponseMetadata"]["HTTPStatusCode"] != 200):
            raise MapitBootstrapCoordinatorError("aws_response_invalid")
        event_page = service == "cloudformation" and method == "describe_stack_events"
        for key in ("NextToken", "NextMarker", "Marker"):
            value = result.get(key)
            if value not in (None, ""):
                if not (event_page and key == "NextToken" and type(value) is str and len(value) <= 4096):
                    raise MapitBootstrapCoordinatorError("aws_response_invalid")
        if "IsTruncated" in result and (type(result["IsTruncated"]) is not bool or result["IsTruncated"]):
            raise MapitBootstrapCoordinatorError("aws_response_invalid")
        self._now()
        self._budget()
        return result

    def _absent(self, service: str, method: str, *, kind: str, **kwargs: Any) -> None:
        self._budget()
        self._now()
        if self._calls + self._accepted_calls >= MAX_CALLS_PER_STEP:
            raise MapitBootstrapCoordinatorError("aws_call_failed")
        self._calls += 1
        try:
            response = getattr(self.clients[service], method)(**kwargs)
        except Exception as exc:
            code, status, message = _error(exc)
            exact = (
                kind == "stack" and code == "ValidationError" and status in (400, 404)
                and message == f"Stack with id {STACK_NAME} does not exist"
                or kind == "table" and code == "ResourceNotFoundException" and status == 400
                or kind in {"role", "policy", "role_policy"} and code == "NoSuchEntity" and status == 404
                or kind == "parameter" and code == "ParameterNotFound" and status == 400
            )
            self._now()
            self._budget()
            if exact:
                return
            raise MapitBootstrapCoordinatorError("aws_call_failed") from None
        if (not isinstance(response, Mapping) or not isinstance(response.get("ResponseMetadata"), Mapping)
                or type(response["ResponseMetadata"].get("HTTPStatusCode")) is not int
                or response["ResponseMetadata"]["HTTPStatusCode"] != 200):
            raise MapitBootstrapCoordinatorError("aws_response_invalid")
        self._now()
        self._budget()
        raise MapitBootstrapCoordinatorError("resource_conflict")

    def _identity(self) -> None:
        result = self._call("sts", "get_caller_identity")
        if (result.get("Account") != self.authority.account_id
                or result.get("Arn") != self.authority.expected_caller_arn):
            raise MapitBootstrapCoordinatorError("authority_invalid")

    def _external_evidence(self, callback: Callable[..., Mapping[str, Any]], category: str,
                           *args: Any, runtime_phase: str | None = None) -> None:
        self._budget()
        self._now()
        try:
            result = callback(*args, phase=runtime_phase) if runtime_phase is not None else callback(*args)
        except Exception:
            self._now()
            self._budget()
            raise MapitBootstrapCoordinatorError(category) from None
        self._now()
        self._budget()
        if runtime_phase is None:
            valid = (_valid_source_evidence(result, self.authority) if category == "source_unverified"
                     else _valid_protection_evidence(result, self.authority))
            calls = result.get("calls") if isinstance(result, Mapping) else None
            if type(calls) is int and 1 <= calls <= 8:
                self._accepted_calls += calls
        else:
            calls = result.get("calls") if isinstance(result, Mapping) else None
            if type(calls) is int and 1 <= calls <= 64:
                self._accepted_calls += calls
            valid = _valid_runtime_evidence(result, self.authority, runtime_phase)
        if not valid:
            raise MapitBootstrapCoordinatorError(category)
        if self._calls + self._accepted_calls > MAX_CALLS_PER_STEP:
            raise MapitBootstrapCoordinatorError("aws_call_failed")

    def _fresh_evidence(self, stage: str) -> None:
        self._external_evidence(self.fresh_source, "source_unverified", self.authority)
        self._external_evidence(self.fresh_protections, "protections_unverified", self.authority)
        self._external_evidence(self.closed_runtime_verifier, "runtime_unverified",
                                self.clients, self.authority, self.plan.template,
                                runtime_phase=stage)

    def _verify_key(self) -> None:
        key = self._call("kms", "describe_key", KeyId="alias/aws/ssm").get("KeyMetadata")
        if (not isinstance(key, Mapping) or key.get("Arn") != self.authority.ssm_key_arn
                or key.get("AWSAccountId") != self.authority.account_id
                or key.get("KeyManager") != "AWS" or key.get("Enabled") is not True
                or key.get("KeyState") != "Enabled" or key.get("KeyUsage") != "ENCRYPT_DECRYPT"):
            raise MapitBootstrapCoordinatorError("runtime_unverified")

    def _fixed_paths(self) -> tuple[str, ...]:
        return (CONFIG_PARAMETER,) + tuple(
            f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
            for key in self.authority._tenant_keys
        )

    def _check_absence(self) -> None:
        self._absent("cloudformation", "describe_stacks", kind="stack", StackName=STACK_NAME)
        self._absent("dynamodb", "describe_table", kind="table", TableName=STACK_NAME)
        self._absent("iam", "get_role", kind="role", RoleName=OPERATOR_ROLE_NAME)
        boundary_arn = f"arn:aws:iam::{self.authority.account_id}:policy/{OPERATOR_BOUNDARY_NAME}"
        self._absent("iam", "get_policy", kind="policy", PolicyArn=boundary_arn)
        self._absent("iam", "get_role_policy", kind="role_policy", RoleName=RUNTIME_ROLE_NAME,
                     PolicyName="honda-mapit-mcp-dev-mapit-identity-bindings-runtime-read")
        for path in self._fixed_paths():
            self._absent("ssm", "get_parameter", kind="parameter", Name=path, WithDecryption=False)

    def _preflight_reads(self) -> None:
        self._identity()
        self._fresh_evidence("preflight")
        self._verify_key()
        self._check_absence()

    def _state(self, *, last_epoch: int, preflight: bool,
               intent: Mapping[str, Any] | None, acknowledged: bool,
               stack_id: str | None, readback: bool,
               receipt: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return {
            "schema": 1, "kind": KIND, "environment": ENVIRONMENT,
            "namespace": NAMESPACE, "operation": OPERATION,
            "account_id": self.authority.account_id, "source_sha": self.authority.source_sha,
            "run_id": self.authority.run_id, "caller_arn": self.authority.expected_caller_arn,
            "authorized_from_epoch": self.authority.authorized_from_epoch,
            "authorized_until_epoch": self.authority.authorized_until_epoch,
            "ci_evidence_sha256": self.authority.ci_evidence_sha256,
            "runtime_evidence_sha256": self.authority.runtime_evidence_sha256,
            "authority_sha256": self.authority._binding_sha256,
            "template_sha256": self.plan.template_sha256,
            "last_observed_epoch": last_epoch, "preflight": preflight,
            "intent": dict(intent) if intent is not None else None,
            "acknowledged": acknowledged, "acknowledged_stack_id": stack_id,
            "readback": readback, "readback_receipt": dict(receipt) if receipt is not None else None,
        }

    def _load(self) -> dict[str, Any] | None:
        try:
            value = self.journal.load()
        except Exception:
            raise MapitBootstrapCoordinatorError("journal_invalid") from None
        if value is None:
            return None
        expected = set(self._state(last_epoch=0, preflight=False, intent=None,
                                   acknowledged=False, stack_id=None, readback=False))
        if not _exact_keys(value, expected):
            raise MapitBootstrapCoordinatorError("journal_invalid")
        fixed = self._state(last_epoch=value.get("last_observed_epoch"),
                            preflight=value.get("preflight"), intent=value.get("intent"),
                            acknowledged=value.get("acknowledged"),
                            stack_id=value.get("acknowledged_stack_id"),
                            readback=value.get("readback"), receipt=value.get("readback_receipt"))
        for key, item in fixed.items():
            if value.get(key) != item or type(value.get(key)) is not type(item):
                raise MapitBootstrapCoordinatorError("journal_invalid")
        if (type(value["last_observed_epoch"]) is not int
                or any(type(value[k]) is not bool for k in ("preflight", "acknowledged", "readback"))):
            raise MapitBootstrapCoordinatorError("journal_invalid")
        intent = value["intent"]
        if intent is not None and not validate_intent(intent, self.authority, self.plan):
            raise MapitBootstrapCoordinatorError("journal_invalid")
        stack_id = value["acknowledged_stack_id"]
        if stack_id is not None:
            match = _STACK_ARN.fullmatch(stack_id) if type(stack_id) is str else None
            if match is None or match.group(1) != self.authority.account_id:
                raise MapitBootstrapCoordinatorError("journal_invalid")
        if (value["acknowledged"] != (intent is not None and stack_id is not None)
                or stack_id is not None and intent is None
                or value["readback"] and (not value["acknowledged"] or not value["preflight"])
                or intent is not None and not value["preflight"]):
            raise MapitBootstrapCoordinatorError("journal_invalid")
        receipt = value["readback_receipt"]
        if value["readback"]:
            if (not _exact_keys(receipt, {"stack_id", "template_sha256", "table_id", "table_created_at_utc"})
                    or receipt.get("stack_id") != stack_id
                    or receipt.get("template_sha256") != self.plan.template_sha256
                    or type(receipt.get("table_id")) is not str or _TABLE_ID.fullmatch(receipt["table_id"]) is None
                    or not self._valid_creation_receipt_time(receipt.get("table_created_at_utc"))):
                raise MapitBootstrapCoordinatorError("journal_invalid")
        elif receipt is not None:
            raise MapitBootstrapCoordinatorError("journal_invalid")
        return dict(value)

    def _save(self, *, preflight: bool, intent: Mapping[str, Any] | None,
              acknowledged: bool, stack_id: str | None, readback: bool,
              receipt: Mapping[str, Any] | None = None) -> None:
        self._now()
        self._budget()
        state = self._state(last_epoch=self._last_epoch, preflight=preflight, intent=intent,
                            acknowledged=acknowledged, stack_id=stack_id, readback=readback,
                            receipt=receipt)
        try:
            self.journal.save(state)
        except Exception:
            self._invalid = True
            raise MapitBootstrapCoordinatorError("journal_failed") from None
        self._now()
        self._budget()

    def _preflight(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is not None and state.get("intent") is not None:
            raise MapitBootstrapCoordinatorError("preflight_conflict")
        self._preflight_reads()
        self._save(preflight=True, intent=None, acknowledged=False, stack_id=None, readback=False)
        return self._safe("preflight", True, "preflight_verified")

    def _create_token(self) -> str:
        return create_only_intent(self.authority, self.plan, journal_state=None,
                                  window=self.window)["client_request_token"]

    def _create(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("preflight") is not True:
            raise MapitBootstrapCoordinatorError("preflight_required")
        if state.get("intent") is not None:
            raise MapitBootstrapCoordinatorError("create_intent_present")
        # Re-read source, protections, current closed runtime and every absence
        # immediately before consuming the sole create allowance.
        self._preflight_reads()
        intent = create_only_intent(self.authority, self.plan,
                                    journal_state=None, window=self.window)
        self._save(preflight=True, intent=intent, acknowledged=False,
                   stack_id=None, readback=False)
        # Bind caller identity again after the durable one-shot intent and as
        # close as possible to the sole CloudFormation dispatch.
        self._identity()
        self._now()
        self._budget()
        self._now()
        if self._calls + self._accepted_calls >= MAX_CALLS_PER_STEP:
            raise MapitBootstrapCoordinatorError("aws_call_failed")
        self._calls += 1
        template_body = self.plan.template_json
        try:
            response = self.clients["cloudformation"].create_stack(
                StackName=STACK_NAME, TemplateBody=template_body,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                ClientRequestToken=intent["client_request_token"],
                EnableTerminationProtection=True,
                Tags=[{"Key": "Project", "Value": "honda-mapit-mcp"},
                      {"Key": "Environment", "Value": ENVIRONMENT},
                      {"Key": "Purpose", "Value": "mapit-enrolled-identity-bindings"},
                      {"Key": "OperatorRunId", "Value": str(self.authority.run_id)}],
            )
        except Exception:
            self._now()
            self._budget()
            raise MapitBootstrapCoordinatorError("create_outcome_unknown") from None
        self._now()
        self._budget()
        stack_id = response.get("StackId") if isinstance(response, Mapping) else None
        metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
        match = _STACK_ARN.fullmatch(stack_id) if type(stack_id) is str else None
        if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
                or metadata["HTTPStatusCode"] != 200 or match is None
                or match.group(1) != self.authority.account_id):
            raise MapitBootstrapCoordinatorError("create_outcome_unknown")
        self._save(preflight=True, intent=intent, acknowledged=True,
                   stack_id=stack_id, readback=False)
        return self._safe("create", True, "create_acknowledged")

    def _readback(self, state: dict[str, Any] | None) -> dict[str, Any]:
        if state is None or state.get("intent") is None:
            raise MapitBootstrapCoordinatorError("preflight_required")
        self._identity()
        self._fresh_evidence("readback")
        stack_reply = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME)
        rows = stack_reply.get("Stacks")
        if type(rows) is not list or len(rows) != 1 or not isinstance(rows[0], Mapping):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        stack = rows[0]
        stack_id = stack.get("StackId")
        match = _STACK_ARN.fullmatch(stack_id) if type(stack_id) is str else None
        if (match is None or match.group(1) != self.authority.account_id
                or stack.get("StackName") != STACK_NAME):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        if state.get("acknowledged") and state.get("acknowledged_stack_id") != stack_id:
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        if stack.get("StackStatus") == "CREATE_IN_PROGRESS":
            raise MapitBootstrapCoordinatorError("stack_in_progress")
        if stack.get("StackStatus") != "CREATE_COMPLETE":
            raise MapitBootstrapCoordinatorError("stack_not_complete")
        if stack.get("EnableTerminationProtection") is not True or stack.get("RoleARN") not in (None, ""):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": ENVIRONMENT,
                         "Purpose": "mapit-enrolled-identity-bindings",
                         "OperatorRunId": str(self.authority.run_id)}
        tags = stack.get("Tags")
        if (type(tags) is not list or len(tags) != len(expected_tags)
                or any(not isinstance(row, Mapping) or set(row) != {"Key", "Value"} for row in tags)
                or {row["Key"]: row["Value"] for row in tags} != expected_tags):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        template_reply = self._call("cloudformation", "get_template",
                                    StackName=STACK_NAME, TemplateStage="Original")
        actual_template = template_reply.get("TemplateBody")
        if isinstance(actual_template, str):
            try:
                actual_template = json.loads(actual_template, object_pairs_hook=self._unique_object)
            except Exception:
                actual_template = None
        if not isinstance(actual_template, Mapping) or _canonical(actual_template) != self.plan.template_json.encode("ascii"):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        events = self._call("cloudformation", "describe_stack_events", StackName=STACK_NAME)
        event_rows = events.get("StackEvents")
        if (type(event_rows) is not list or not 1 <= len(event_rows) <= 100
                or not self._matching_create_event(event_rows, stack_id,
                                                    state["intent"]["client_request_token"])):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        resource_reply = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME)
        resources = resource_reply.get("StackResources")
        if type(resources) is not list or len(resources) != len(_EXPECTED_TYPES):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        by_name: dict[str, Mapping[str, Any]] = {}
        for row in resources:
            if (not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str
                    or row["LogicalResourceId"] in by_name
                    or _EXPECTED_TYPES.get(row["LogicalResourceId"]) != row.get("ResourceType")
                    or row.get("ResourceStatus") != "CREATE_COMPLETE"
                    or row.get("StackId") != stack_id or row.get("StackName") != STACK_NAME
                    or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]):
                raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
            by_name[row["LogicalResourceId"]] = row
        if set(by_name) != set(_EXPECTED_TYPES):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        account = self.authority.account_id
        boundary_arn = f"arn:aws:iam::{account}:policy/{OPERATOR_BOUNDARY_NAME}"
        expected_physical = {
            "MapitIdentityBindings": STACK_NAME,
            "IdentityEnrollerBoundary": boundary_arn,
            "IdentityEnrollerRole": OPERATOR_ROLE_NAME,
        }
        if any(by_name[key]["PhysicalResourceId"] != val for key, val in expected_physical.items()):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        table_id, created_at_utc = self._verify_table(
            by_name["MapitIdentityBindings"]["PhysicalResourceId"], stack_id)
        receipt = {"stack_id": stack_id, "template_sha256": self.plan.template_sha256,
                   "table_id": table_id, "table_created_at_utc": created_at_utc}
        if state.get("readback") is True and state.get("readback_receipt") != receipt:
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        self._verify_iam(boundary_arn)
        self._verify_key()
        self._verify_parameters_absent()
        self._save(preflight=True, intent=state["intent"], acknowledged=True,
                   stack_id=stack_id, readback=True, receipt=receipt)
        return self._safe("readback", True, "readback_verified")

    def _matching_create_event(self, events: list[Any], stack_id: str, token: str) -> bool:
        matches = []
        for event in events:
            if (not isinstance(event, Mapping)
                    or event.get("ClientRequestToken") != token
                    or event.get("StackId") != stack_id
                    or event.get("StackName") != STACK_NAME
                    or event.get("LogicalResourceId") != STACK_NAME
                    or event.get("PhysicalResourceId") != stack_id
                    or event.get("ResourceType") != "AWS::CloudFormation::Stack"
                    or event.get("ResourceStatus") != "CREATE_COMPLETE"):
                continue
            stamp = event.get("Timestamp")
            if not isinstance(stamp, datetime) or stamp.tzinfo is None:
                continue
            epoch = stamp.astimezone(timezone.utc).timestamp()
            if self.authority.authorized_from_epoch <= epoch < self.authority.authorized_until_epoch:
                matches.append(event)
        return len(matches) == 1

    def _verify_table(self, name: str, stack_id: str) -> tuple[str, str]:
        response = self._call("dynamodb", "describe_table", TableName=name)
        table = response.get("Table")
        props = self.plan.template["Resources"]["MapitIdentityBindings"]["Properties"]
        expected_arn = f"arn:aws:dynamodb:{REGION}:{self.authority.account_id}:table/{STACK_NAME}"
        if (not isinstance(table, Mapping) or table.get("TableName") != STACK_NAME
                or table.get("TableArn") != expected_arn or table.get("TableStatus") != "ACTIVE"
                or table.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST"
                or table.get("OnDemandThroughput") != props.get("OnDemandThroughput")
                or table.get("KeySchema") != props.get("KeySchema")
                or table.get("AttributeDefinitions") != props.get("AttributeDefinitions")
                or table.get("DeletionProtectionEnabled") is not props.get("DeletionProtectionEnabled")
                or table.get("SSEDescription") is not None
                or table.get("GlobalSecondaryIndexes") not in (None, [])
                or table.get("LocalSecondaryIndexes") not in (None, [])):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        table_id = table.get("TableId")
        created = table.get("CreationDateTime")
        if (type(table_id) is not str or _TABLE_ID.fullmatch(table_id) is None
                or not isinstance(created, datetime) or created.tzinfo is None):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        created_utc = created.astimezone(timezone.utc)
        created_epoch = created_utc.timestamp()
        if not self.authority.authorized_from_epoch <= created_epoch < self.authority.authorized_until_epoch:
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        created_text = created_utc.isoformat(timespec="microseconds")
        tags_reply = self._call("dynamodb", "list_tags_of_resource", ResourceArn=expected_arn)
        tags = tags_reply.get("Tags")
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev",
                         "Purpose": "mapit-enrolled-identity-bindings",
                         "OperatorRunId": str(self.authority.run_id)}
        optional_cfn_tags = {
            "aws:cloudformation:stack-id": stack_id,
            "aws:cloudformation:stack-name": STACK_NAME,
            "aws:cloudformation:logical-id": "MapitIdentityBindings",
        }
        if type(tags) is not list or tags_reply.get("NextToken") not in (None, ""):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        observed_tags: dict[str, str] = {}
        for tag in tags:
            if (not isinstance(tag, Mapping) or set(tag) != {"Key", "Value"}
                    or type(tag.get("Key")) is not str or type(tag.get("Value")) is not str
                    or tag["Key"] in observed_tags):
                raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
            observed_tags[tag["Key"]] = tag["Value"]
        if (any(observed_tags.get(key) != value for key, value in expected_tags.items())
                or any(value != optional_cfn_tags[key]
                       for key, value in observed_tags.items()
                       if key in optional_cfn_tags)
                or set(observed_tags) - set(expected_tags) - set(optional_cfn_tags)):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        item = self._call("dynamodb", "get_item", TableName=expected_arn,
                          Key={"key": {"S": "identity-bindings-v1"}},
                          ConsistentRead=True, ReturnConsumedCapacity="NONE")
        if set(item) - {"ResponseMetadata"}:
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        return table_id, created_text

    def _valid_creation_receipt_time(self, value: Any) -> bool:
        if type(value) is not str or len(value) > 40:
            return False
        try:
            created = datetime.fromisoformat(value)
        except Exception:
            return False
        if created.tzinfo is None or created.utcoffset() != timezone.utc.utcoffset(created):
            return False
        canonical = created.astimezone(timezone.utc).isoformat(timespec="microseconds")
        epoch = created.timestamp()
        return (value == canonical and math.isfinite(epoch)
                and self.authority.authorized_from_epoch <= epoch < self.authority.authorized_until_epoch)

    def _verify_iam(self, boundary_arn: str) -> None:
        template = self.plan.template["Resources"]
        role = self._call("iam", "get_role", RoleName=OPERATOR_ROLE_NAME).get("Role")
        role_props = template["IdentityEnrollerRole"]["Properties"]
        if (not isinstance(role, Mapping) or role.get("RoleName") != OPERATOR_ROLE_NAME
                or role.get("Arn") != f"arn:aws:iam::{self.authority.account_id}:role/{OPERATOR_ROLE_NAME}"
                or role.get("Path") != "/" or role.get("MaxSessionDuration") != 3600
                or not isinstance(role.get("PermissionsBoundary"), Mapping)
                or set(role["PermissionsBoundary"]) != {"PermissionsBoundaryArn", "PermissionsBoundaryType"}
                or role["PermissionsBoundary"].get("PermissionsBoundaryArn") != boundary_arn
                or role["PermissionsBoundary"].get("PermissionsBoundaryType") not in {"Policy", "PermissionsBoundaryPolicy"}):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        actual_trust = self._decode_document(role.get("AssumeRolePolicyDocument"))
        if actual_trust is None or _canonical(actual_trust) != _canonical(role_props["AssumeRolePolicyDocument"]):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        inline = self._call("iam", "get_role_policy", RoleName=OPERATOR_ROLE_NAME,
                            PolicyName=OPERATOR_ROLE_NAME + "-policy")
        actual_inline = self._decode_document(inline.get("PolicyDocument"))
        expected_inline = role_props["Policies"][0]["PolicyDocument"]
        if actual_inline is None or _canonical(actual_inline) != _canonical(expected_inline):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        inline_names = self._call("iam", "list_role_policies", RoleName=OPERATOR_ROLE_NAME)
        if (type(inline_names.get("PolicyNames")) is not list
                or inline_names["PolicyNames"] != [OPERATOR_ROLE_NAME + "-policy"]
                or inline_names.get("IsTruncated", False) is not False
                or inline_names.get("Marker") not in (None, "")):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        attached = self._call("iam", "list_attached_role_policies", RoleName=OPERATOR_ROLE_NAME)
        if (type(attached.get("AttachedPolicies")) is not list
                or attached["AttachedPolicies"] != []
                or attached.get("IsTruncated", False) is not False
                or attached.get("Marker") not in (None, "")):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        boundary = self._call("iam", "get_policy", PolicyArn=boundary_arn).get("Policy")
        if (not isinstance(boundary, Mapping) or boundary.get("Arn") != boundary_arn
                or boundary.get("PolicyName") != OPERATOR_BOUNDARY_NAME
                or boundary.get("Path") != "/" or boundary.get("DefaultVersionId") != "v1"):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        version = self._call("iam", "get_policy_version", PolicyArn=boundary_arn,
                             VersionId="v1").get("PolicyVersion")
        # Only one default version is accepted; unused/non-default versions are
        # not silently treated as the active permissions boundary.
        if not isinstance(version, Mapping) or version.get("IsDefaultVersion") is not True:
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        expected_boundary = template["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
        actual_boundary = self._decode_document(version.get("Document") if isinstance(version, Mapping) else None)
        if actual_boundary is None or _canonical(actual_boundary) != _canonical(expected_boundary):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")
        runtime = template["RuntimeIdentityBindingPolicy"]["Properties"]
        actual_runtime = self._decode_document(self._call(
            "iam", "get_role_policy", RoleName=RUNTIME_ROLE_NAME,
            PolicyName=runtime["PolicyName"]).get("PolicyDocument"))
        if actual_runtime is None or _canonical(actual_runtime) != _canonical(runtime["PolicyDocument"]):
            raise MapitBootstrapCoordinatorError("stack_readback_mismatch")

    def _verify_parameters_absent(self) -> None:
        for path in self._fixed_paths():
            self._absent("ssm", "get_parameter", kind="parameter", Name=path, WithDecryption=False)

    @staticmethod
    def _decode_document(value: Any) -> Mapping[str, Any] | None:
        if isinstance(value, Mapping):
            return value
        if type(value) is not str or len(value) > 256 * 1024:
            return None
        try:
            raw = unquote_to_bytes(value)
            if len(raw) > 64 * 1024:
                return None
            def unique(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError
                    result[key] = item
                return result
            decoded = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique)
            return decoded if isinstance(decoded, Mapping) else None
        except Exception:
            return None

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        decoded: dict[str, Any] = {}
        for key, value in pairs:
            if key in decoded:
                raise ValueError("duplicate_json_key")
            decoded[key] = value
        return decoded

    def run_step(self, step: str) -> dict[str, Any]:
        if type(step) is not str or step not in self.STEPS:
            return self._safe("unknown", False, "step_invalid")
        try:
            with self.journal.locked():
                start = self.monotonic()
                if (type(start) not in (int, float) or isinstance(start, bool)
                        or not math.isfinite(start) or start < 0):
                    raise MapitBootstrapCoordinatorError("window_invalid")
                self._started = self._last_mono = float(start)
                self._calls = self._accepted_calls = 0
                self._invalid = False
                state = self._load()
                if state is not None:
                    self._last_epoch = state["last_observed_epoch"]
                self._now()
                if step == "preflight":
                    return self._preflight(state)
                if step == "create":
                    return self._create(state)
                return self._readback(state)
        except MapitBootstrapCoordinatorError as exc:
            return self._safe(step, False, exc.category)
        except MapitBootstrapContractError as exc:
            categories = {
                "clock_invalid": "window_invalid", "clock_rollback": "window_invalid",
                "window_not_open": "window_expired", "journal_consumed": "create_intent_present",
            }
            return self._safe(step, False, categories.get(exc.category, "authority_invalid"))
        except Exception:
            return self._safe(step, False, "operator_internal_error")

__all__ = ["MapitBootstrapCoordinator", "MapitBootstrapCoordinatorError"]
