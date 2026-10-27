"""Pure, bounded data model for the retained-dev delivery contract."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

MAX_RECEIPT_BYTES = 64 * 1024
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_APP_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:[0-9]{12}:stack/honda-mapit-mcp-dev-retained/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_ARTIFACT_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:[0-9]{12}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_CONTROLS_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:[0-9]{12}:stack/honda-mapit-mcp-dev-retained-controls/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_BUCKET = re.compile(r"honda-mapit-mcp-dev-retained-[0-9]{12}-eu-west-1\Z")
_CFN_ROLE = re.compile(r"arn:aws:iam::[0-9]{12}:role/honda-mapit-mcp-dev-retained-cfn-update\Z")
_RECEIPT_KINDS = {"controls", "artifact", "prior-template", "prior-code", "lambda", "api", "iam"}
_RECEIPT_MODES = {"read_only", "bounded_write", "unknown"}
_RECEIPT_STATES = {"closed", "open", "unknown"}
_RESOURCE_FIELDS = {
    "controls": {"stack_id", "stack_status", "termination_protection", "role_arn", "resource_types", "resources", "template", "stack_tags", "stack_events", "shutdown_state_machine", "shutdown_state_machine_tags", "tripwire_rule", "tripwire_rule_tags", "tripwire_targets", "tripwire_alarm", "tripwire_alarm_tags", "control_roles"},
    "artifact": {
        "stack_id", "stack_status", "termination_protection", "role_arn", "resource_types", "resources", "template", "stack_tags", "bucket", "location", "public_access_block",
        "encryption", "ownership", "versioning", "lifecycle", "policy_status", "tags", "policy", "stack_events",
    },
    "prior-template": {"stack_id", "template_sha256", "stack_status", "termination_protection", "role_arn", "resource_types", "resources", "template", "stack_tags"},
    "prior-code": {"function_name", "code_sha256", "source"},
    "lambda": {"function_name", "code_sha256", "reserved_concurrency", "state", "configuration", "tags"},
    "api": {"api_id", "name", "protocol", "disabled", "routes_empty"},
    "iam": {
        "role_name", "role_arn", "path", "tags", "trust_policy", "policy_name",
        "policy_document", "attached_policy_names", "boundary_arn", "boundary_name",
        "boundary_path", "boundary_document", "boundary_version_id", "boundary_type",
    },
}


class DeliveryContractError(ValueError):
    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise DeliveryContractError("receipt_invalid") from None
    if len(raw) > MAX_RECEIPT_BYTES:
        raise DeliveryContractError("receipt_too_large")
    return raw


def _mapping(value: Any, name: str) -> dict[str, Any]:
    # Dataclass replacement/revalidation may pass the already-frozen receipt
    # back in. Normalize MappingProxyType/tuple snapshots before applying the
    # strict wire-shape checks; never let freezing make a valid binding
    # impossible to reload.
    value = _thaw(value)
    if not isinstance(value, Mapping) or any(type(k) is not str for k in value):
        raise DeliveryContractError(f"{name}_invalid")
    result = dict(value)
    expected_kind = {"prior_template": "prior-template", "prior_code": "prior-code"}.get(name, name)
    closure = result.get("closure")
    permissions = result.get("permissions")
    if set(result) != {"kind", "observed_at_epoch", "source", "resource", "closure", "permissions"} or result.get("kind") != expected_kind or result.get("kind") not in _RECEIPT_KINDS or type(result.get("observed_at_epoch")) is not int or result["observed_at_epoch"] <= 0 or result.get("source") != "aws-readback" or not isinstance(result.get("resource"), Mapping) or not result["resource"] or not isinstance(closure, Mapping) or set(closure) != {"state", "checks"} or closure.get("state") != "closed" or not isinstance(closure.get("checks"), Mapping) or not closure["checks"] or not isinstance(permissions, Mapping) or set(permissions) != {"mode", "checks"} or permissions.get("mode") != "read_only" or not isinstance(permissions.get("checks"), Mapping) or not permissions["checks"]:
        raise DeliveryContractError(f"{name}_invalid")
    resource = result["resource"]
    required_resource_fields = _RESOURCE_FIELDS[result["kind"]]
    if set(resource) != required_resource_fields or any(type(key) is not str for key in resource):
        raise DeliveryContractError(f"{name}_invalid")
    # The receipt is a private inventory, not a free-form assertion.  Require
    # non-empty identifiers and mappings where the later readback compares
    # structured AWS documents.  Values remain opaque to this pure model.
    for key in ("stack_id", "bucket", "function_name", "api_id", "role_name", "boundary_arn"):
        if key in resource and (type(resource[key]) is not str or not resource[key]):
            raise DeliveryContractError(f"{name}_invalid")
    if "role_arn" in resource and resource["role_arn"] is not None and (type(resource["role_arn"]) is not str or not resource["role_arn"]):
        raise DeliveryContractError(f"{name}_invalid")
    for key in ("trust_policy", "policy", "policy_document", "boundary_document", "configuration", "template"):
        if key in resource and not isinstance(resource[key], Mapping):
            raise DeliveryContractError(f"{name}_invalid")
    for key in ("resources", "stack_tags", "stack_events", "shutdown_state_machine_tags", "tripwire_rule_tags", "tripwire_targets", "tripwire_alarm_tags", "tags"):
        if key in resource and not isinstance(resource[key], list):
            raise DeliveryContractError(f"{name}_invalid")
    for key in ("shutdown_state_machine", "tripwire_rule", "tripwire_alarm", "control_roles"):
        if key in resource and not isinstance(resource[key], Mapping):
            raise DeliveryContractError(f"{name}_invalid")
    _canonical(result)
    return result


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class RetainedDevDeliveryBinding:
    account_id: str
    source_sha: str
    run_id: str
    authorized_from_epoch: int
    authorized_until_epoch: int
    expected_caller_arn: str
    app_stack_arn: str
    artifact_stack_arn: str
    controls_stack_arn: str
    artifact_bucket: str
    cfn_role_arn: str
    controls_receipt: Mapping[str, Any]
    artifact_receipt: Mapping[str, Any]
    prior_template_receipt: Mapping[str, Any]
    prior_code_receipt: Mapping[str, Any]
    lambda_receipt: Mapping[str, Any]
    api_receipt: Mapping[str, Any]
    iam_receipt: Mapping[str, Any]

    def __post_init__(self) -> None:
        if type(self.account_id) is not str or _ACCOUNT.fullmatch(self.account_id) is None or self.account_id == "000000000000":
            raise DeliveryContractError("account_invalid")
        if type(self.source_sha) is not str or _SHA1.fullmatch(self.source_sha) is None or self.source_sha == "0" * 40:
            raise DeliveryContractError("source_invalid")
        if type(self.run_id) is not str or _UUID.fullmatch(self.run_id) is None:
            raise DeliveryContractError("run_invalid")
        if type(self.authorized_from_epoch) is not int or type(self.authorized_until_epoch) is not int or isinstance(self.authorized_from_epoch, bool) or isinstance(self.authorized_until_epoch, bool) or self.authorized_from_epoch <= 0 or self.authorized_until_epoch <= self.authorized_from_epoch or self.authorized_until_epoch - self.authorized_from_epoch > 3600:
            raise DeliveryContractError("window_invalid")
        if type(self.expected_caller_arn) is not str or not re.fullmatch(rf"arn:aws:(?:iam|sts)::{self.account_id}:(?:user|role)/[^\s:/]+|arn:aws:sts::{self.account_id}:assumed-role/[^\s:/]+/[^\s:/]+", self.expected_caller_arn):
            raise DeliveryContractError("caller_invalid")
        if type(self.app_stack_arn) is not str or _APP_STACK.fullmatch(self.app_stack_arn) is None or self.app_stack_arn.split(":")[4] != self.account_id:
            raise DeliveryContractError("app_stack_invalid")
        if type(self.artifact_stack_arn) is not str or _ARTIFACT_STACK.fullmatch(self.artifact_stack_arn) is None or self.artifact_stack_arn.split(":")[4] != self.account_id or type(self.controls_stack_arn) is not str or _CONTROLS_STACK.fullmatch(self.controls_stack_arn) is None or self.controls_stack_arn.split(":")[4] != self.account_id or type(self.artifact_bucket) is not str or _BUCKET.fullmatch(self.artifact_bucket) is None or type(self.cfn_role_arn) is not str or _CFN_ROLE.fullmatch(self.cfn_role_arn) is None or self.cfn_role_arn.split(":")[4] != self.account_id:
            raise DeliveryContractError("resource_binding_invalid")
        for value, name, field_name in ((self.controls_receipt, "controls", "controls_receipt"), (self.artifact_receipt, "artifact", "artifact_receipt"), (self.prior_template_receipt, "prior_template", "prior_template_receipt"), (self.prior_code_receipt, "prior_code", "prior_code_receipt"), (self.lambda_receipt, "lambda", "lambda_receipt"), (self.api_receipt, "api", "api_receipt"), (self.iam_receipt, "iam", "iam_receipt")):
            object.__setattr__(self, field_name, _freeze(_mapping(value, name)))
        controls = self.controls_receipt["resource"]
        artifact = self.artifact_receipt["resource"]
        prior_template = self.prior_template_receipt["resource"]
        if (
            controls.get("stack_id") != self.controls_stack_arn
            or artifact.get("stack_id") != self.artifact_stack_arn
            or prior_template.get("stack_id") != self.app_stack_arn
            or artifact.get("bucket") != self.artifact_bucket
            or artifact.get("location") != "eu-west-1"
        ):
            raise DeliveryContractError("receipt_binding_invalid")

    def __repr__(self) -> str:
        return "RetainedDevDeliveryBinding(<redacted>)"

    @property
    def binding_sha256(self) -> str:
        return hashlib.sha256(_canonical(_thaw(self.__dict__))).hexdigest()


@dataclass(frozen=True)
class DeliveryIntent:
    operation: str
    run_id: str
    template_sha256: str
    artifact_key: str
    prior_closed_template_sha256: str

    def __post_init__(self) -> None:
        if self.operation not in {"publish", "update", "recovery"} or _UUID.fullmatch(self.run_id) is None or _SHA256.fullmatch(self.template_sha256) is None or not re.fullmatch(r"runtime/[0-9a-f]{64}\.zip\Z", self.artifact_key) or _SHA256.fullmatch(self.prior_closed_template_sha256) is None:
            raise DeliveryContractError("intent_invalid")
