"""Pure, non-deploying contract for a fresh MAPIT namespace bootstrap.

This module validates a proposed authority, binds the fixed MAPIT bootstrap
template to explicit source/CI/runtime evidence digests, and can construct a
single create-only intent record. It performs no file, network, AWS, or journal
I/O and is not a cloud-state validator or permission to deploy.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from scripts.build_aws_dev_mapit_binding_bootstrap import (
    STACK_NAME,
    build_dev_mapit_binding_bootstrap,
)

SCHEMA = 1
KIND = "dev-mapit-identity-binding-bootstrap"
ENVIRONMENT = "dev"
NAMESPACE = "mapit"
OPERATION = "create-stack-once"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_USER_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+\Z")
_KMS_ARN = re.compile(r"arn:aws:kms:eu-west-1:([0-9]{12}):key/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")


class MapitBootstrapContractError(ValueError):
    """A fixed, non-sensitive contract failure category."""

    _CATEGORIES = frozenset({
        "authority_invalid", "evidence_invalid", "window_invalid",
        "clock_invalid", "clock_rollback", "window_not_open",
        "plan_invalid", "journal_consumed", "intent_invalid",
    })

    def __init__(self, category: str):
        safe = category if type(category) is str and category in self._CATEGORIES else "authority_invalid"
        self.category = safe
        super().__init__(safe)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _valid_key_tuple(value: Any, *, maximum: int) -> bool:
    return (
        type(value) is tuple
        and 1 <= len(value) <= maximum
        and all(type(item) is str and _TENANT_KEY.fullmatch(item) for item in value)
        and len(set(value)) == len(value)
    )


@dataclass(frozen=True, repr=False)
class MapitBootstrapAuthority:
    """Validated, fresh MAPIT namespace authority; evidence values are digests only."""

    account_id: str
    operator_user_arn: str
    source_sha: str
    run_id: int
    expected_caller_arn: str
    authorized_from_epoch: int
    authorized_until_epoch: int
    ci_evidence_sha256: str
    runtime_evidence_sha256: str
    ssm_key_arn: str
    _tenant_keys: tuple[str, ...] = field(repr=False)
    _excluded_tenant_keys: tuple[str, ...] = field(repr=False)
    _binding_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return "MapitBootstrapAuthority(<validated; identifiers redacted>)"


def make_authority(*, account_id: str, operator_user_arn: str, source_sha: str,
                   run_id: int, expected_caller_arn: str,
                   authorized_from_epoch: int, authorized_until_epoch: int,
                   ci_evidence_sha256: str, runtime_evidence_sha256: str,
                   ssm_key_arn: str, tenant_keys: tuple[str, ...],
                   excluded_tenant_keys: tuple[str, ...]) -> MapitBootstrapAuthority:
    """Validate exact inputs; evidence hashes are references, not verified evidence."""
    valid = (
        type(account_id) is str and _ACCOUNT.fullmatch(account_id) is not None
        and account_id != "000000000000"
        and type(operator_user_arn) is str and _USER_ARN.fullmatch(operator_user_arn) is not None
        and _USER_ARN.fullmatch(operator_user_arn).group(1) == account_id
        and type(expected_caller_arn) is str and expected_caller_arn == operator_user_arn
        and type(source_sha) is str and _SHA40.fullmatch(source_sha) is not None and set(source_sha) != {"0"}
        and type(run_id) is int and not isinstance(run_id, bool) and run_id > 0
        and type(authorized_from_epoch) is int and not isinstance(authorized_from_epoch, bool)
        and type(authorized_until_epoch) is int and not isinstance(authorized_until_epoch, bool)
        and authorized_from_epoch > 0
        and 0 < authorized_until_epoch - authorized_from_epoch <= 600
        and type(ci_evidence_sha256) is str and _SHA256.fullmatch(ci_evidence_sha256) is not None
        and type(runtime_evidence_sha256) is str and _SHA256.fullmatch(runtime_evidence_sha256) is not None
        and type(ssm_key_arn) is str and _KMS_ARN.fullmatch(ssm_key_arn) is not None
        and _KMS_ARN.fullmatch(ssm_key_arn).group(1) == account_id
        and _valid_key_tuple(tenant_keys, maximum=8)
        and _valid_key_tuple(excluded_tenant_keys, maximum=16)
        and not (set(tenant_keys) & set(excluded_tenant_keys))
    )
    if not valid:
        raise MapitBootstrapContractError("authority_invalid")

    public_binding = {
        "schema": SCHEMA, "kind": KIND, "environment": ENVIRONMENT,
        "namespace": NAMESPACE, "operation": OPERATION,
        "account_id": account_id, "operator_user_arn": operator_user_arn,
        "source_sha": source_sha, "run_id": run_id,
        "expected_caller_arn": expected_caller_arn,
        "authorized_from_epoch": authorized_from_epoch,
        "authorized_until_epoch": authorized_until_epoch,
        "ci_evidence_sha256": ci_evidence_sha256,
        "runtime_evidence_sha256": runtime_evidence_sha256,
        "ssm_key_arn": ssm_key_arn,
        "tenant_keys": list(tenant_keys),
        "excluded_tenant_keys": list(excluded_tenant_keys),
    }
    return MapitBootstrapAuthority(
        account_id, operator_user_arn, source_sha, run_id, expected_caller_arn,
        authorized_from_epoch, authorized_until_epoch, ci_evidence_sha256,
        runtime_evidence_sha256, ssm_key_arn, tenant_keys, excluded_tenant_keys,
        _digest(public_binding),
    )


def _validate_authority(authority: Any) -> MapitBootstrapAuthority:
    """Recompute the seal at each trust boundary; frozen dataclasses can be copied."""
    if type(authority) is not MapitBootstrapAuthority:
        raise MapitBootstrapContractError("authority_invalid")
    try:
        checked = make_authority(
            account_id=authority.account_id,
            operator_user_arn=authority.operator_user_arn,
            source_sha=authority.source_sha,
            run_id=authority.run_id,
            expected_caller_arn=authority.expected_caller_arn,
            authorized_from_epoch=authority.authorized_from_epoch,
            authorized_until_epoch=authority.authorized_until_epoch,
            ci_evidence_sha256=authority.ci_evidence_sha256,
            runtime_evidence_sha256=authority.runtime_evidence_sha256,
            ssm_key_arn=authority.ssm_key_arn,
            tenant_keys=authority._tenant_keys,
            excluded_tenant_keys=authority._excluded_tenant_keys,
        )
    except Exception:
        raise MapitBootstrapContractError("authority_invalid") from None
    if checked._binding_sha256 != authority._binding_sha256:
        raise MapitBootstrapContractError("authority_invalid")
    return checked


@dataclass(frozen=True, repr=False)
class MapitBootstrapPlan:
    """Pure template snapshot; callers get a fresh decoded copy on access."""

    template_json: str = field(repr=False)
    template_sha256: str
    authority_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return "MapitBootstrapPlan(<template redacted>)"

    @property
    def template(self) -> dict[str, Any]:
        try:
            value = json.loads(self.template_json)
        except Exception:
            raise MapitBootstrapContractError("plan_invalid") from None
        if type(value) is not dict:
            raise MapitBootstrapContractError("plan_invalid")
        return value


def build_plan(authority: MapitBootstrapAuthority) -> MapitBootstrapPlan:
    """Build only the pinned four-resource MAPIT factory template."""
    authority = _validate_authority(authority)
    try:
        template = build_dev_mapit_binding_bootstrap(
            account_id=authority.account_id,
            operator_user_arn=authority.operator_user_arn,
            tenant_keys=authority._tenant_keys,
            excluded_tenant_keys=authority._excluded_tenant_keys,
            ssm_key_arn=authority.ssm_key_arn,
        )
        encoded = _canonical(template).decode("utf-8")
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        if template.get("Metadata", {}).get("Readiness") != "NOT_DEPLOY_READY":
            raise ValueError
    except Exception:
        raise MapitBootstrapContractError("plan_invalid") from None
    return MapitBootstrapPlan(encoded, digest, authority._binding_sha256)


class ExclusiveWindow:
    """In-process wall/monotonic guard for one exclusive authorization window."""

    __slots__ = ("_wall", "_mono", "_last_wall", "_last_mono", "_wall_origin",
                 "_mono_origin", "_authority_sha256", "_invalid")

    def __init__(self, authority: MapitBootstrapAuthority, *,
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        authority = _validate_authority(authority)
        if not callable(wall_clock) or not callable(monotonic):
            raise MapitBootstrapContractError("authority_invalid")
        self._wall = wall_clock
        self._mono = monotonic
        self._last_wall: float | None = None
        self._last_mono: float | None = None
        self._wall_origin: float | None = None
        self._mono_origin: float | None = None
        self._invalid = False
        self._authority_sha256 = authority._binding_sha256
        self.check(authority)

    def check(self, authority: MapitBootstrapAuthority) -> tuple[float, float]:
        if self._invalid:
            raise MapitBootstrapContractError("clock_rollback")
        try:
            authority = _validate_authority(authority)
        except MapitBootstrapContractError:
            self._invalid = True
            raise MapitBootstrapContractError("authority_invalid") from None
        if authority._binding_sha256 != self._authority_sha256:
            self._invalid = True
            raise MapitBootstrapContractError("authority_invalid")
        try:
            wall, mono = self._wall(), self._mono()
        except Exception:
            self._invalid = True
            raise MapitBootstrapContractError("clock_invalid") from None
        if (type(wall) not in (int, float) or isinstance(wall, bool)
                or type(mono) not in (int, float) or isinstance(mono, bool)
                or not math.isfinite(wall) or not math.isfinite(mono)):
            self._invalid = True
            raise MapitBootstrapContractError("clock_invalid")
        wall, mono = float(wall), float(mono)
        if ((self._last_wall is not None and wall < self._last_wall)
                or (self._last_mono is not None and mono < self._last_mono)):
            self._invalid = True
            raise MapitBootstrapContractError("clock_rollback")
        if self._wall_origin is None:
            self._wall_origin, self._mono_origin = wall, mono
        assert self._mono_origin is not None and self._wall_origin is not None
        # A frozen/backward wall clock must not extend the immutable wall cutoff.
        effective_wall = max(wall, self._wall_origin + (mono - self._mono_origin))
        if not authority.authorized_from_epoch <= effective_wall < authority.authorized_until_epoch:
            self._invalid = True
            raise MapitBootstrapContractError("window_not_open")
        self._last_wall, self._last_mono = wall, mono
        return effective_wall, mono


_INTENT_FIELDS = frozenset({
    "schema", "kind", "environment", "namespace", "operation", "phase",
    "account_id", "source_sha", "run_id", "expected_caller_arn",
    "authorized_from_epoch", "authorized_until_epoch", "ci_evidence_sha256",
    "runtime_evidence_sha256", "stack_name", "template_sha256",
    "authority_sha256", "client_request_token", "intent_created_epoch",
})


def create_only_intent(authority: MapitBootstrapAuthority, plan: MapitBootstrapPlan, *,
                       journal_state: Any, window: ExclusiveWindow) -> dict[str, Any]:
    """Return a durable-intent payload; any existing journal state consumes the attempt.

    The caller must persist this payload before any external create request. This
    function itself performs no persistence and cannot prove a journal write.
    """
    if journal_state is not None:
        raise MapitBootstrapContractError("journal_consumed")
    authority = _validate_authority(authority)
    if type(plan) is not MapitBootstrapPlan or plan.authority_sha256 != authority._binding_sha256:
        raise MapitBootstrapContractError("plan_invalid")
    expected_plan = build_plan(authority)
    if (plan.template_json != expected_plan.template_json
            or plan.template_sha256 != expected_plan.template_sha256):
        raise MapitBootstrapContractError("plan_invalid")
    if type(window) is not ExclusiveWindow:
        raise MapitBootstrapContractError("window_invalid")
    wall, _ = window.check(authority)
    token_material = {
        "schema": SCHEMA, "kind": KIND, "operation": OPERATION,
        "account_id": authority.account_id, "source_sha": authority.source_sha,
        "run_id": authority.run_id, "template_sha256": plan.template_sha256,
        "authority_sha256": authority._binding_sha256,
    }
    token = _digest(token_material)
    intent = {
        "schema": SCHEMA, "kind": KIND, "environment": ENVIRONMENT,
        "namespace": NAMESPACE, "operation": OPERATION, "phase": "create_intent_saved",
        "account_id": authority.account_id, "source_sha": authority.source_sha,
        "run_id": authority.run_id, "expected_caller_arn": authority.expected_caller_arn,
        "authorized_from_epoch": authority.authorized_from_epoch,
        "authorized_until_epoch": authority.authorized_until_epoch,
        "ci_evidence_sha256": authority.ci_evidence_sha256,
        "runtime_evidence_sha256": authority.runtime_evidence_sha256,
        "stack_name": STACK_NAME, "template_sha256": plan.template_sha256,
        "authority_sha256": authority._binding_sha256,
        "client_request_token": token, "intent_created_epoch": int(wall),
    }
    if set(intent) != _INTENT_FIELDS:
        raise MapitBootstrapContractError("intent_invalid")
    return intent


def validate_intent(value: Any, authority: MapitBootstrapAuthority,
                    plan: MapitBootstrapPlan) -> bool:
    """Check a serialized intent's exact schema and binding without authorizing replay."""
    if not isinstance(value, Mapping) or set(value) != _INTENT_FIELDS:
        return False
    exact_types = {
        "schema": int, "kind": str, "environment": str, "namespace": str,
        "operation": str, "phase": str, "account_id": str, "source_sha": str,
        "run_id": int, "expected_caller_arn": str,
        "authorized_from_epoch": int, "authorized_until_epoch": int,
        "ci_evidence_sha256": str, "runtime_evidence_sha256": str,
        "stack_name": str, "template_sha256": str, "authority_sha256": str,
        "client_request_token": str, "intent_created_epoch": int,
    }
    if any(type(value.get(key)) is not expected for key, expected in exact_types.items()):
        return False
    try:
        expected = create_only_intent(authority, plan, journal_state=None,
                                      window=_fixed_window_for_validation(authority, value))
        # Intent timestamp is historical evidence; all other fields must exactly
        # match the deterministic binding. It does not authorize another write.
        return all(value.get(key) == expected.get(key) for key in _INTENT_FIELDS - {"intent_created_epoch"}) and (
            type(value.get("intent_created_epoch")) is int
            and authority.authorized_from_epoch <= value["intent_created_epoch"] < authority.authorized_until_epoch
        )
    except Exception:
        return False


def _fixed_window_for_validation(authority: MapitBootstrapAuthority,
                                 value: Mapping[str, Any]) -> ExclusiveWindow:
    epoch = value.get("intent_created_epoch")
    if type(epoch) is not int:
        raise MapitBootstrapContractError("intent_invalid")
    return ExclusiveWindow(authority, wall_clock=lambda: epoch, monotonic=lambda: 0.0)
