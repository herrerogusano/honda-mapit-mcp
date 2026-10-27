from __future__ import annotations

import copy
import dataclasses
import hashlib
import json

import pytest

from scripts.dev_mapit_bootstrap_contract import (
    ENVIRONMENT,
    KIND,
    NAMESPACE,
    OPERATION,
    ExclusiveWindow,
    MapitBootstrapContractError,
    build_plan,
    create_only_intent,
    make_authority,
    validate_intent,
)
from scripts.build_aws_dev_mapit_binding_bootstrap import STACK_NAME

ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/dev-mapit-operator"
KMS = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"
FRESH = tuple(f"tenant-{i:064x}" for i in (201, 202))
HISTORICAL = tuple(f"tenant-{i:064x}" for i in (101, 102, 103))
SOURCE = "a" * 40
CI = "b" * 64
RUNTIME = "c" * 64


def authority(**changes):
    fields = {
        "account_id": ACCOUNT,
        "operator_user_arn": OPERATOR,
        "source_sha": SOURCE,
        "run_id": 42,
        "expected_caller_arn": OPERATOR,
        "authorized_from_epoch": 1_800_000_000,
        "authorized_until_epoch": 1_800_000_600,
        "ci_evidence_sha256": CI,
        "runtime_evidence_sha256": RUNTIME,
        "ssm_key_arn": KMS,
        "tenant_keys": FRESH,
        "excluded_tenant_keys": HISTORICAL,
    }
    fields.update(changes)
    return make_authority(**fields)


class Clock:
    def __init__(self, wall=1_800_000_001.25, mono=50.0):
        self.wall = wall
        self.mono = mono

    def time(self):
        return self.wall

    def monotonic(self):
        return self.mono


def test_contract_builds_only_fixed_mapit_template_and_canonical_plan():
    auth = authority()
    plan = build_plan(auth)
    template = plan.template
    assert template["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
    assert template["Resources"]["MapitIdentityBindings"]["Properties"]["TableName"] == STACK_NAME
    assert set(template["Resources"]) == {
        "MapitIdentityBindings", "IdentityEnrollerBoundary",
        "IdentityEnrollerRole", "RuntimeIdentityBindingPolicy",
    }
    assert plan.template_sha256 == hashlib.sha256(
        json.dumps(template, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                   allow_nan=False).encode()
    ).hexdigest()
    template["Resources"].clear()
    assert len(plan.template["Resources"]) == 4
    assert "tenant-" not in repr(auth)
    assert "tenant-" not in repr(plan)


@pytest.mark.parametrize("changes", [
    {"expected_caller_arn": "arn:aws:iam::123456789012:root"},
    {"account_id": "000000000000"},
    {"authorized_from_epoch": 0, "authorized_until_epoch": 600},
    {"authorized_from_epoch": True},
    {"run_id": True},
    {"authorized_until_epoch": 1_800_000_600 + 1},
    {"source_sha": "0" * 40},
    {"ci_evidence_sha256": "z" * 64},
    {"runtime_evidence_sha256": "x" * 64},
    {"tenant_keys": (FRESH[0], HISTORICAL[0])},
    {"tenant_keys": (FRESH[0], FRESH[0])},
    {"excluded_tenant_keys": ()},
    {"ssm_key_arn": f"arn:aws:kms:eu-west-1:999999999999:key/{'1' * 8}-{'1' * 4}-{'1' * 4}-{'1' * 4}-{'1' * 12}"},
])
def test_authority_rejects_invalid_or_historical_binding(changes):
    with pytest.raises(MapitBootstrapContractError):
        authority(**changes)


def test_exact_authority_schema_does_not_accept_secret_or_session_material():
    # The constructor exposes only fixed scalar/evidence fields; credential
    # material cannot be smuggled through a flexible mapping.
    with pytest.raises(TypeError):
        authority(access_key="canary", session_token="canary")
    assert "canary" not in repr(authority())


def test_create_intent_binds_schema_template_evidence_and_is_create_only():
    auth = authority()
    plan = build_plan(auth)
    clock = Clock()
    window = ExclusiveWindow(auth, wall_clock=clock.time, monotonic=clock.monotonic)
    intent = create_only_intent(auth, plan, journal_state=None, window=window)
    assert intent["schema"] == 1
    assert intent["kind"] == KIND
    assert intent["environment"] == ENVIRONMENT == "dev"
    assert intent["namespace"] == NAMESPACE == "mapit"
    assert intent["operation"] == OPERATION == "create-stack-once"
    assert intent["phase"] == "create_intent_saved"
    assert intent["stack_name"] == STACK_NAME
    assert intent["template_sha256"] == plan.template_sha256
    assert intent["ci_evidence_sha256"] == CI
    assert intent["runtime_evidence_sha256"] == RUNTIME
    assert "tenant_keys" not in intent and "secret" not in json.dumps(intent).lower()
    assert validate_intent(intent, auth, plan)
    mutated = copy.deepcopy(intent)
    mutated["namespace"] = "synthetic"
    assert not validate_intent(mutated, auth, plan)
    for key, value in (("schema", True), ("run_id", True),
                       ("intent_created_epoch", True), ("source_sha", 123)):
        malformed = copy.deepcopy(intent)
        malformed[key] = value
        assert not validate_intent(malformed, auth, plan)
    with pytest.raises(MapitBootstrapContractError, match="journal_consumed"):
        create_only_intent(auth, plan, journal_state=intent, window=window)
    with pytest.raises(MapitBootstrapContractError, match="journal_consumed"):
        create_only_intent(auth, plan, journal_state={}, window=window)


def test_intent_rejects_different_plan_or_authority():
    auth = authority()
    plan = build_plan(auth)
    other = authority(run_id=43)
    clock = Clock()
    window = ExclusiveWindow(auth, wall_clock=clock.time, monotonic=clock.monotonic)
    with pytest.raises(MapitBootstrapContractError, match="plan_invalid"):
        create_only_intent(other, plan, journal_state=None, window=window)


def test_forged_frozen_authority_and_tampered_plan_are_revalidated():
    auth = authority()
    plan = build_plan(auth)
    clock = Clock()
    window = ExclusiveWindow(auth, wall_clock=clock.time, monotonic=clock.monotonic)
    forged_authority = dataclasses.replace(auth, run_id=99)
    with pytest.raises(MapitBootstrapContractError, match="authority_invalid"):
        create_only_intent(forged_authority, plan, journal_state=None, window=window)
    forged_plan = dataclasses.replace(plan, template_sha256="d" * 64)
    with pytest.raises(MapitBootstrapContractError, match="plan_invalid"):
        create_only_intent(auth, forged_plan, journal_state=None, window=window)


def test_exclusive_window_accepts_start_rejects_end_and_wall_or_monotonic_rollback():
    auth = authority()
    clock = Clock(wall=float(auth.authorized_from_epoch), mono=10.0)
    guard = ExclusiveWindow(auth, wall_clock=clock.time, monotonic=clock.monotonic)
    clock.wall += 1
    clock.mono += 1
    guard.check(auth)
    clock.wall -= 0.5
    with pytest.raises(MapitBootstrapContractError, match="clock_rollback"):
        guard.check(auth)
    clock.wall += 10
    clock.mono += 10
    with pytest.raises(MapitBootstrapContractError, match="clock_rollback"):
        guard.check(auth)

    clock2 = Clock(wall=float(auth.authorized_from_epoch), mono=10.0)
    guard2 = ExclusiveWindow(auth, wall_clock=clock2.time, monotonic=clock2.monotonic)
    clock2.mono -= 0.1
    with pytest.raises(MapitBootstrapContractError, match="clock_rollback"):
        guard2.check(auth)

    clock3 = Clock(wall=float(auth.authorized_until_epoch), mono=10.0)
    with pytest.raises(MapitBootstrapContractError, match="window_not_open"):
        ExclusiveWindow(auth, wall_clock=clock3.time, monotonic=clock3.monotonic)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), True, "1800000001"])
def test_exclusive_window_rejects_invalid_clock_values(bad):
    auth = authority()
    with pytest.raises(MapitBootstrapContractError, match="clock_invalid"):
        ExclusiveWindow(auth, wall_clock=lambda: bad, monotonic=lambda: 1.0)


def test_window_guard_is_bound_to_its_authority():
    auth = authority()
    other = authority(run_id=43)
    guard = ExclusiveWindow(auth, wall_clock=lambda: 1_800_000_001,
                            monotonic=lambda: 1.0)
    with pytest.raises(MapitBootstrapContractError, match="authority_invalid"):
        guard.check(other)
    with pytest.raises(MapitBootstrapContractError, match="clock_rollback"):
        guard.check(auth)


def test_create_intent_requires_real_window_guard():
    auth = authority()
    with pytest.raises(MapitBootstrapContractError, match="window_invalid"):
        create_only_intent(auth, build_plan(auth), journal_state=None, window=object())
