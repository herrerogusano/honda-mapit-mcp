"""Independent recurrent-lineage and readiness-gate holdouts."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from scripts.run_dev_multiuser_accepted_continuation import (
    AcceptedContinuationError,
    AcceptedContinuationInputs,
    _only_artifact_source_window_delta,
    _predecessor_mode,
    _valid_platform_preflight,
    run_accepted_runtime_continuation,
    validate_recurrent_accepted_pair_lineage,
)
from scripts.probe_aws_dev_multiuser_arm import CHECKS
from scripts.run_aws_retained_dev_bootstrap import write_private_authorization
from tests import test_dev_multiuser_recurrent_continuation as recurrent
from tests import test_dev_multiuser_confirmed_pair_recovery as pair


def _validate(*, current_users, current_reset, current_runtime, previous,
              previous_manifest, manifest):
    return validate_recurrent_accepted_pair_lineage(
        current_users=current_users, current_reset=current_reset,
        current_runtime=current_runtime, previous_lineage=previous,
        previous_manifest=previous_manifest, current_manifest=manifest,
        account=pair.ACCOUNT, pool=pair.POOL,
    )


def test_recurrent_reset_keeps_828c_creation_digest_separate_from_54ad_consumption():
    predecessor, previous, users, reset, runtime, manifest = recurrent._recurrent_fixture()
    state = reset.load()
    assert state["latest_pair_sha256"] == previous["first_pair_sha256"]
    assert state["first_confirmed_pair_sha256"] == previous["first_pair_sha256"]
    assert state["consumed_pair_sha256"] == previous["accepted_pair_sha256"]
    result = _validate(current_users=users, current_reset=reset, current_runtime=runtime,
        previous=previous, previous_manifest=predecessor["accepted_manifest"], manifest=manifest)
    assert result["previous_reset_sha256"] == previous["accepted_reset_sha256"]
    assert result["consumed_pair_sha256"] == previous["accepted_pair_sha256"]


@pytest.mark.parametrize("field", [
    "first_confirmed_pair_sha256", "previous_reset_sha256",
    "consumed_pair_sha256", "latest_pair_sha256",
])
def test_recurrent_lineage_rejects_each_changed_reset_digest(field):
    predecessor, previous, users, reset, runtime, manifest = recurrent._recurrent_fixture()
    state = reset.load()
    state[field] = "0" * 64
    tampered = pair.Journal(state)
    with pytest.raises(AcceptedContinuationError) as exc:
        _validate(current_users=users, current_reset=tampered, current_runtime=runtime,
            previous=previous, previous_manifest=predecessor["accepted_manifest"], manifest=manifest)
    assert exc.value.category == "history_invalid"


@pytest.mark.parametrize("field,value", [
    ("api_id", "other-api"), ("user_pool_id", "eu-west-1_otherpool"),
    ("client_id", "other-client"), ("jwks_sha256", "0" * 64),
    ("table_arn", f"arn:aws:dynamodb:eu-west-1:{pair.ACCOUNT}:table/other"),
])
def test_recurrent_manifest_cannot_rebind_identity_or_storage(field, value):
    predecessor, previous, users, reset, runtime, manifest = recurrent._recurrent_fixture()
    # Supply the additional fixed identity fields used by the recurrent proof.
    previous_manifest = deepcopy(predecessor["accepted_manifest"])
    previous_manifest.update({
        "api_id": "a1b2c3d4e5", "user_pool_id": pair.POOL,
        "client_id": "synthetic-client", "jwks_sha256": "a" * 64,
        "table_arn": f"arn:aws:dynamodb:eu-west-1:{pair.ACCOUNT}:table/honda-mapit-mcp-dev-tenants",
    })
    manifest.update({key: previous_manifest[key] for key in (
        "api_id", "user_pool_id", "client_id", "jwks_sha256", "table_arn")})
    manifest[field] = value
    with pytest.raises(AcceptedContinuationError) as exc:
        _validate(current_users=users, current_reset=reset, current_runtime=runtime,
            previous=previous, previous_manifest=previous_manifest, manifest=manifest)
    assert exc.value.category == "history_invalid"


def test_recurrent_runtime_must_point_to_predecessor_target_and_template_diff_is_closed():
    predecessor, previous, users, reset, runtime, manifest = recurrent._recurrent_fixture()
    binding = runtime.load()["binding"]
    binding["prior"] = "0" * 64
    bad_runtime = pair.Journal({"phase": "accepted", "binding": binding})
    with pytest.raises(AcceptedContinuationError) as exc:
        _validate(current_users=users, current_reset=reset, current_runtime=bad_runtime,
            previous=previous, previous_manifest=predecessor["accepted_manifest"], manifest=manifest)
    assert exc.value.category == "history_invalid"

    before = {"Resources": {"McpHandler": {"Properties": {
        "Code": {"S3Key": "runtime/old.zip"},
        "Environment": {"Variables": {
            "MAPIT_SOURCE_SHA256": "a" * 40,
            "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": "b" * 64,
            "MAPIT_DEV_EXECUTION_START_EPOCH": "1000",
            "MAPIT_DEV_EXECUTION_END_EPOCH": "1300",
        }}}}}, "Metadata": {"SourceSha256": "a" * 40, "ManifestSha256": "b" * 64,
        "ExecutionStartEpoch": 1000, "ExecutionEndEpoch": 1300,
        "ManifestContract": {"source_sha": "a" * 40}}}
    after = deepcopy(before)
    after["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"] = "runtime/new.zip"
    after_vars = after["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]
    after_vars.update({"MAPIT_SOURCE_SHA256": "c" * 40,
        "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": "d" * 64,
        "MAPIT_DEV_EXECUTION_START_EPOCH": "2000", "MAPIT_DEV_EXECUTION_END_EPOCH": "2300"})
    after["Metadata"].update({"SourceSha256": "c" * 40, "ManifestSha256": "d" * 64,
        "ExecutionStartEpoch": 2000, "ExecutionEndEpoch": 2300,
        "ManifestContract": {"source_sha": "c" * 40}})
    assert _only_artifact_source_window_delta(before, after)
    altered = deepcopy(after)
    altered["Resources"]["McpHandler"]["Properties"]["Timeout"] = 30
    assert not _only_artifact_source_window_delta(before, altered)


def _minimal_inputs(tmp_path: Path, monkeypatch, *, partial_predecessor: bool) -> AcceptedContinuationInputs:
    from scripts import build_aws_dev_runtime as runtime_builder

    private_root = tmp_path / "fresh-private-root"
    private_root.mkdir()
    wheel_dir = tmp_path / "wheels"
    wheel_dir.mkdir()
    artifact_dir = tmp_path / "accepted-artifact"
    artifact_dir.mkdir()
    auth = {
        "account": pair.ACCOUNT, "source_sha": "c" * 40, "run_id": 2026100701,
        "expected_caller_arn": f"arn:aws:iam::{pair.ACCOUNT}:user/synthetic-operator",
        "start": 1_900_000_000, "end": 1_900_003_600, "ci_run_id": 77,
    }
    auth_path = write_private_authorization(tmp_path / "authorization.json", auth, acl_checker=lambda _p: True)
    paths = {}
    for name in ("app_binding", "roles_binding", "controls_binding", "artifact_binding", "role_bindings",
                 "original_users", "first_pair_users", "first_reset_users", "first_reset",
                 "prior_reset_users", "prior_reset", "accepted_users", "accepted_reset", "accepted_runtime"):
        path = tmp_path / f"{name}.json"
        path.write_text("{}", encoding="utf-8")
        paths[name] = path
    # Keep this path validation local and explicit; the behavior under test is
    # that the ARM gate precedes client construction, not wheel inventory.
    monkeypatch.setattr(runtime_builder, "_validate_external_wheel_dir", lambda _p, _r: wheel_dir)
    extra = {"predecessor_users_path": tmp_path / "predecessor-users.json"} if partial_predecessor else {}
    if partial_predecessor:
        extra["predecessor_users_path"].write_text("{}", encoding="utf-8")
    return AcceptedContinuationInputs(
        authorization_path=auth_path, private_root=private_root,
        app_binding_path=paths["app_binding"], roles_binding_path=paths["roles_binding"],
        controls_binding_path=paths["controls_binding"], artifact_binding_path=paths["artifact_binding"],
        role_bindings_path=paths["role_bindings"], wheel_dir=wheel_dir,
        original_creation_users_path=paths["original_users"], first_pair_users_path=paths["first_pair_users"],
        first_reset_users_path=paths["first_reset_users"], first_reset_path=paths["first_reset"],
        prior_reset_users_path=paths["prior_reset_users"], prior_reset_path=paths["prior_reset"],
        accepted_users_path=paths["accepted_users"], accepted_reset_path=paths["accepted_reset"],
        accepted_runtime_path=paths["accepted_runtime"], accepted_artifact_dir=artifact_dir, **extra,
    )


def test_partial_predecessor_tuple_fails_before_readiness_or_client_factory(tmp_path, monkeypatch):
    inputs = _minimal_inputs(tmp_path, monkeypatch, partial_predecessor=True)
    calls = {"platform": 0, "clients": 0}

    def platform(_wheel):
        calls["platform"] += 1
        return {"success": True, "category": "multiuser_arm_probe_passed",
                "checks": {name: True for name in CHECKS}}

    def clients_factory():
        calls["clients"] += 1
        raise AssertionError("clients must not be constructed")

    result = run_accepted_runtime_continuation(
        inputs, clients_factory=clients_factory, source_verifier=lambda _auth: None,
        acl_checker=lambda _path: True, platform_preflight=platform,
    )
    assert result["success"] is False and result["category"] == "bindings_invalid"
    assert calls == {"platform": 0, "clients": 0}
    assert list(inputs.private_root.iterdir()) == []


def test_failed_arm_readiness_precedes_any_client_construction_or_journal(tmp_path, monkeypatch):
    inputs = _minimal_inputs(tmp_path, monkeypatch, partial_predecessor=False)
    calls = {"platform": 0, "clients": 0}
    bad_checks = {name: True for name in CHECKS}
    bad_checks[CHECKS[-1]] = False

    def platform(_wheel):
        calls["platform"] += 1
        return {"success": True, "category": "multiuser_arm_probe_passed", "checks": bad_checks}

    def clients_factory():
        calls["clients"] += 1
        raise AssertionError("clients must not be constructed")

    result = run_accepted_runtime_continuation(
        inputs, clients_factory=clients_factory, source_verifier=lambda _auth: None,
        acl_checker=lambda _path: True, platform_preflight=platform,
    )
    assert result["success"] is False and result["category"] == "platform_preflight_failed"
    assert calls == {"platform": 1, "clients": 0}
    assert list(inputs.private_root.iterdir()) == []
