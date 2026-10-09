from __future__ import annotations

import copy

import pytest

from scripts.dev_owner_enrolled_observation import (
    ObservationEvidenceError,
    canonical_bytes,
    make_capsule,
    make_progress_projection,
    validate_capsule,
    validate_capsule_for_accepted_update,
    validate_observation_window,
)


_ACCOUNT = "123456789012"
_OPERATOR = f"arn:aws:iam::{_ACCOUNT}:user/dev-operator"
_SHA = "a" * 64
_DELIVERY_BINDING = {
    "schema": 1,
    "target_template_sha256": "b" * 64,
    "artifact_sha256": "c" * 64,
    "client_request_token": "owner-enrolled-0123456789abcdef",
    "historical_tenant_keys": ["opaque-historical-A", "opaque-historical-B"],
}


def _progress():
    return make_progress_projection(
        resource_ids={f"Logical{i:02d}": f"physical-resource-{i:02d}" for i in range(19)},
        historical_rows={
            "opaque-historical-A": {"status": {"S": "revoked"}, "session": "never-persist-this"},
            "opaque-historical-B": {"status": {"S": "active"}, "subject": "never-persist-this-either"},
        },
        historical_tenant_keys=list(_DELIVERY_BINDING["historical_tenant_keys"]),
        authorization_table_id="11111111-1111-4111-8111-111111111111",
        synthetic_policy={"policy_name": "fixed-runtime-read", "policy_document": {"Statement": []}},
    )


def _window(**changes):
    value = {
        "schema": 1,
        "kind": "owner-enrolled-readonly-observation",
        "account_id": _ACCOUNT,
        "operator_arn": _OPERATOR,
        "source_sha": "d" * 40,
        "ci_run_id": 73,
        "authorized_from_epoch": 1000,
        "authorized_until_epoch": 1600,
        "github_owner_id": 7,
        "github_repository_id": 8,
    }
    value.update(changes)
    return value


def test_capsule_projection_omits_raw_tenant_keys_rows_and_secret_fields():
    progress = _progress()
    capsule = make_capsule(
        delivery_binding=_DELIVERY_BINDING,
        progress=progress,
        target_template_sha256=_DELIVERY_BINDING["target_template_sha256"],
        artifact_sha256=_DELIVERY_BINDING["artifact_sha256"],
        owner_context_sha256=_SHA,
        accepted_read_call_count=41,
    )

    encoded = canonical_bytes(capsule)
    assert b"opaque-historical-A" not in encoded
    assert b"opaque-historical-B" not in encoded
    assert b"never-persist-this" not in encoded
    assert set(capsule["progress"]["historical_row_sha256"]) == {"tenant_a", "tenant_b"}
    assert validate_capsule(capsule, delivery_binding=_DELIVERY_BINDING) == capsule


def test_capsule_is_bound_to_exact_update_receipt_and_progress():
    capsule = make_capsule(
        delivery_binding=_DELIVERY_BINDING,
        progress=_progress(),
        target_template_sha256=_DELIVERY_BINDING["target_template_sha256"],
        artifact_sha256=_DELIVERY_BINDING["artifact_sha256"],
        owner_context_sha256=_SHA,
        accepted_read_call_count=41,
    )
    receipt = {
        "target_template_sha256": _DELIVERY_BINDING["target_template_sha256"],
        "artifact_sha256": _DELIVERY_BINDING["artifact_sha256"],
        "completion_event_token": _DELIVERY_BINDING["client_request_token"],
        "owner_context_sha256": _SHA,
        "runtime_evidence_sha256": capsule["runtime_evidence_sha256"],
    }
    accepted = {"binding": _DELIVERY_BINDING, "phase": "accepted", "receipt": receipt}
    assert validate_capsule_for_accepted_update(
        capsule, delivery_binding=_DELIVERY_BINDING, accepted_update_state=accepted) == capsule

    for mutate in (
        lambda value: value["progress"].update(authorization_table_id="different-table"),
        lambda value: value.update(target_template_sha256="e" * 64),
        lambda value: value.update(artifact_sha256="f" * 64),
    ):
        tampered = copy.deepcopy(capsule)
        mutate(tampered)
        with pytest.raises(ObservationEvidenceError):
            validate_capsule_for_accepted_update(
                tampered, delivery_binding=_DELIVERY_BINDING, accepted_update_state=accepted)

    wrong_receipt = copy.deepcopy(accepted)
    wrong_receipt["receipt"]["completion_event_token"] = "other-token"
    with pytest.raises(ObservationEvidenceError):
        validate_capsule_for_accepted_update(
            capsule, delivery_binding=_DELIVERY_BINDING, accepted_update_state=wrong_receipt)


def test_fresh_observation_window_accepts_git_sha_and_rejects_stale_or_widened_windows():
    window = _window()
    assert validate_observation_window(
        window, account_id=_ACCOUNT, operator_arn=_OPERATOR,
        github_owner_id=7, github_repository_id=8, now=1001.0) is window

    bad_windows = [
        _window(source_sha="d" * 64),
        _window(authorized_until_epoch=1601),
        _window(authorized_from_epoch=1600),
        _window(authorized_from_epoch=True),
        _window(github_owner_id=True),
    ]
    for bad in bad_windows:
        with pytest.raises(ObservationEvidenceError) as exc:
            validate_observation_window(
                bad, account_id=_ACCOUNT, operator_arn=_OPERATOR,
                github_owner_id=7, github_repository_id=8, now=1001.0)
        assert exc.value.category == "observation_window_invalid"


def test_expired_original_delivery_window_does_not_replace_fresh_observation_window():
    # The capsule remains bound to its original delivery identity, while the
    # separate read-only observation authorization has a distinct fresh window.
    capsule = make_capsule(
        delivery_binding=_DELIVERY_BINDING,
        progress=_progress(),
        target_template_sha256=_DELIVERY_BINDING["target_template_sha256"],
        artifact_sha256=_DELIVERY_BINDING["artifact_sha256"],
        owner_context_sha256=_SHA,
        accepted_read_call_count=41,
    )
    fresh = _window(authorized_from_epoch=2000, authorized_until_epoch=2500)
    assert validate_observation_window(
        fresh, account_id=_ACCOUNT, operator_arn=_OPERATOR,
        github_owner_id=7, github_repository_id=8, now=2001.0) is fresh
    assert validate_capsule(capsule, delivery_binding=_DELIVERY_BINDING) == capsule
