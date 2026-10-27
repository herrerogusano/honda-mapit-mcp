import copy

import pytest

from scripts.dev_owner_enrolled_observation import (
    ObservationEvidenceError,
    make_capsule,
    make_progress_projection,
    validate_capsule,
    validate_capsule_for_accepted_update,
    validate_observation_window,
)


def _binding():
    return {
        "schema": 1,
        "target_template_sha256": "a" * 64,
        "artifact_sha256": "b" * 64,
        "client_request_token": "owner-enrolled-run-123",
    }


def _progress():
    resource_ids = {f"Resource{i}": f"physical-{i}" for i in range(19)}
    rows = {
        "opaque-tenant-selector-A": {"tenant": "A", "revision": 2},
        "opaque-tenant-selector-B": {"tenant": "B", "revision": 3},
    }
    return make_progress_projection(
        resource_ids=resource_ids,
        historical_rows=rows,
        historical_tenant_keys=["opaque-tenant-selector-B", "opaque-tenant-selector-A"],
        authorization_table_id="table-id-123",
        synthetic_policy={"Statement": [{"Effect": "Allow"}]},
    )


def _capsule():
    return make_capsule(
        delivery_binding=_binding(), progress=_progress(),
        target_template_sha256="a" * 64, artifact_sha256="b" * 64,
        owner_context_sha256="c" * 64, accepted_read_call_count=42,
    )


def test_capsule_uses_fixed_tenant_slots_and_binds_terminal_update_receipt():
    capsule = _capsule()
    assert set(capsule["progress"]["historical_row_sha256"]) == {"tenant_a", "tenant_b"}
    assert "opaque-tenant-selector" not in repr(capsule)
    state = {
        "binding": _binding(), "phase": "accepted",
        "receipt": {
            "target_template_sha256": "a" * 64,
            "artifact_sha256": "b" * 64,
            "completion_event_token": "owner-enrolled-run-123",
            "owner_context_sha256": "c" * 64,
            "runtime_evidence_sha256": capsule["runtime_evidence_sha256"],
        },
    }
    assert validate_capsule_for_accepted_update(
        capsule, delivery_binding=_binding(), accepted_update_state=state) == capsule


@pytest.mark.parametrize("mutation", [
    lambda value: value["progress"]["historical_row_sha256"].update({"opaque-A": "d" * 64}),
    lambda value: value["progress"].update({"authorization_table_id": "other-table"}),
    lambda value: value.update({"owner_context_sha256": "e" * 64}),
])
def test_capsule_tampering_fails_closed(mutation):
    capsule = copy.deepcopy(_capsule())
    mutation(capsule)
    with pytest.raises(ObservationEvidenceError):
        validate_capsule(capsule, delivery_binding=_binding())


def test_observation_window_requires_fresh_git_commit_sha_and_bounded_time():
    window = {
        "schema": 1, "kind": "owner-enrolled-readonly-observation",
        "account_id": "123456789012", "operator_arn": "arn:aws:iam::123456789012:user/operator",
        "source_sha": "d" * 40, "ci_run_id": 99,
        "authorized_from_epoch": 1000, "authorized_until_epoch": 1599,
        "github_owner_id": 12, "github_repository_id": 34,
    }
    assert validate_observation_window(window, account_id=window["account_id"],
        operator_arn=window["operator_arn"], github_owner_id=12,
        github_repository_id=34, now=1200) == window
    for source in ("e" * 64, "d" * 39, "D" * 40):
        invalid = dict(window, source_sha=source)
        with pytest.raises(ObservationEvidenceError):
            validate_observation_window(invalid, account_id=window["account_id"],
                operator_arn=window["operator_arn"], github_owner_id=12,
                github_repository_id=34, now=1200)

