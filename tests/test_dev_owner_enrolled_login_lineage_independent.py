from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from scripts.dev_owner_enrolled_login_lineage import (
    OwnerEnrolledLoginLineageError,
    credential_snapshot_from_explicit_credentials,
    is_registered_owner_enrolled_lineage,
    validate_owner_enrolled_login_lineage,
)
from test_dev_owner_enrolled_login_lineage import _accepted_lineage_fixture


def _validate(delivery, context, state, current, owner):
    return validate_owner_enrolled_login_lineage(
        original_context=context,
        delivery_authority=delivery.auth,
        accepted_receipts=delivery.coordinator.accepted,
        accepted_update_state=state,
        current_runtime_readback=current,
        owner_identity_readback=owner,
    )


def test_old_context_digest_cannot_be_reintroduced_in_accepted_receipt():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    state["receipt"]["owner_context_sha256"] = context.context_digest
    current["current_context_sha256"] = context.context_digest
    current["state"]["owner_context_sha256"] = context.context_digest
    owner["current_context_sha256"] = context.context_digest

    with pytest.raises(OwnerEnrolledLoginLineageError, match="delivery_receipt_invalid"):
        _validate(delivery, context, state, current, owner)


def test_saved_receipt_context_and_fresh_runtime_projection_must_match_exactly():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    state["receipt"]["owner_context_sha256"] = "e" * 64

    with pytest.raises(OwnerEnrolledLoginLineageError, match="current_readback_invalid"):
        _validate(delivery, context, state, current, owner)


def test_accepted_journal_binding_cannot_be_swapped_to_another_authority():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    state["binding"]["authority"]["source_sha"] = "f" * 40

    with pytest.raises(OwnerEnrolledLoginLineageError, match="delivery_receipt_invalid"):
        _validate(delivery, context, state, current, owner)


def test_lineage_result_is_registered_by_identity_not_dataclass_equality():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    lineage = _validate(delivery, context, state, current, owner)
    clone = replace(lineage)

    assert is_registered_owner_enrolled_lineage(lineage)
    assert not is_registered_owner_enrolled_lineage(clone)


def test_runtime_and_oauth_projections_must_share_same_snapshot_instance():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    owner["credential_snapshot"] = credential_snapshot_from_explicit_credentials(SimpleNamespace(
        access_key="AKIA9999999999ABCDE", secret_key="x" * 40, token="y" * 32))

    with pytest.raises(OwnerEnrolledLoginLineageError, match="credential_binding_invalid"):
        _validate(delivery, context, state, current, owner)
