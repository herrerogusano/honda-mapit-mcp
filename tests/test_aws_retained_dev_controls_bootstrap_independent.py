from __future__ import annotations

import pytest

from scripts.aws_retained_dev_controls_bootstrap import RetainedDevControlsCoordinator
from test_aws_retained_dev_controls_bootstrap import _coordinator, _seed_preflight


@pytest.mark.parametrize(
    "document",
    [
        '{"Statement":1,"Statement":2}',
        '{"Statement":{"Effect":"Allow"},"Statement":{"Effect":"Deny"}}',
    ],
)
def test_iam_policy_document_parser_rejects_duplicate_keys(document):
    assert RetainedDevControlsCoordinator._document(document) is None


def test_iam_policy_document_parser_rejects_malformed_percent_encoding():
    assert RetainedDevControlsCoordinator._document('{"Statement":"%zz"}') is None


def test_unknown_create_reconciliation_state_can_be_reloaded():
    journal = None
    coordinator = _coordinator(journal)
    _seed_preflight(coordinator, coordinator.journal)
    original = coordinator.clients["cloudformation"].create_stack

    def ambiguous(**kwargs):
        coordinator.clients["cloudformation"].created = True
        raise RuntimeError("ambiguous")

    coordinator.clients["cloudformation"].create_stack = ambiguous
    assert coordinator.run_step("create")["category"] == "create_outcome_unknown"
    coordinator.clients["cloudformation"].create_stack = original
    assert coordinator.run_step("readback")["category"] == "readback_verified"
    assert coordinator.run_step("readback")["category"] != "journal_invalid"
