from __future__ import annotations

import pytest
from types import SimpleNamespace

from scripts.aws_retained_dev_proof_bootstrap import (
    RetainedDevProofBootstrapCoordinator,
    RetainedDevProofBootstrapError,
)
from scripts.run_aws_retained_dev_proof_bootstrap import FileCasJournal
from tests.test_aws_retained_dev_proof_bootstrap import (
    RUN,
    _coordinator,
    _ok,
)


def test_default_file_journal_implements_the_coordinator_cas_contract():
    assert callable(getattr(FileCasJournal, "compare_and_set", None))


def test_binding_loader_bounds_bytes_read_not_only_initial_stat():
    class UnstablePath:
        def stat(self):
            return SimpleNamespace(st_size=1)

        def read_bytes(self):
            import json
            from scripts.run_aws_retained_dev_proof_bootstrap import _BINDING_FIELDS
            value = {key: "fixture" for key in _BINDING_FIELDS}
            value["account_id"] = "x" * 9000
            return json.dumps(value).encode()

    from scripts.run_aws_retained_dev_proof_bootstrap import _load_bindings

    with pytest.raises(RuntimeError, match="bindings_file_invalid"):
        _load_bindings(UnstablePath())


def test_malformed_stack_readback_has_a_safe_category():
    journal = None
    coordinator, cfn = _coordinator(journal)
    assert coordinator.run_step("preflight")["ok"]
    assert coordinator.run_step("create")["ok"]
    cfn.describe_stacks = lambda **kwargs: _ok(Stacks="malformed")
    result = coordinator.run_step("readback")
    assert result["category"] == "stack_readback_mismatch"


def test_policy_version_must_echo_the_requested_default_version():
    coordinator, cfn = _coordinator()
    cfn.created = True
    iam = coordinator.clients["iam"]
    iam.get_policy_version = lambda **kwargs: _ok(
        PolicyVersion={
            "VersionId": "v2",
            "IsDefaultVersion": True,
            "Document": coordinator.template["Resources"]["RetainedDevReadOnlyProofBoundary"]["Properties"]["PolicyDocument"],
        }
    )
    coordinator._started = 0.0
    with pytest.raises(RetainedDevProofBootstrapError, match="boundary_readback_mismatch"):
        coordinator._verify_boundary()


def test_missing_role_policy_pagination_flag_fails_closed():
    coordinator, cfn = _coordinator()
    cfn.created = True
    iam = coordinator.clients["iam"]
    iam.list_role_policies = lambda **kwargs: _ok(
        PolicyNames=[RUN.replace(RUN, "honda-mapit-mcp-dev-retained-readonly-proof-policy")],
    )
    coordinator._started = 0.0
    with pytest.raises(RetainedDevProofBootstrapError, match="role_readback_mismatch"):
        coordinator._verify_role(cfn.describe_stacks()["Stacks"][0]["StackId"])


def test_missing_attached_policy_pagination_flag_fails_closed():
    coordinator, cfn = _coordinator()
    cfn.created = True
    iam = coordinator.clients["iam"]
    iam.list_role_policies = lambda **kwargs: _ok(
        PolicyNames=["honda-mapit-mcp-dev-retained-readonly-proof-policy"], IsTruncated=False
    )
    iam.list_attached_role_policies = lambda **kwargs: _ok(AttachedPolicies=[])
    coordinator._started = 0.0
    with pytest.raises(RetainedDevProofBootstrapError, match="role_readback_mismatch"):
        coordinator._verify_role(cfn.describe_stacks()["Stacks"][0]["StackId"])


def test_journal_binding_must_include_caller_and_authority_window():
    from tests.test_aws_retained_dev_proof_bootstrap import Journal

    journal = Journal()
    first, _ = _coordinator(journal)
    assert first.run_step("preflight")["ok"]
    bindings = first.bindings
    second = RetainedDevProofBootstrapCoordinator(
        first.clients,
        journal,
        bindings=bindings,
        expected_caller_arn=f"arn:aws:iam::123456789012:role/other-proof-caller",
        source_sha=first.source_sha,
        run_id=first.run_id,
        authorized_from_epoch=1_893_455_001,
        authorized_until_epoch=1_893_458_001,
        wall_clock=lambda: 1_893_456_100,
        monotonic=lambda: 1.0,
    )
    with pytest.raises(RetainedDevProofBootstrapError, match="journal_invalid"):
        second._state()


def test_uncertain_create_never_fabricates_create_acknowledgement():
    from tests.test_aws_retained_dev_proof_bootstrap import Journal

    journal = Journal()
    coordinator, cfn = _coordinator(journal, fail_create=True)
    assert coordinator.run_step("preflight")["ok"]
    assert coordinator.run_step("create")["category"] == "create_outcome_unknown"
    cfn.fail_create = False
    cfn.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["acknowledged"] is False


def test_journal_rejects_acknowledged_state_without_intent_or_stack_id():
    from tests.test_aws_retained_dev_proof_bootstrap import Journal

    journal = Journal()
    coordinator, _ = _coordinator(journal)
    state = coordinator._base()
    state.update({"revision": 1, "last_observed_epoch": 1_893_456_100, "preflight": True, "acknowledged": True})
    journal.state = state
    with pytest.raises(RetainedDevProofBootstrapError, match="journal_invalid"):
        coordinator._state()


def test_journal_rejects_receipt_ack_mismatch():
    from tests.test_aws_retained_dev_proof_bootstrap import Journal

    journal = Journal()
    coordinator, _ = _coordinator(journal)
    state = coordinator._base()
    stack_id = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-readonly-proof/11111111-2222-4333-8444-555555555555"
    state.update({
        "revision": 1,
        "last_observed_epoch": 1_893_456_100,
        "preflight": True,
        "intent": {"client_request_token": coordinator.run_id},
        "acknowledged": False,
        "acknowledged_stack_id": stack_id,
        "readback": True,
        "readback_receipt": {"stack_id": stack_id, "template_sha256": coordinator.template_sha256, "client_request_token": coordinator.run_id, "acknowledged": True},
    })
    journal.state = state
    with pytest.raises(RetainedDevProofBootstrapError, match="journal_invalid"):
        coordinator._state()


def test_restart_restores_persisted_wall_clock_fence():
    from tests.test_aws_retained_dev_proof_bootstrap import Journal

    journal = Journal()
    first, _ = _coordinator(journal)
    assert first.run_step("preflight")["ok"]
    second, _ = _coordinator(journal)
    loaded = second._state()
    assert loaded is not None
    assert second._last_epoch >= loaded["last_observed_epoch"]
