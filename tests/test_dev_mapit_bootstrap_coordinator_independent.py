from __future__ import annotations

from scripts.dev_mapit_bootstrap_coordinator import MapitBootstrapCoordinatorError
from tests.test_dev_mapit_bootstrap_coordinator import _coordinator


def test_expiry_after_intent_is_consumed_and_create_is_not_dispatched():
    coordinator, journal, cfn, _ddb, _iam = _coordinator()
    clock = coordinator.wall_clock.__self__
    original_save = journal.save

    def save(state):
        original_save(state)
        if state["intent"] is not None:
            clock.wall = coordinator.authority.authorized_until_epoch

    journal.save = save
    assert coordinator.run_step("preflight")["ok"] is True
    result = coordinator.run_step("create")
    assert result["ok"] is False
    assert journal.state["intent"] is not None
    assert cfn.create_calls == []
    assert coordinator.run_step("create")["ok"] is False
    assert cfn.create_calls == []


def test_fresh_post_intent_sts_identity_is_required_before_single_create():
    coordinator, journal, cfn, _ddb, _iam = _coordinator()
    sts = coordinator.clients["sts"]
    original = sts.get_caller_identity
    count = 0

    def drift_after_intent():
        nonlocal count
        count += 1
        response = original()
        if count == 3:
            response = {**response, "Arn": "arn:aws:iam::123456789012:user/other"}
        return response

    sts.get_caller_identity = drift_after_intent
    assert coordinator.run_step("preflight")["ok"] is True
    result = coordinator.run_step("create")
    assert result["category"] == "authority_invalid"
    assert journal.state["intent"] is not None
    assert cfn.create_calls == []
    assert coordinator.run_step("create")["ok"] is False
    assert cfn.create_calls == []


def test_unknown_create_ack_can_only_reconcile_exact_later_stack_readback():
    coordinator, journal, cfn, ddb, iam = _coordinator(fail_create=True)
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["category"] == "create_outcome_unknown"
    assert len(cfn.create_calls) == 1
    assert journal.state["acknowledged"] is False

    # Model the service having committed the one request while its client saw
    # an ambiguous failure. Reconciliation is read-only and binds the exact
    # durable request token through the root CREATE_COMPLETE event.
    cfn.stack = True
    cfn.token = journal.state["intent"]["client_request_token"]
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["acknowledged"] is True
    assert journal.state["readback"] is True
    assert len(cfn.create_calls) == 1
    assert cfn.event_reads == 1


def test_paginated_stack_resource_readback_is_not_accepted():
    coordinator, _journal, _cfn, ddb, iam = _coordinator()
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["ok"] is True
    ddb.created = iam.created = True
    cfn = coordinator.clients["cloudformation"]
    original = cfn.describe_stack_resources

    def paginated(**kwargs):
        return {**original(**kwargs), "NextToken": "second-page-canary"}

    cfn.describe_stack_resources = paginated
    result = coordinator.run_step("readback")
    assert result["ok"] is False
    assert result["category"] in {"aws_response_invalid", "stack_readback_mismatch"}
