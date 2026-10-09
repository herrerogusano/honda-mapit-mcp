from __future__ import annotations

import pytest

from scripts.run_dev_owner_invitation import _GuardedClients
from scripts.run_dev_mapit_binding_key_setup import _digest, _verify_current_bootstrap
from tests.test_run_dev_mapit_binding_key_setup import _accepted_coordinator_state


def _fixture():
    coordinator, state = _accepted_coordinator_state()
    authority, plan = coordinator.authority, coordinator.plan
    guard = _GuardedClients(coordinator.clients, owner_key=authority._tenant_keys[0],
        account_id=authority.account_id, start=authority.authorized_from_epoch,
        end=authority.authorized_until_epoch,
        wall_clock=lambda: authority.authorized_from_epoch + 10, monotonic=lambda: 100.0)
    digest = _digest({"authority_sha256": authority._binding_sha256,
        "intent": state["intent"], "readback_receipt": state["readback_receipt"],
        "template_sha256": plan.template_sha256})
    return coordinator, state, guard, digest


def test_real_bootstrap_readback_composes_through_invitation_guard():
    coordinator, state, guard, digest = _fixture()
    _verify_current_bootstrap(guard.wrap(), coordinator.authority, state,
        coordinator.plan, digest, [0], 100, 150, lambda: 100.0)
    assert guard.calls >= 10
    assert guard.write_dispatch_started is False


@pytest.mark.parametrize("table_suffix,key", [
    ("honda-mapit-mcp-dev-mapit-identity-bindings", "another-binding"),
    ("honda-mapit-mcp-dev-mapit-identity-bindings", "tenant-" + "e" * 64),
    ("honda-mapit-mcp-dev-tenants", "identity-bindings-v1"),
    ("honda-mapit-mcp-dev-identity-bindings", "identity-bindings-v1"),
])
def test_guard_refuses_unrelated_table_key_pairs_before_sdk(table_suffix, key):
    coordinator, _state, guard, _digest_value = _fixture()
    with pytest.raises(ValueError):
        guard.wrap()["dynamodb"].get_item(
            TableName=f"arn:aws:dynamodb:eu-west-1:{coordinator.authority.account_id}:table/{table_suffix}",
            Key={"key": {"S": key}}, ConsistentRead=True, ReturnConsumedCapacity="NONE")
    assert guard.calls == 0 and guard.write_dispatch_started is False


def test_new_binding_table_stays_unwritable_even_when_invitation_write_is_armed():
    coordinator, _state, guard, _digest_value = _fixture()
    guard.armed = True
    with pytest.raises(ValueError):
        guard.wrap()["dynamodb"].put_item(
            TableName=f"arn:aws:dynamodb:eu-west-1:{coordinator.authority.account_id}:table/honda-mapit-mcp-dev-mapit-identity-bindings",
            Item={"key": {"S": "identity-bindings-v1"}, "status": {"S": "active"}, "revision": {"N": "1"}},
            ConditionExpression="attribute_not_exists(#key)", ExpressionAttributeNames={"#key": "key"},
            ReturnValues="NONE", ReturnConsumedCapacity="NONE")
    assert guard.calls == 0 and guard.write_dispatch_started is False
