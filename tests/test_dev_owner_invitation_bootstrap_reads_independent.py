from __future__ import annotations

import pytest

from scripts.run_dev_owner_invitation import _GuardedClients
from scripts.run_dev_mapit_binding_key_setup import _verify_current_bootstrap
from tests.test_dev_mapit_bootstrap_coordinator import ACCOUNT, STACK_NAME
from tests.test_dev_owner_invitation_bootstrap_reads import _fixture


@pytest.mark.parametrize("change", [
    lambda request: request.update(Key={"key": {"S": "identity-bindings-v1", "N": "1"}}),
    lambda request: request.update(Key={"key": {"S": "identity-bindings-v1"}, "extra": {"S": "x"}}),
    lambda request: request.update(Key={"other": {"S": "identity-bindings-v1"}}),
    lambda request: request.update(ConsistentRead=False),
    lambda request: request.update(ReturnConsumedCapacity="TOTAL"),
])
def test_binding_table_get_requires_exact_consistent_key_shape_before_dispatch(change):
    coordinator, _state, guard, _digest_value = _fixture()
    calls = []
    ddb = coordinator.clients["dynamodb"]
    original = ddb.get_item
    ddb.get_item = lambda **kwargs: calls.append(kwargs) or original(**kwargs)
    request = {
        "TableName": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{STACK_NAME}",
        "Key": {"key": {"S": "identity-bindings-v1"}},
        "ConsistentRead": True,
        "ReturnConsumedCapacity": "NONE",
    }
    change(request)

    with pytest.raises(ValueError):
        guard.wrap()["dynamodb"].get_item(**request)

    assert guard.calls == 0
    assert calls == []
    assert guard.write_dispatch_started is False


def test_real_bootstrap_composition_reads_exact_binding_row_without_any_write():
    coordinator, state, guard, digest = _fixture()
    calls = []
    ddb = coordinator.clients["dynamodb"]
    original = ddb.get_item
    ddb.get_item = lambda **kwargs: calls.append(kwargs) or original(**kwargs)

    _verify_current_bootstrap(guard.wrap(), coordinator.authority, state,
        coordinator.plan, digest, [0], 100, 150, lambda: 100.0)

    assert calls
    assert all(call["TableName"] ==
        f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{STACK_NAME}"
        and call["Key"] == {"key": {"S": "identity-bindings-v1"}}
        and call["ConsistentRead"] is True
        and call["ReturnConsumedCapacity"] == "NONE" for call in calls)
    assert guard.calls >= len(calls)
    assert guard.write_dispatch_started is False
