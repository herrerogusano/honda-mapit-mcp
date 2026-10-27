from __future__ import annotations

import copy

import pytest

from scripts.dev_owner_enrolled_runtime_readback import OwnerEnrolledReadbackError
from test_dev_owner_enrolled_runtime_readback import (
    _build_owner_enrolled_current_state_fixture,
)


@pytest.mark.parametrize("mutation", [
    "authority", "target", "clients", "context", "evidence_path", "acl_checker",
])
def test_constructor_inputs_cannot_drift_before_first_sdk_read(tmp_path, mutation):
    fixture = _build_owner_enrolled_current_state_fixture(tmp_path)
    current = fixture["current"]
    before_calls = len(fixture["scenario"].calls)

    if mutation == "authority":
        current.authority["owner_tenant_key"] = "tenant-" + "9" * 64
    elif mutation == "target":
        current.target["Resources"]["McpApi"]["Properties"]["Name"] = "unexpected"
    elif mutation == "clients":
        current.clients = dict(current.clients)
    elif mutation == "context":
        current.context = copy.copy(current.context)
    elif mutation == "acl_checker":
        current.acl_checker = lambda _path: True
    else:
        current.mapit_evidence_path = current.mapit_evidence_path.parent / "other.json"

    with pytest.raises(OwnerEnrolledReadbackError) as caught:
        current("pre_update", fixture["delivery_binding"])

    assert caught.value.category == "current_state_unverified"
    assert len(fixture["scenario"].calls) == before_calls
