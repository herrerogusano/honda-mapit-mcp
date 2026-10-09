from __future__ import annotations

import base64
import hashlib
import threading

import pytest

from scripts.dev_owner_enrolled_delivery import OwnerEnrolledDeliveryError
from scripts.dev_owner_enrolled_delivery_sdk import (
    OwnerEnrolledDeliverySdkError,
)
from test_dev_owner_enrolled_delivery_sdk import _setup


def _set_valid_head(clients, archive: bytes):
    digest = hashlib.sha256(archive).hexdigest()
    clients["s3"].head = {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "ContentLength": len(archive),
        "ChecksumSHA256": base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
        "ServerSideEncryption": "AES256",
        "ContentType": "application/zip",
    }


def _sdk_call_count(clients):
    return sum(len(client.calls) for client in clients.values())


def test_long_core_preflight_and_idle_do_not_spend_each_30_second_write_step():
    h, clients, adapter, _target, _target_sha = _setup()
    _set_valid_head(clients, h.archive)
    h.coordinator._publish_once = adapter.publish_once
    h.coordinator._update_once = adapter.update_once

    assert h.coordinator.preflight()["phase"] == "ready"
    calls_before_publish = adapter.calls
    h.wall += 40
    h.mono += 40
    assert h.coordinator.publish()["phase"] == "published"
    calls_after_publish = adapter.calls
    assert calls_after_publish > calls_before_publish
    assert len([call for call in clients["s3"].calls if call[0] == "put_object"]) == 1

    h.wall += 40
    h.mono += 40
    assert h.coordinator.update()["phase"] == "acknowledged"
    assert adapter.calls > calls_after_publish
    assert len([call for call in clients["cloudformation"].calls if call[0] == "update_stack"]) == 1
    assert adapter.calls == _sdk_call_count(clients) < 48


def test_in_step_deadline_after_identity_read_consumes_intent_without_put_or_retry():
    h, clients, adapter, _target, _target_sha = _setup()
    h.coordinator._publish_once = adapter.publish_once
    assert h.coordinator.preflight()["phase"] == "ready"
    original_identity = clients["sts"].get_caller_identity

    def delayed_identity(**kwargs):
        response = original_identity(**kwargs)
        h.mono += 30.0
        return response

    clients["sts"].get_caller_identity = delayed_identity
    with pytest.raises(OwnerEnrolledDeliveryError, match="artifact_write_unknown"):
        h.coordinator.publish()
    assert adapter.calls == 1
    assert h.artifact_journal.state["phase"] == "intent"
    assert not [call for call in clients["s3"].calls if call[0] == "put_object"]

    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": h.auth}, h.archive)
    assert adapter.calls == 1
    assert not [call for call in clients["s3"].calls if call[0] == "put_object"]


def test_ambiguous_put_failure_is_sticky_and_never_dispatches_twice():
    h, clients, adapter, _target, _target_sha = _setup()
    clients["s3"].raise_on.add("put_object")
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": h.auth}, h.archive)
    count_after_unknown = adapter.calls
    put_count = len([call for call in clients["s3"].calls if call[0] == "put_object"])
    assert put_count == 1

    with pytest.raises(OwnerEnrolledDeliverySdkError, match="artifact_write_unknown"):
        adapter.publish_once({"authority": h.auth}, h.archive)
    assert adapter.calls == count_after_unknown
    assert len([call for call in clients["s3"].calls if call[0] == "put_object"]) == 1


@pytest.mark.parametrize("clock_change", ["wall_expired", "monotonic_rollback"])
def test_absolute_expiry_and_session_rollback_still_reject_before_sdk_calls(clock_change):
    h, clients, adapter, _target, _target_sha = _setup()
    if clock_change == "wall_expired":
        h.wall = h.auth["authorized_until_epoch"]
    else:
        h.mono -= 1
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="window_closed"):
        adapter.publish_once({"authority": h.auth}, h.archive)
    assert adapter.calls == 0
    assert _sdk_call_count(clients) == 0


def test_mutated_callback_binding_fails_before_consuming_valid_operation():
    h, clients, adapter, _target, _target_sha = _setup()
    _set_valid_head(clients, h.archive)
    forged = dict(h.auth)
    forged["source_sha"] = "f" * 40
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="binding_invalid"):
        adapter.publish_once({"authority": forged}, h.archive)
    assert adapter.calls == 0
    assert _sdk_call_count(clients) == 0

    receipt = adapter.publish_once({"authority": h.auth}, h.archive)
    assert receipt["status"] == "verified"
    assert len([call for call in clients["s3"].calls if call[0] == "put_object"]) == 1


def test_aggregate_call_cap_is_shared_across_idle_and_write_steps():
    h, clients, adapter, _target, _target_sha = _setup()
    for _ in range(47):
        adapter._call("sts", "get_caller_identity")
    assert adapter.calls == 47

    # The operation gets a fresh 30-second timer, not a fresh call allowance.
    h.mono += 31.0
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="call_budget_exhausted"):
        adapter.publish_once({"authority": h.auth}, h.archive)
    assert adapter.calls == 48
    assert not [call for call in clients["s3"].calls if call[0] == "put_object"]


def test_concurrent_cross_operation_attempt_is_consumed_without_second_write():
    h, clients, adapter, target, _target_sha = _setup()
    _set_valid_head(clients, h.archive)
    entered = threading.Event()
    release = threading.Event()
    original_identity = clients["sts"].get_caller_identity
    publish_result = []

    def blocked_identity(**kwargs):
        response = original_identity(**kwargs)
        entered.set()
        assert release.wait(2)
        return response

    clients["sts"].get_caller_identity = blocked_identity

    def publish():
        publish_result.append(adapter.publish_once({"authority": h.auth}, h.archive))

    worker = threading.Thread(target=publish)
    worker.start()
    assert entered.wait(2)
    before = adapter.calls
    with pytest.raises(OwnerEnrolledDeliverySdkError, match="update_write_unknown"):
        adapter.update_once(h.auth["stack_id"], target,
            f"owner-enrolled-{h.auth['run_id']}", h.auth["service_role_arn"])
    assert adapter.calls == before
    assert not [call for call in clients["cloudformation"].calls if call[0] == "update_stack"]
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    assert publish_result[0]["status"] == "verified"
    assert len([call for call in clients["s3"].calls if call[0] == "put_object"]) == 1
    assert len([call for call in clients["cloudformation"].calls if call[0] == "update_stack"]) == 0
