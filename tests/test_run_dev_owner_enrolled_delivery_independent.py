from __future__ import annotations

import pytest

import scripts.run_dev_owner_enrolled_delivery as runner
from tests.test_run_dev_owner_enrolled_delivery import _AUTHORITY, _Client, _Clock, _ok


def _clients(*, stack_replies, clock):
    api_id = "abcdefghij"
    return {
        "sts": _Client([_ok({"Account": _AUTHORITY["account_id"],
                             "Arn": _AUTHORITY["operator_arn"]}) for _ in stack_replies]),
        "apigatewayv2": _Client([_ok({"ApiId": api_id,
                                      "DisableExecuteApiEndpoint": True}) for _ in stack_replies]),
        "lambda": _Client([_ok({"ReservedConcurrentExecutions": 0}) for _ in stack_replies]),
        "cloudformation": _Client(stack_replies),
    }


@pytest.mark.parametrize("extra", [
    {"NextToken": "opaque"},
    {"Marker": "opaque"},
    {"IsTruncated": True},
])
def test_poll_rejects_paginated_or_truncated_stack_readback(extra):
    clock = _Clock()
    stacks = _ok({"Stacks": [{
        "StackId": _AUTHORITY["stack_id"],
        "StackName": "honda-mapit-mcp-dev-retained",
        "RoleARN": _AUTHORITY["service_role_arn"],
        "StackStatus": "UPDATE_COMPLETE",
    }], **extra})
    clients = _clients(stack_replies=[stacks], clock=clock)

    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=clock,
                                    monotonic=clock, sleep=clock.sleep)

    assert exc.value.category == "current_state_unverified"
    assert len(clients["cloudformation"].calls) == 1
    assert len(clients["sts"].calls) == 1
    assert len(clients["apigatewayv2"].calls) == 1


def test_poll_fences_wall_clock_rollback_after_a_successful_read():
    class RollbackClock:
        def __init__(self):
            self.wall_values = iter([200.0, 200.0, 200.0, 200.0, 199.0])
            self.mono = 0.0

        def wall(self):
            return next(self.wall_values)

        def monotonic(self):
            self.mono += 0.1
            return self.mono

    clock = RollbackClock()
    clients = _clients(stack_replies=[_ok({"Stacks": [{
        "StackId": _AUTHORITY["stack_id"],
        "StackName": "honda-mapit-mcp-dev-retained",
        "RoleARN": _AUTHORITY["service_role_arn"],
        "StackStatus": "UPDATE_IN_PROGRESS",
    }]})], clock=clock)

    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=clock.wall,
                                    monotonic=clock.monotonic, sleep=lambda _n: None)

    assert exc.value.category == "current_state_unverified"
    assert len(clients["cloudformation"].calls) == 0
    assert len(clients["sts"].calls) == 1
    assert len(clients["apigatewayv2"].calls) == 1


def test_poll_checks_cutoff_after_sdk_call_before_accepting_update_complete():
    class AdvancingClock:
        def __init__(self):
            self.wall_value = 200.0
            self.mono_value = 0.0

        def wall(self):
            return self.wall_value

        def monotonic(self):
            return self.mono_value

    clock = AdvancingClock()

    class LateStackClient(_Client):
        def __getattr__(self, method):
            original = super().__getattr__(method)

            def call(**kwargs):
                result = original(**kwargs)
                clock.wall_value = _AUTHORITY["execution_end_epoch"]
                return result

            return call

    clients = _clients(stack_replies=[_ok({"Stacks": [{
        "StackId": _AUTHORITY["stack_id"],
        "StackName": "honda-mapit-mcp-dev-retained",
        "RoleARN": _AUTHORITY["service_role_arn"],
        "StackStatus": "UPDATE_COMPLETE",
    }]})], clock=clock)
    clients["cloudformation"] = LateStackClient(clients["cloudformation"].replies)

    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=clock.wall,
                                    monotonic=clock.monotonic, sleep=lambda _n: None)

    assert exc.value.category == "current_state_unverified"
    assert len(clients["cloudformation"].calls) == 1


def test_poll_cutoff_after_sleep_prevents_second_round_of_reads():
    clock = _Clock()
    clients = {
        "sts": _Client([_ok({"Account": _AUTHORITY["account_id"],
                             "Arn": _AUTHORITY["operator_arn"]})]),
        "apigatewayv2": _Client([_ok({"ApiId": "abcdefghij",
                                      "DisableExecuteApiEndpoint": True})]),
        "lambda": _Client([_ok({"ReservedConcurrentExecutions": 0})]),
        "cloudformation": _Client([_ok({"Stacks": [{
            "StackId": _AUTHORITY["stack_id"],
            "StackName": "honda-mapit-mcp-dev-retained",
            "RoleARN": _AUTHORITY["service_role_arn"],
            "StackStatus": "UPDATE_IN_PROGRESS",
        }]})]),
    }

    def expire(_interval):
        clock.value = _AUTHORITY["execution_end_epoch"]

    with pytest.raises(runner.OwnerEnrolledDeliveryRunnerError) as exc:
        runner._poll_update_complete(clients, _AUTHORITY, clock=clock,
                                    monotonic=clock, sleep=expire)

    assert exc.value.category == "window_closed"
    assert sum(len(client.calls) for client in clients.values()) == 4
    assert len(clients["cloudformation"].calls) == 1


def test_safe_failure_preserves_only_allowlisted_category_not_exception_text():
    class ProviderError(RuntimeError):
        category = "artifact_write_unknown"

    assert runner._safe_failure(ProviderError("opaque credential-shaped text")) == "artifact_write_unknown"

    class UntrustedProviderError(RuntimeError):
        category = "access_key=must-not-escape"

    assert runner._safe_failure(UntrustedProviderError("sensitive provider response")) == "delivery_failed"


def test_private_exclusive_write_never_overwrites_existing_receipt(tmp_path):
    target = tmp_path / "authorization.json"
    original = b"previous immutable bytes"
    target.write_bytes(original)

    with pytest.raises(ValueError):
        runner._write_exclusive(target, b"replacement", maximum=1024,
                                acl_checker=lambda _path: True)

    assert target.read_bytes() == original


def test_private_exclusive_write_retains_partial_file_if_postwrite_acl_fails(tmp_path):
    target = tmp_path / "authorization.json"
    checks = []

    def acl_checker(_path):
        checks.append("check")
        return len(checks) == 1

    with pytest.raises(Exception):
        runner._write_exclusive(target, b"intent bytes", maximum=1024,
                                acl_checker=acl_checker)

    assert len(checks) >= 2
    assert target.exists()
    assert target.read_bytes() == b"intent bytes"


@pytest.mark.parametrize("stored", [
    {"schema": True, "delivery_state": {"binding": {}, "phase": "ready", "receipt": None}},
    {"schema": 1, "delivery_state": {"binding": {}, "phase": "ready", "receipt": None},
     "extra": "not allowed"},
    {"schema": 1, "delivery_state": {"binding": {}, "phase": "unknown", "receipt": None}},
    {"schema": 1, "delivery_state": {"binding": [], "phase": "ready", "receipt": None}},
])
def test_intent_adapter_rejects_malformed_envelopes_and_core_states(tmp_path, stored):
    state_dir = tmp_path / "journal"
    state_dir.mkdir()
    runner.FileJournal(state_dir).save(stored)

    with pytest.raises(ValueError, match="^delivery_journal_invalid$"):
        runner._DeliveryIntentJournal(state_dir).load()


def test_persisted_artifact_intent_is_never_replayed_by_the_core(tmp_path):
    from tests.test_dev_owner_enrolled_delivery import Harness

    harness = Harness()
    artifact_dir = tmp_path / "artifact-intent"
    update_dir = tmp_path / "update-intent"
    artifact_dir.mkdir()
    update_dir.mkdir()
    artifact = runner._DeliveryIntentJournal(artifact_dir)
    update = runner._DeliveryIntentJournal(update_dir)
    harness.coordinator._artifact_journal = artifact
    harness.coordinator._update_journal = update

    assert harness.coordinator.preflight() == {"ok": True, "phase": "ready"}
    state = artifact.load()
    assert state["phase"] == "ready"
    state["phase"] = "intent"
    artifact.save(state)

    for _ in range(2):
        with pytest.raises(Exception):
            harness.coordinator.publish()
        assert artifact.load()["phase"] == "intent"
        assert harness.publish_calls == 0
