from __future__ import annotations

import socket

import pytest

import mapit.aws_dev_control_bundle as bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy


_POLICY = AwsDevShutdownPolicy("a1b2c3d4e5")
_NOW = 1_800_000_000


def _build(*, started: int = _NOW, now: int = _NOW, lead: int = 120):
    return bundle.build_dev_control_bundle(
        _POLICY,
        resource_started_epoch=started,
        activation_start_epoch=now + lead,
        now_epoch=now,
    )


def test_bundle_merges_the_fixed_components_without_arming_any_trigger():
    result = _build()
    resources = result["Resources"]
    assert len(resources) == 11
    assert {
        "ShutdownStateMachine", "ShutdownSchedule", "RequestTripwireAlarm",
        "RequestTripwireAlarmRule", "CleanupScheduleGroup", "CleanupSchedule",
    } <= set(resources)
    assert all(item["Condition"] == "SupportedRegion" for item in resources.values())
    assert resources["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["CleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    metadata = result["Metadata"]
    assert metadata["NoActivation"] is True
    assert metadata["NoHardBillingCap"] is True
    assert "revalidate this explicit epoch snapshot" in metadata["SchedulePolicy"]
    assert "not an SLA" in metadata["NoGuarantee"]


@pytest.mark.parametrize("lead", [120, 300])
def test_activation_arming_edges_are_inclusive_and_derived_schedules_stay_bounded(lead: int):
    result = _build(lead=lead)
    snapshot = result["Metadata"]["EpochSnapshot"]
    assert snapshot["ActivationStart"] == _NOW + lead
    assert snapshot["RuntimeEnd"] == _NOW + lead + 300
    assert snapshot["ShutdownSchedule"] == snapshot["RuntimeEnd"] - 120
    assert snapshot["CleanupSchedule"] == _NOW + 2700
    assert snapshot["ResourceDeadline"] == _NOW + 3600
    assert snapshot["RuntimeEnd"] < snapshot["CleanupSchedule"] < snapshot["ResourceDeadline"]


@pytest.mark.parametrize("lead", [119, 301])
def test_activation_outside_the_arming_edges_is_rejected(lead: int):
    with pytest.raises(ValueError):
        _build(lead=lead)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "1800000000", 10**100])
def test_epoch_inputs_reject_nonpositive_nonstrict_or_unrepresentable_values(value):
    with pytest.raises(ValueError):
        bundle.build_dev_control_bundle(
            _POLICY,
            resource_started_epoch=value,
            activation_start_epoch=_NOW + 120,
            now_epoch=_NOW,
        )


def test_future_resource_start_and_stale_cleanup_order_fail_closed():
    with pytest.raises(ValueError):
        _build(started=_NOW + 1)
    # Cleanup would precede the runtime end for this old resource snapshot.
    with pytest.raises(ValueError, match="before scheduled cleanup"):
        _build(started=_NOW - 2500)


def test_epoch_arithmetic_near_calendar_limit_fails_before_component_factories(monkeypatch):
    def unexpected_factory(*_args, **_kwargs):
        raise AssertionError("component factory must not run after epoch overflow")

    monkeypatch.setattr(bundle, "build_dev_shutdown_control", unexpected_factory)
    monkeypatch.setattr(bundle, "build_dev_cleanup_schedule", unexpected_factory)
    with pytest.raises(ValueError):
        bundle.build_dev_control_bundle(
            _POLICY,
            resource_started_epoch=253_402_300_700,
            activation_start_epoch=253_402_300_820,
            now_epoch=253_402_300_700,
        )


def test_composition_is_offline_and_uses_only_the_injected_epoch_snapshot(monkeypatch):
    def deny_network(*_args, **_kwargs):
        raise AssertionError("bundle must not use network")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    result = _build()
    snapshot = result["Metadata"]["EpochSnapshot"]
    assert snapshot["Now"] == _NOW
    assert snapshot["ResourceStarted"] == _NOW
