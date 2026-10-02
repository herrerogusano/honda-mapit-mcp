from __future__ import annotations

import pytest

import mapit.aws_dev_control_bundle as bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy


def _compose(*, started: int = 1_800_000_000, start: int = 1_800_000_120, now: int = 1_800_000_000):
    return bundle.build_dev_control_bundle(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        resource_started_epoch=started,
        activation_start_epoch=start,
        now_epoch=now,
    )


def test_bundle_composes_eight_shutdown_and_three_cleanup_resources_disabled() -> None:
    template = _compose()
    resources = template["Resources"]
    assert len(resources) == 11
    assert set(resources) == {
        "ShutdownWorkflowRole", "ShutdownStateMachine", "SchedulerGroup",
        "SchedulerInvokeRole", "ShutdownSchedule", "RequestTripwireAlarm",
        "RequestTripwireEventRole", "RequestTripwireAlarmRule",
        "CleanupScheduleGroup", "CleanupSchedulerRole", "CleanupSchedule",
    }
    assert all(resource["Condition"] == "SupportedRegion" for resource in resources.values())
    assert template["Conditions"] == {
        "SupportedRegion": {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]}
    }
    assert "Outputs" not in template
    assert resources["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["CleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert template["Metadata"]["NoActivation"] is True


def test_bundle_derives_shutdown_and_cleanup_inside_the_fixed_timing_budgets() -> None:
    template = _compose()
    snapshot = template["Metadata"]["EpochSnapshot"]
    assert snapshot == {
        "ResourceStarted": 1_800_000_000,
        "Now": 1_800_000_000,
        "ActivationStart": 1_800_000_120,
        "RuntimeEnd": 1_800_000_420,
        "ShutdownSchedule": 1_800_000_300,
        "CleanupSchedule": 1_800_002_700,
        "ResourceDeadline": 1_800_003_600,
    }
    assert snapshot["ActivationStart"] >= snapshot["Now"] + 120
    assert snapshot["ActivationStart"] <= snapshot["Now"] + 300
    assert snapshot["RuntimeEnd"] - snapshot["ActivationStart"] == 300
    assert snapshot["RuntimeEnd"] < snapshot["CleanupSchedule"]
    assert snapshot["ResourceDeadline"] - snapshot["CleanupSchedule"] == 900
    limits = template["Metadata"]["Limits"]
    assert limits["ResourceLifetimeSeconds"] == 3600
    assert limits["EndpointWindowSeconds"] == 300
    assert limits["ShutdownAdvanceSeconds"] == 120
    assert limits["ClosureBudgetSeconds"] == {
        "SchedulerPrecision": 60,
        "WorkflowTimeout": 45,
        "AdditionalMargin": 15,
        "Total": 120,
    }
    assert limits["OperatorCleanupTailSeconds"] == 900
    assert template["Metadata"]["NoHardBillingCap"] is True
    assert "not an SLA" in template["Metadata"]["NoGuarantee"]


@pytest.mark.parametrize("lead", [120, 300])
def test_inclusive_activation_lead_boundaries_are_accepted(lead: int) -> None:
    result = _compose(start=1_800_000_000 + lead)
    assert result["Metadata"]["EpochSnapshot"]["ActivationStart"] == 1_800_000_000 + lead


@pytest.mark.parametrize("lead", [119, 301])
def test_activation_outside_arming_window_is_rejected(lead: int) -> None:
    with pytest.raises(ValueError):
        _compose(start=1_800_000_000 + lead)


def test_resource_start_must_be_positive_and_not_in_the_future() -> None:
    with pytest.raises(ValueError):
        _compose(started=0)
    with pytest.raises(ValueError):
        _compose(started=1_800_000_001, now=1_800_000_000)


@pytest.mark.parametrize("field,value", [
    ("resource_started_epoch", True),
    ("resource_started_epoch", 0),
    ("resource_started_epoch", 1.5),
    ("activation_start_epoch", "1800000120"),
    ("activation_start_epoch", 0),
    ("now_epoch", False),
    ("now_epoch", 0),
])
def test_epoch_values_require_strict_integers(field: str, value: object) -> None:
    args = {
        "resource_started_epoch": 1_800_000_000,
        "activation_start_epoch": 1_800_000_120,
        "now_epoch": 1_800_000_000,
    }
    args[field] = value
    with pytest.raises(ValueError):
        bundle.build_dev_control_bundle(AwsDevShutdownPolicy("a1b2c3d4e5"), **args)  # type: ignore[arg-type]


def test_calendar_overflow_fails_closed_before_component_generation() -> None:
    with pytest.raises(ValueError):
        _compose(
            started=253_402_300_790,
            now=253_402_300_790,
            start=253_402_300_910,
        )


def test_resource_name_collision_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = bundle.build_dev_cleanup_schedule

    def collision(timestamp: str):
        result = original(timestamp)
        result["Resources"]["ShutdownSchedule"] = {}
        return result

    monkeypatch.setattr(bundle, "build_dev_cleanup_schedule", collision)
    with pytest.raises(ValueError, match="collide"):
        _compose()


def test_mismatched_region_conditions_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    original = bundle.build_dev_cleanup_schedule

    def mismatch(timestamp: str):
        result = original(timestamp)
        result["Conditions"] = {}
        return result

    monkeypatch.setattr(bundle, "build_dev_cleanup_schedule", mismatch)
    with pytest.raises(ValueError, match="conditions"):
        _compose()


def test_invalid_policy_is_revalidated_before_composition() -> None:
    policy = AwsDevShutdownPolicy("a1b2c3d4e5")
    object.__setattr__(policy, "api_id", "not-valid")
    with pytest.raises(ValueError):
        bundle.build_dev_control_bundle(
            policy,
            resource_started_epoch=1_800_000_000,
            activation_start_epoch=1_800_000_120,
            now_epoch=1_800_000_000,
        )
