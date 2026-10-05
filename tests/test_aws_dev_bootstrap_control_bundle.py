from __future__ import annotations

import pytest

import mapit.aws_dev_bootstrap_control_bundle as bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy


def _compose(
    *,
    started: int = 1_800_000_000,
    start: int = 1_800_000_120,
    now: int = 1_800_000_000,
    pool: str = "eu-west-1_123456789ABC",
    stack_uuid: str = "12345678-1234-1234-1234-123456789abc",
) -> dict:
    return bundle.build_dev_bootstrap_control_bundle(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        user_pool_id=pool,
        stack_uuid=stack_uuid,
        resource_started_epoch=started,
        activation_start_epoch=start,
        now_epoch=now,
    )


def test_composed_bootstrap_has_eight_shutdown_and_four_exact_cleanup_resources() -> None:
    template = _compose()
    resources = template["Resources"]
    assert set(resources) == {
        "ShutdownWorkflowRole", "ShutdownStateMachine", "SchedulerGroup",
        "SchedulerInvokeRole", "ShutdownSchedule", "RequestTripwireAlarm",
        "RequestTripwireEventRole", "RequestTripwireAlarmRule",
        "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup",
        "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
    }
    assert len(resources) == 12
    assert all(resource["Condition"] == "SupportedRegion" for resource in resources.values())
    assert template["Conditions"] == {
        "SupportedRegion": {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]}
    }
    assert "Outputs" not in template
    assert resources["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert resources["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert template["Metadata"]["NoActivation"] is True


def test_cleanup_component_replaces_legacy_wildcard_cleanup_without_stale_prerequisite() -> None:
    template = _compose()
    cleanup = template["Resources"]["BootstrapCleanupSchedule"]["Properties"]
    assert cleanup["ScheduleExpression"] == "at(2027-01-15T08:45:00)"
    assert cleanup["Target"]["Input"]["Fn::Sub"][1]["StackArn"] == {
        "Fn::Sub": "arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/honda-mapit-mcp-dev/12345678-1234-1234-1234-123456789abc"
    }
    metadata = template["Metadata"]
    component_text = repr(metadata["Components"]["ApplicationCleanup"])
    assert "service role" not in component_text.lower()
    assert metadata["Readiness"] == "COMPOSED_BOOTSTRAP_REHEARSAL_NOT_DEPLOY_READY"
    assert metadata["OAuthConfigured"] is False
    assert metadata["UserCreated"] is False
    assert "associated CloudFormation service role" not in repr(metadata)
    assert "full OAuth" not in repr(metadata).lower()


def test_endpoint_window_and_resource_lifetime_snapshot_are_preserved() -> None:
    metadata = _compose()["Metadata"]
    assert metadata["EpochSnapshot"] == {
        "ResourceStarted": 1_800_000_000,
        "Now": 1_800_000_000,
        "ActivationStart": 1_800_000_120,
        "RuntimeEnd": 1_800_000_420,
        "ShutdownSchedule": 1_800_000_300,
        "CleanupSchedule": 1_800_002_700,
        "ResourceDeadline": 1_800_003_600,
    }
    assert metadata["Limits"]["EndpointWindowSeconds"] == 300
    assert metadata["Limits"]["ResourceLifetimeSeconds"] == 3600
    assert metadata["Limits"]["OperatorCleanupTailSeconds"] == 900
    assert "not an SLA" in metadata["NoGuarantee"]
    assert "legacy" not in repr(metadata["Components"]["ApplicationCleanup"]).lower()


def test_wrapper_fails_closed_if_bootstrap_cleanup_collides_with_shutdown_resources(monkeypatch: pytest.MonkeyPatch) -> None:
    original = bundle.build_dev_bootstrap_cleanup

    def collision(*args, **kwargs):
        template = original(*args, **kwargs)
        template["Resources"]["ShutdownStateMachine"] = {}
        return template

    monkeypatch.setattr(bundle, "build_dev_bootstrap_cleanup", collision)
    with pytest.raises(ValueError, match="collide"):
        _compose()


def test_wrapper_fails_closed_if_region_conditions_diverge(monkeypatch: pytest.MonkeyPatch) -> None:
    original = bundle.build_dev_bootstrap_cleanup

    def mismatch(*args, **kwargs):
        template = original(*args, **kwargs)
        template["Conditions"] = {}
        return template

    monkeypatch.setattr(bundle, "build_dev_bootstrap_cleanup", mismatch)
    with pytest.raises(ValueError, match="conditions"):
        _compose()


@pytest.mark.parametrize("kwargs", [
    {"start": 1_800_000_119},
    {"start": 1_800_000_301},
    {"started": 1_800_000_001},
    {"pool": "eu-west-1_short"},
    {"stack_uuid": "00000000-0000-0000-0000-000000000000"},
])
def test_wrapper_reuses_strict_timing_and_target_validation(kwargs: dict) -> None:
    with pytest.raises(ValueError):
        _compose(**kwargs)


def test_wrapper_returns_fresh_values() -> None:
    one = _compose()
    two = _compose()
    assert one == two and one is not two
    one["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] = "ENABLED"
    assert two["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
