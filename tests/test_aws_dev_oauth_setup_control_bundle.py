from __future__ import annotations

import copy

import pytest

from mapit.aws_dev_oauth_cleanup import build_dev_oauth_setup_cleanup
from mapit.aws_dev_oauth_setup_control_bundle import build_dev_oauth_setup_control_bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle

POLICY = AwsDevShutdownPolicy("a1b2c3d4e5")
POOL = "eu-west-1_A1b2C3d4E"
STACK_UUID = "11111111-2222-3333-4444-555555555555"
STARTED = 1893456000
NOW = 1893456060
ACTIVATE = 1893456240


def _setup_cleanup():
    return build_dev_oauth_setup_cleanup(POLICY, POOL, STACK_UUID, "2030-01-01T00:45:00")


def _bundle():
    return build_dev_oauth_setup_control_bundle(
        POLICY, user_pool_id=POOL, stack_uuid=STACK_UUID,
        resource_started_epoch=STARTED, now_epoch=NOW, activation_start_epoch=ACTIVATE,
    )


def test_setup_cleanup_is_base_scope_plus_cognito_children_only():
    base = build_dev_bootstrap_control_bundle(
        POLICY, user_pool_id=POOL, stack_uuid=STACK_UUID,
        resource_started_epoch=STARTED, now_epoch=NOW, activation_start_epoch=ACTIVATE,
    )
    cleanup = _setup_cleanup()
    assert set(cleanup["Resources"]) == {
        "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup",
        "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
    }
    base_statements = base["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    setup_statements = cleanup["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert setup_statements[0] == base_statements[0]
    assert setup_statements[1]["Resource"] == base_statements[1]["Resource"]
    assert setup_statements[1]["Action"] == [
        "cognito-idp:DeleteUserPool", "cognito-idp:DeleteUserPoolDomain",
        "cognito-idp:DeleteResourceServer", "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DeleteManagedLoginBranding",
    ]
    assert setup_statements[2] == {
        "Effect": "Allow", "Action": "cognito-idp:DescribeUserPoolDomain", "Resource": "*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
    }
    assert setup_statements[3:] == base_statements[2:]
    serialized = repr(cleanup)
    for denied in ("DeleteRoute", "RemovePermission", "s3:", "kms:", "iam:PutRolePolicy"):
        assert denied not in serialized
    assert cleanup["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"


def test_setup_bundle_keeps_12_resources_and_same_disabled_controls():
    base = build_dev_bootstrap_control_bundle(
        POLICY, user_pool_id=POOL, stack_uuid=STACK_UUID,
        resource_started_epoch=STARTED, now_epoch=NOW, activation_start_epoch=ACTIVATE,
    )
    result = _bundle()
    assert len(result["Resources"]) == 12
    for name in (
        "ShutdownStateMachine", "ShutdownWorkflowRole", "SchedulerGroup", "SchedulerInvokeRole",
        "ShutdownSchedule", "RequestTripwireAlarm", "RequestTripwireAlarmRule", "RequestTripwireEventRole",
    ):
        if name in base["Resources"]:
            assert result["Resources"][name] == base["Resources"][name]
    assert result["Resources"]["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"
    assert result["Resources"]["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert result["Resources"]["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert result["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert result["Metadata"]["ControlsForOAuthSetup"] is True
    assert "OAuthConfigured" not in result["Metadata"]
    role_statements = result["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert role_statements[1]["Resource"] == {
        "Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{POOL}"
    }
    assert "enabled, exact-target 45-minute deletion timer" in " ".join(result["Metadata"]["MissingPrerequisites"])


def test_setup_cleanup_rejects_invalid_pool_or_timing():
    with pytest.raises(ValueError):
        build_dev_oauth_setup_cleanup(POLICY, "eu-west-1_short", STACK_UUID, "2030-01-01T00:45:00")
    with pytest.raises(ValueError):
        build_dev_oauth_setup_cleanup(POLICY, POOL, STACK_UUID, "not-a-time")


def test_base_cleanup_factory_result_is_not_mutated_by_setup_variant():
    from mapit.aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup

    baseline = build_dev_bootstrap_cleanup(POLICY, POOL, STACK_UUID, "2030-01-01T00:45:00")
    saved = copy.deepcopy(baseline)
    _setup_cleanup()
    assert baseline == saved
