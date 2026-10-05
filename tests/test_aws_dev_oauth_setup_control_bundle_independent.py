from __future__ import annotations

import copy

import pytest

from mapit.aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle
from mapit.aws_dev_oauth_cleanup import build_dev_oauth_setup_cleanup
from mapit.aws_dev_oauth_setup_control_bundle import build_dev_oauth_setup_control_bundle
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy


API = "a1b2c3d4e5"
POOL = "eu-west-1_A1b2C3d4E"
STACK_UUID = "11111111-2222-3333-4444-555555555555"
STARTED = 1_893_456_000
NOW = STARTED + 60
ACTIVATE = NOW + 180


def _base():
    return build_dev_bootstrap_control_bundle(
        AwsDevShutdownPolicy(API), user_pool_id=POOL, stack_uuid=STACK_UUID,
        resource_started_epoch=STARTED, activation_start_epoch=ACTIVATE, now_epoch=NOW,
    )


def _oauth():
    return build_dev_oauth_setup_control_bundle(
        AwsDevShutdownPolicy(API), user_pool_id=POOL, stack_uuid=STACK_UUID,
        resource_started_epoch=STARTED, activation_start_epoch=ACTIVATE, now_epoch=NOW,
    )


def _statements(template):
    return template["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def test_setup_bundle_preserves_eight_controls_and_only_adds_cognito_cleanup_scope():
    base = _base()
    result = _oauth()
    base_resources, resources = base["Resources"], result["Resources"]
    shutdown_names = set(base_resources) - {
        "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup",
        "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
    }
    assert len(resources) == 12
    assert {name for name in resources if name in shutdown_names} == shutdown_names
    assert all(resources[name] == base_resources[name] for name in shutdown_names)
    for name in ("BootstrapCleanupScheduleGroup", "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule"):
        assert resources[name] == base_resources[name]
    assert resources["BootstrapCleanupSchedule"]["Properties"]["State"] == "DISABLED"
    assert resources["ShutdownSchedule"]["Properties"]["State"] == "DISABLED"

    old, new = _statements(base), _statements(result)
    assert len(old) == 6 and len(new) == 7
    assert new[0] == old[0]
    assert new[1]["Resource"] == old[1]["Resource"]
    assert new[1]["Action"] == [
        "cognito-idp:DeleteUserPool", "cognito-idp:DeleteUserPoolDomain",
        "cognito-idp:DeleteResourceServer", "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DeleteManagedLoginBranding",
    ]
    assert new[2] == {
        "Effect": "Allow", "Action": "cognito-idp:DescribeUserPoolDomain", "Resource": "*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
    }
    assert new[3:] == old[2:]
    assert resources["BootstrapDeletionRole"]["Properties"]["RoleName"] == (
        base_resources["BootstrapDeletionRole"]["Properties"]["RoleName"]
    )
    assert resources["BootstrapCleanupSchedule"]["Properties"]["Target"] == (
        base_resources["BootstrapCleanupSchedule"]["Properties"]["Target"]
    )
    assert result["Metadata"]["NoActivation"] is True
    assert "OAuthConfigured" not in result["Metadata"]
    assert result["Metadata"]["OAuthSetupCleanupOnly"] is True


@pytest.mark.parametrize("lead", [119, 301])
def test_setup_bundle_rejects_activation_outside_inherited_window(lead):
    with pytest.raises(ValueError):
        build_dev_oauth_setup_control_bundle(
            AwsDevShutdownPolicy(API), user_pool_id=POOL, stack_uuid=STACK_UUID,
            resource_started_epoch=STARTED, activation_start_epoch=NOW + lead, now_epoch=NOW,
        )


def test_setup_cleanup_returns_fresh_objects_and_fails_closed_on_base_policy_drift(monkeypatch):
    import mapit.aws_dev_oauth_cleanup as cleanup

    args = (AwsDevShutdownPolicy(API), POOL, STACK_UUID, "2030-01-01T00:45:00")
    first = build_dev_oauth_setup_cleanup(*args)
    snapshot = copy.deepcopy(first)
    first["Resources"]["BootstrapDeletionRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"].clear()
    second = build_dev_oauth_setup_cleanup(*args)
    assert second == snapshot

    original = cleanup.build_dev_bootstrap_cleanup

    def changed_base(*call_args):
        value = original(*call_args)
        _statements(value)[0]["Action"] = ["apigateway:*"]
        return value

    monkeypatch.setattr(cleanup, "build_dev_bootstrap_cleanup", changed_base)
    with pytest.raises(ValueError, match="bootstrap cleanup contract invalid"):
        build_dev_oauth_setup_cleanup(*args)
