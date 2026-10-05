"""Pure disabled control bundle for the Cognito-only OAuth setup stage."""

from __future__ import annotations

from typing import Any

from .aws_dev_bootstrap_control_bundle import build_dev_bootstrap_control_bundle
from .aws_dev_oauth_cleanup import build_dev_oauth_setup_cleanup
from .aws_dev_shutdown import AwsDevShutdownPolicy

_CLEANUP_RESOURCES = frozenset({
    "BootstrapDeletionRole", "BootstrapCleanupScheduleGroup",
    "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule",
})
_SHUTDOWN_RESOURCES = frozenset({
    "RequestTripwireAlarm", "RequestTripwireAlarmRule", "RequestTripwireEventRole",
    "SchedulerGroup", "SchedulerInvokeRole", "ShutdownSchedule", "ShutdownStateMachine", "ShutdownWorkflowRole",
})
_SCHEDULE_NAME = "BootstrapCleanupSchedule"


def build_dev_oauth_setup_control_bundle(
    policy: AwsDevShutdownPolicy,
    *,
    user_pool_id: str,
    stack_uuid: str,
    resource_started_epoch: int,
    activation_start_epoch: int,
    now_epoch: int,
) -> dict[str, Any]:
    """Compose the 8 shutdown controls and 4 exact Cognito cleanup resources.

    This remains a disabled planning artifact. The activation timestamp and
    45-minute cleanup schedule require fresh operator revalidation before any
    future use; this factory does not create or arm resources.
    """
    draft = build_dev_bootstrap_control_bundle(
        policy,
        user_pool_id=user_pool_id,
        stack_uuid=stack_uuid,
        resource_started_epoch=resource_started_epoch,
        activation_start_epoch=activation_start_epoch,
        now_epoch=now_epoch,
    )
    resources = draft.get("Resources")
    if not isinstance(resources, dict) or len(resources) != 12 or not _CLEANUP_RESOURCES <= resources.keys():
        raise ValueError("bootstrap control component invalid")
    if resources.keys() != _CLEANUP_RESOURCES | _SHUTDOWN_RESOURCES:
        raise ValueError("bootstrap control component invalid")
    expression = resources[_SCHEDULE_NAME].get("Properties", {}).get("ScheduleExpression")
    if type(expression) is not str or not expression.startswith("at(") or not expression.endswith(")"):
        raise ValueError("bootstrap cleanup schedule invalid")
    cleanup = build_dev_oauth_setup_cleanup(
        policy,
        user_pool_id,
        stack_uuid,
        expression[3:-1],
    )
    cleanup_resources = cleanup.get("Resources")
    if not isinstance(cleanup_resources, dict) or set(cleanup_resources) != _CLEANUP_RESOURCES:
        raise ValueError("OAuth setup cleanup component invalid")
    combined = {name: value for name, value in resources.items() if name not in _CLEANUP_RESOURCES}
    if len(combined) != 8 or set(combined).intersection(cleanup_resources):
        raise ValueError("OAuth setup control component invalid")
    if draft.get("Conditions") != cleanup.get("Conditions"):
        raise ValueError("OAuth setup control conditions invalid")
    if any(
        resources[name].get("Properties", {}).get("State") != "DISABLED"
        for name in ("ShutdownSchedule", "BootstrapCleanupSchedule")
    ):
        raise ValueError("OAuth setup control schedule is not disabled")
    combined.update(cleanup_resources)
    metadata = dict(draft.get("Metadata", {}))
    components = dict(metadata.get("Components", {}))
    components["ApplicationCleanup"] = cleanup.get("Metadata", {})
    metadata.update({
        "Readiness": "OAUTH_SETUP_CONTROL_BUNDLE_NOT_DEPLOY_READY",
        "ControlsForOAuthSetup": True,
        "OAuthSetupCleanupOnly": True,
        "NoActivation": True,
        "NoRuntimeArtifactPermissions": True,
        "Components": components,
        "MissingPrerequisites": [
            "owned bootstrap stack and exact API/pool bindings read back",
            "expanded Cognito-only cleanup role policy updated and verified before OAuth setup update",
            "an enabled, exact-target 45-minute deletion timer read back with at least five minutes remaining before app update",
            "full closed OAuth setup deletion and absence readback rehearsed",
            "runtime identity binding, API activation, and enrollment remain separate gates",
        ],
    })
    metadata.pop("OAuthConfigured", None)
    return {
        "AWSTemplateFormatVersion": draft["AWSTemplateFormatVersion"],
        "Description": "Review-only disabled Cognito OAuth setup controls; not deployment-ready.",
        "Metadata": metadata,
        "Conditions": draft["Conditions"],
        "Resources": combined,
    }


__all__ = ["build_dev_oauth_setup_control_bundle"]
