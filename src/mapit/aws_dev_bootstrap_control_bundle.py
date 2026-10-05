"""Pure composition of shutdown controls and exact bootstrap-stack cleanup."""

from __future__ import annotations

from typing import Any

from .aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup
from .aws_dev_shutdown import AwsDevShutdownPolicy
from .aws_dev_control_bundle import build_dev_control_bundle

_LEGACY_CLEANUP_RESOURCES = frozenset({
    "CleanupScheduleGroup", "CleanupSchedulerRole", "CleanupSchedule",
})


def build_dev_bootstrap_control_bundle(
    policy: AwsDevShutdownPolicy,
    *,
    user_pool_id: str,
    stack_uuid: str,
    resource_started_epoch: int,
    activation_start_epoch: int,
    now_epoch: int,
) -> dict[str, Any]:
    """Replace the legacy app-stack deletion draft with exact bootstrap cleanup.

    Timing validation and shutdown scheduling are reused from the accepted
    bundle factory. All resources remain disabled and the epoch snapshot must
    be revalidated immediately before any future use.
    """
    draft = build_dev_control_bundle(
        policy,
        resource_started_epoch=resource_started_epoch,
        activation_start_epoch=activation_start_epoch,
        now_epoch=now_epoch,
    )
    original_resources = draft.get("Resources")
    if not isinstance(original_resources, dict) or not _LEGACY_CLEANUP_RESOURCES <= original_resources.keys():
        raise ValueError("shutdown component resources are invalid")
    old_cleanup = original_resources["CleanupSchedule"]["Properties"].get("ScheduleExpression")
    if type(old_cleanup) is not str or not old_cleanup.startswith("at(") or not old_cleanup.endswith(")"):
        raise ValueError("cleanup schedule expression is invalid")

    cleanup = build_dev_bootstrap_cleanup(
        policy,
        user_pool_id,
        stack_uuid,
        old_cleanup[3:-1],
    )
    shutdown_resources = {
        name: resource for name, resource in original_resources.items()
        if name not in _LEGACY_CLEANUP_RESOURCES
    }
    cleanup_resources = cleanup.get("Resources")
    if not isinstance(cleanup_resources, dict):
        raise ValueError("bootstrap cleanup resources are invalid")
    if set(shutdown_resources).intersection(cleanup_resources):
        raise ValueError("component resource names collide")
    if draft.get("Conditions") != cleanup.get("Conditions"):
        raise ValueError("component region conditions do not match")

    metadata = dict(draft["Metadata"])
    metadata["Readiness"] = "COMPOSED_BOOTSTRAP_REHEARSAL_NOT_DEPLOY_READY"
    metadata["Purpose"] = "closed synthetic bootstrap creation, shutdown, and deletion rehearsal"
    metadata["OAuthConfigured"] = False
    metadata["UserCreated"] = False
    metadata["PermissionsAndCleanupPending"] = True
    components = dict(metadata.get("Components", {}))
    components["ApplicationCleanup"] = cleanup.get("Metadata", {})
    metadata["Components"] = components
    metadata["MissingPrerequisites"] = [
        "explicit reviewed approval for the closed bootstrap rehearsal",
        "fresh exact API, pool, stack UUID, region, and account binding readbacks",
        "deployment-time schedule and one-hour resource-lifetime revalidation",
        "independent shutdown and exact bootstrap cleanup readbacks",
        "operator verifies bootstrap stack deletion and cleans surviving control resources",
    ]

    return {
        "AWSTemplateFormatVersion": draft["AWSTemplateFormatVersion"],
        "Description": "Review-only composed disabled bootstrap rehearsal controls; not deployment-ready.",
        "Metadata": metadata,
        "Conditions": draft["Conditions"],
        "Resources": {**shutdown_resources, **cleanup_resources},
    }


__all__ = ["build_dev_bootstrap_control_bundle"]
