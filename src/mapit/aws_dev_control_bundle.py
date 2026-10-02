"""Pure offline composition of the disabled dev shutdown and cleanup drafts.

This is a review artifact, not a deployment controller. The supplied epoch
snapshot must be revalidated immediately before any future use; this module
does not read a clock, contact AWS, or activate any resource.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from .aws_dev_cleanup_schedule import build_dev_cleanup_schedule
from .aws_dev_shutdown import AwsDevShutdownPolicy
from .aws_dev_shutdown_control import build_dev_shutdown_control

_REGION = "eu-west-1"
_MAX_RUNTIME_SECONDS = 300
_SHUTDOWN_LEAD_SECONDS = 120
_MIN_ARMING_LEAD_SECONDS = 120
_MAX_ARMING_LEAD_SECONDS = 300
_RESOURCE_LIFETIME_SECONDS = 3600
_CLEANUP_AFTER_RESOURCE_SECONDS = 2700
_SCHEDULER_MAX_DELAY_SECONDS = 60
_WORKFLOW_MAX_SECONDS = 45
_EXTRA_CLOSE_MARGIN_SECONDS = 15
_OPERATOR_CLEANUP_TAIL_SECONDS = 900
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _epoch_datetime(value: object, field_name: str) -> datetime:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer UTC epoch")
    try:
        result = _EPOCH + timedelta(seconds=value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{field_name} is outside the supported UTC range") from exc
    return result


def _schedule_timestamp(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S")


def build_dev_control_bundle(
    policy: AwsDevShutdownPolicy,
    *,
    resource_started_epoch: int,
    activation_start_epoch: int,
    now_epoch: int,
) -> dict[str, Any]:
    """Compose fixed, disabled shutdown and application-cleanup components.

    Epochs must be strict integers (not booleans) representable as UTC
    datetimes. Activation is bounded to a 120–300 second arming lead, the
    endpoint window is at most five minutes, and cleanup is scheduled 45
    minutes after the first resource. All schedules remain DISABLED.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")
    policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    if policy.region != _REGION:
        raise ValueError("unsupported development region")

    resource_started = _epoch_datetime(resource_started_epoch, "resource_started_epoch")
    activation_start = _epoch_datetime(activation_start_epoch, "activation_start_epoch")
    now = _epoch_datetime(now_epoch, "now_epoch")
    if resource_started > now:
        raise ValueError("resource start must not be in the future")
    arming_lead = activation_start_epoch - now_epoch
    if not _MIN_ARMING_LEAD_SECONDS <= arming_lead <= _MAX_ARMING_LEAD_SECONDS:
        raise ValueError("activation start is outside the bounded arming window")

    runtime_end_epoch = activation_start_epoch + _MAX_RUNTIME_SECONDS
    shutdown_epoch = runtime_end_epoch - _SHUTDOWN_LEAD_SECONDS
    cleanup_epoch = resource_started_epoch + _CLEANUP_AFTER_RESOURCE_SECONDS
    resource_deadline_epoch = resource_started_epoch + _RESOURCE_LIFETIME_SECONDS
    runtime_end = _epoch_datetime(runtime_end_epoch, "runtime_end_epoch")
    shutdown_at = _epoch_datetime(shutdown_epoch, "shutdown_epoch")
    cleanup_at = _epoch_datetime(cleanup_epoch, "cleanup_epoch")
    _epoch_datetime(resource_deadline_epoch, "resource_deadline_epoch")
    if runtime_end >= cleanup_at:
        raise ValueError("runtime window must end before scheduled cleanup")

    shutdown = build_dev_shutdown_control(policy, _schedule_timestamp(shutdown_at))
    cleanup = build_dev_cleanup_schedule(_schedule_timestamp(cleanup_at))
    shutdown_resources = shutdown.get("Resources")
    cleanup_resources = cleanup.get("Resources")
    if not isinstance(shutdown_resources, dict) or not isinstance(cleanup_resources, dict):
        raise ValueError("component resources are invalid")
    if set(shutdown_resources).intersection(cleanup_resources):
        raise ValueError("component resource names collide")
    if shutdown.get("Conditions") != cleanup.get("Conditions"):
        raise ValueError("component region conditions do not match")

    resources = {**shutdown_resources, **cleanup_resources}
    metadata = {
        "Readiness": "COMPOSED_COMPONENTS_NOT_DEPLOY_READY",
        "Region": _REGION,
        "NoActivation": True,
        "NoHardBillingCap": True,
        "EpochSnapshot": {
            "ResourceStarted": resource_started_epoch,
            "Now": now_epoch,
            "ActivationStart": activation_start_epoch,
            "RuntimeEnd": runtime_end_epoch,
            "ShutdownSchedule": shutdown_epoch,
            "CleanupSchedule": cleanup_epoch,
            "ResourceDeadline": resource_deadline_epoch,
        },
        "Limits": {
            "ResourceLifetimeSeconds": _RESOURCE_LIFETIME_SECONDS,
            "EndpointWindowSeconds": _MAX_RUNTIME_SECONDS,
            "ActivationArmingLeadSeconds": {
                "Minimum": _MIN_ARMING_LEAD_SECONDS,
                "Maximum": _MAX_ARMING_LEAD_SECONDS,
            },
            "ShutdownAdvanceSeconds": _SHUTDOWN_LEAD_SECONDS,
            "ClosureBudgetSeconds": {
                "SchedulerPrecision": _SCHEDULER_MAX_DELAY_SECONDS,
                "WorkflowTimeout": _WORKFLOW_MAX_SECONDS,
                "AdditionalMargin": _EXTRA_CLOSE_MARGIN_SECONDS,
                "Total": (
                    _SCHEDULER_MAX_DELAY_SECONDS
                    + _WORKFLOW_MAX_SECONDS
                    + _EXTRA_CLOSE_MARGIN_SECONDS
                ),
            },
            "CleanupAfterResourceStartSeconds": _CLEANUP_AFTER_RESOURCE_SECONDS,
            "OperatorCleanupTailSeconds": _OPERATOR_CLEANUP_TAIL_SECONDS,
        },
        "SchedulePolicy": (
            "All generated schedules and the EventBridge rule remain disabled; "
            "revalidate this explicit epoch snapshot immediately before any use."
        ),
        "NoGuarantee": (
            "Timing budgets are planning bounds, not an SLA, hard billing cap, "
            "or guarantee of control-plane completion."
        ),
        "Components": {
            "Shutdown": shutdown.get("Metadata", {}),
            "ApplicationCleanup": cleanup.get("Metadata", {}),
        },
    }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Review-only composed disabled dev controls; not deployment-ready.",
        "Metadata": metadata,
        "Conditions": shutdown["Conditions"],
        "Resources": resources,
    }


__all__ = ["build_dev_control_bundle"]
