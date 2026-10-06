"""Offline retained-dev artifact and independent stop drafts; no AWS calls.

These drafts preserve the existing dev rehearsal factories and clocks. They
create neither an active endpoint nor permission for business/secret access.
Actual bootstrap/readbacks, dev CD and fresh activation remain prerequisites.
"""
from __future__ import annotations

from typing import Any

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control
from scripts.build_aws_dev_runtime_template import fixed_runtime_bucket_template

PREFIX = "honda-mapit-mcp-dev-retained"


def _namespace(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _namespace(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_namespace(child) for child in value]
    if isinstance(value, str):
        return value.replace("honda-mapit-mcp-dev", PREFIX)
    return value


def build_retained_dev_controls(api_id: str) -> dict[str, Any]:
    """Five disabled control resources, without any Lambda or cleanup timer."""
    policy = AwsDevShutdownPolicy(api_id)
    template = _namespace(build_dev_shutdown_control(policy, "2030-01-01T00:00:00"))
    for name in ("SchedulerGroup", "SchedulerInvokeRole", "ShutdownSchedule"):
        del template["Resources"][name]
    if len(template["Resources"]) != 5:
        raise ValueError("retained_dev_control_shape_invalid")
    template["Conditions"]["SupportedRegion"] = {"Fn::And": [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, PREFIX + "-controls"]},
    ]}
    template["Description"] = "Closed retained-dev independent stop draft; not deploy-ready."
    template["Metadata"] = {
        "Readiness": "RETAINED_DEV_CONTROLS_NOT_DEPLOY_READY",
        "Environment": "dev", "NoActivation": True, "NoControlLambda": True,
        "BillingHardCap": False, "NoAutomaticReopening": True,
        "FreshScheduledCloseRequiredBeforeActivation": True,
        "NoInheritedRehearsalClockOrCleanup": True,
    }
    return template


def build_retained_dev_artifacts() -> dict[str, Any]:
    """Private retained bucket/policy; only terminal journals expire after 30d."""
    template = _namespace(fixed_runtime_bucket_template())
    template["Description"] = "Private retained-dev artifact draft; no credentials or history."
    template["Metadata"] = {
        "Readiness": "RETAINED_DEV_ARTIFACTS_NOT_DEPLOY_READY",
        "Environment": "dev", "NoDeployment": True,
        "NoCredentialsOrHistory": True, "TerminalJournalRetentionDays": 30,
        "RuntimeAndPendingJournalsDoNotExpire": True,
        "ExplicitReviewedRetirementRequired": True,
    }
    template["Conditions"]["SupportedDeployment"]["Fn::And"][1]["Fn::Equals"][1] = PREFIX + "-runtime-artifacts"
    for resource in template["Resources"].values():
        resource["DeletionPolicy"] = "Retain"
        resource["UpdateReplacePolicy"] = "Retain"
        for tag in resource.get("Properties", {}).get("Tags", []):
            if tag.get("Key") == "Purpose":
                tag["Value"] = "retained-dev-artifacts"
        if resource["Type"] == "AWS::S3::Bucket":
            resource["Properties"]["LifecycleConfiguration"] = {"Rules": [{
                "Id": "DevTerminalJournalRetention", "Status": "Enabled",
                "Prefix": "journals/", "TagFilters": [{"Key": "cd-terminal", "Value": "true"}],
                "ExpirationInDays": 30,
            }]}
    return template
