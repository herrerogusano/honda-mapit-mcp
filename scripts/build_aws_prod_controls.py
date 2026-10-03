"""Offline fixed production emergency stop, independent of Lambda capacity."""
from __future__ import annotations

from typing import Any

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control


def _prod_values(value: Any) -> Any:
    """Translate only the project's fixed environment namespace in a fresh tree."""
    if isinstance(value, dict):
        return {key: _prod_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_prod_values(item) for item in value]
    if isinstance(value, str):
        if value == "dev":
            return "prod"
        return (value.replace("honda-mapit-mcp-dev", "honda-mapit-mcp-prod")
                .replace("fixed-dev-shutdown", "fixed-prod-shutdown")
                .replace("StartFixedDevShutdownWorkflow", "StartFixedProdShutdownWorkflow")
                .replace("fixed-target dev shutdown", "fixed-target prod shutdown")
                .replace("development", "production"))
    return value


def fixed_prod_controls_template(api_id: str) -> dict[str, Any]:
    """Reuse the reviewed stop/readback workflow with separate prod bindings.

    No custom domain, automatic reopening, positive reserve or control Lambda.
    Alarm/rule start disabled. There is no periodic dev cleanup schedule.
    """
    policy = AwsDevShutdownPolicy(api_id)
    template = _prod_values(build_dev_shutdown_control(policy, "2030-01-01T00:00:00"))
    for name in ("SchedulerGroup", "SchedulerInvokeRole", "ShutdownSchedule"):
        del template["Resources"][name]
    template["Description"] = "Private production emergency-stop controls, initially disabled; not a billing hard cap."
    template["Metadata"] = {"NoActivation": True, "Environment": "prod", "BillingHardCap": False,
                            "NoControlLambda": True, "NoDevCleanupSchedule": True}
    template["Conditions"]["SupportedRegion"] = {"Fn::And": [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-prod-controls"]},
    ]}
    # Keep API request count, not only Lambda invocations: throttled/denied
    # requests can still incur API cost without occupying Lambda capacity.
    return template


__all__ = ["fixed_prod_controls_template"]
