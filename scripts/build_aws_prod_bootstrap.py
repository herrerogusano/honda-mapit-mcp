"""Offline closed production bootstrap; never deploys or opens an endpoint."""
from __future__ import annotations

from typing import Any

from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template


def fixed_prod_bootstrap_template() -> dict[str, Any]:
    """Reuse the validated closed scaffold, not the temporary identity stack."""
    template = fixed_bootstrap_template()
    template["Description"] = "Closed private production bootstrap; activation requires separate verified runtime and controls."
    template["Metadata"] = {"NoActivation": True, "RuntimeImplementation": False,
                            "Environment": "prod", "RetainedIdentityReused": True}
    template["Parameters"]["EnvironmentName"].update(
        Default="prod", AllowedValues=["prod"], Description="Fixed private production environment."
    )
    template["Conditions"]["SupportedDeployment"]["Fn::And"][1]["Fn::Equals"][1] = "honda-mapit-mcp-prod"
    del template["Resources"]["McpUserPool"]
    del template["Outputs"]["UserPoolId"]
    stage = template["Resources"]["McpApiStage"]["Properties"]
    stage["DefaultRouteSettings"] = {"ThrottlingBurstLimit": 2, "ThrottlingRateLimit": 1.0,
                                     "DetailedMetricsEnabled": False}
    stage.pop("AccessLogSettings", None)
    function = template["Resources"]["McpHandler"]["Properties"]
    function.update(Runtime="python3.13", Architectures=["arm64"], MemorySize=256, Timeout=15)
    role = template["Resources"]["McpHandlerRole"]["Properties"]
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    statements.append({
        "Effect": "Allow", "Action": "ssm:GetParameter",
        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/honda-mapit-mcp/prod/mapit-refresh-token"},
    })
    # No write/history/list/discovery rights and no KMS permission are added for
    # the AWS-managed alias/aws/ssm key. Existing log permissions stay scoped.
    for resource in template["Resources"].values():
        tags = resource.get("Properties", {}).get("Tags")
        if isinstance(tags, list):
            for tag in tags:
                if tag.get("Key") == "Environment": tag["Value"] = "prod"
    return template


__all__ = ["fixed_prod_bootstrap_template"]
