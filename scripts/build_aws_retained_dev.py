"""Build the closed retained-dev bootstrap candidate offline only.

This factory derives the already-closed shared-identity five-resource scaffold.
It never imports an AWS SDK, reads credentials, calls AWS, or makes the
candidate deploy-ready.  Any activation requires fresh operator, bootstrap,
CD, independent-shutdown, and activation acceptance.
"""

from __future__ import annotations

import copy
from typing import Any

from scripts.build_aws_shared_identity_dev import build_shared_identity_bootstrap_template

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained"
CONDITION_NAME = "SupportedDeployment"
EXPECTED_RESOURCES = frozenset({"McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"})
FORBIDDEN_RESOURCE_MARKERS = frozenset({"McpUserPool", "McpUserPoolDomain", "UserPool", "UserPoolDomain"})
FORBIDDEN_ACTION_PREFIXES = frozenset({
    "cognito-idp:",
    "dynamodb:",
    "secretsmanager:",
    "ssm:",
    "kms:",
    "s3:",
})
LOG_ACTIONS = ["logs:CreateLogStream", "logs:PutLogEvents"]
HANDLER_CODE = (
    'def handler(event, context):\n'
    '    return {"statusCode": 503, "headers": {"content-type": "application/json", "cache-control": "no-store"}, "body": "{\\"error\\":\\"service_unavailable\\"}"}\n'
)


class RetainedDevTemplateError(ValueError):
    """Safe local error for retained-dev template contract violations."""


def _fail(category: str = "retained_dev_template_invalid") -> None:
    raise RetainedDevTemplateError(category)


def _contains_forbidden(value: Any) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and any(marker in key for marker in FORBIDDEN_RESOURCE_MARKERS):
                return True
            if _contains_forbidden(child):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden(child) for child in value)
    elif isinstance(value, str):
        return any(marker in value for marker in FORBIDDEN_RESOURCE_MARKERS)
    return False


def _walk_actions(value: Any) -> list[str]:
    actions: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "Action":
                values = child if isinstance(child, list) else [child]
                actions.extend(item for item in values if isinstance(item, str))
            actions.extend(_walk_actions(child))
    elif isinstance(value, list):
        for child in value:
            actions.extend(_walk_actions(child))
    return actions


def _expected_condition(stack_name: str = STACK_NAME) -> dict[str, Any]:
    return {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, stack_name]},
        ]
    }


def _validate_closed_scaffold(template: dict[str, Any], *, stack_name: str = STACK_NAME, retained_names: bool = False) -> None:
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != set(EXPECTED_RESOURCES):
        _fail("retained_dev_resource_set_invalid")
    conditions = template.get("Conditions")
    if conditions != {CONDITION_NAME: _expected_condition(stack_name)}:
        _fail("retained_dev_condition_invalid")
    parameters = template.get("Parameters")
    if retained_names:
        if parameters is not None:
            _fail("retained_dev_parameter_invalid")
    else:
        environment = parameters.get("EnvironmentName") if isinstance(parameters, dict) else None
        if not isinstance(environment, dict) or environment.get("Default") != "dev" or environment.get("AllowedValues") != ["dev"]:
            _fail("retained_dev_parameter_invalid")
    for resource in resources.values():
        if not isinstance(resource, dict) or resource.get("Condition") != CONDITION_NAME:
            _fail("retained_dev_resource_condition_invalid")

    expected_types = {
        "McpApi": "AWS::ApiGatewayV2::Api",
        "McpApiStage": "AWS::ApiGatewayV2::Stage",
        "McpHandlerRole": "AWS::IAM::Role",
        "McpHandlerLogGroup": "AWS::Logs::LogGroup",
        "McpHandler": "AWS::Lambda::Function",
    }
    for logical_id, expected_type in expected_types.items():
        resource = resources.get(logical_id)
        if not isinstance(resource, dict) or resource.get("Type") != expected_type:
            _fail("retained_dev_resource_type_invalid")

    api = resources.get("McpApi")
    api_properties = api.get("Properties") if isinstance(api, dict) else None
    if (
        not isinstance(api_properties, dict)
        or api_properties.get("ProtocolType") != "HTTP"
        or api_properties.get("Description") != "Phase 8 draft; default public execute-api endpoint disabled."
    ):
        _fail("retained_dev_api_shape_invalid")
    if api_properties.get("DisableExecuteApiEndpoint") is not True:
        _fail("retained_dev_endpoint_not_closed")
    if set(api_properties) != {"Description", "DisableExecuteApiEndpoint", "Name", "ProtocolType", "Tags"}:
        _fail("retained_dev_api_shape_invalid")

    stage = resources.get("McpApiStage")
    stage_properties = stage.get("Properties") if isinstance(stage, dict) else None
    if not isinstance(stage_properties, dict) or set(stage_properties) != {
        "ApiId", "AutoDeploy", "DefaultRouteSettings", "StageName"
    }:
        _fail("retained_dev_stage_shape_invalid")
    if stage_properties.get("ApiId") != {"Ref": "McpApi"} or stage_properties.get("AutoDeploy") is not True:
        _fail("retained_dev_stage_shape_invalid")
    if stage_properties.get("StageName") != "$default":
        _fail("retained_dev_stage_shape_invalid")
    settings = stage_properties.get("DefaultRouteSettings")
    if settings != {"DetailedMetricsEnabled": False, "ThrottlingBurstLimit": 1, "ThrottlingRateLimit": 1}:
        _fail("retained_dev_stage_shape_invalid")

    handler = resources.get("McpHandler")
    handler_properties = handler.get("Properties") if isinstance(handler, dict) else None
    if not isinstance(handler_properties, dict) or type(handler_properties.get("ReservedConcurrentExecutions")) is not int or handler_properties.get("ReservedConcurrentExecutions") != 0:
        _fail("retained_dev_handler_not_reserved_zero")
    if set(handler_properties) != {
        "Architectures", "Code", "FunctionName", "Handler", "MemorySize",
        "ReservedConcurrentExecutions", "Role", "Runtime", "Tags", "Timeout",
    }:
        _fail("retained_dev_handler_scope_invalid")
    if handler_properties.get("Architectures") != ["arm64"]:
        _fail("retained_dev_handler_scope_invalid")
    if handler_properties.get("Code") != {"ZipFile": HANDLER_CODE}:
        _fail("retained_dev_handler_scope_invalid")
    if handler_properties.get("Handler") != "index.handler" or handler_properties.get("Runtime") != "python3.13":
        _fail("retained_dev_handler_scope_invalid")
    if type(handler_properties.get("MemorySize")) is not int or handler_properties.get("MemorySize") != 256:
        _fail("retained_dev_handler_scope_invalid")
    if type(handler_properties.get("Timeout")) is not int or handler_properties.get("Timeout") != 20:
        _fail("retained_dev_handler_scope_invalid")
    if handler_properties.get("Role") != {"Fn::GetAtt": ["McpHandlerRole", "Arn"]}:
        _fail("retained_dev_handler_scope_invalid")
    if handler.get("DependsOn") != ["McpHandlerLogGroup"]:
        _fail("retained_dev_handler_scope_invalid")

    log_group = resources.get("McpHandlerLogGroup")
    log_properties = log_group.get("Properties") if isinstance(log_group, dict) else None
    if not isinstance(log_properties, dict) or set(log_properties) != {"LogGroupName", "RetentionInDays", "Tags"}:
        _fail("retained_dev_log_group_invalid")
    if type(log_properties.get("RetentionInDays")) is not int or log_properties.get("RetentionInDays") != 7:
        _fail("retained_dev_log_group_invalid")

    role = resources.get("McpHandlerRole")
    role_properties = role.get("Properties") if isinstance(role, dict) else None
    if not isinstance(role_properties, dict):
        _fail("retained_dev_log_role_invalid")
    if set(role_properties) != {"AssumeRolePolicyDocument", "Policies", "RoleName", "Tags"}:
        _fail("retained_dev_log_role_invalid")
    if "ManagedPolicyArns" in role_properties:
        _fail("retained_dev_log_role_invalid")
    trust = role_properties.get("AssumeRolePolicyDocument", {}).get("Statement")
    if trust != [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]:
        _fail("retained_dev_log_role_invalid")
    policies = role_properties.get("Policies")
    if not isinstance(policies, list) or len(policies) != 1:
        _fail("retained_dev_log_role_invalid")
    statements = policies[0].get("PolicyDocument", {}).get("Statement") if isinstance(policies[0], dict) else None
    if not isinstance(statements, list) or len(statements) != 1:
        _fail("retained_dev_log_role_invalid")
    statement = statements[0]
    if statement.get("Effect") != "Allow" or statement.get("Action") != LOG_ACTIONS:
        _fail("retained_dev_log_role_invalid")
    expected_log_arn = (
        "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/"
        + ("honda-mapit-mcp-dev-retained-handler:*" if retained_names else "honda-mapit-mcp-${EnvironmentName}-handler:*")
    )
    if statement.get("Resource") != {"Fn::Sub": expected_log_arn}:
        _fail("retained_dev_log_role_invalid")
    if any(action.startswith(prefix) for action in _walk_actions(template) for prefix in FORBIDDEN_ACTION_PREFIXES):
        _fail("retained_dev_permissions_invalid")
    if _contains_forbidden(template):
        _fail("retained_dev_identity_scope_invalid")
    if retained_names:
        expected = {
            "api": "honda-mapit-mcp-dev-retained-api",
            "handler": "honda-mapit-mcp-dev-retained-handler",
            "log_group": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
            "role": "honda-mapit-mcp-dev-retained-handler-role",
            "policy": "honda-mapit-mcp-dev-retained-owned-log-writes",
            "project": "honda-mapit-mcp",
            "environment": "dev",
            "purpose": "retained-dev",
        }
        if api_properties.get("Name") != expected["api"]:
            _fail("retained_dev_physical_name_invalid")
        if handler_properties.get("FunctionName") != expected["handler"]:
            _fail("retained_dev_physical_name_invalid")
        if resources["McpHandlerLogGroup"]["Properties"].get("LogGroupName") != expected["log_group"]:
            _fail("retained_dev_physical_name_invalid")
        if role_properties.get("RoleName") != expected["role"]:
            _fail("retained_dev_physical_name_invalid")
        if policies[0].get("PolicyName") != expected["policy"]:
            _fail("retained_dev_physical_name_invalid")
        for resource_name in ("McpApi", "McpHandler", "McpHandlerLogGroup", "McpHandlerRole"):
            tags = resources[resource_name]["Properties"].get("Tags")
            if isinstance(tags, dict):
                flattened = tags
                if set(flattened) != {"Project", "Environment", "Purpose"}:
                    _fail("retained_dev_tag_invalid")
            else:
                values = tags if isinstance(tags, list) else []
                flattened = {
                    item.get("Key"): item.get("Value")
                    for item in values
                    if isinstance(item, dict) and isinstance(item.get("Key"), str)
                }
                if len(values) != 3 or set(flattened) != {"Project", "Environment", "Purpose"}:
                    _fail("retained_dev_tag_invalid")
            if flattened.get("Project") != expected["project"] or flattened.get("Environment") != expected["environment"] or flattened.get("Purpose") != expected["purpose"]:
                _fail("retained_dev_tag_invalid")


def _rename_physical_labels(template: dict[str, Any]) -> None:
    resources = template["Resources"]
    resources["McpApi"]["Properties"]["Name"] = "honda-mapit-mcp-dev-retained-api"
    resources["McpHandler"]["Properties"]["FunctionName"] = "honda-mapit-mcp-dev-retained-handler"
    resources["McpHandlerLogGroup"]["Properties"]["LogGroupName"] = "/aws/lambda/honda-mapit-mcp-dev-retained-handler"
    role_properties = resources["McpHandlerRole"]["Properties"]
    role_properties["RoleName"] = "honda-mapit-mcp-dev-retained-handler-role"
    role_properties["Policies"][0]["PolicyName"] = "honda-mapit-mcp-dev-retained-owned-log-writes"
    role_properties["Policies"][0]["PolicyDocument"]["Statement"][0]["Resource"] = {"Fn::Sub": (
        "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/"
        "honda-mapit-mcp-dev-retained-handler:*"
    )}
    for resource_name in ("McpApi", "McpHandler", "McpHandlerLogGroup", "McpHandlerRole"):
        tags = resources[resource_name]["Properties"].get("Tags")
        if isinstance(tags, dict):
            tags["Project"] = "honda-mapit-mcp"
            tags["Environment"] = "dev"
            tags["Purpose"] = "retained-dev"
        elif isinstance(tags, list):
            tags[:] = [item for item in tags if isinstance(item, dict) and item.get("Key") not in {"Project", "Environment", "Purpose"}]
            tags.extend([
                {"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": "dev"},
                {"Key": "Purpose", "Value": "retained-dev"},
            ])


def build_retained_dev_template() -> dict[str, Any]:
    """Return a fresh closed five-resource retained-dev candidate."""
    try:
        template = copy.deepcopy(build_shared_identity_bootstrap_template())
    except RetainedDevTemplateError:
        raise
    except Exception:
        _fail("retained_dev_source_invalid")
    if not isinstance(template, dict):
        _fail("retained_dev_source_invalid")
    _validate_closed_scaffold(template, stack_name="honda-mapit-mcp-dev")
    _rename_physical_labels(template)
    template["Conditions"] = {CONDITION_NAME: _expected_condition()}
    # All retained physical labels and tags are literal, so the old rehearsal
    # parameter would be unused and would fail cfn-lint W2001.
    template.pop("Parameters", None)
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        _fail("retained_dev_metadata_invalid")
    metadata.update({
        "Readiness": "RETAINED_DEV_NOT_DEPLOY_READY",
        "Purpose": "retained dev closed bootstrap scaffold only",
        "RetainedResourcePurpose": "closed retained-dev foundation; no runtime or business data path",
        "StackName": STACK_NAME,
        "Region": REGION,
        "RequiresFreshOperatorAcceptance": True,
        "RequiresFreshBootstrapAcceptance": True,
        "RequiresFreshCDAcceptance": True,
        "RequiresIndependentShutdownAcceptance": True,
        "RequiresActivationAcceptance": True,
        "NotDeployReady": True,
        "NoNewPoolDomainUserOrMfa": True,
        "NoCredentialsSsmOrBusinessCalls": True,
        "ExactScaffoldLogRoleOnly": True,
    })
    _validate_closed_scaffold(template, retained_names=True)
    return template


__all__ = [
    "CONDITION_NAME",
    "EXPECTED_RESOURCES",
    "REGION",
    "RetainedDevTemplateError",
    "STACK_NAME",
    "build_retained_dev_template",
]
