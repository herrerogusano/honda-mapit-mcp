"""Create a closed, non-deploy-ready bootstrap rehearsal template offline.

The factory selects six fixed resources from the repository scaffold. It does
not deploy, contact AWS, create an OAuth client/user, or open the API endpoint.
"""

from __future__ import annotations

import json
import re
import stat
from pathlib import Path
from typing import Any

MAX_TEMPLATE_BYTES = 128 * 1024
_RESOURCE_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpUserPool": "AWS::Cognito::UserPool",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
}
_PSEUDO_PARAMETERS = frozenset({
    "AWS::AccountId", "AWS::NotificationARNs", "AWS::NoValue", "AWS::Partition",
    "AWS::Region", "AWS::StackId", "AWS::StackName", "AWS::URLSuffix",
})
_FORBIDDEN_LAMBDA_PROPERTIES = frozenset({
    "Environment", "VpcConfig", "Layers", "FileSystemConfigs", "DeadLetterConfig",
    "CodeSigningConfigArn", "EphemeralStorage", "FunctionUrlConfig",
})
_ALLOWED_USER_POOL_PROPERTIES = frozenset({
    "AdminCreateUserConfig", "EnabledMfas", "MfaConfiguration", "UserPoolName",
    "UserPoolTags", "UserPoolTier", "UsernameAttributes",
})
_EXPECTED_HANDLER = (
    'def handler(event, context):\n'
    '    return {"statusCode": 503, "headers": {"content-type": "application/json", '
    '"cache-control": "no-store"}, "body": "{\\"error\\":\\"service_unavailable\\"}"}\n'
)


class BootstrapTemplateError(ValueError):
    """Safe local template error; deliberately contains no input path/value."""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _has_link_ancestor(path: Path) -> bool:
    current = path.absolute()
    while True:
        if _is_link_or_reparse(current):
            return True
        if current.parent == current:
            return False
        current = current.parent


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BootstrapTemplateError("scaffold_invalid")
        result[key] = value
    return result


def _read_scaffold() -> dict[str, Any]:
    path = _repo_root() / "infra" / "aws" / "template.json"
    if _has_link_ancestor(path) or not path.is_file():
        raise BootstrapTemplateError("scaffold_unavailable")
    try:
        size = path.stat().st_size
        if size <= 0 or size > MAX_TEMPLATE_BYTES:
            raise BootstrapTemplateError("scaffold_size_invalid")
        with path.open("rb") as stream:
            raw = stream.read(MAX_TEMPLATE_BYTES + 1)
    except BootstrapTemplateError:
        raise
    except OSError:
        raise BootstrapTemplateError("scaffold_unavailable") from None
    if len(raw) != size or len(raw) > MAX_TEMPLATE_BYTES:
        raise BootstrapTemplateError("scaffold_size_invalid")
    try:
        document = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_reject_duplicate_keys)
    except BootstrapTemplateError:
        raise
    except (UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
        raise BootstrapTemplateError("scaffold_invalid") from None
    if not isinstance(document, dict):
        raise BootstrapTemplateError("scaffold_invalid")
    return document


def _expect(condition: bool, category: str = "scaffold_contract_invalid") -> None:
    if not condition:
        raise BootstrapTemplateError(category)


def _validate_scaffold(document: dict[str, Any]) -> None:
    resources = document.get("Resources")
    parameters = document.get("Parameters")
    _expect(isinstance(resources, dict) and isinstance(parameters, dict))
    environment = parameters.get("EnvironmentName")
    _expect(
        isinstance(environment, dict)
        and environment.get("Type") == "String"
        and environment.get("Default") == "dev"
        and environment.get("AllowedValues") == ["dev", "prod"]
    )

    selected: dict[str, dict[str, Any]] = {}
    for name, expected_type in _RESOURCE_TYPES.items():
        resource = resources.get(name)
        _expect(isinstance(resource, dict) and resource.get("Type") == expected_type)
        properties = resource.get("Properties")
        _expect(isinstance(properties, dict))
        selected[name] = resource

    api = selected["McpApi"]["Properties"]
    _expect(api.get("ProtocolType") == "HTTP" and api.get("DisableExecuteApiEndpoint") is True)
    _expect(not ({"Body", "BodyS3Location", "Target"} & api.keys()))
    stage = selected["McpApiStage"]["Properties"]
    _expect(stage.get("ApiId") == {"Ref": "McpApi"} and stage.get("StageName") == "$default")

    pool = selected["McpUserPool"]["Properties"]
    _expect(pool.keys() <= _ALLOWED_USER_POOL_PROPERTIES)
    _expect(pool.get("UserPoolTier") == "ESSENTIALS")
    _expect("DeletionProtection" not in pool or pool.get("DeletionProtection") == "INACTIVE")

    role = selected["McpHandlerRole"]["Properties"]
    trust_document = role.get("AssumeRolePolicyDocument")
    trust = trust_document.get("Statement") if isinstance(trust_document, dict) else None
    _expect(
        isinstance(trust, list) and trust == [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }]
        and not role.get("ManagedPolicyArns"),
    )
    policies = role.get("Policies")
    _expect(isinstance(policies, list) and len(policies) == 1)
    policy_document = policies[0].get("PolicyDocument") if isinstance(policies[0], dict) else None
    statements = policy_document.get("Statement") if isinstance(policy_document, dict) else None
    _expect(isinstance(statements, list) and len(statements) == 1)
    statement = statements[0]
    _expect(
        statement.get("Effect") == "Allow"
        and statement.get("Action") == ["logs:CreateLogStream", "logs:PutLogEvents"]
        and isinstance(statement.get("Resource"), dict)
        and "log-group:/aws/lambda/honda-mapit-mcp-${EnvironmentName}-handler:*"
        in statement["Resource"].get("Fn::Sub", "")
    )

    log_group = selected["McpHandlerLogGroup"]["Properties"]
    _expect(log_group.get("RetentionInDays") == 7)

    function = selected["McpHandler"]["Properties"]
    _expect(function.get("Handler") == "index.handler")
    _expect(type(function.get("ReservedConcurrentExecutions")) is int)
    _expect(function.get("ReservedConcurrentExecutions") == 0)
    code = function.get("Code")
    _expect(isinstance(code, dict) and set(code) == {"ZipFile"} and code.get("ZipFile") == _EXPECTED_HANDLER)
    _expect(not (_FORBIDDEN_LAMBDA_PROPERTIES & function.keys()))
    _expect(
        function.get("Role") == {"Fn::GetAtt": ["McpHandlerRole", "Arn"]}
        and selected["McpHandler"].get("DependsOn") == ["McpHandlerLogGroup"]
    )

    for name, resource in selected.items():
        _expect(resource.get("DeletionPolicy") in (None, "Delete"))
        _expect(resource.get("UpdateReplacePolicy") in (None, "Delete"))


def _validate_references(value: Any, allowed_resources: set[str]) -> None:
    if isinstance(value, dict):
        if "DependsOn" in value:
            dependencies = value["DependsOn"]
            if type(dependencies) is str:
                dependencies = [dependencies]
            _expect(
                isinstance(dependencies, list)
                and all(type(dependency) is str and dependency in allowed_resources for dependency in dependencies),
                "dangling_resource_reference",
            )
        if set(value) == {"Ref"}:
            reference = value["Ref"]
            _expect(
                type(reference) is str
                and (reference in allowed_resources or reference == "EnvironmentName" or reference in _PSEUDO_PARAMETERS),
                "dangling_resource_reference",
            )
        if set(value) == {"Fn::GetAtt"}:
            getatt = value["Fn::GetAtt"]
            _expect(
                isinstance(getatt, list) and len(getatt) == 2
                and getatt[0] in allowed_resources and type(getatt[1]) is str,
                "dangling_resource_reference",
            )
        if "Fn::Sub" in value:
            substitution = value["Fn::Sub"]
            if type(substitution) is str:
                template, substitutions = substitution, {}
            else:
                _expect(
                    isinstance(substitution, list) and len(substitution) == 2
                    and type(substitution[0]) is str and isinstance(substitution[1], dict),
                    "dangling_resource_reference",
                )
                template, substitutions = substitution
            allowed = allowed_resources | {"EnvironmentName"} | _PSEUDO_PARAMETERS | set(substitutions)
            for reference in re.findall(r"\$\{([^}]+)\}", template):
                if reference.startswith("!"):
                    continue
                root_reference = reference.split(".", 1)[0]
                _expect(root_reference in allowed, "dangling_resource_reference")
        for child in value.values():
            _validate_references(child, allowed_resources)
    elif isinstance(value, list):
        for child in value:
            _validate_references(child, allowed_resources)


def fixed_bootstrap_template() -> dict[str, Any]:
    """Return a fresh closed bootstrap rehearsal template from the fixed scaffold."""
    document = _read_scaffold()
    _validate_scaffold(document)
    source_resources = document["Resources"]
    resources: dict[str, Any] = {}
    for name in _RESOURCE_TYPES:
        resource = source_resources[name]
        selected = json.loads(json.dumps(resource))
        selected["Condition"] = "SupportedDeployment"
        selected["DeletionPolicy"] = "Delete"
        selected["UpdateReplacePolicy"] = "Delete"
        if name == "McpUserPool":
            selected["Properties"]["DeletionProtection"] = "INACTIVE"
        resources[name] = selected
    parameters = {"EnvironmentName": json.loads(json.dumps(document["Parameters"]["EnvironmentName"]))}
    parameters["EnvironmentName"]["Default"] = "dev"
    parameters["EnvironmentName"]["AllowedValues"] = ["dev"]
    parameters["EnvironmentName"]["Description"] = "Fixed dev environment for a closed bootstrap rehearsal."
    _validate_references({"Resources": resources, "Parameters": parameters}, set(resources))

    return {
        "AWSTemplateFormatVersion": document.get("AWSTemplateFormatVersion", "2010-09-09"),
        "Description": "Bootstrap rehearsal only: create, shut down, and delete a closed dev stack; not deploy-ready.",
        "Metadata": {
            "Readiness": "BOOTSTRAP_REHEARSAL_NOT_DEPLOY_READY",
            "Purpose": "closed creation, shutdown, and deletion rehearsal",
            "RuntimeImplementation": False,
            "ApiEndpointOpen": False,
            "OAuthConfigured": False,
            "UserCreated": False,
            "PermissionsAndCleanupPending": True,
            "DeletionPolicy": "Delete",
            "NoActivation": True,
        },
        "Parameters": parameters,
        "Conditions": {
            "SupportedDeployment": {
                "Fn::And": [
                    {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
                    {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev"]},
                ]
            }
        },
        "Resources": resources,
        "Outputs": {
            "ApiId": {
                "Condition": "SupportedDeployment",
                "Value": {"Ref": "McpApi"},
            },
            "UserPoolId": {
                "Condition": "SupportedDeployment",
                "Value": {"Ref": "McpUserPool"},
            },
        },
    }


__all__ = ["BootstrapTemplateError", "MAX_TEMPLATE_BYTES", "fixed_bootstrap_template"]
