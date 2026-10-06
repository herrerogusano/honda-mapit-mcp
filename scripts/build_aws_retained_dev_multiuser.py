"""Build the closed, opt-in retained-dev multi-user IaC candidate.

This is a pure CloudFormation factory.  It deep-copies the already reviewed
five-resource retained-dev scaffold and adds an explicitly bounded Cognito /
API / DynamoDB composition.  It does not import an SDK, read credentials,
contact AWS, create users, or claim that the candidate is deploy-ready.
"""
from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from scripts.build_aws_retained_dev import (
    CONDITION_NAME,
    REGION,
    STACK_NAME,
    build_retained_dev_template,
)
from scripts.build_aws_dev_oauth_template import _validate_callback

_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_SUBJECT = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_BUCKET = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
_TENANT_KEY = re.compile(r"^tenant-[0-9a-f]{64}$")

MULTIUSER_STACK_NAME = STACK_NAME
TABLE_NAME = "honda-mapit-mcp-dev-tenants"
RESOURCE_IDENTIFIER = "McpResourceIdentifier"
BASE_RESOURCES = frozenset({
    "McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
})
NEW_RESOURCES = frozenset({
    "McpUserPool", "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient",
    "McpManagedLoginBranding", "McpJwtAuthorizer", "McpLambdaIntegration", "McpPostRoute",
    "McpProtectedResourceMetadataRoute", "McpAuthorizationServerMetadataRoute",
    "McpLambdaInvokePermission", "McpProtectedResourceMetadataInvokePermission",
    "McpAuthorizationServerMetadataInvokePermission", "McpTenantsTable",
})
EXPECTED_RESOURCES = BASE_RESOURCES | NEW_RESOURCES


class MultiuserTemplateError(ValueError):
    """Stable local error for the closed multi-user template contract."""


def _fail(category: str) -> None:
    raise MultiuserTemplateError(category)


def _validate_inputs(
    *, api_id: str, bucket: str, zip_sha256: str, source_sha256: str,
    jwks_sha256: str, manifest_sha256: str, account_id: str,
    execution_start_epoch: int, execution_end_epoch: int, callback_url: str,
    subjects: tuple[str, str], tenant_keys: tuple[str, str],
) -> str:
    if type(api_id) is not str or not _API_ID.fullmatch(api_id):
        _fail("multiuser_api_id_invalid")
    if type(bucket) is not str or not _BUCKET.fullmatch(bucket) or ".." in bucket:
        _fail("multiuser_bucket_invalid")
    if type(zip_sha256) is not str or not _SHA256.fullmatch(zip_sha256):
        _fail("multiuser_zip_hash_invalid")
    if type(source_sha256) is not str or not _GIT_SHA.fullmatch(source_sha256):
        _fail("multiuser_source_hash_invalid")
    if type(jwks_sha256) is not str or not _SHA256.fullmatch(jwks_sha256):
        _fail("multiuser_jwks_hash_invalid")
    if type(manifest_sha256) is not str or not _SHA256.fullmatch(manifest_sha256):
        _fail("multiuser_manifest_hash_invalid")
    if type(account_id) is not str or not _ACCOUNT_ID.fullmatch(account_id):
        _fail("multiuser_account_invalid")
    if (
        type(execution_start_epoch) is not int
        or type(execution_end_epoch) is not int
        or execution_start_epoch <= 0
        or execution_end_epoch <= execution_start_epoch
        or execution_end_epoch - execution_start_epoch > 300
    ):
        _fail("multiuser_execution_window_invalid")
    try:
        callback = _validate_callback(callback_url)
    except Exception:
        _fail("multiuser_callback_invalid")
    if type(subjects) is not tuple or len(subjects) != 2:
        _fail("multiuser_subject_binding_invalid")
    if type(tenant_keys) is not tuple or len(tenant_keys) != 2:
        _fail("multiuser_tenant_binding_invalid")
    if any(type(value) is not str or _SUBJECT.fullmatch(value) is None for value in subjects):
        _fail("multiuser_subject_binding_invalid")
    if any(type(value) is not str or _TENANT_KEY.fullmatch(value) is None for value in tenant_keys):
        _fail("multiuser_tenant_binding_invalid")
    if len(set(subjects)) != 2:
        _fail("multiuser_subject_binding_invalid")
    if len(set(tenant_keys)) != 2:
        _fail("multiuser_tenant_binding_invalid")
    return callback


def _tagged(resource: dict[str, Any]) -> dict[str, Any]:
    resource["Condition"] = CONDITION_NAME
    resource["DeletionPolicy"] = "Retain"
    resource["UpdateReplacePolicy"] = "Retain"
    return resource


def _resource(type_name: str, properties: dict[str, Any]) -> dict[str, Any]:
    return _tagged({"Type": type_name, "Properties": properties})


def _fixed_parameters(api_id: str, resource_identifier: str, callback_url: str) -> dict[str, Any]:
    return {
        "ObservedApiId": {
            "Type": "String", "Default": api_id, "AllowedValues": [api_id],
            "Description": "Operator-read API ID; not generated or inferred by this template.",
        },
        RESOURCE_IDENTIFIER: {
            "Type": "String", "Default": resource_identifier,
            "AllowedValues": [resource_identifier],
            "Description": "Exact observed API resource identifier.",
        },
        "OAuthCallbackURL": {
            "Type": "String", "Default": callback_url, "AllowedValues": [callback_url],
            "Description": "Exact operator-confirmed loopback callback.",
        },
    }


def _new_resources(
    *, bucket: str, zip_sha256: str, source_sha256: str, jwks_sha256: str,
    tenant_keys: tuple[str, str],
) -> dict[str, dict[str, Any]]:
    integration_target = {"Fn::Join": ["/", ["integrations", {"Ref": "McpLambdaIntegration"}]]}
    resources: dict[str, dict[str, Any]] = {
        "McpUserPool": _resource("AWS::Cognito::UserPool", {
            "UserPoolName": "honda-mapit-mcp-dev-multiuser",
            "MfaConfiguration": "OFF",
            "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
            "UsernameConfiguration": {"CaseSensitive": False},
            "UserPoolTags": {"Project": "honda-mapit-mcp", "Environment": "dev"},
        }),
        "McpUserPoolDomain": _resource("AWS::Cognito::UserPoolDomain", {
            "Domain": {"Fn::Sub": "honda-mapit-mcp-dev-multiuser-${AWS::AccountId}"},
            "ManagedLoginVersion": 2,
            "UserPoolId": {"Ref": "McpUserPool"},
        }),
        "McpResourceServer": _resource("AWS::Cognito::UserPoolResourceServer", {
            "Identifier": {"Ref": RESOURCE_IDENTIFIER},
            "Name": "honda-mapit-mcp-dev-multiuser",
            "Scopes": [{"ScopeName": "use", "ScopeDescription": "Read-only MCP access."}],
            "UserPoolId": {"Ref": "McpUserPool"},
        }),
        "McpUserPoolClient": _resource("AWS::Cognito::UserPoolClient", {
            "UserPoolId": {"Ref": "McpUserPool"},
            "ClientName": "honda-mapit-mcp-dev-multiuser-pkce",
            "GenerateSecret": False,
            "AllowedOAuthFlowsUserPoolClient": True,
            "AllowedOAuthFlows": ["code"],
            "AllowedOAuthScopes": [{"Fn::Sub": "${McpResourceIdentifier}/use"}],
            "SupportedIdentityProviders": ["COGNITO"],
            "CallbackURLs": [{"Ref": "OAuthCallbackURL"}],
            "DefaultRedirectURI": {"Ref": "OAuthCallbackURL"},
            "EnableTokenRevocation": True,
            "PreventUserExistenceErrors": "ENABLED",
            "AccessTokenValidity": 60,
            "IdTokenValidity": 60,
            "RefreshTokenValidity": 30,
            "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
        }),
        "McpManagedLoginBranding": _resource("AWS::Cognito::ManagedLoginBranding", {
            "ClientId": {"Ref": "McpUserPoolClient"},
            "UseCognitoProvidedValues": True,
            "UserPoolId": {"Ref": "McpUserPool"},
        }),
        "McpJwtAuthorizer": _resource("AWS::ApiGatewayV2::Authorizer", {
            "ApiId": {"Ref": "McpApi"},
            "AuthorizerType": "JWT",
            "IdentitySource": ["$request.header.Authorization"],
            "JwtConfiguration": {
                "Audience": [{"Ref": RESOURCE_IDENTIFIER}],
                "Issuer": {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${McpUserPool}"},
            },
            "Name": "honda-mapit-mcp-dev-multiuser-jwt",
        }),
        "McpLambdaIntegration": _resource("AWS::ApiGatewayV2::Integration", {
            "ApiId": {"Ref": "McpApi"},
            "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST",
            "PayloadFormatVersion": "2.0",
            "TimeoutInMillis": 20000,
            "IntegrationUri": {"Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${McpHandler.Arn}/invocations"},
        }),
        "McpPostRoute": _resource("AWS::ApiGatewayV2::Route", {
            "ApiId": {"Ref": "McpApi"}, "RouteKey": "POST /mcp", "AuthorizationType": "JWT",
            "AuthorizerId": {"Ref": "McpJwtAuthorizer"},
            "AuthorizationScopes": [{"Fn::Sub": "${McpResourceIdentifier}/use"}],
            "Target": integration_target,
        }),
        "McpProtectedResourceMetadataRoute": _resource("AWS::ApiGatewayV2::Route", {
            "ApiId": {"Ref": "McpApi"}, "RouteKey": "GET /.well-known/oauth-protected-resource/mcp",
            "AuthorizationType": "NONE", "Target": integration_target,
        }),
        "McpAuthorizationServerMetadataRoute": _resource("AWS::ApiGatewayV2::Route", {
            "ApiId": {"Ref": "McpApi"}, "RouteKey": "GET /.well-known/oauth-authorization-server",
            "AuthorizationType": "NONE", "Target": integration_target,
        }),
        "McpLambdaInvokePermission": _resource("AWS::Lambda::Permission", {
            "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "McpHandler"},
            "Principal": "apigateway.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${McpApi}/$default/POST/mcp"},
        }),
        "McpProtectedResourceMetadataInvokePermission": _resource("AWS::Lambda::Permission", {
            "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "McpHandler"},
            "Principal": "apigateway.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${McpApi}/$default/GET/.well-known/oauth-protected-resource/mcp"},
        }),
        "McpAuthorizationServerMetadataInvokePermission": _resource("AWS::Lambda::Permission", {
            "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "McpHandler"},
            "Principal": "apigateway.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
            "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${McpApi}/$default/GET/.well-known/oauth-authorization-server"},
        }),
        "McpTenantsTable": _resource("AWS::DynamoDB::Table", {
            "TableName": TABLE_NAME,
            "BillingMode": "PAY_PER_REQUEST",
            "OnDemandThroughput": {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 1},
            "AttributeDefinitions": [
                {"AttributeName": "key", "AttributeType": "S"},
            ],
            "KeySchema": [
                {"AttributeName": "key", "KeyType": "HASH"},
            ],
            "Tags": [
                {"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": "dev"},
                {"Key": "Purpose", "Value": "multiuser-authorization"},
            ],
        }),
    }
    resources["McpUserPoolClient"]["DependsOn"] = ["McpResourceServer", "McpUserPoolDomain"]
    resources["McpManagedLoginBranding"]["DependsOn"] = ["McpUserPoolDomain"]
    return resources


def _validate_template(template: dict[str, Any], *, tenant_keys: tuple[str, str]) -> None:
    if not isinstance(template, dict) or template.get("AWSTemplateFormatVersion") != "2010-09-09":
        _fail("multiuser_template_invalid")
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != EXPECTED_RESOURCES:
        _fail("multiuser_resource_set_invalid")
    if template.get("Conditions", {}).get(CONDITION_NAME) != {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        ]
    }:
        _fail("multiuser_condition_invalid")
    for name in NEW_RESOURCES:
        resource = resources.get(name)
        if not isinstance(resource, dict) or resource.get("Condition") != CONDITION_NAME:
            _fail("multiuser_resource_condition_invalid")
        if resource.get("DeletionPolicy") != "Retain" or resource.get("UpdateReplacePolicy") != "Retain":
            _fail("multiuser_retention_invalid")
    pool = resources["McpUserPool"]["Properties"]
    if (
        pool.get("MfaConfiguration") != "OFF"
        or pool.get("AdminCreateUserConfig") != {"AllowAdminCreateUserOnly": True}
        or pool.get("UserPoolTags") != {"Project": "honda-mapit-mcp", "Environment": "dev"}
    ):
        _fail("multiuser_pool_invalid")
    if "EmailConfiguration" in pool or "SmsConfiguration" in pool or "McpUserPoolUser" in resources:
        _fail("multiuser_pool_identity_invalid")
    table = resources["McpTenantsTable"]["Properties"]
    if set(table) != {"TableName", "BillingMode", "OnDemandThroughput", "AttributeDefinitions", "KeySchema", "Tags"}:
        _fail("multiuser_table_shape_invalid")
    if (
        table.get("BillingMode") != "PAY_PER_REQUEST"
        or table.get("TableName") != TABLE_NAME
        or table.get("OnDemandThroughput") != {"MaxReadRequestUnits": 10, "MaxWriteRequestUnits": 1}
        or table.get("AttributeDefinitions") != [{"AttributeName": "key", "AttributeType": "S"}]
        or table.get("KeySchema") != [{"AttributeName": "key", "KeyType": "HASH"}]
    ):
        _fail("multiuser_table_shape_invalid")
    policy = resources["McpHandlerRole"]["Properties"].get("Policies")
    if not isinstance(policy, list) or len(policy) != 2:
        _fail("multiuser_role_invalid")
    tenant_policy = next((item for item in policy if isinstance(item, dict) and item.get("PolicyName") == "honda-mapit-mcp-dev-retained-tenant-read"), None)
    if tenant_policy is None:
        _fail("multiuser_role_invalid")
    statements = tenant_policy.get("PolicyDocument", {}).get("Statement")
    expected_condition = {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(tenant_keys)}}
    if statements != [{"Effect": "Allow", "Action": ["dynamodb:GetItem"], "Resource": {"Fn::GetAtt": ["McpTenantsTable", "Arn"]}, "Condition": expected_condition}]:
        _fail("multiuser_role_invalid")
    handler = resources["McpHandler"]["Properties"]
    if handler.get("Handler") != "mapit.aws_dev_multiuser_entrypoint.handler" or handler.get("ReservedConcurrentExecutions") != 0:
        _fail("multiuser_handler_invalid")
    if handler.get("Code", {}).get("S3Key", "").startswith("runtime/") is not True:
        _fail("multiuser_handler_invalid")
    if "Environment" not in handler or not isinstance(handler["Environment"].get("Variables"), dict):
        _fail("multiuser_handler_invalid")
    if set(handler["Environment"]["Variables"]) != {
        "MAPIT_MCP_ENV", "MAPIT_DEV_MULTIUSER_MODE", "MAPIT_SOURCE_SHA256", "MAPIT_COGNITO_JWKS_SHA256",
        "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256", "MAPIT_DEV_EXPECTED_ACCOUNT_ID",
        "MAPIT_DEV_EXECUTION_START_EPOCH", "MAPIT_DEV_EXECUTION_END_EPOCH",
        "MAPIT_COGNITO_USER_POOL_ID", "MAPIT_COGNITO_CLIENT_ID", "MAPIT_OBSERVED_API_ID",
    }:
        _fail("multiuser_handler_environment_invalid")
    for item in policy:
        statements = item.get("PolicyDocument", {}).get("Statement", []) if isinstance(item, dict) else []
        for statement in statements if isinstance(statements, list) else []:
            actions = statement.get("Action", []) if isinstance(statement, dict) else []
            actions = actions if isinstance(actions, list) else [actions]
            if any(action not in {"logs:CreateLogStream", "logs:PutLogEvents", "dynamodb:GetItem"}
                   for action in actions):
                _fail("multiuser_permissions_invalid")
    for name in ("McpPostRoute", "McpProtectedResourceMetadataRoute", "McpAuthorizationServerMetadataRoute"):
        props = resources[name]["Properties"]
        if props.get("Target") != {"Fn::Join": ["/", ["integrations", {"Ref": "McpLambdaIntegration"}]]}:
            _fail("multiuser_route_invalid")
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict) or metadata.get("NotDeployReady") is not True:
        _fail("multiuser_readiness_invalid")


def build_retained_dev_multiuser_template(
    *, api_id: str, bucket: str, zip_sha256: str, source_sha256: str,
    jwks_sha256: str, manifest_sha256: str, account_id: str,
    execution_start_epoch: int, execution_end_epoch: int, callback_url: str,
    subjects: tuple[str, str], tenant_keys: tuple[str, str],
) -> dict[str, Any]:
    """Return a fresh non-deploy-ready multi-user candidate."""
    callback = _validate_inputs(
        api_id=api_id, bucket=bucket, zip_sha256=zip_sha256,
        source_sha256=source_sha256, jwks_sha256=jwks_sha256,
        manifest_sha256=manifest_sha256, account_id=account_id,
        execution_start_epoch=execution_start_epoch,
        execution_end_epoch=execution_end_epoch,
        callback_url=callback_url, subjects=subjects,
        tenant_keys=tenant_keys,
    )
    template = copy.deepcopy(build_retained_dev_template())
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != BASE_RESOURCES:
        _fail("multiuser_base_invalid")
    base_api = resources.get("McpApi", {}).get("Properties", {})
    base_handler = resources.get("McpHandler", {}).get("Properties", {})
    if (
        base_api.get("DisableExecuteApiEndpoint") is not True
        or base_handler.get("Architectures") != ["arm64"]
        or base_handler.get("MemorySize") != 256
        or base_handler.get("Timeout") != 20
        or base_handler.get("ReservedConcurrentExecutions") != 0
    ):
        _fail("multiuser_base_not_closed")
    base_policies = resources.get("McpHandlerRole", {}).get("Properties", {}).get("Policies")
    if not isinstance(base_policies, list) or len(base_policies) != 1:
        _fail("multiuser_base_role_invalid")
    resource_identifier = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"
    template["Parameters"] = _fixed_parameters(api_id, resource_identifier, callback)
    resources.update(_new_resources(
        bucket=bucket, zip_sha256=zip_sha256, source_sha256=source_sha256,
        jwks_sha256=jwks_sha256,
        tenant_keys=tenant_keys,
    ))
    handler = resources["McpHandler"]["Properties"]
    handler.update({
        "Code": {"S3Bucket": bucket, "S3Key": f"runtime/{zip_sha256}.zip"},
        "Handler": "mapit.aws_dev_multiuser_entrypoint.handler",
        "Environment": {"Variables": {
            "MAPIT_MCP_ENV": "dev",
            "MAPIT_DEV_MULTIUSER_MODE": "synthetic",
            "MAPIT_SOURCE_SHA256": source_sha256,
            "MAPIT_COGNITO_JWKS_SHA256": jwks_sha256,
            "MAPIT_DEV_MULTIUSER_MANIFEST_SHA256": manifest_sha256,
            "MAPIT_DEV_EXPECTED_ACCOUNT_ID": account_id,
            "MAPIT_DEV_EXECUTION_START_EPOCH": str(execution_start_epoch),
            "MAPIT_DEV_EXECUTION_END_EPOCH": str(execution_end_epoch),
            "MAPIT_COGNITO_USER_POOL_ID": {"Ref": "McpUserPool"},
            "MAPIT_COGNITO_CLIENT_ID": {"Ref": "McpUserPoolClient"},
            "MAPIT_OBSERVED_API_ID": {"Ref": "ObservedApiId"},
        }},
    })
    role_policies = resources["McpHandlerRole"]["Properties"].get("Policies")
    if not isinstance(role_policies, list) or len(role_policies) != 1:
        _fail("multiuser_base_role_invalid")
    role_policies.append({
        "PolicyName": "honda-mapit-mcp-dev-retained-tenant-read",
        "PolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": ["dynamodb:GetItem"],
                "Resource": {"Fn::GetAtt": ["McpTenantsTable", "Arn"]},
                "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": list(tenant_keys)}},
            }],
        },
    })
    template["Metadata"].update({
        "Readiness": "RETAINED_DEV_MULTIUSER_NOT_DEPLOY_READY",
        "Purpose": "explicitly opt-in dev multi-user authorization composition",
        "NotDeployReady": True,
        "NoUsersOrPasswordsInTemplate": True,
        "MfaConfiguration": "OFF; administrator-created users only; operator setup required",
        "ObservedSubjectDigests": [hashlib.sha256(value.encode("ascii")).hexdigest() for value in subjects],
        "ObservedTenantKeyDigests": [hashlib.sha256(value.encode("ascii")).hexdigest() for value in tenant_keys],
        "SourceSha256": source_sha256,
        "JwksSha256": jwks_sha256,
        "ManifestSha256": manifest_sha256,
        "ExpectedAccountId": account_id,
        "ExecutionStartEpoch": execution_start_epoch,
        "ExecutionEndEpoch": execution_end_epoch,
        "ManifestContract": {
            "schema": 1,
            "builder": "build_retained_dev_multiuser_archive",
            "environment": "dev",
            "synthetic": True,
            "source_sha": source_sha256,
            "api_id": api_id,
            "user_pool_id": {"Ref": "McpUserPool"},
            "client_id": {"Ref": "McpUserPoolClient"},
            "jwks_sha256": jwks_sha256,
            "table_arn": f"arn:aws:dynamodb:{REGION}:{account_id}:table/{TABLE_NAME}",
            "tenants": [
                {"key": tenant_keys[0], "subject": subjects[0], "label": "synthetic-A"},
                {"key": tenant_keys[1], "subject": subjects[1], "label": "synthetic-B"},
            ],
        },
        "ObservedApiIdBindingRequired": api_id,
        "PendingGates": [
            "fresh V2 preflight and exact Cognito/API/DynamoDB readbacks",
            "dev-only role and closed CD/recovery review",
            "operator creates at most two technical users outside CloudFormation",
            "implement and review the multi-user Lambda entrypoint before activation",
        ],
    })
    outputs = template.setdefault("Outputs", {})
    outputs["McpUserPoolId"] = {"Condition": CONDITION_NAME, "Value": {"Ref": "McpUserPool"}}
    outputs["McpUserPoolClientId"] = {"Condition": CONDITION_NAME, "Value": {"Ref": "McpUserPoolClient"}}
    outputs["McpTenantsTableName"] = {"Condition": CONDITION_NAME, "Value": {"Ref": "McpTenantsTable"}}
    _validate_template(template, tenant_keys=tenant_keys)
    return template


build_dev_multiuser_template = build_retained_dev_multiuser_template


def build_retained_dev_multiuser_setup(*, api_id: str, callback_url: str) -> dict[str, Any]:
    """First closed phase: obtain actual pool/client IDs before packaging.

    Preserve every original runtime resource byte-for-byte. Only the isolated
    OAuth test resources and an empty authorization table are added. No API
    routes, Lambda permission, runtime code or handler permission is activated.
    """
    if type(api_id) is not str or _API_ID.fullmatch(api_id) is None:
        _fail("multiuser_api_id_invalid")
    try:
        callback = _validate_callback(callback_url)
    except Exception:
        _fail("multiuser_callback_invalid")
    template = copy.deepcopy(build_retained_dev_template())
    resource = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"
    template["Parameters"] = _fixed_parameters(api_id, resource, callback)
    template["Parameters"].pop("ObservedApiId")
    children = _new_resources(bucket="synthetic-unused", zip_sha256="1" * 64,
        source_sha256="1" * 40, jwks_sha256="1" * 64,
        tenant_keys=("tenant-" + "a" * 64, "tenant-" + "b" * 64))
    names = {"McpUserPool", "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient",
             "McpManagedLoginBranding", "McpTenantsTable"}
    template["Resources"].update({name: children[name] for name in names})
    template["Metadata"].update({"Readiness": "RETAINED_DEV_MULTIUSER_CLOSED_SETUP",
        "NotDeployReady": True, "RuntimeUnchanged": True, "NoUsersOrPasswordsInTemplate": True})
    return template

__all__ = [
    "MULTIUSER_STACK_NAME", "TABLE_NAME", "MultiuserTemplateError",
    "build_dev_multiuser_template", "build_retained_dev_multiuser_template",
    "build_retained_dev_multiuser_setup",
]
