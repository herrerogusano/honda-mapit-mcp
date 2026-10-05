"""Compose offline production OAuth and closed runtime CloudFormation candidates.

The OAuth candidate adds only a resource server, public authorization-code
client, and managed-login branding to the separately retained identity pool.
The runtime candidate is a separate stack update over the fixed prod bootstrap.
Neither factory calls AWS or activates the API/Lambda.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts.build_aws_dev_oauth_template import _validate_callback
from scripts.build_aws_dev_runtime_template import _validate_bucket_name
from scripts.build_aws_prod_bootstrap import fixed_prod_bootstrap_template

_REGION = "eu-west-1"
_OAUTH_STACK = "honda-mapit-mcp-prod-oauth"
_PROD_STACK = "honda-mapit-mcp-prod"
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,64}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
_OAUTH_NAMES = {"ProdMcpResourceServer", "ProdMcpUserPoolClient", "ProdMcpManagedLoginBranding"}


class ProdOAuthTemplateError(ValueError):
    """Closed local validation failure without supplied values or identifiers."""


def _fail(category: str) -> None:
    raise ProdOAuthTemplateError(category)


def _validate_callback_8786(callback_url: str) -> str:
    try:
        exact = _validate_callback(callback_url)
        parsed = urlsplit(exact)
    except Exception:
        _fail("prod_callback_invalid")
    if type(parsed.port) is not int or parsed.port != 8786:
        _fail("prod_callback_invalid")
    return exact


def _identity_bindings(user_pool_id: str, api_id: str, callback_url: str) -> tuple[str, str, str]:
    if type(user_pool_id) is not str or not _POOL_ID.fullmatch(user_pool_id):
        _fail("prod_user_pool_invalid")
    if type(api_id) is not str or not _API_ID.fullmatch(api_id):
        _fail("prod_api_id_invalid")
    callback = _validate_callback_8786(callback_url)
    return user_pool_id, api_id, callback


def _uri(api_id: str) -> str:
    return f"https://{api_id}.execute-api.{_REGION}.amazonaws.com/mcp"


def _condition(stack_name: str) -> dict[str, Any]:
    return {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, _REGION]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, stack_name]},
        ]
    }


def _oauth_resources(user_pool_id: str, resource_uri: str, callback_url: str) -> dict[str, dict[str, Any]]:
    custom_scope = f"{resource_uri}/use"
    resources = {
        "ProdMcpResourceServer": {
            "Type": "AWS::Cognito::UserPoolResourceServer",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "Identifier": resource_uri,
                "Name": "honda-mapit-mcp-prod",
                "Scopes": [{"ScopeName": "use", "ScopeDescription": "Call the protected production MCP endpoint."}],
                "UserPoolId": user_pool_id,
            },
        },
        "ProdMcpUserPoolClient": {
            "Type": "AWS::Cognito::UserPoolClient",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "DependsOn": ["ProdMcpResourceServer"],
            "Properties": {
                "ClientName": "honda-mapit-mcp-prod-codex",
                "UserPoolId": user_pool_id,
                "GenerateSecret": False,
                "AllowedOAuthFlowsUserPoolClient": True,
                "AllowedOAuthFlows": ["code"],
                "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
                "AllowedOAuthScopes": [custom_scope],
                "CallbackURLs": [callback_url],
                "DefaultRedirectURI": callback_url,
                "SupportedIdentityProviders": ["COGNITO"],
                "EnableTokenRevocation": True,
                "PreventUserExistenceErrors": "ENABLED",
                "AccessTokenValidity": 5,
                "IdTokenValidity": 5,
                "RefreshTokenValidity": 1,
                "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
            },
        },
        "ProdMcpManagedLoginBranding": {
            "Type": "AWS::Cognito::ManagedLoginBranding",
            "Condition": "SupportedDeployment",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "ClientId": {"Ref": "ProdMcpUserPoolClient"},
                "UseCognitoProvidedValues": True,
                "UserPoolId": user_pool_id,
            },
        },
    }
    return resources


def build_prod_oauth_template(*, user_pool_id: str, api_id: str, callback_url: str) -> dict[str, Any]:
    """Return a Cognito-only candidate bound to the retained pool and exact API.

    The callback is supplied by the operator from the intended server-specific
    Codex registration and must use port 8786. It is validated, not inferred.
    """
    user_pool_id, api_id, callback_url = _identity_bindings(user_pool_id, api_id, callback_url)
    uri = _uri(api_id)
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Production single-owner Cognito OAuth client candidate; no pool/domain/user/compute creation and not deploy-ready.",
        "Metadata": {
            "Readiness": "PROD_OAUTH_CLIENT_NOT_DEPLOY_READY",
            "Environment": "prod",
            "Region": _REGION,
            "StackName": _OAUTH_STACK,
            "UsesExistingPermanentIdentityPool": True,
            "UsesExistingManagedLoginV2Domain": True,
            "PublicClientNoSecret": True,
            "AuthorizationCodeFlow": True,
            "PKCEExpectedFromCodexClient": True,
            "ExactCallbackPort": 8786,
            "NoPoolDomainUserOrComputeResources": True,
            "NoActivation": True,
            "MissingPrerequisites": [
                "read back the retained pool and API ownership before applying this candidate",
                "confirm this exact callback against the server-specific Codex registration",
                "read back client/resource-server/branding and test human PKCE/MFA separately",
                "review exact client/resource-server retirement before applying",
            ],
        },
        "Conditions": {"SupportedDeployment": _condition(_OAUTH_STACK)},
        "Resources": _oauth_resources(user_pool_id, uri, callback_url),
        "Outputs": {
            "ProdMcpClientId": {"Condition": "SupportedDeployment", "Value": {"Ref": "ProdMcpUserPoolClient"}},
            "ProdMcpResourceUri": {"Condition": "SupportedDeployment", "Value": uri},
        },
    }


def _validate_policy(policy: CognitoProdPolicy) -> CognitoProdPolicy:
    if type(policy) is not CognitoProdPolicy:
        _fail("prod_policy_invalid")
    try:
        validated = CognitoProdPolicy(
            user_pool_id=policy.user_pool_id,
            api_id=policy.api_id,
            client_id=policy.client_id,
            owner_subject=policy.owner_subject,
            request_deadline_seconds=policy.request_deadline_seconds,
        )
    except Exception:
        _fail("prod_policy_invalid")
    if validated.request_deadline_seconds != 14.0:
        _fail("prod_policy_invalid")
    return validated


def _closed_prod_bootstrap() -> dict[str, Any]:
    template = fixed_prod_bootstrap_template()
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != {
        "McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
    }:
        _fail("prod_bootstrap_invalid")
    api = resources["McpApi"].get("Properties", {})
    function = resources["McpHandler"].get("Properties", {})
    if (
        api.get("DisableExecuteApiEndpoint") is not True
        or type(function.get("ReservedConcurrentExecutions")) is not int
        or function["ReservedConcurrentExecutions"] != 0
        or not isinstance(function.get("Code"), dict)
        or "ZipFile" not in function["Code"]
    ):
        _fail("prod_bootstrap_not_closed")
    return template


def build_prod_runtime_template(
    policy: CognitoProdPolicy,
    *,
    bucket: str,
    zip_sha256: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    """Compose runtime/API resources over the fixed closed prod bootstrap.

    The OAuth client/resource server already exist in the separate permanent
    pool. This stack adds no Cognito resources, users, client secrets or IAM
    grants beyond the fixed bootstrap's exact GetParameter permission.
    """
    policy = _validate_policy(policy)
    try:
        bucket = _validate_bucket_name(bucket)
    except Exception:
        _fail("prod_artifact_bucket_invalid")
    if type(zip_sha256) is not str or not _SHA256.fullmatch(zip_sha256):
        _fail("prod_artifact_hash_invalid")
    if type(manifest_sha256) is not str or not _SHA256.fullmatch(manifest_sha256):
        _fail("prod_manifest_hash_invalid")
    template = _closed_prod_bootstrap()
    resources = template["Resources"]
    function = resources["McpHandler"]["Properties"]
    function["Handler"] = "mapit.aws_prod_entrypoint.handler"
    function["Code"] = {"S3Bucket": bucket, "S3Key": f"runtime/{zip_sha256}.zip"}
    function["Environment"] = {"Variables": {
        "MAPIT_MCP_ENV": "prod",
        "MAPIT_PROD_MANIFEST_SHA256": manifest_sha256,
    }}
    resource_uri = policy.resource_url
    issuer = policy.issuer_url
    resources.update({
        "McpJwtAuthorizer": {
            "Type": "AWS::ApiGatewayV2::Authorizer",
            "Condition": "SupportedDeployment", "DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete",
            "Properties": {
                "ApiId": {"Ref": "McpApi"}, "Name": "honda-mapit-mcp-prod-jwt",
                "AuthorizerType": "JWT", "IdentitySource": ["$request.header.Authorization"],
                "JwtConfiguration": {"Issuer": issuer, "Audience": [resource_uri]},
            },
        },
        "McpLambdaIntegration": {
            "Type": "AWS::ApiGatewayV2::Integration",
            "Condition": "SupportedDeployment", "DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete",
            "Properties": {
                "ApiId": {"Ref": "McpApi"}, "IntegrationType": "AWS_PROXY",
                "IntegrationMethod": "POST", "PayloadFormatVersion": "2.0",
                "TimeoutInMillis": 15000,
                "IntegrationUri": {"Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${McpHandler.Arn}/invocations"},
            },
        },
        "McpPostRoute": {
            "Type": "AWS::ApiGatewayV2::Route",
            "Condition": "SupportedDeployment", "DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete",
            "Properties": {
                "ApiId": {"Ref": "McpApi"}, "RouteKey": "POST /mcp",
                "AuthorizationType": "JWT", "AuthorizerId": {"Ref": "McpJwtAuthorizer"},
                "AuthorizationScopes": [policy.required_scope],
                "Target": {"Fn::Join": ["/", ["integrations", {"Ref": "McpLambdaIntegration"}]]},
            },
        },
        "McpMetadataRoute": {
            "Type": "AWS::ApiGatewayV2::Route",
            "Condition": "SupportedDeployment", "DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete",
            "Properties": {
                "ApiId": {"Ref": "McpApi"}, "RouteKey": f"GET {_METADATA_PATH}",
                "AuthorizationType": "NONE",
                "Target": {"Fn::Join": ["/", ["integrations", {"Ref": "McpLambdaIntegration"}]]},
            },
        },
        "McpPostInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Condition": "SupportedDeployment", "DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete",
            "Properties": {
                "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "McpHandler"},
                "Principal": "apigateway.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
                "SourceArn": {"Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${McpApi}/$default/POST/mcp"},
            },
        },
        "McpMetadataInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Condition": "SupportedDeployment", "DeletionPolicy": "Delete", "UpdateReplacePolicy": "Delete",
            "Properties": {
                "Action": "lambda:InvokeFunction", "FunctionName": {"Ref": "McpHandler"},
                "Principal": "apigateway.amazonaws.com", "SourceAccount": {"Ref": "AWS::AccountId"},
                "SourceArn": {"Fn::Sub": f"arn:${{AWS::Partition}}:execute-api:${{AWS::Region}}:${{AWS::AccountId}}:${{McpApi}}/$default/GET/{_METADATA_PATH.lstrip('/')}"},
            },
        },
    })
    function["ReservedConcurrentExecutions"] = 0
    resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] = True
    template["Metadata"].update({
        "Readiness": "PROD_RUNTIME_CANDIDATE_NOT_DEPLOY_READY",
        "Environment": "prod", "Region": _REGION,
        "RuntimeImplementation": True, "RuntimeActivation": False,
        "RetainedIdentityPoolReused": True, "OAuthClientAndResourceServerCreatedSeparately": True,
        "ManifestSha256BoundInEnvironment": True,
        "ZipSha256AndManifestSha256AreDistinct": True,
        "MissingPrerequisites": [
            "observed API/pool/client bindings and exact callback are independently read back",
            "runtime ZIP and public JWKS manifest are built and verified outside Git/OneDrive",
            "production IAM, parameter version, owner binding and cleanup are reviewed",
            "API remains disabled and Lambda concurrency remains zero until separate activation gate",
        ],
    })
    template["Description"] = "Closed prod runtime/API candidate reusing retained identity; no activation and not deploy-ready."
    return template


__all__ = ["ProdOAuthTemplateError", "build_prod_oauth_template", "build_prod_runtime_template"]
