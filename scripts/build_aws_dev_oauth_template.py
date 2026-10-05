"""Compose a closed, dev-only OAuth runtime template for offline review.

This factory never calls AWS, activates the endpoint, creates a user, or proves
that identifiers/callbacks exist. Real-ID output belongs in a private external
file after observed-ID readback, ownership/callback confirmation, exact cleanup
review, and artifact-retirement acceptance.
"""

from __future__ import annotations

import copy
import re
from urllib.parse import urlsplit
from typing import Any

from mapit.aws_dev_runtime import CognitoDevPolicy
from scripts.build_aws_dev_bootstrap import (
    BootstrapTemplateError,
    fixed_bootstrap_template,
    _read_scaffold,
    _validate_scaffold,
)
from scripts.build_aws_dev_runtime import _validate_policy
from scripts.build_aws_dev_runtime_template import (
    RuntimeTemplateError,
    fixed_runtime_candidate_template,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"
_RESOURCE_TYPES = {
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
    "McpJwtAuthorizer": "AWS::ApiGatewayV2::Authorizer",
    "McpLambdaIntegration": "AWS::ApiGatewayV2::Integration",
    "McpPostRoute": "AWS::ApiGatewayV2::Route",
    "McpLambdaInvokePermission": "AWS::Lambda::Permission",
}
_RESOURCE_PROPERTIES = {
    "McpUserPoolDomain": {"Domain", "ManagedLoginVersion", "UserPoolId"},
    "McpResourceServer": {"Identifier", "Name", "Scopes", "UserPoolId"},
    "McpUserPoolClient": {
        "AccessTokenValidity", "AllowedOAuthFlows", "AllowedOAuthFlowsUserPoolClient", "AllowedOAuthScopes",
        "CallbackURLs", "ClientName", "DefaultRedirectURI", "EnableTokenRevocation", "GenerateSecret",
        "IdTokenValidity", "PreventUserExistenceErrors", "RefreshTokenValidity", "SupportedIdentityProviders",
        "TokenValidityUnits", "UserPoolId",
    },
    "McpManagedLoginBranding": {"ClientId", "UseCognitoProvidedValues", "UserPoolId"},
    "McpJwtAuthorizer": {"ApiId", "AuthorizerType", "IdentitySource", "JwtConfiguration", "Name"},
    "McpLambdaIntegration": {
        "ApiId", "IntegrationMethod", "IntegrationType", "IntegrationUri", "PayloadFormatVersion", "TimeoutInMillis",
    },
    "McpPostRoute": {"ApiId", "AuthorizationScopes", "AuthorizationType", "AuthorizerId", "RouteKey", "Target"},
    "McpLambdaInvokePermission": {"Action", "FunctionName", "Principal", "SourceAccount", "SourceArn"},
}
_RESOURCE_DEPENDS_ON = {
    "McpUserPoolClient": ["McpResourceServer", "McpUserPoolDomain"],
    "McpManagedLoginBranding": ["McpUserPoolDomain"],
}
_SETUP_RESOURCE_NAMES = (
    "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding",
)


class OAuthTemplateError(ValueError):
    """Closed local validation error without input values."""


def _fail(category: str) -> None:
    raise OAuthTemplateError(category)


def _validate_callback(callback_url: str) -> str:
    if type(callback_url) is not str or not callback_url or len(callback_url) > 1024:
        _fail("oauth_callback_invalid")
    try:
        callback_url.encode("ascii", errors="strict")
    except UnicodeError:
        _fail("oauth_callback_invalid")
    if any(ord(char) <= 0x20 or ord(char) == 0x7F for char in callback_url) or any(
        char in callback_url for char in ("\\", "*", "?", "#")
    ):
        _fail("oauth_callback_invalid")
    try:
        parsed = urlsplit(callback_url)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        _fail("oauth_callback_invalid")
    if (
        parsed.scheme != "http"
        or parsed.username is not None
        or parsed.password is not None
        or host not in {"localhost", "127.0.0.1", "::1"}
        or type(port) is not int
        or not 1024 <= port <= 65535
        or not parsed.path.startswith("/")
        or not parsed.path
        or parsed.query
        or parsed.fragment
    ):
        _fail("oauth_callback_invalid")
    expected_authority = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
    if parsed.netloc != expected_authority:
        _fail("oauth_callback_invalid")
    return callback_url


def _validate_windows(start: int, end: int) -> tuple[int, int]:
    if type(start) is not int or type(end) is not int or start <= 0 or end <= 0:
        _fail("oauth_execution_window_invalid")
    if not 1 <= end - start <= 300:
        _fail("oauth_execution_window_invalid")
    return start, end


def _validate_source_oauth(source: dict[str, Any]) -> dict[str, dict[str, Any]]:
    resources = source.get("Resources")
    if not isinstance(resources, dict):
        _fail("oauth_scaffold_invalid")
    selected: dict[str, dict[str, Any]] = {}
    for name, expected_type in _RESOURCE_TYPES.items():
        item = resources.get(name)
        if not isinstance(item, dict) or item.get("Type") != expected_type or not isinstance(item.get("Properties"), dict):
            _fail("oauth_scaffold_invalid")
        expected_top_level = {"Type", "Properties"}
        if name in _RESOURCE_DEPENDS_ON:
            expected_top_level.add("DependsOn")
            if item.get("DependsOn") != _RESOURCE_DEPENDS_ON[name]:
                _fail("oauth_scaffold_invalid")
        if set(item) != expected_top_level or set(item["Properties"]) != _RESOURCE_PROPERTIES[name]:
            _fail("oauth_scaffold_invalid")
        selected[name] = item
    props = {name: item["Properties"] for name, item in selected.items()}
    if (
        props["McpUserPoolDomain"].get("UserPoolId") != {"Ref": "McpUserPool"}
        or props["McpUserPoolDomain"].get("ManagedLoginVersion") != 2
        or props["McpUserPoolDomain"].get("Domain") != {"Fn::Sub": "hm-${EnvironmentName}-${AWS::StackName}"}
    ):
        _fail("oauth_scaffold_invalid")
    resource_server = props["McpResourceServer"]
    if (
        resource_server.get("UserPoolId") != {"Ref": "McpUserPool"}
        or resource_server.get("Identifier") != {"Ref": "McpResourceUri"}
        or resource_server.get("Scopes") != [{"ScopeName": "use", "ScopeDescription": "Call the protected MCP endpoint."}]
    ):
        _fail("oauth_scope_invalid")
    client = props["McpUserPoolClient"]
    if (
        client.get("UserPoolId") != {"Ref": "McpUserPool"}
        or client.get("GenerateSecret") is not False
        or client.get("AllowedOAuthFlowsUserPoolClient") is not True
        or client.get("AllowedOAuthFlows") != ["code"]
        or client.get("AllowedOAuthScopes") != [{"Fn::Sub": "${McpResourceUri}/use"}]
        or client.get("CallbackURLs") != [{"Ref": "OAuthCallbackURL"}]
        or client.get("DefaultRedirectURI") != {"Ref": "OAuthCallbackURL"}
        or client.get("SupportedIdentityProviders") != ["COGNITO"]
        or type(client.get("AccessTokenValidity")) is not int
        or client.get("AccessTokenValidity") != 5
        or type(client.get("IdTokenValidity")) is not int
        or client.get("IdTokenValidity") != 5
        or type(client.get("RefreshTokenValidity")) is not int
        or client.get("RefreshTokenValidity") != 1
        or client.get("TokenValidityUnits") != {
            "AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"
        }
        or client.get("EnableTokenRevocation") is not True
        or client.get("PreventUserExistenceErrors") != "ENABLED"
    ):
        _fail("oauth_client_invalid")
    branding = props["McpManagedLoginBranding"]
    if (
        branding.get("UserPoolId") != {"Ref": "McpUserPool"}
        or branding.get("ClientId") != {"Ref": "McpUserPoolClient"}
        or branding.get("UseCognitoProvidedValues") is not True
    ):
        _fail("oauth_branding_invalid")
    authorizer = props["McpJwtAuthorizer"]
    if (
        authorizer.get("ApiId") != {"Ref": "McpApi"}
        or authorizer.get("AuthorizerType") != "JWT"
        or authorizer.get("IdentitySource") != ["$request.header.Authorization"]
        or authorizer.get("JwtConfiguration") != {
            "Issuer": {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${McpUserPool}"},
            "Audience": [{"Ref": "McpResourceUri"}],
        }
    ):
        _fail("oauth_authorizer_invalid")
    integration = props["McpLambdaIntegration"]
    if (
        integration.get("ApiId") != {"Ref": "McpApi"}
        or integration.get("IntegrationType") != "AWS_PROXY"
        or integration.get("IntegrationMethod") != "POST"
        or integration.get("PayloadFormatVersion") != "2.0"
        or integration.get("TimeoutInMillis") != 20000
        or integration.get("IntegrationUri") != {
            "Fn::Sub": "arn:${AWS::Partition}:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${McpHandler.Arn}/invocations"
        }
    ):
        _fail("oauth_integration_invalid")
    route = props["McpPostRoute"]
    if (
        route.get("ApiId") != {"Ref": "McpApi"}
        or route.get("RouteKey") != "POST /mcp"
        or route.get("AuthorizationType") != "JWT"
        or route.get("AuthorizerId") != {"Ref": "McpJwtAuthorizer"}
        or route.get("AuthorizationScopes") != [{"Fn::Sub": "${McpResourceUri}/use"}]
        or route.get("Target") != {"Fn::Join": ["/", ["integrations", {"Ref": "McpLambdaIntegration"}]]}
    ):
        _fail("oauth_post_route_invalid")
    permission = props["McpLambdaInvokePermission"]
    if (
        permission.get("Action") != "lambda:InvokeFunction"
        or permission.get("FunctionName") != {"Ref": "McpHandler"}
        or permission.get("Principal") != "apigateway.amazonaws.com"
        or permission.get("SourceAccount") != {"Ref": "AWS::AccountId"}
        or permission.get("SourceArn") != {
            "Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${McpApi}/$default/POST/mcp"
        }
    ):
        _fail("oauth_post_permission_invalid")
    pool = resources.get("McpUserPool", {}).get("Properties", {})
    if (
        pool.get("MfaConfiguration") != "ON"
        or pool.get("EnabledMfas") != ["SOFTWARE_TOKEN_MFA"]
        or pool.get("AdminCreateUserConfig") != {"AllowAdminCreateUserOnly": True}
    ):
        _fail("oauth_pool_policy_invalid")
    return selected


def _oauth_parameters(resource_uri: str, callback_url: str) -> dict[str, dict[str, Any]]:
    return {
        "McpResourceUri": {
            "Type": "String",
            "Default": resource_uri,
            "AllowedValues": [resource_uri],
            "Description": "Exact dev MCP audience and Cognito resource-server identifier.",
        },
        "OAuthCallbackURL": {
            "Type": "String",
            "Default": callback_url,
            "AllowedValues": [callback_url],
            "Description": "Explicit operator-confirmed loopback callback; syntax does not prove client registration.",
        },
    }


def build_dev_oauth_setup_template(api_id: str, *, callback_url: str) -> dict[str, Any]:
    """Compose the pre-runtime Cognito setup stage without fake identities.

    The API and pool are created/owned by the existing fixed bootstrap stack.
    This update adds only Cognito domain/resource-server/client/branding; it
    does not require the generated client ID or future owner subject as input.
    """
    if type(api_id) is not str or not _API_ID.fullmatch(api_id):
        _fail("oauth_api_id_invalid")
    callback_url = _validate_callback(callback_url)
    resource_uri = f"https://{api_id}.execute-api.eu-west-1.amazonaws.com/mcp"
    try:
        template = fixed_bootstrap_template()
        source = _read_scaffold()
        _validate_scaffold(source)
        oauth_resources = _validate_source_oauth(source)
    except OAuthTemplateError:
        raise
    except BootstrapTemplateError:
        _fail("oauth_scaffold_invalid")
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != {
        "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"
    }:
        _fail("oauth_setup_base_invalid")
    if (
        resources["McpApi"].get("Properties", {}).get("DisableExecuteApiEndpoint") is not True
        or type(resources["McpHandler"].get("Properties", {}).get("ReservedConcurrentExecutions")) is not int
        or resources["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] != 0
    ):
        _fail("oauth_setup_base_not_closed")
    for name in _SETUP_RESOURCE_NAMES:
        cloned = copy.deepcopy(oauth_resources[name])
        cloned["Condition"] = "SupportedDeployment"
        cloned["DeletionPolicy"] = "Delete"
        cloned["UpdateReplacePolicy"] = "Delete"
        if name in resources:
            _fail("oauth_setup_resource_collision")
        resources[name] = cloned
    template["Parameters"].update({
        **_oauth_parameters(resource_uri, callback_url),
    })
    template["Outputs"]["McpClientId"] = {
        "Condition": "SupportedDeployment",
        "Value": {"Ref": "McpUserPoolClient"},
    }
    template["Metadata"].update({
        "Readiness": "OAUTH_SETUP_NOT_DEPLOY_READY",
        "OAuthSetupStageOnly": True,
        "UpdateOnlyForObservedBootstrapApiAndPool": True,
        "ObservedBootstrapOwnershipAndReadbackRequired": True,
        "NoActivation": True,
        "NoUserCreation": True,
        "NoRuntimeImplementation": True,
        "NoRoutesOrInvokePermissions": True,
        "MissingPrerequisites": [
            "verify the existing dev bootstrap API and pool belong to the intended stack before update",
            "read back generated client ID before constructing the separate final runtime binding",
            "confirm actual owner subject and the client's effective registered callback",
            "review exact cleanup permissions and enrollment/retirement procedure before provisioning",
        ],
    })
    template["Description"] = "Dev-only Cognito OAuth setup stage with API disabled and inline 503 handler; not deploy-ready."
    template["Metadata"]["OAuthConfigured"] = True
    return template


def build_dev_oauth_template(
    policy: CognitoDevPolicy,
    *,
    bucket: str,
    zip_sha256: str,
    jwks_sha256: str,
    callback_url: str,
    execution_start: int,
    execution_end: int,
) -> dict[str, Any]:
    """Compose a closed development candidate without external calls."""
    try:
        validated_policy = _validate_policy(policy)
    except Exception:
        _fail("oauth_policy_invalid")
    callback_url = _validate_callback(callback_url)
    start, end = _validate_windows(execution_start, execution_end)
    if type(jwks_sha256) is not str or not _SHA256.fullmatch(jwks_sha256):
        _fail("oauth_jwks_hash_invalid")
    try:
        template = fixed_runtime_candidate_template(bucket, zip_sha256)
    except (RuntimeTemplateError, TypeError, ValueError):
        _fail("oauth_runtime_candidate_invalid")
    try:
        source = _read_scaffold()
        _validate_scaffold(source)
        oauth_resources = _validate_source_oauth(source)
    except OAuthTemplateError:
        raise
    except BootstrapTemplateError:
        _fail("oauth_scaffold_invalid")
    resources = template.get("Resources")
    if not isinstance(resources, dict) or set(resources) != {
        "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"
    }:
        _fail("oauth_runtime_candidate_invalid")
    if (
        resources["McpApi"].get("Properties", {}).get("DisableExecuteApiEndpoint") is not True
        or type(resources["McpHandler"].get("Properties", {}).get("ReservedConcurrentExecutions")) is not int
        or resources["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] != 0
    ):
        _fail("oauth_runtime_candidate_not_closed")
    if validated_policy.resource_url != f"https://{validated_policy.api_host}/mcp":
        _fail("oauth_policy_invalid")
    for name, resource in oauth_resources.items():
        cloned = copy.deepcopy(resource)
        cloned["Condition"] = "SupportedDeployment"
        cloned["DeletionPolicy"] = "Delete"
        cloned["UpdateReplacePolicy"] = "Delete"
        if name in resources:
            _fail("oauth_resource_collision")
        resources[name] = cloned
    resources["McpProtectedResourceMetadataRoute"] = {
        "Type": "AWS::ApiGatewayV2::Route",
        "Condition": "SupportedDeployment",
        "DeletionPolicy": "Delete",
        "UpdateReplacePolicy": "Delete",
        "Properties": {
            "ApiId": {"Ref": "McpApi"},
            "RouteKey": f"GET {_METADATA_PATH}",
            "AuthorizationType": "NONE",
            "Target": {"Fn::Join": ["/", ["integrations", {"Ref": "McpLambdaIntegration"}]]},
        },
    }
    resources["McpProtectedResourceMetadataInvokePermission"] = {
        "Type": "AWS::Lambda::Permission",
        "Condition": "SupportedDeployment",
        "DeletionPolicy": "Delete",
        "UpdateReplacePolicy": "Delete",
        "Properties": {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": "McpHandler"},
            "Principal": "apigateway.amazonaws.com",
            "SourceAccount": {"Ref": "AWS::AccountId"},
            "SourceArn": {
                "Fn::Sub": f"arn:${{AWS::Partition}}:execute-api:${{AWS::Region}}:${{AWS::AccountId}}:${{McpApi}}/$default/GET/{_METADATA_PATH.lstrip('/')}"
            },
        },
    }
    template["Parameters"].update(_oauth_parameters(validated_policy.resource_url, callback_url))
    variables = {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_COGNITO_USER_POOL_ID": validated_policy.user_pool_id,
        "MAPIT_API_ID": validated_policy.api_id,
        "MAPIT_COGNITO_CLIENT_ID": validated_policy.client_id,
        "MAPIT_OWNER_SUBJECT": validated_policy.owner_subject,
        "MAPIT_COGNITO_JWKS_SHA256": jwks_sha256,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(start),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(end),
    }
    resources["McpHandler"]["Properties"]["Environment"] = {"Variables": variables}
    outputs = template.get("Outputs")
    if not isinstance(outputs, dict):
        _fail("oauth_runtime_candidate_invalid")
    outputs["McpClientId"] = {
        "Condition": "SupportedDeployment",
        "Value": {"Ref": "McpUserPoolClient"},
    }
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        _fail("oauth_runtime_candidate_invalid")
    metadata.update({
        "Readiness": "OAUTH_RUNTIME_COMPOSITION_NOT_DEPLOY_READY",
        "ObservedIdentifierReadbackRequired": True,
        "OwnerBindingConfirmationRequired": True,
        "EffectiveCallbackConfirmationRequired": True,
        "ScopedCleanupReviewRequired": True,
        "RuntimeArtifactRetirementRequired": True,
        "NoActivation": True,
        "NoUserCreation": True,
        "ZipSha256AndJwksSha256AreDistinctBindings": True,
        "MissingPrerequisites": [
            "observed Cognito pool, API, and app-client identifiers read back before deployment",
            "owner subject and exact effective loopback callback independently confirmed",
            "scoped cleanup permissions cover every added OAuth/API child resource",
            "runtime artifact object retirement and empty-bucket verification reviewed",
            "bounded synthetic interoperability and activation gates separately accepted",
        ],
    })
    return template


__all__ = ["OAuthTemplateError", "build_dev_oauth_setup_template", "build_dev_oauth_template"]
