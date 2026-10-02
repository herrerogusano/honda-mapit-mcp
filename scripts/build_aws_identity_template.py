"""Build a permanent, isolated Cognito identity stack for offline review.

The template deliberately contains no MAPIT API, Lambda, IAM role, user,
credential, or dev/prod compute resources. It retains its four Cognito
resources and is restricted to one fixed identity stack in eu-west-1.
"""

from __future__ import annotations

import copy
from typing import Any

from scripts.build_aws_dev_bootstrap import _read_scaffold, _validate_scaffold

_REGION = "eu-west-1"
_STACK = "honda-mapit-mcp-identity"
_DOMAIN = "hm-honda-mapit-mcp-identity"
_CALLBACK = "http://127.0.0.1:8785/callback"
_NAMES = {
    "McpUserPool": "AWS::Cognito::UserPool",
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
}
_SOURCE_TYPES = {
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
}
_SOURCE_PROPERTY_KEYS = {
    "McpUserPoolDomain": {"Domain", "ManagedLoginVersion", "UserPoolId"},
    "McpUserPoolClient": {
        "AccessTokenValidity", "AllowedOAuthFlows", "AllowedOAuthFlowsUserPoolClient", "AllowedOAuthScopes",
        "CallbackURLs", "ClientName", "DefaultRedirectURI", "EnableTokenRevocation", "GenerateSecret",
        "IdTokenValidity", "PreventUserExistenceErrors", "RefreshTokenValidity", "SupportedIdentityProviders",
        "TokenValidityUnits", "UserPoolId",
    },
    "McpManagedLoginBranding": {"ClientId", "UseCognitoProvidedValues", "UserPoolId"},
}
_SOURCE_DEPENDS_ON = {
    "McpUserPoolClient": ["McpResourceServer", "McpUserPoolDomain"],
    "McpManagedLoginBranding": ["McpUserPoolDomain"],
}


class IdentityTemplateError(ValueError):
    """Safe local identity-template error."""


def fixed_identity_template() -> dict[str, Any]:
    """Return a fresh retained Cognito-only identity template."""
    try:
        source = _read_scaffold()
        _validate_scaffold(source)
        oauth: dict[str, dict[str, Any]] = {}
        for name, kind in _SOURCE_TYPES.items():
            item = source["Resources"].get(name)
            expected_keys = {"Type", "Properties"}
            if name in _SOURCE_DEPENDS_ON:
                expected_keys.add("DependsOn")
            if (
                not isinstance(item, dict) or item.get("Type") != kind
                or not isinstance(item.get("Properties"), dict)
                or set(item) != expected_keys
                or set(item["Properties"]) != _SOURCE_PROPERTY_KEYS[name]
                or (name in _SOURCE_DEPENDS_ON and item.get("DependsOn") != _SOURCE_DEPENDS_ON[name])
            ):
                raise IdentityTemplateError("identity_scaffold_invalid")
            oauth[name] = item
        domain_props = oauth["McpUserPoolDomain"]["Properties"]
        client_props = oauth["McpUserPoolClient"]["Properties"]
        branding_props = oauth["McpManagedLoginBranding"]["Properties"]
        if (
            domain_props.get("UserPoolId") != {"Ref": "McpUserPool"}
            or type(domain_props.get("ManagedLoginVersion")) is not int
            or domain_props.get("ManagedLoginVersion") != 2
            or client_props.get("UserPoolId") != {"Ref": "McpUserPool"}
            or client_props.get("GenerateSecret") is not False
            or client_props.get("AllowedOAuthFlows") != ["code"]
            or client_props.get("AllowedOAuthFlowsUserPoolClient") is not True
            or client_props.get("EnableTokenRevocation") is not True
            or client_props.get("SupportedIdentityProviders") != ["COGNITO"]
            or client_props.get("AccessTokenValidity") != 5
            or client_props.get("IdTokenValidity") != 5
            or client_props.get("RefreshTokenValidity") != 1
            or branding_props.get("UseCognitoProvidedValues") is not True
        ):
            raise IdentityTemplateError("identity_scaffold_invalid")
    except Exception:
        raise IdentityTemplateError("identity_scaffold_invalid") from None

    pool = copy.deepcopy(source["Resources"]["McpUserPool"])
    pool["Properties"].update({
        "UserPoolName": "honda-mapit-mcp-identity-users",
        "UserPoolTier": "ESSENTIALS",
        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": True},
        "MfaConfiguration": "ON",
        "EnabledMfas": ["SOFTWARE_TOKEN_MFA"],
        "UsernameAttributes": ["email"],
        "UserPoolTags": {"Project": "honda-mapit-mcp", "Environment": "identity"},
        "DeletionProtection": "ACTIVE",
    })
    domain = copy.deepcopy(oauth["McpUserPoolDomain"])
    domain["Properties"].update({
        "UserPoolId": {"Ref": "McpUserPool"},
        "Domain": _DOMAIN,
        "ManagedLoginVersion": 2,
    })
    client = copy.deepcopy(oauth["McpUserPoolClient"])
    client["DependsOn"] = ["McpUserPoolDomain"]
    client["Properties"].update({
        "ClientName": "honda-mapit-mcp-identity-login",
        "UserPoolId": {"Ref": "McpUserPool"},
        "GenerateSecret": False,
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthFlows": ["code"],
        "ExplicitAuthFlows": ["ALLOW_REFRESH_TOKEN_AUTH"],
        "AllowedOAuthScopes": ["openid"],
        "CallbackURLs": [_CALLBACK],
        "DefaultRedirectURI": _CALLBACK,
        "SupportedIdentityProviders": ["COGNITO"],
        "EnableTokenRevocation": True,
        "PreventUserExistenceErrors": "ENABLED",
        "AccessTokenValidity": 5,
        "IdTokenValidity": 5,
        "RefreshTokenValidity": 1,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
    })
    branding = copy.deepcopy(oauth["McpManagedLoginBranding"])
    branding["Properties"].update({
        "UserPoolId": {"Ref": "McpUserPool"},
        "ClientId": {"Ref": "McpUserPoolClient"},
        "UseCognitoProvidedValues": True,
    })

    resources = {
        "McpUserPool": pool,
        "McpUserPoolDomain": domain,
        "McpUserPoolClient": client,
        "McpManagedLoginBranding": branding,
    }
    for item in resources.values():
        item["Condition"] = "IdentityStackSupported"
        item["DeletionPolicy"] = "Retain"
        item["UpdateReplacePolicy"] = "Retain"
    if any(resources[name].get("Type") != kind for name, kind in _NAMES.items()):
        raise IdentityTemplateError("identity_scaffold_invalid")

    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Permanent identity-only Cognito stack; separate from dev/prod compute and not yet deploy-ready.",
        "Metadata": {
            "Readiness": "PERMANENT_IDENTITY_NOT_DEPLOY_READY",
            "IdentityNamespace": "honda-mapit-mcp-identity",
            "SeparateFromDevAndProdCompute": True,
            "MfaEnrollmentRequired": True,
            "TotpOnly": True,
            "OAuthClientPurpose": "loopback code + PKCE login; openid scope only",
            "NoMcpScopeOrProtectedResourceAccess": True,
            "NoComputeOrApiResources": True,
            "NoUsersOrSecretsCreated": True,
            "RetainedResourcesRequireOperatorManagedRetirement": True,
            "CallbackURI": _CALLBACK,
            "MissingPrerequisites": [
                "operator confirms the fixed local callback listener and account ownership",
                "operator-managed Cognito MFA enrollment and recovery procedure",
                "separate production client and compute identity review",
            ],
        },
        "Conditions": {
            "IdentityStackSupported": {
                "Fn::And": [
                    {"Fn::Equals": [{"Ref": "AWS::Region"}, _REGION]},
                    {"Fn::Equals": [{"Ref": "AWS::StackName"}, _STACK]},
                ]
            }
        },
        "Resources": resources,
        "Outputs": {
            "OAuthClientId": {"Condition": "IdentityStackSupported", "Value": {"Ref": "McpUserPoolClient"}},
        },
    }


__all__ = ["IdentityTemplateError", "fixed_identity_template"]
