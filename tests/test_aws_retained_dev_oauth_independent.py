from __future__ import annotations

import copy
import json

import pytest

from scripts.build_aws_retained_dev import STACK_NAME, build_retained_dev_template
from scripts.build_aws_retained_dev_oauth import build_retained_dev_oauth_setup


API_ID = "abcdef1234"
POOL_ID = "eu-west-1_AbCdEfGhI"
CALLBACK = "http://127.0.0.1:8787/callback"
EXPECTED_CHILDREN = {"McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding"}
EXPECTED_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
}


def build():
    return build_retained_dev_oauth_setup(API_ID, POOL_ID, callback_url=CALLBACK)


def test_oauth_is_exactly_the_closed_scaffold_plus_three_retained_children():
    template = build()
    assert {name: resource["Type"] for name, resource in template["Resources"].items()} == EXPECTED_TYPES
    scaffold = build_retained_dev_template()
    for name, resource in scaffold["Resources"].items():
        assert template["Resources"][name] == resource
    assert template["Conditions"] == scaffold["Conditions"]
    assert set(template["Resources"]) - set(scaffold["Resources"]) == EXPECTED_CHILDREN
    for name in EXPECTED_CHILDREN:
        resource = template["Resources"][name]
        assert resource["Condition"] == "SupportedDeployment"
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"
        assert resource["Properties"]["UserPoolId"] == POOL_ID


def test_oauth_reuses_existing_pool_without_pool_domain_mfa_route_or_invoke_scope():
    template = build()
    encoded = json.dumps(template, sort_keys=True)
    forbidden_types = {
        "AWS::Cognito::UserPool", "AWS::Cognito::UserPoolDomain",
        "AWS::Lambda::Permission", "AWS::ApiGatewayV2::Route",
    }
    assert not forbidden_types & {resource["Type"] for resource in template["Resources"].values()}
    assert "MfaConfiguration" not in encoded
    assert "AWS::Cognito::UserPoolDomain" not in encoded
    assert "lambda:InvokeFunction" not in encoded
    assert template["Metadata"] == {
        "Readiness": "RETAINED_DEV_OAUTH_NOT_DEPLOY_READY",
        "NotDeployReady": True,
        "ExistingPoolAndDomainUnchanged": True,
        "NoNewUserOrMfaReset": True,
        "NoRoutesOrInvocationPermission": True,
        "NoRuntimeSecretsOrData": True,
        "SharedPoolChildrenRetained": True,
        "FreshPrivateBindingUpdateAndReadbackRequired": True,
    }
    role = template["Resources"]["McpHandlerRole"]["Properties"]
    actions = role["Policies"][0]["PolicyDocument"]["Statement"][0]["Action"]
    assert actions == ["logs:CreateLogStream", "logs:PutLogEvents"]


def test_client_resource_audience_callback_and_parameters_are_exactly_bound():
    template = build()
    server = template["Resources"]["McpResourceServer"]["Properties"]
    client = template["Resources"]["McpUserPoolClient"]["Properties"]
    assert server["Name"] == STACK_NAME
    assert server["Identifier"] == {"Ref": "McpResourceUri"}
    assert server["Scopes"] == [{"ScopeName": "use", "ScopeDescription": "Call the protected MCP endpoint."}]
    assert client["ClientName"] == f"{STACK_NAME}-client"
    assert client["GenerateSecret"] is False
    assert client["AllowedOAuthFlowsUserPoolClient"] is True
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["AllowedOAuthScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    assert client["CallbackURLs"] == [{"Ref": "OAuthCallbackURL"}]
    assert client["DefaultRedirectURI"] == {"Ref": "OAuthCallbackURL"}
    assert client["SupportedIdentityProviders"] == ["COGNITO"]
    assert client["EnableTokenRevocation"] is True
    assert "ClientSecret" not in client
    assert set(template["Parameters"]) == {"McpResourceUri", "OAuthCallbackURL"}
    assert template["Parameters"]["McpResourceUri"]["Default"] == f"https://{API_ID}.execute-api.eu-west-1.amazonaws.com/mcp"
    assert template["Parameters"]["OAuthCallbackURL"]["Default"] == CALLBACK
    assert "EnvironmentName" not in json.dumps(template["Parameters"])
    assert template["Outputs"]["UserPoolId"]["Value"] == POOL_ID


def test_oauth_factory_is_fresh_and_rejects_wrong_region_or_non_loopback_bindings():
    baseline = copy.deepcopy(build())
    mutated = build()
    mutated["Resources"]["McpUserPoolClient"]["Properties"]["GenerateSecret"] = True
    assert build() == baseline

    for api_id, pool_id, callback in (
        ("bad", POOL_ID, CALLBACK),
        (API_ID, "us-east-1_AbCdEfGhI", CALLBACK),
        (API_ID, POOL_ID, "https://example.com/callback"),
    ):
        with pytest.raises(ValueError):
            build_retained_dev_oauth_setup(api_id, pool_id, callback_url=callback)
