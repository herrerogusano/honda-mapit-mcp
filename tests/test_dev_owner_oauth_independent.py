from __future__ import annotations

from scripts.build_aws_dev_owner_oauth import (
    REGION,
    STACK_NAME,
    build_dev_owner_oauth_template,
)


def _candidate(callback: str = "http://localhost:39031/callback/codex-dev-owner"):
    return build_dev_owner_oauth_template(
        account_id="123456789012",
        api_id="abcdefghij",
        owner_pool_id="eu-west-1_abcdefghijk",
        callback_url=callback,
    )


def test_independent_candidate_has_closed_resource_and_property_inventory():
    template = _candidate()
    resources = template["Resources"]
    assert set(resources) == {
        "McpResourceServer",
        "McpUserPoolClient",
        "McpManagedLoginBranding",
    }
    assert "McpUserPool" not in resources
    assert "McpUserPoolDomain" not in resources
    assert "McpApi" not in resources
    assert set(template) == {
        "AWSTemplateFormatVersion", "Description", "Conditions", "Metadata", "Resources",
    }

    expected_properties = {
        "McpResourceServer": {"Identifier", "Name", "Scopes", "UserPoolId"},
        "McpUserPoolClient": {
            "AccessTokenValidity", "AllowedOAuthFlows", "AllowedOAuthFlowsUserPoolClient",
            "AllowedOAuthScopes", "CallbackURLs", "ClientName", "DefaultRedirectURI",
            "EnableTokenRevocation", "ExplicitAuthFlows", "GenerateSecret", "IdTokenValidity",
            "PreventUserExistenceErrors", "RefreshTokenValidity", "SupportedIdentityProviders",
            "TokenValidityUnits", "UserPoolId",
        },
        "McpManagedLoginBranding": {"ClientId", "UseCognitoProvidedValues", "UserPoolId"},
    }
    for logical_id, expected in expected_properties.items():
        assert set(resources[logical_id]["Properties"]) == expected
        assert resources[logical_id]["DeletionPolicy"] == "Retain"
        assert resources[logical_id]["UpdateReplacePolicy"] == "Retain"


def test_independent_conditions_and_dependencies_bind_exact_dev_target():
    template = _candidate()
    condition = template["Conditions"]["SupportedDeployment"]["Fn::And"]
    assert condition == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, "123456789012"]},
    ]
    assert all(r["Condition"] == "SupportedDeployment" for r in template["Resources"].values())
    assert template["Resources"]["McpUserPoolClient"]["DependsOn"] == ["McpResourceServer"]
    client = template["Resources"]["McpUserPoolClient"]["Properties"]
    assert client["EnableTokenRevocation"] is True
    assert client["PreventUserExistenceErrors"] == "ENABLED"
    assert client["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["AllowedOAuthScopes"] == [
        "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp/use"
    ]
    assert client["GenerateSecret"] is False
    assert template["Metadata"]["Readiness"] == "DEV_OWNER_OAUTH_NOT_DEPLOY_READY"
    assert template["Metadata"]["NoEndpointActivation"] is True


def test_generated_template_isolation_and_no_sensitive_input_echo():
    first = _candidate()
    first["Resources"]["McpUserPoolClient"]["Properties"]["CallbackURLs"].clear()
    second = _candidate()
    assert second["Resources"]["McpUserPoolClient"]["Properties"]["CallbackURLs"] == [
        "http://localhost:39031/callback/codex-dev-owner"
    ]
    rendered = repr(second)
    assert "123456789012" in rendered
    assert "secret=" not in rendered
    assert "client_secret" not in rendered.lower()
