from __future__ import annotations

import pytest

from scripts.build_aws_dev_owner_oauth import (
    CLIENT_NAME,
    REGION,
    RESOURCE_SERVER_NAME,
    STACK_NAME,
    DevOwnerOAuthTemplateError,
    build_dev_owner_oauth_template,
)
from scripts.build_aws_shared_identity_dev import build_shared_identity_oauth_setup_retained_template

ACCOUNT = "123456789012"
API_ID = "abcdefghij"
POOL = "eu-west-1_abcdefghijk"
CALLBACK = "http://localhost:39031/callback/codex-dev-owner"
URI = f"https://{API_ID}.execute-api.{REGION}.amazonaws.com/mcp"


def _build(**changes):
    values = {"account_id": ACCOUNT, "api_id": API_ID,
              "owner_pool_id": POOL, "callback_url": CALLBACK}
    values.update(changes)
    return build_dev_owner_oauth_template(**values)


def test_candidate_contains_only_retained_owner_pool_oauth_children():
    template = _build()
    resources = template["Resources"]
    assert set(resources) == {
        "McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding",
    }
    expected_types = {
        "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
        "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
        "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
    }
    for logical_id, expected_type in expected_types.items():
        resource = resources[logical_id]
        assert resource["Type"] == expected_type
        assert resource["Condition"] == "SupportedDeployment"
        assert resource["DeletionPolicy"] == resource["UpdateReplacePolicy"] == "Retain"

    assert template["Conditions"]["SupportedDeployment"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, ACCOUNT]},
    ]
    server = resources["McpResourceServer"]["Properties"]
    assert server == {
        "UserPoolId": POOL,
        "Identifier": URI,
        "Name": RESOURCE_SERVER_NAME,
        "Scopes": [{"ScopeName": "use", "ScopeDescription": "Call the protected MCP endpoint."}],
    }


def test_public_pkce_client_is_dev_only_and_uses_exact_callback_and_scope():
    template = _build()
    client = template["Resources"]["McpUserPoolClient"]["Properties"]
    assert client["ClientName"] == CLIENT_NAME
    assert client["UserPoolId"] == POOL
    assert client["GenerateSecret"] is False
    assert client["AllowedOAuthFlowsUserPoolClient"] is True
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    assert client["AllowedOAuthScopes"] == [f"{URI}/use"]
    assert client["CallbackURLs"] == [CALLBACK]
    assert client["DefaultRedirectURI"] == CALLBACK
    assert client["SupportedIdentityProviders"] == ["COGNITO"]
    assert client["AccessTokenValidity"] == client["IdTokenValidity"] == 5
    assert client["RefreshTokenValidity"] == 1
    assert client["TokenValidityUnits"] == {
        "AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days",
    }
    assert client["AllowedOAuthScopes"] == [f"{URI}/use"]
    assert not any("admin" in scope or scope == "openid"
                   for scope in client["AllowedOAuthScopes"])
    assert "McpResourceServer" in template["Resources"]["McpUserPoolClient"]["DependsOn"]
    assert template["Resources"]["McpManagedLoginBranding"]["Properties"] == {
        "UserPoolId": POOL,
        "ClientId": {"Ref": "McpUserPoolClient"},
        "UseCognitoProvidedValues": True,
    }
    assert "Parameters" not in template and "Outputs" not in template
    assert template["Metadata"]["Readiness"] == "DEV_OWNER_OAUTH_NOT_DEPLOY_READY"
    assert template["Metadata"]["OwnerAndMfaUnchanged"] is True
    assert template["Metadata"]["ExistingOauthClientUnchanged"] is True


@pytest.mark.parametrize("changes", [
    {"account_id": "12345678901x"},
    {"account_id": "000000000000"},
    {"api_id": "../abcdefgh"},
    {"api_id": "ABCDEFGHIJ"},
    {"owner_pool_id": "us-east-1_abcdefghijk"},
    {"owner_pool_id": "eu-west-1_"},
    {"callback_url": "https://localhost:39031/callback"},
    {"callback_url": "http://example.com:39031/callback"},
    {"callback_url": "http://localhost:39031/callback?secret=x"},
])
def test_invalid_bindings_and_callbacks_fail_closed(changes):
    with pytest.raises(DevOwnerOAuthTemplateError, match="^dev_owner_oauth_invalid$"):
        _build(**changes)


def test_factory_returns_independent_copy_and_does_not_mutate_shared_factory():
    before = build_shared_identity_oauth_setup_retained_template(
        API_ID, POOL, callback_url=CALLBACK,
    )
    first = _build()
    first["Resources"]["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"].clear()
    after = build_shared_identity_oauth_setup_retained_template(
        API_ID, POOL, callback_url=CALLBACK,
    )
    assert before == after
    second = _build()
    assert second["Resources"]["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"] == [f"{URI}/use"]
    assert set(second["Resources"]) == {
        "McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding",
    }
