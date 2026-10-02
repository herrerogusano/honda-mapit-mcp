from __future__ import annotations

from scripts.build_aws_identity_template import fixed_identity_template


def test_identity_template_is_permanent_isolated_and_mfa_only():
    template = fixed_identity_template()
    resources = template["Resources"]
    assert set(resources) == {"McpUserPool", "McpUserPoolDomain", "McpUserPoolClient", "McpManagedLoginBranding"}
    assert template["Conditions"]["IdentityStackSupported"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-identity"]},
    ]
    for resource in resources.values():
        assert resource["Condition"] == "IdentityStackSupported"
        assert resource["DeletionPolicy"] == "Retain"
        assert resource["UpdateReplacePolicy"] == "Retain"

    pool = resources["McpUserPool"]["Properties"]
    assert pool["UserPoolTier"] == "ESSENTIALS"
    assert pool["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}
    assert pool["UsernameAttributes"] == ["email"]
    assert pool["MfaConfiguration"] == "ON"
    assert pool["EnabledMfas"] == ["SOFTWARE_TOKEN_MFA"]
    assert pool["DeletionProtection"] == "ACTIVE"

    domain = resources["McpUserPoolDomain"]["Properties"]
    assert domain == {"UserPoolId": {"Ref": "McpUserPool"}, "Domain": "hm-honda-mapit-mcp-identity", "ManagedLoginVersion": 2}
    client = resources["McpUserPoolClient"]["Properties"]
    assert client["GenerateSecret"] is False
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["AllowedOAuthFlowsUserPoolClient"] is True
    assert client["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    assert client["AllowedOAuthScopes"] == ["openid"]
    assert client["CallbackURLs"] == ["http://127.0.0.1:8785/callback"]
    assert client["DefaultRedirectURI"] == "http://127.0.0.1:8785/callback"
    assert client["EnableTokenRevocation"] is True
    assert client["AccessTokenValidity"] == client["IdTokenValidity"] == 5
    assert client["RefreshTokenValidity"] == 1
    assert client["TokenValidityUnits"] == {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"}
    assert "McpResourceServer" not in resources
    assert not any("Api" in name or "Lambda" in name or "Role" in name for name in resources)
    assert template["Metadata"]["SeparateFromDevAndProdCompute"] is True
    assert template["Metadata"]["NoComputeOrApiResources"] is True


def test_identity_factory_returns_fresh_templates_and_no_user_or_secret():
    first = fixed_identity_template()
    first["Resources"]["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"].append("use")
    second = fixed_identity_template()
    assert second["Resources"]["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"] == ["openid"]
    rendered = str(second)
    assert "AdminCreateUser" in rendered
    assert "ClientSecret" not in rendered
    assert set(second["Resources"]) == {"McpUserPool", "McpUserPoolDomain", "McpUserPoolClient", "McpManagedLoginBranding"}
