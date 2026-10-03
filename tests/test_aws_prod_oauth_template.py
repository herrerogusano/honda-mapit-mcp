from __future__ import annotations

import json

import pytest

from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts.build_aws_prod_bootstrap import fixed_prod_bootstrap_template
from scripts import build_aws_prod_oauth_template as composer

POOL = "eu-west-1_A1b2C3d4E"
API = "a1b2c3d4e5"
CLIENT = "ProdClient123456"
OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
CALLBACK = "http://localhost:8786/mcp/oauth/callback/codex-fixed-server"
URI = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"


def policy():
    return CognitoProdPolicy(user_pool_id=POOL, api_id=API, client_id=CLIENT, owner_subject=OWNER)


def test_prod_oauth_template_adds_only_three_retained_resources_to_existing_pool():
    before = fixed_prod_bootstrap_template()
    template = composer.build_prod_oauth_template(user_pool_id=POOL, api_id=API, callback_url=CALLBACK)
    assert set(template["Resources"]) == {
        "ProdMcpResourceServer", "ProdMcpUserPoolClient", "ProdMcpManagedLoginBranding",
    }
    assert all(item["DeletionPolicy"] == item["UpdateReplacePolicy"] == "Retain"
               for item in template["Resources"].values())
    assert not any(item["Type"] in {
        "AWS::Cognito::UserPool", "AWS::Cognito::UserPoolDomain", "AWS::Lambda::Function",
        "AWS::ApiGatewayV2::Api", "AWS::IAM::Role",
    } for item in template["Resources"].values())
    resources = template["Resources"]
    resource_server = resources["ProdMcpResourceServer"]["Properties"]
    assert resource_server == {
        "Identifier": URI, "Name": "honda-mapit-mcp-prod",
        "Scopes": [{"ScopeName": "use", "ScopeDescription": "Call the protected production MCP endpoint."}],
        "UserPoolId": POOL,
    }
    client = resources["ProdMcpUserPoolClient"]["Properties"]
    assert client["UserPoolId"] == POOL and client["GenerateSecret"] is False
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["AllowedOAuthFlowsUserPoolClient"] is True
    assert client["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH"]
    assert client["AllowedOAuthScopes"] == [f"{URI}/use"]
    assert client["CallbackURLs"] == [CALLBACK] and client["DefaultRedirectURI"] == CALLBACK
    assert client["AccessTokenValidity"] == client["IdTokenValidity"] == 5
    assert client["RefreshTokenValidity"] == 1 and client["EnableTokenRevocation"] is True
    assert resources["ProdMcpManagedLoginBranding"]["Properties"] == {
        "ClientId": {"Ref": "ProdMcpUserPoolClient"}, "UseCognitoProvidedValues": True,
        "UserPoolId": POOL,
    }
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"][0] == {
        "Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]
    }
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"][1] == {
        "Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-prod-oauth"]
    }
    assert "McpUserPool" not in template["Resources"]
    assert fixed_prod_bootstrap_template() == before


@pytest.mark.parametrize("api_id", ["", "BADAPI0000", "a1b2c3d4e", "a1b2c3d4e5/x"])
def test_prod_oauth_rejects_invalid_api_binding(api_id):
    with pytest.raises(composer.ProdOAuthTemplateError, match="prod_api_id_invalid"):
        composer.build_prod_oauth_template(user_pool_id=POOL, api_id=api_id, callback_url=CALLBACK)


@pytest.mark.parametrize("pool", ["us-east-1_A1b2C3d4E", "eu-west-1_x", "eu-west-1_" + "x" * 65, ""])
def test_prod_oauth_rejects_invalid_persistent_pool(pool):
    with pytest.raises(composer.ProdOAuthTemplateError, match="prod_user_pool_invalid"):
        composer.build_prod_oauth_template(user_pool_id=pool, api_id=API, callback_url=CALLBACK)


@pytest.mark.parametrize("callback", [
    "http://localhost:8785/callback", "http://localhost:8787/callback",
    "https://localhost:8786/callback", "http://example.invalid:8786/callback",
    "http://user@localhost:8786/callback", "http://localhost:8786/callback?token=x",
    "http://localhost:8786/callback#fragment", "http://localhost:8786/callback\\evil",
    "http://localhost:8786/callback\r\nX: y", "http://localhost:8786/*",
])
def test_prod_oauth_rejects_nonexact_loopback_callback(callback):
    with pytest.raises(composer.ProdOAuthTemplateError, match="prod_callback_invalid"):
        composer.build_prod_oauth_template(user_pool_id=POOL, api_id=API, callback_url=callback)


def test_callback_is_preserved_exactly_and_templates_are_fresh():
    first = composer.build_prod_oauth_template(user_pool_id=POOL, api_id=API, callback_url=CALLBACK)
    second = composer.build_prod_oauth_template(user_pool_id=POOL, api_id=API, callback_url=CALLBACK)
    first["Resources"]["ProdMcpUserPoolClient"]["Properties"]["CallbackURLs"].append("bad")
    assert second["Resources"]["ProdMcpUserPoolClient"]["Properties"]["CallbackURLs"] == [CALLBACK]
    assert second["Metadata"]["Readiness"] == "PROD_OAUTH_CLIENT_NOT_DEPLOY_READY"


def test_prod_runtime_template_reuses_closed_bootstrap_and_adds_exact_protected_routes():
    before = fixed_prod_bootstrap_template()
    result = composer.build_prod_runtime_template(
        policy(), bucket="honda-mapit-prod-runtime-artifacts", zip_sha256="a" * 64,
        manifest_sha256="b" * 64,
    )
    resources = result["Resources"]
    assert len(resources) == 11
    assert not any(item["Type"].startswith("AWS::Cognito") for item in resources.values())
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    handler = resources["McpHandler"]["Properties"]
    assert handler["Handler"] == "mapit.aws_prod_entrypoint.handler"
    assert handler["Code"] == {"S3Bucket": "honda-mapit-prod-runtime-artifacts", "S3Key": f"runtime/{'a' * 64}.zip"}
    assert handler["Environment"]["Variables"] == {
        "MAPIT_MCP_ENV": "prod", "MAPIT_PROD_MANIFEST_SHA256": "b" * 64,
    }
    assert "AWS_REGION" not in handler["Environment"]["Variables"]
    assert handler["ReservedConcurrentExecutions"] == 0
    assert resources["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"] == {
        "Issuer": f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL}",
        "Audience": [URI],
    }
    assert resources["McpPostRoute"]["Properties"]["RouteKey"] == "POST /mcp"
    assert resources["McpPostRoute"]["Properties"]["AuthorizationType"] == "JWT"
    assert resources["McpPostRoute"]["Properties"]["AuthorizationScopes"] == [f"{URI}/use"]
    assert resources["McpMetadataRoute"]["Properties"]["RouteKey"] == "GET /.well-known/oauth-protected-resource/mcp"
    assert resources["McpMetadataRoute"]["Properties"]["AuthorizationType"] == "NONE"
    assert resources["McpPostInvokePermission"]["Properties"]["SourceArn"]["Fn::Sub"].endswith("/$default/POST/mcp")
    assert resources["McpMetadataInvokePermission"]["Properties"]["SourceArn"]["Fn::Sub"].endswith(
        "/$default/GET/.well-known/oauth-protected-resource/mcp"
    )
    assert len(resources["McpHandlerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]) == 2
    assert result["Metadata"]["RuntimeActivation"] is False
    assert fixed_prod_bootstrap_template() == before


@pytest.mark.parametrize("kwargs", [
    {"bucket": "xn--honda-bucket", "zip_sha256": "a" * 64, "manifest_sha256": "b" * 64},
    {"bucket": "honda-prod-runtime", "zip_sha256": "A" * 64, "manifest_sha256": "b" * 64},
    {"bucket": "honda-prod-runtime--x-s3", "zip_sha256": "a" * 64, "manifest_sha256": "b" * 64},
])
def test_prod_runtime_rejects_invalid_artifact_binding(kwargs):
    with pytest.raises(composer.ProdOAuthTemplateError):
        composer.build_prod_runtime_template(policy(), **kwargs)


def test_runtime_rejects_nonprod_or_mutated_policy():
    from mapit.aws_dev_runtime import CognitoDevPolicy
    with pytest.raises(composer.ProdOAuthTemplateError, match="prod_policy_invalid"):
        composer.build_prod_runtime_template(
            CognitoDevPolicy(user_pool_id=POOL, api_id=API, client_id=CLIENT, owner_subject=OWNER),
            bucket="honda-mapit-prod-runtime-artifacts", zip_sha256="a" * 64, manifest_sha256="b" * 64,
        )
    altered = policy()
    object.__setattr__(altered, "api_id", "bad")
    with pytest.raises(composer.ProdOAuthTemplateError, match="prod_policy_invalid"):
        composer.build_prod_runtime_template(
            altered, bucket="honda-mapit-prod-runtime-artifacts", zip_sha256="a" * 64,
            manifest_sha256="b" * 64,
        )


def test_generated_templates_are_json_serializable_and_have_no_secrets_or_users():
    oauth = composer.build_prod_oauth_template(user_pool_id=POOL, api_id=API, callback_url=CALLBACK)
    runtime = composer.build_prod_runtime_template(
        policy(), bucket="honda-mapit-prod-runtime-artifacts", zip_sha256="a" * 64, manifest_sha256="b" * 64,
    )
    for template in (oauth, runtime):
        rendered = json.dumps(template)
        assert "Secret" not in rendered or "GenerateSecret" in rendered
        assert "Password" not in rendered
        assert not any(item["Type"] == "AWS::Cognito::UserPool" for item in template["Resources"].values())
