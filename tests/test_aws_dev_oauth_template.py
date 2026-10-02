from __future__ import annotations

import copy
from pathlib import Path

import pytest

from mapit.aws_dev_runtime import cognito_dev_policy
from scripts import build_aws_dev_oauth_template as composer
from scripts.build_aws_dev_bootstrap import _read_scaffold
from scripts.build_aws_dev_runtime_template import fixed_runtime_candidate_template


POOL = "eu-west-1_AbCdEf123"
API = "abc123def4"
CLIENT = "syntheticclient123"
OWNER = "00000000-0000-4000-8000-000000000001"
BUCKET = "honda-runtime-artifact-test-bucket"
ZIP_HASH = "1" * 64
JWKS_HASH = "2" * 64
CALLBACK = "http://localhost:39031/callback/synthetic-client"
START = 1_800_000_000
END = START + 300


def _policy():
    return cognito_dev_policy(user_pool_id=POOL, api_id=API, client_id=CLIENT, owner_subject=OWNER)


def _build(**overrides):
    values = {
        "policy": _policy(),
        "bucket": BUCKET,
        "zip_sha256": ZIP_HASH,
        "jwks_sha256": JWKS_HASH,
        "callback_url": CALLBACK,
        "execution_start": START,
        "execution_end": END,
    }
    values.update(overrides)
    policy = values.pop("policy")
    return composer.build_dev_oauth_template(policy, **values)


def test_builds_closed_dev_oauth_runtime_composition():
    template = _build()
    resources = template["Resources"]
    assert len(resources) == 16
    assert all(item["Condition"] == "SupportedDeployment" for item in resources.values())
    assert all(item["DeletionPolicy"] == item["UpdateReplacePolicy"] == "Delete" for item in resources.values())
    assert template["Parameters"]["EnvironmentName"]["AllowedValues"] == ["dev"]
    assert template["Parameters"]["McpResourceUri"]["AllowedValues"] == [f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"]
    assert template["Parameters"]["OAuthCallbackURL"]["AllowedValues"] == [CALLBACK]

    api = resources["McpApi"]["Properties"]
    handler = resources["McpHandler"]["Properties"]
    original_candidate = fixed_runtime_candidate_template(BUCKET, ZIP_HASH)
    assert api["DisableExecuteApiEndpoint"] is True
    assert type(handler["ReservedConcurrentExecutions"]) is int and handler["ReservedConcurrentExecutions"] == 0
    assert handler["Handler"] == "mapit.aws_dev_entrypoint.handler"
    assert handler["Code"] == {"S3Bucket": BUCKET, "S3Key": f"runtime/{ZIP_HASH}.zip"}
    assert handler["Role"] == {"Fn::GetAtt": ["McpHandlerRole", "Arn"]}
    assert resources["McpHandlerRole"] == original_candidate["Resources"]["McpHandlerRole"]
    assert resources["McpHandlerLogGroup"] == original_candidate["Resources"]["McpHandlerLogGroup"]
    role_text = repr(resources["McpHandlerRole"])
    assert "s3:" not in role_text.lower()
    assert handler["Environment"]["Variables"] == {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_COGNITO_USER_POOL_ID": POOL,
        "MAPIT_API_ID": API,
        "MAPIT_COGNITO_CLIENT_ID": CLIENT,
        "MAPIT_OWNER_SUBJECT": OWNER,
        "MAPIT_COGNITO_JWKS_SHA256": JWKS_HASH,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(START),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(END),
    }
    assert "AWS_REGION" not in handler["Environment"]["Variables"]
    assert resources["McpUserPoolClient"]["Properties"]["GenerateSecret"] is False
    assert resources["McpUserPoolClient"]["Properties"]["AllowedOAuthFlows"] == ["code"]
    assert resources["McpUserPoolClient"]["Properties"]["AllowedOAuthScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    assert resources["McpUserPool"]["Properties"]["MfaConfiguration"] == "ON"
    assert resources["McpUserPool"]["Properties"]["EnabledMfas"] == ["SOFTWARE_TOKEN_MFA"]
    assert "McpUserPoolUser" not in resources
    assert all(item["Type"] != "AWS::Cognito::UserPoolUser" for item in resources.values())

    post = resources["McpPostRoute"]["Properties"]
    get = resources["McpProtectedResourceMetadataRoute"]["Properties"]
    assert post["RouteKey"] == "POST /mcp" and post["AuthorizationType"] == "JWT"
    assert post["AuthorizationScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    assert get["RouteKey"] == "GET /.well-known/oauth-protected-resource/mcp"
    assert get["AuthorizationType"] == "NONE"
    assert get["Target"] == post["Target"]
    assert resources["McpLambdaInvokePermission"]["Properties"]["SourceArn"]["Fn::Sub"].endswith("/$default/POST/mcp")
    assert resources["McpProtectedResourceMetadataInvokePermission"]["Properties"]["SourceArn"]["Fn::Sub"].endswith(
        "/$default/GET/.well-known/oauth-protected-resource/mcp"
    )
    assert template["Outputs"]["McpClientId"] == {
        "Condition": "SupportedDeployment",
        "Value": {"Ref": "McpUserPoolClient"},
    }
    assert template["Metadata"]["Readiness"] == "OAUTH_RUNTIME_COMPOSITION_NOT_DEPLOY_READY"
    assert template["Metadata"]["ObservedIdentifierReadbackRequired"] is True
    assert template["Metadata"]["OwnerBindingConfirmationRequired"] is True
    assert template["Metadata"]["EffectiveCallbackConfirmationRequired"] is True
    assert template["Metadata"]["ScopedCleanupReviewRequired"] is True
    assert template["Metadata"]["RuntimeArtifactRetirementRequired"] is True


@pytest.mark.parametrize("callback", [
    "https://localhost:39031/callback",
    "http://example.com:39031/callback",
    "http://localhost/callback",
    "http://localhost:80/callback",
    "http://localhost:65536/callback",
    "http://user@localhost:39031/callback",
    "http://localhost:39031/callback?code=secret",
    "http://localhost:39031/callback#fragment",
    "http://localhost:39031/callback\\path",
    "http://localhost:39031/callback/*",
    "http://localhost:39031/callback path",
    "http://LOCALHOST:39031/callback",
    "http://[::1]/callback",
    "http://localhost:39031",
    "http://localhost:39031/callback\r\nX: y",
    "http://localhost:39031/" + "a" * 1024,
])
def test_invalid_callback_fails_closed(callback):
    with pytest.raises(composer.OAuthTemplateError, match="oauth_callback_invalid"):
        _build(callback_url=callback)


@pytest.mark.parametrize("callback", [
    "http://localhost:39031/callback",
    "http://127.0.0.1:45454/oauth/callback",
    "http://[::1]:60000/cb",
])
def test_exact_valid_loopback_callback_is_preserved(callback):
    template = _build(callback_url=callback)
    assert template["Parameters"]["OAuthCallbackURL"]["Default"] == callback


@pytest.mark.parametrize("start,end", [
    (True, START + 1),
    (START, False),
    (0, 1),
    (-1, 1),
    (START, START),
    (START, START + 301),
    (START + 5, START + 4),
])
def test_invalid_execution_windows_rejected(start, end):
    with pytest.raises(composer.OAuthTemplateError, match="oauth_execution_window_invalid"):
        _build(execution_start=start, execution_end=end)


@pytest.mark.parametrize("name,value", [
    ("zip_sha256", "A" * 64),
    ("zip_sha256", "g" * 64),
    ("jwks_sha256", "A" * 64),
    ("jwks_sha256", "f" * 63),
])
def test_hash_inputs_are_strict_and_jwks_is_separate(name, value):
    with pytest.raises(composer.OAuthTemplateError):
        _build(**{name: value})


@pytest.mark.parametrize("policy", [None, "not-a-policy"])
def test_policy_must_be_exact_validated_cognito_policy(policy):
    with pytest.raises(composer.OAuthTemplateError, match="oauth_policy_invalid"):
        _build(policy=policy)


def test_original_and_runtime_scaffolds_are_not_mutated():
    source_before = copy.deepcopy(_read_scaffold())
    candidate_before = fixed_runtime_candidate_template(BUCKET, ZIP_HASH)
    candidate_snapshot = copy.deepcopy(candidate_before)
    template = _build()
    template["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]["MAPIT_MCP_ENV"] = "changed"
    assert _read_scaffold() == source_before
    assert fixed_runtime_candidate_template(BUCKET, ZIP_HASH) == candidate_snapshot


def test_changed_client_scope_in_fixed_source_scaffold_rejected(monkeypatch: pytest.MonkeyPatch):
    scaffold = copy.deepcopy(_read_scaffold())
    scaffold["Resources"]["McpUserPoolClient"]["Properties"]["AllowedOAuthFlows"] = ["implicit"]
    monkeypatch.setattr(composer, "_read_scaffold", lambda: scaffold)
    with pytest.raises(composer.OAuthTemplateError, match="oauth_client_invalid"):
        _build()


def test_changed_post_auth_scope_in_fixed_source_scaffold_rejected(monkeypatch: pytest.MonkeyPatch):
    scaffold = copy.deepcopy(_read_scaffold())
    scaffold["Resources"]["McpPostRoute"]["Properties"]["AuthorizationScopes"] = []
    monkeypatch.setattr(composer, "_read_scaffold", lambda: scaffold)
    with pytest.raises(composer.OAuthTemplateError, match="oauth_post_route_invalid"):
        _build()


def test_changed_pool_mfa_in_fixed_source_scaffold_rejected(monkeypatch: pytest.MonkeyPatch):
    scaffold = copy.deepcopy(_read_scaffold())
    scaffold["Resources"]["McpUserPool"]["Properties"]["MfaConfiguration"] = "OFF"
    monkeypatch.setattr(composer, "_read_scaffold", lambda: scaffold)
    with pytest.raises(composer.OAuthTemplateError, match="oauth_pool_policy_invalid"):
        _build()


@pytest.mark.parametrize(("resource", "property_name", "value"), [
    ("McpUserPoolDomain", "CustomDomainConfig", {"CertificateArn": "synthetic"}),
    ("McpUserPoolClient", "AnalyticsConfiguration", {"ApplicationId": "synthetic"}),
])
def test_unreviewed_oauth_resource_properties_rejected(monkeypatch: pytest.MonkeyPatch, resource, property_name, value):
    scaffold = copy.deepcopy(_read_scaffold())
    scaffold["Resources"][resource]["Properties"][property_name] = value
    monkeypatch.setattr(composer, "_read_scaffold", lambda: scaffold)
    with pytest.raises(composer.OAuthTemplateError, match="oauth_scaffold_invalid"):
        _build()
