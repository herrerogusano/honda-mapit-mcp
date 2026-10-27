from __future__ import annotations

import json
import re

import pytest

from mapit.multiuser_common import CLAUDE_CALLBACK_URL, MultiuserError
from scripts import build_multiuser_stack as stack

PSEUDO = {"AWS::Region", "AWS::AccountId", "AWS::Partition", "AWS::StackName", "AWS::URLSuffix"}


def _references(value, names: set[str]) -> set[str]:
    found: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key == "Ref" and isinstance(item, str):
                found.add(item)
            elif key == "Fn::GetAtt":
                target = item[0] if isinstance(item, list) else item.split(".")[0]
                found.add(target)
            elif key == "Fn::Sub":
                text = item if isinstance(item, str) else item[0]
                for match in re.findall(r"\$\{([^}!]+)\}", text):
                    found.add(match.split(".")[0])
                if isinstance(item, list):
                    found |= _references(item[1], names)
            else:
                found |= _references(item, names)
    elif isinstance(value, list):
        for item in value:
            found |= _references(item, names)
    return {name for name in found if name in names}


def _graph(template) -> dict[str, set[str]]:
    resources = template["Resources"]
    names = set(resources)
    graph = {}
    for name, resource in resources.items():
        depends = resource.get("DependsOn", [])
        depends = [depends] if isinstance(depends, str) else depends
        graph[name] = _references(resource.get("Properties", {}), names) | set(depends)
    return graph


def _find_cycle(graph):
    state: dict[str, int] = {}

    def visit(node, path):
        state[node] = 1
        for nxt in graph[node]:
            if state.get(nxt) == 1:
                return path + [node, nxt]
            if state.get(nxt) is None:
                found = visit(nxt, path + [node])
                if found:
                    return found
        state[node] = 2
        return None

    for node in graph:
        if node not in state:
            found = visit(node, [])
            if found:
                return found
    return None


@pytest.fixture(params=["dev", "prod"])
def env(request):
    return request.param


def test_cycle_detector_detects_a_real_cycle():
    graph = {"A": {"B"}, "B": {"C"}, "C": {"A"}}
    assert _find_cycle(graph)


def test_naive_client_ids_in_identity_env_would_cycle(env):
    template = stack.build_multiuser_template(env)
    template["Resources"]["IdentityFunction"]["Properties"]["Environment"]["Variables"]["X"] = {"Ref": "ClaudeClient"}
    assert _find_cycle(_graph(template))


def test_no_reference_cycles(env):
    template = stack.build_multiuser_template(env)
    assert _find_cycle(_graph(template)) is None
    graph = _graph(template)
    assert "IdentityFunction" in graph["UserPool"]
    assert not {"ClaudeClient", "CodexClient", "UserPool"} & graph["IdentityFunction"]
    # All references resolve to resources, parameters or pseudo parameters.
    known = set(template["Resources"]) | set(template["Parameters"]) | PSEUDO
    text = json.dumps(template)
    for ref in re.findall(r'"Ref": "([^"]+)"', text):
        assert ref in known
    for sub in re.findall(r"\$\{([^}!]+)\}", text):
        assert sub.split(".")[0] in known


def test_resources_and_core_properties(env):
    template = stack.build_multiuser_template(env)
    resources = template["Resources"]
    expected = {
        "UserPool", "UserPoolDomain", "ResourceServer", "ClaudeClient", "CodexClient",
        "ClaudeManagedLoginBranding", "CodexManagedLoginBranding", "IdentityCognitoInvokePermission",
        "InvitationsTable", "PublicConfigParameter", "HttpApi", "HttpApiStage", "JwtAuthorizer",
        "McpIntegration", "IdentityIntegration", "McpPostRoute", "McpMetadataRoute",
        "InvitationGetRoute", "InvitationPostRoute", "PrivacyGetRoute", "McpPostInvokePermission",
        "McpMetadataInvokePermission", "IdentityInvitationInvokePermission",
        "IdentityPrivacyInvokePermission", "McpLogGroup", "IdentityLogGroup", "IdentityRole",
        "McpRole", "McpFunction", "IdentityFunction",
    }
    assert set(resources) == expected | ({"Budget"} if env == "prod" else set())
    assert all(item["Condition"] == "SupportedDeployment" for item in resources.values())
    pool = resources["UserPool"]["Properties"]
    assert pool["UsernameAttributes"] == ["email"]
    assert pool["UsernameConfiguration"] == {"CaseSensitive": False}
    assert pool["AdminCreateUserConfig"] == {"AllowAdminCreateUserOnly": True}
    assert pool["UserPoolTier"] == "ESSENTIALS"
    assert pool["Policies"]["PasswordPolicy"] == {
        "MinimumLength": 6, "RequireUppercase": False, "RequireLowercase": False, "RequireNumbers": False,
        "RequireSymbols": False, "TemporaryPasswordValidityDays": 1}
    assert pool["MfaConfiguration"] == "OPTIONAL" and pool["EnabledMfas"] == ["SOFTWARE_TOKEN_MFA"]
    assert pool["Schema"][0]["Name"] == "tenant_id" and pool["Schema"][0]["Mutable"] is False
    assert pool["AccountRecoverySetting"] == {"RecoveryMechanisms": [{"Name": "admin_only", "Priority": 1}]}
    assert pool["DeletionProtection"] == ("ACTIVE" if env == "prod" else "INACTIVE")
    assert pool["LambdaConfig"]["PreTokenGenerationConfig"]["LambdaVersion"] == "V2_0"
    assert resources["UserPoolDomain"]["Properties"]["ManagedLoginVersion"] == 2
    assert resources["ResourceServer"]["Properties"]["Identifier"] == {
        "Fn::Sub": "https://${HttpApi}.execute-api.${AWS::Region}.amazonaws.com/mcp"}
    claude_urls = [CLAUDE_CALLBACK_URL, "https://claude.com/api/mcp/auth_callback",
                   "http://localhost:8790/callback"]
    for name, callbacks in (("ClaudeClient", claude_urls), ("CodexClient", [{"Ref": "CodexCallbackUrl"}])):
        client = resources[name]["Properties"]
        assert client["CallbackURLs"] == callbacks
        assert client["GenerateSecret"] is False and client["AllowedOAuthFlows"] == ["code"]
        assert client["AllowedOAuthScopes"][0] == "openid"
        assert client["AllowedOAuthScopes"][1]["Fn::Sub"].endswith("/mcp/use")
        assert client["ExplicitAuthFlows"] == ["ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_USER_PASSWORD_AUTH"]
        assert (client["AccessTokenValidity"], client["IdTokenValidity"], client["RefreshTokenValidity"]) == (60, 60, 30)
        assert client["EnableTokenRevocation"] is True and client["PreventUserExistenceErrors"] == "ENABLED"
        assert client["WriteAttributes"] == ["locale"]
        assert "custom:tenant_id" in client["ReadAttributes"]
    for name in ("ClaudeManagedLoginBranding", "CodexManagedLoginBranding"):
        assert resources[name]["Properties"]["UseCognitoProvidedValues"] is True
    table = resources["InvitationsTable"]["Properties"]
    assert table["KeySchema"] == [{"AttributeName": "email", "KeyType": "HASH"}]
    assert table["BillingMode"] == "PAY_PER_REQUEST"
    assert table["DeletionProtectionEnabled"] is (env == "prod")
    assert "SSESpecification" not in table
    stage = resources["HttpApiStage"]["Properties"]
    assert stage["StageName"] == "$default" and stage["AutoDeploy"] is True
    assert stage["DefaultRouteSettings"]["ThrottlingRateLimit"] == 10
    assert stage["DefaultRouteSettings"]["ThrottlingBurstLimit"] == 20
    jwt = resources["JwtAuthorizer"]["Properties"]["JwtConfiguration"]
    assert jwt["Issuer"] == {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${UserPool}"}
    routes = {item["Properties"]["RouteKey"]: item["Properties"] for item in resources.values()
              if item["Type"] == "AWS::ApiGatewayV2::Route"}
    assert set(routes) == {"POST /mcp", "GET /.well-known/oauth-protected-resource/mcp",
                           "GET /invitacion", "POST /invitacion", "GET /privacidad"}
    assert routes["POST /mcp"]["AuthorizationType"] == "JWT"
    assert all(routes[key]["AuthorizationType"] == "NONE" for key in routes if key != "POST /mcp")


def test_functions_and_environment(env):
    resources = stack.build_multiuser_template(env)["Resources"]
    mcp = resources["McpFunction"]["Properties"]
    identity = resources["IdentityFunction"]["Properties"]
    for function, handler, timeout in ((mcp, stack.MCP_HANDLER, 20), (identity, stack.IDENTITY_HANDLER, 5)):
        assert function["Runtime"] == "python3.13" and function["Architectures"] == ["arm64"]
        assert function["Handler"] == handler and function["Timeout"] == timeout and function["MemorySize"] == 512
        assert function["Code"]["S3Bucket"] == {"Fn::ImportValue": f"honda-mapit-mcp-{env}-multiuser-artifacts-bucket"}
        assert function["Code"]["S3Key"] == {"Ref": "ArtifactKey"}
        assert "ReservedConcurrentExecutions" not in function
    assert set(mcp["Environment"]["Variables"]) == {
        "MAPIT_MCP_ENV", "MULTIUSER_ISSUER_URL", "MULTIUSER_RESOURCE_URL", "MULTIUSER_CLIENT_IDS",
        "MULTIUSER_USER_POOL_ID", "MULTIUSER_TABLE", "MAPIT_CONFIG_JSON", "MULTIUSER_GEOGRAPHY"}
    assert set(identity["Environment"]["Variables"]) == {
        "MAPIT_MCP_ENV", "MULTIUSER_TABLE", "MAPIT_CONFIG_JSON", "MULTIUSER_RESOURCE_URL",
        "MULTIUSER_PUBLIC_CONFIG_PARAMETER", "MULTIUSER_CODEX_CALLBACK_PORT", "MULTIUSER_PRIVACY_CONTACT"}
    assert identity["Environment"]["Variables"]["MULTIUSER_PUBLIC_CONFIG_PARAMETER"] == \
        f"/honda-mapit-mcp/{env}/multiuser/public-config"
    parameter = resources["PublicConfigParameter"]["Properties"]
    assert parameter["Type"] == "String"
    rendered = parameter["Value"]["Fn::Sub"].replace("${HttpApi}", "a1b2c3d4e5").replace(
        "${AWS::Region}", "eu-west-1").replace("${ClaudeClient}", "c1").replace(
        "${CodexClient}", "c2").replace("${CodexCallbackPort}", "1455")
    assert json.loads(rendered) == {
        "resource_url": "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com/mcp",
        "claude_client_id": "c1", "codex_client_id": "c2", "codex_callback_port": 1455}


def _statements(resources, role):
    return resources[role]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def _actions(statements):
    result = []
    for statement in statements:
        action = statement["Action"]
        result.extend(action if isinstance(action, list) else [action])
    return set(result)


def test_iam_least_privilege(env):
    resources = stack.build_multiuser_template(env)["Resources"]
    identity = _statements(resources, "IdentityRole")
    mcp = _statements(resources, "McpRole")
    assert _actions(identity) == {"dynamodb:GetItem", "dynamodb:UpdateItem", "ssm:PutParameter",
                                  "ssm:GetParameter", "kms:Encrypt", "logs:CreateLogStream", "logs:PutLogEvents"}
    assert _actions(mcp) == {"ssm:GetParameter", "ssm:DeleteParameter", "kms:Decrypt", "dynamodb:Scan", "dynamodb:UpdateItem",
                             "dynamodb:DeleteItem", "cognito-idp:AdminDeleteUser",
                             "logs:CreateLogStream", "logs:PutLogEvents"}
    users = f"parameter/honda-mapit-mcp/{env}/users/*"
    for statements in (identity, mcp):
        for statement in statements:
            assert statement["Effect"] == "Allow"
            resource = json.dumps(statement["Resource"])
            assert resource != '"*"'
            actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
            if any(a in ("ssm:PutParameter", "ssm:DeleteParameter") for a in actions):
                assert resource.endswith(users + '"}')
            if any(a.startswith("kms:") for a in actions):
                assert statement["Condition"]["StringEquals"]["kms:ViaService"] == "ssm.eu-west-1.amazonaws.com"
                assert statement["Condition"]["ForAnyValue:StringEquals"]["kms:ResourceAliases"] == "alias/aws/ssm"
            if any(a.startswith("dynamodb:") for a in actions):
                assert statement["Resource"] == {"Fn::GetAtt": ["InvitationsTable", "Arn"]}
            if any(a.startswith("cognito-idp:") for a in actions):
                assert statement["Resource"] == {"Fn::GetAtt": ["UserPool", "Arn"]}
            if any(a.startswith("logs:") for a in actions):
                assert f"/aws/lambda/honda-mapit-mcp-{env}-" in resource
    public_read = [s for s in identity if s["Action"] == "ssm:GetParameter"][0]
    assert public_read["Resource"]["Fn::Sub"].endswith(f"parameter/honda-mapit-mcp/{env}/multiuser/public-config")
    cognito = resources["IdentityCognitoInvokePermission"]["Properties"]
    assert cognito["Principal"] == "cognito-idp.amazonaws.com"
    assert cognito["SourceArn"] == {"Fn::GetAtt": ["UserPool", "Arn"]}
    for name in ("McpLogGroup", "IdentityLogGroup"):
        assert resources[name]["Properties"]["RetentionInDays"] == 14


def test_parameters_no_echo_and_no_defaults_with_private_data(env):
    params = stack.build_multiuser_template(env)["Parameters"]
    expected = {"ArtifactKey", "DomainPrefix", "CodexCallbackUrl", "CodexCallbackPort",
                "MapitConfigJson", "PrivacyContact", "Geography"}
    assert set(params) == expected | ({"BudgetEmail"} if env == "prod" else set())
    assert params["MapitConfigJson"]["NoEcho"] is True
    assert params["PrivacyContact"]["NoEcho"] is True
    if env == "prod":
        assert params["BudgetEmail"]["NoEcho"] is True
    assert all("Default" not in value for key, value in params.items() if key != "Geography")
    assert params["Geography"]["AllowedValues"] == ["0", "1"]
    pattern = re.compile(params["CodexCallbackUrl"]["AllowedPattern"])
    assert pattern.fullmatch("http://localhost:1455/auth/callback")
    assert pattern.fullmatch("http://127.0.0.1:8786/mcp/oauth/callback/x")
    for bad in ("https://localhost:1455/cb", "http://example.com:1455/cb", "http://localhost/cb",
                "http://localhost:1455/cb?x=1", "http://127.0.0.2:1455/cb"):
        assert not pattern.fullmatch(bad)


def test_budget_only_in_prod():
    prod = stack.build_multiuser_template("prod")["Resources"]["Budget"]["Properties"]
    assert prod["Budget"]["BudgetLimit"] == {"Amount": 5, "Unit": "USD"}
    assert "account-wide" in prod["Budget"]["BudgetName"] and "CostFilters" not in prod["Budget"]
    assert prod["Budget"]["TimeUnit"] == "MONTHLY" and prod["Budget"]["BudgetType"] == "COST"
    notes = [(n["Notification"]["NotificationType"], n["Notification"]["Threshold"])
             for n in prod["NotificationsWithSubscribers"]]
    assert notes == [("ACTUAL", 80), ("FORECASTED", 100)]
    assert all(n["Subscribers"] == [{"SubscriptionType": "EMAIL", "Address": {"Ref": "BudgetEmail"}}]
               for n in prod["NotificationsWithSubscribers"])
    assert "Budget" not in stack.build_multiuser_template("dev")["Resources"]


def test_outputs(env):
    outputs = stack.build_multiuser_template(env)["Outputs"]
    assert set(outputs) == {"McpUrl", "ApiBaseUrl", "UserPoolId", "ClaudeClientId", "CodexClientId",
                            "IssuerUrl", "TableName", "LoginDomain"}


def test_artifacts_template(env):
    template = stack.build_artifacts_template(env)
    bucket = template["Resources"]["ArtifactBucket"]["Properties"]
    assert all(bucket["PublicAccessBlockConfiguration"].values())
    assert bucket["BucketEncryption"]["ServerSideEncryptionConfiguration"][0][
        "ServerSideEncryptionByDefault"] == {"SSEAlgorithm": "AES256"}
    assert bucket["VersioningConfiguration"] == {"Status": "Enabled"}
    assert bucket["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
    statement = template["Resources"]["ArtifactBucketPolicy"]["Properties"]["PolicyDocument"]["Statement"][0]
    assert statement["Effect"] == "Deny" and statement["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert template["Outputs"]["BucketName"]["Export"]["Name"] == stack.artifacts_export_name(env)


def test_templates_are_json_serializable_and_env_validated():
    for env in ("dev", "prod"):
        json.dumps(stack.build_multiuser_template(env))
        json.dumps(stack.build_artifacts_template(env))
    with pytest.raises(MultiuserError):
        stack.build_multiuser_template("staging")
    with pytest.raises(MultiuserError):
        stack.build_artifacts_template("staging")
