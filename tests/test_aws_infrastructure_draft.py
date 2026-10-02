"""Offline structural checks for the explicitly non-deployable Phase 8 draft."""

import ast
import json
from pathlib import Path


TEMPLATE_PATH = Path(__file__).parents[1] / "infra" / "aws" / "template.json"


def template():
    return json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))


def resources_by_type(document, resource_type):
    return {
        name: resource
        for name, resource in document["Resources"].items()
        if resource["Type"] == resource_type
    }


def test_template_is_explicitly_offline_draft_with_environment_and_placeholders():
    document = template()
    assert document["Metadata"]["Readiness"] == "DRAFT_NOT_DEPLOY_READY"
    assert document["Metadata"]["NoRuntimeImplementation"] is True
    assert document["Parameters"]["EnvironmentName"]["Default"] == "dev"
    assert document["Parameters"]["EnvironmentName"]["AllowedValues"] == ["dev", "prod"]
    assert document["Parameters"]["McpResourceUri"]["Default"] == "https://mcp-dev.example.invalid/mcp"
    callback = document["Parameters"]["OAuthCallbackURL"]["Default"]
    assert callback == "http://localhost:39031/callback/REPLACE_WITH_ACTUAL_CLIENT_CALLBACK"
    assert "Not deploy-ready" in document["Description"]
    assert "Enable" not in document["Parameters"]


def test_environment_namespaces_and_stack_specific_cognito_domain():
    document = template()
    resources = document["Resources"]
    for resource_name in ("McpApi", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"):
        name = resources[resource_name]["Properties"].get("Name")
        if name is None:
            name = resources[resource_name]["Properties"].get("RoleName")
        if name is None:
            name = resources[resource_name]["Properties"].get("LogGroupName")
        if name is None:
            name = resources[resource_name]["Properties"].get("FunctionName")
        assert "${EnvironmentName}" in name["Fn::Sub"]
        assert "honda-mapit-mcp" in name["Fn::Sub"]
    domain = resources["McpUserPoolDomain"]["Properties"]["Domain"]["Fn::Sub"]
    assert "${EnvironmentName}" in domain and "${AWS::StackName}" in domain
    assert "at most 63 characters" in document["Metadata"]["UserPoolDomainConstraint"]
    dev = "honda-mapit-mcp-${EnvironmentName}-api".replace("${EnvironmentName}", "dev")
    prod = "honda-mapit-mcp-${EnvironmentName}-api".replace("${EnvironmentName}", "prod")
    assert dev != prod


def test_cognito_is_admin_created_code_only_and_bound_to_one_resource_scope():
    document = template()
    resources = document["Resources"]
    pool = resources["McpUserPool"]["Properties"]
    assert pool["UserPoolTier"] == "ESSENTIALS"
    assert pool["AdminCreateUserConfig"]["AllowAdminCreateUserOnly"] is True
    assert pool["MfaConfiguration"] == "ON"
    assert pool["EnabledMfas"] == ["SOFTWARE_TOKEN_MFA"]
    assert "SoftwareTokenMfaConfiguration" not in pool
    assert "InviteMessageTemplate" not in pool
    assert "EmailConfiguration" not in pool
    assert "VerificationMessageTemplate" not in pool
    assert not resources_by_type(document, "AWS::Cognito::UserPoolUser")

    client = resources["McpUserPoolClient"]["Properties"]
    assert client["GenerateSecret"] is False
    assert client["AllowedOAuthFlowsUserPoolClient"] is True
    assert client["AllowedOAuthFlows"] == ["code"]
    assert client["AllowedOAuthScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    assert client["SupportedIdentityProviders"] == ["COGNITO"]
    assert client["CallbackURLs"] == [{"Ref": "OAuthCallbackURL"}]

    resource_server = resources["McpResourceServer"]["Properties"]
    assert resource_server["Identifier"] == {"Ref": "McpResourceUri"}
    assert resource_server["Scopes"] == [{"ScopeName": "use", "ScopeDescription": "Call the protected MCP endpoint."}]
    branding = resources["McpManagedLoginBranding"]["Properties"]
    assert branding["UseCognitoProvidedValues"] is True


def test_api_and_lambda_are_closed_by_default_and_only_protect_post_mcp():
    document = template()
    resources = document["Resources"]
    api = resources["McpApi"]["Properties"]
    assert api["ProtocolType"] == "HTTP"
    assert api["DisableExecuteApiEndpoint"] is True
    assert api["Tags"] == {
        "Project": "honda-mapit-mcp", "Environment": {"Ref": "EnvironmentName"},
    }
    assert "Tags" not in resources["McpApiStage"]["Properties"]
    assert "without claiming stage inheritance" in document["Metadata"]["StageTagPolicy"]
    routes = resources_by_type(document, "AWS::ApiGatewayV2::Route")
    assert len(routes) == 1
    route = next(iter(routes.values()))["Properties"]
    assert route["RouteKey"] == "POST /mcp"
    assert route["AuthorizationType"] == "JWT"
    assert route["AuthorizationScopes"] == [{"Fn::Sub": "${McpResourceUri}/use"}]
    authorizer = resources["McpJwtAuthorizer"]["Properties"]
    jwt = authorizer["JwtConfiguration"]
    assert jwt["Audience"] == [{"Ref": "McpResourceUri"}]
    assert jwt["Issuer"] == {"Fn::Sub": "https://cognito-idp.${AWS::Region}.amazonaws.com/${McpUserPool}"}
    assert resources["McpApiStage"]["Properties"]["DefaultRouteSettings"] == {
        "ThrottlingRateLimit": 1,
        "ThrottlingBurstLimit": 1,
        "DetailedMetricsEnabled": False,
    }
    assert "AccessLogSettings" not in resources["McpApiStage"]["Properties"]

    function = resources["McpHandler"]["Properties"]
    assert function["Architectures"] == ["arm64"]
    assert function["Runtime"] == "python3.13"
    assert function["MemorySize"] == 256 and function["Timeout"] == 20
    assert function["ReservedConcurrentExecutions"] == 0
    permission = resources["McpLambdaInvokePermission"]["Properties"]
    assert permission["Principal"] == "apigateway.amazonaws.com"
    source_arn = permission["SourceArn"]["Fn::Sub"]
    assert source_arn.endswith("/$default/POST/mcp")
    assert "*" not in source_arn


def test_handler_is_a_synthetic_constant_503_and_never_logs_or_echoes_event():
    code = template()["Resources"]["McpHandler"]["Properties"]["Code"]["ZipFile"]
    ast.parse(code)
    namespace = {}
    exec(compile(code, "<offline-cfn-inline-handler>", "exec"), namespace)
    response = namespace["handler"]({"headers": {"authorization": "not-for-logs"}, "body": "private"}, None)
    assert response == {
        "statusCode": 503,
        "headers": {"content-type": "application/json", "cache-control": "no-store"},
        "body": '{"error":"service_unavailable"}',
    }
    assert "print(" not in code and "authorization" not in code.lower() and "event." not in code


def test_role_is_limited_to_owned_logs_and_has_short_retention():
    document = template()
    resources = document["Resources"]
    role = resources["McpHandlerRole"]["Properties"]
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(statements) == 1
    assert statements[0]["Action"] == ["logs:CreateLogStream", "logs:PutLogEvents"]
    assert ":log-group:/aws/lambda/honda-mapit-mcp-${EnvironmentName}-handler:*" in statements[0]["Resource"]["Fn::Sub"]
    assert resources["McpHandlerLogGroup"]["Properties"]["RetentionInDays"] == 7
    assert "DeletionPolicy" in resources["McpHandlerLogGroup"]


def test_no_secret_parameter_or_paid_runtime_resource_is_created():
    document = template()
    resource_types = {resource["Type"] for resource in document["Resources"].values()}
    forbidden = {
        "AWS::SSM::Parameter",
        "AWS::KMS::Key",
        "AWS::Bedrock::Agent",
        "AWS::ECS::Cluster",
        "AWS::NATGateway",
        "AWS::S3::Bucket",
        "AWS::Budgets::Budget",
        "AWS::Cognito::UserPoolUser",
    }
    assert resource_types.isdisjoint(forbidden)
    assert document["Outputs"]["ExpectedSessionParameterName"]["Value"] == {
        "Fn::Sub": "honda-mapit-mcp/${EnvironmentName}/mapit-session"
    }
    assert document["Metadata"]["ExpectedSessionParameterName"] == "honda-mapit-mcp/{EnvironmentName}/mapit-session"
    assert document["Metadata"]["NoSecretValuesOrResources"] is True
