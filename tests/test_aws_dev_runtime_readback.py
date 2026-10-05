from __future__ import annotations

import base64
import json

from mapit.aws_dev_runtime import CognitoDevPolicy
from scripts.aws_dev_runtime_readback import check_dev_runtime_readback
from scripts.build_aws_dev_oauth_template import build_dev_oauth_template
from scripts.build_aws_shared_identity_dev import build_shared_identity_dev_template

ACCOUNT = "123456789012"
API = "abcdefghij"
POOL = "eu-west-1_Abcdefghi"
CLIENT = "SyntheticClient123"
CALLBACK = "http://localhost:39031/callback"
STACK_UUID = "22222222-2222-4222-8222-222222222222"
RUN = "11111111-1111-4111-8111-111111111111"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev/{STACK_UUID}"
ZIP_SHA = "a" * 64
JWKS_SHA = "b" * 64
FUNC_ARN = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-handler"
POST_ARN = f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:{API}/$default/POST/mcp"
META_ARN = f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:{API}/$default/GET/.well-known/oauth-protected-resource/mcp"


def ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def fixture(*, shared_identity=False):
    policy = CognitoDevPolicy(POOL, API, CLIENT, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
    runtime_kwargs = dict(
        bucket="honda-mapit-dev-artifact", zip_sha256=ZIP_SHA, jwks_sha256=JWKS_SHA,
        callback_url=CALLBACK, execution_start=1_798_000_000, execution_end=1_798_000_300,
    )
    template = (
        build_shared_identity_dev_template(policy, **runtime_kwargs)
        if shared_identity else build_dev_oauth_template(policy, **runtime_kwargs)
    )
    state = {
        "account_id": ACCOUNT, "region": "eu-west-1", "run_id": RUN,
        "app_stack_id": STACK, "stack_uuid": STACK_UUID, "api_id": API,
        "user_pool_id": POOL, "oauth_setup_client_id": CLIENT, "oauth_setup_verified": True,
        "oauth_setup_callback_url": CALLBACK,
    }
    names = {
        "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
        "McpUserPool": "AWS::Cognito::UserPool", "McpHandlerRole": "AWS::IAM::Role",
        "McpHandlerLogGroup": "AWS::Logs::LogGroup", "McpHandler": "AWS::Lambda::Function",
        "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain", "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
        "McpUserPoolClient": "AWS::Cognito::UserPoolClient", "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
        "McpJwtAuthorizer": "AWS::ApiGatewayV2::Authorizer", "McpLambdaIntegration": "AWS::ApiGatewayV2::Integration",
        "McpPostRoute": "AWS::ApiGatewayV2::Route", "McpLambdaInvokePermission": "AWS::Lambda::Permission",
        "McpProtectedResourceMetadataRoute": "AWS::ApiGatewayV2::Route",
        "McpProtectedResourceMetadataInvokePermission": "AWS::Lambda::Permission",
    }
    if shared_identity:
        names.pop("McpUserPool")
        names.pop("McpUserPoolDomain")
    physical = {name: f"physical-{name}" for name in names}
    physical.update({"McpApi": API, "McpUserPool": POOL, "McpUserPoolClient": CLIENT,
                     "McpHandler": "honda-mapit-mcp-dev-handler", "McpJwtAuthorizer": "auth123",
                     "McpHandlerRole": "honda-mapit-mcp-dev-handler-role",
                     "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-handler",
                     "McpLambdaIntegration": "int123", "McpPostRoute": "post123",
                     "McpProtectedResourceMetadataRoute": "meta123"})
    cfn = Cfn({
        "describe_stacks": ok(Stacks=[{"StackId": STACK, "StackName": "honda-mapit-mcp-dev",
            "StackStatus": "UPDATE_COMPLETE", "RoleARN": None,
            "Tags": [{"Key": "ClosedRehearsalRunId", "Value": RUN}],
            "Outputs": [{"OutputKey": "ApiId", "OutputValue": API},
                        {"OutputKey": "UserPoolId", "OutputValue": POOL},
                        {"OutputKey": "McpClientId", "OutputValue": CLIENT}]}]),
        "describe_stack_resources": ok(StackResources=[{"LogicalResourceId": n, "ResourceType": t,
            "ResourceStatus": "UPDATE_COMPLETE", "PhysicalResourceId": physical[n]} for n, t in names.items()]),
        "get_template": ok(TemplateBody=json.dumps(template)),
    })
    resource_uri = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"
    authorizer = Api({"get_api": ok(ApiId=API, Name="honda-mapit-mcp-dev-api", DisableExecuteApiEndpoint=True),
        "get_authorizers": ok(Items=[{"AuthorizerId": "auth123", "AuthorizerType": "JWT",
            "IdentitySource": ["$request.header.Authorization"], "JwtConfiguration": {
                "Issuer": f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL}", "Audience": [resource_uri]}}]),
        "get_integrations": ok(Items=[{"IntegrationId": "int123", "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST", "PayloadFormatVersion": "2.0", "TimeoutInMillis": 20000,
            "IntegrationUri": f"arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/{FUNC_ARN}/invocations"}]),
        "get_routes": ok(Items=[{"RouteId": "post123", "RouteKey": "POST /mcp", "AuthorizationType": "JWT",
            "AuthorizerId": "auth123", "AuthorizationScopes": [resource_uri + "/use"], "Target": "integrations/int123"},
            {"RouteId": "meta123", "RouteKey": "GET /.well-known/oauth-protected-resource/mcp",
             "AuthorizationType": "NONE", "Target": "integrations/int123"}])})
    statements = [
        {"Sid": "generated" + str(index), "Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": FUNC_ARN,
         "Principal": {"Service": "apigateway.amazonaws.com"},
         "Condition": {"StringEquals": {"AWS:SourceAccount": ACCOUNT}, "ArnLike": {"AWS:SourceArn": arn}}}
        for index, arn in enumerate((POST_ARN, META_ARN))
    ]
    fn_props = template["Resources"]["McpHandler"]["Properties"]
    code_hash = base64.b64encode(bytes.fromhex(ZIP_SHA)).decode("ascii")
    lam = Lambda({"get_function": ok(Configuration={"FunctionArn": FUNC_ARN, "Handler": fn_props["Handler"],
            "CodeSha256": code_hash, "Environment": fn_props["Environment"]}),
        "get_function_concurrency": ok(ReservedConcurrentExecutions=0),
        "get_policy": ok(Policy=json.dumps({"Version": "2012-10-17", "Statement": statements}))})
    return state, template, {"cloudformation": cfn, "apigatewayv2": authorizer, "lambda": lam}


class Api:
    def __init__(self, replies):
        self.replies = replies

    def __getattr__(self, name):
        def call(**kwargs):
            return self.replies[name]
        return call


class Lambda(Api):
    pass


class Cfn(Api):
    pass


def test_full_16_resource_runtime_readback_is_closed_and_ids_stay_private():
    state, template, clients = fixture()
    result = check_dev_runtime_readback(clients, state=state, expected_account_id=ACCOUNT, expected_template=template)
    assert result.verified is True
    assert result.category == "runtime_readback_verified"
    assert result.calls == 10
    assert result.authorizer_id == "auth123"
    assert result.integration_id == "int123"
    assert result.post_route_id == "post123"
    assert result.metadata_route_id == "meta123"
    assert "auth123" not in repr(result)
    assert "auth123" not in str(result.safe_projection())


def test_shared_identity_14_resource_contract_reads_back_without_pool_or_domain_resources():
    state, template, clients = fixture(shared_identity=True)
    result = check_dev_runtime_readback(
        clients, state=state, expected_account_id=ACCOUNT, expected_template=template,
        resource_contract="shared_identity14",
    )
    assert result.verified is True
    assert result.calls == 10
    assert result.category == "runtime_readback_verified"

    # The original default remains the strict standalone 16-resource contract.
    default_result = check_dev_runtime_readback(
        clients, state=state, expected_account_id=ACCOUNT, expected_template=template,
    )
    assert default_result.verified is False
    assert default_result.calls == 0


def test_artifact_code_hash_mismatch_never_reports_runtime_verified():
    state, template, clients = fixture()
    clients["lambda"].replies["get_function"]["Configuration"]["CodeSha256"] = "invalid"
    result = check_dev_runtime_readback(clients, state=state, expected_account_id=ACCOUNT, expected_template=template)
    assert result.verified is False
    assert result.category == "lambda_binding_mismatch"


def test_function_arn_must_match_exact_account_and_handler_name():
    for function_arn in (
        f"arn:aws:lambda:eu-west-1:999999999999:function:honda-mapit-mcp-dev-handler",
        f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:other-handler",
    ):
        state, template, clients = fixture()
        clients["lambda"].replies["get_function"]["Configuration"]["FunctionArn"] = function_arn
        # The API integration agrees with the forged readback ARN; that must
        # not make an unowned function acceptable.
        clients["apigatewayv2"].replies["get_integrations"]["Items"][0]["IntegrationUri"] = (
            f"arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/{function_arn}/invocations"
        )
        result = check_dev_runtime_readback(clients, state=state, expected_account_id=ACCOUNT, expected_template=template)
        assert result.verified is False
        assert result.category == "integration_mismatch"


def test_extra_route_or_open_api_fails_closed():
    state, template, clients = fixture()
    clients["apigatewayv2"].replies["get_api"]["DisableExecuteApiEndpoint"] = False
    result = check_dev_runtime_readback(clients, state=state, expected_account_id=ACCOUNT, expected_template=template)
    assert result.category == "api_not_closed"

    state, template, clients = fixture()
    clients["apigatewayv2"].replies["get_routes"]["Items"].append({"RouteId": "third", "RouteKey": "DELETE /mcp"})
    result = check_dev_runtime_readback(clients, state=state, expected_account_id=ACCOUNT, expected_template=template)
    assert result.category == "routes_readback_invalid"
