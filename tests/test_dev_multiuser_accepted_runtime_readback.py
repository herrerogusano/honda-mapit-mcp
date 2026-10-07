from __future__ import annotations

import json

from scripts.run_dev_multiuser_accepted_continuation import _verify_multiuser_runtime_children

ACCOUNT = "123456789012"
API = "abcdefghij"
POOL = "eu-west-1_A1b2C3d4E"
CLIENT = "SyntheticClient123"
URI = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"
FUNCTION = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"
INTEGRATION_URI = f"arn:aws:apigateway:eu-west-1:lambda:path/2015-03-31/functions/{FUNCTION}/invocations"


class _Api:
    def __init__(self):
        self.authorizer = {
            "AuthorizerId": "auth-123", "AuthorizerType": "JWT",
            "IdentitySource": ["$request.header.Authorization"],
            "JwtConfiguration": {
                "Issuer": f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL}",
                "Audience": [URI],
            },
        }
        self.integration = {
            "IntegrationId": "integration-123", "IntegrationType": "AWS_PROXY",
            "IntegrationMethod": "POST", "PayloadFormatVersion": "2.0",
            "TimeoutInMillis": 20000, "IntegrationUri": INTEGRATION_URI,
        }
        self.routes = [
            {"RouteId": "post-123", "RouteKey": "POST /mcp", "AuthorizationType": "JWT",
             "AuthorizerId": "auth-123", "AuthorizationScopes": [URI + "/use"],
             "Target": "integrations/integration-123"},
            {"RouteId": "protected-123", "RouteKey": "GET /.well-known/oauth-protected-resource/mcp",
             "AuthorizationType": "NONE", "Target": "integrations/integration-123"},
            {"RouteId": "server-123", "RouteKey": "GET /.well-known/oauth-authorization-server",
             "AuthorizationType": "NONE", "Target": "integrations/integration-123"},
        ]

    def get_authorizers(self, **kwargs):
        return {"Items": [self.authorizer], "NextToken": None, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_integrations(self, **kwargs):
        return {"Items": [self.integration], "NextToken": None, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_routes(self, **kwargs):
        return {"Items": self.routes, "NextToken": None, "ResponseMetadata": {"HTTPStatusCode": 200}}


class _Lambda:
    def __init__(self):
        self.role = ROLE
        self.statements = [
            {"Sid": "allow-post", "Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": FUNCTION,
             "Principal": {"Service": "apigateway.amazonaws.com"},
             "Condition": {"StringEquals": {"AWS:SourceAccount": ACCOUNT},
                           "ArnLike": {"AWS:SourceArn": f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:{API}/$default/POST/mcp"}}},
            {"Sid": "allow-protected", "Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": FUNCTION,
             "Principal": {"Service": "apigateway.amazonaws.com"},
             "Condition": {"StringEquals": {"AWS:SourceAccount": ACCOUNT},
                           "ArnLike": {"AWS:SourceArn": f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:{API}/$default/GET/.well-known/oauth-protected-resource/mcp"}}},
            {"Sid": "allow-server", "Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": FUNCTION,
             "Principal": {"Service": "apigateway.amazonaws.com"},
             "Condition": {"StringEquals": {"AWS:SourceAccount": ACCOUNT},
                           "ArnLike": {"AWS:SourceArn": f"arn:aws:execute-api:eu-west-1:{ACCOUNT}:{API}/$default/GET/.well-known/oauth-authorization-server"}}},
        ]

    def get_function(self, **kwargs):
        return {"Configuration": {"FunctionArn": FUNCTION, "Role": self.role}, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_policy(self, **kwargs):
        return {"Policy": json.dumps({"Version": "2012-10-17", "Statement": self.statements}), "ResponseMetadata": {"HTTPStatusCode": 200}}


def _fixture():
    types = {
        "McpJwtAuthorizer": "AWS::ApiGatewayV2::Authorizer",
        "McpLambdaIntegration": "AWS::ApiGatewayV2::Integration",
        "McpPostRoute": "AWS::ApiGatewayV2::Route",
        "McpProtectedResourceMetadataRoute": "AWS::ApiGatewayV2::Route",
        "McpAuthorizationServerMetadataRoute": "AWS::ApiGatewayV2::Route",
        "McpLambdaInvokePermission": "AWS::Lambda::Permission",
        "McpProtectedResourceMetadataInvokePermission": "AWS::Lambda::Permission",
        "McpAuthorizationServerMetadataInvokePermission": "AWS::Lambda::Permission",
    }
    ids = {
        "McpJwtAuthorizer": "auth-123", "McpLambdaIntegration": "integration-123",
        "McpPostRoute": "post-123", "McpProtectedResourceMetadataRoute": "protected-123",
        "McpAuthorizationServerMetadataRoute": "server-123",
        "McpLambdaInvokePermission": "permission-post",
        "McpProtectedResourceMetadataInvokePermission": "permission-protected",
        "McpAuthorizationServerMetadataInvokePermission": "permission-server",
        "McpUserPool": POOL,
    }
    rows = {name: {"PhysicalResourceId": value} for name, value in ids.items()}
    template = {"Resources": {name: {"Type": kind} for name, kind in types.items()}}
    return template, rows


def test_accepted_runtime_api_children_and_handler_role_are_exact():
    template, rows = _fixture()
    _verify_multiuser_runtime_children(
        {"apigatewayv2": _Api(), "lambda": _Lambda()}, template, rows,
        account=ACCOUNT, api_id=API,
    )


def test_accepted_runtime_rejects_wrong_audience_or_execution_role():
    template, rows = _fixture()
    api = _Api(); api.authorizer["JwtConfiguration"]["Audience"] = [CLIENT]
    try:
        _verify_multiuser_runtime_children({"apigatewayv2": api, "lambda": _Lambda()}, template, rows, account=ACCOUNT, api_id=API)
    except Exception as exc:
        assert getattr(exc, "category", None) == "accepted_runtime_invalid"
    else:
        raise AssertionError("wrong JWT audience accepted")

    lam = _Lambda(); lam.role = f"arn:aws:iam::{ACCOUNT}:role/other"
    try:
        _verify_multiuser_runtime_children({"apigatewayv2": _Api(), "lambda": lam}, template, rows, account=ACCOUNT, api_id=API)
    except Exception as exc:
        assert getattr(exc, "category", None) == "accepted_runtime_invalid"
    else:
        raise AssertionError("wrong Lambda role accepted")


def test_accepted_runtime_rejects_extra_lambda_invoke_permission():
    template, rows = _fixture()
    lam = _Lambda(); lam.statements.append(dict(lam.statements[0], Sid="extra"))
    try:
        _verify_multiuser_runtime_children({"apigatewayv2": _Api(), "lambda": lam}, template, rows, account=ACCOUNT, api_id=API)
    except Exception as exc:
        assert getattr(exc, "category", None) == "accepted_runtime_invalid"
    else:
        raise AssertionError("extra invoke permission accepted")


def test_public_routes_allow_only_absent_or_empty_authorization_scopes():
    template, rows = _fixture()
    api = _Api()
    assert _verify_multiuser_runtime_children(
        {"apigatewayv2": api, "lambda": _Lambda()}, template, rows,
        account=ACCOUNT, api_id=API,
    ) is None
    for route in api.routes[1:]:
        route["AuthorizationScopes"] = []
    assert _verify_multiuser_runtime_children(
        {"apigatewayv2": api, "lambda": _Lambda()}, template, rows,
        account=ACCOUNT, api_id=API,
    ) is None

    for invalid in (["unexpected/scope"], "", {}, ()):
        api = _Api()
        api.routes[1]["AuthorizationScopes"] = invalid
        try:
            _verify_multiuser_runtime_children(
                {"apigatewayv2": api, "lambda": _Lambda()}, template, rows,
                account=ACCOUNT, api_id=API,
            )
        except Exception as exc:
            assert getattr(exc, "category", None) == "accepted_runtime_invalid"
        else:
            raise AssertionError("malformed/public route scopes accepted")

    api = _Api()
    api.routes[0]["AuthorizationScopes"] = []
    try:
        _verify_multiuser_runtime_children(
            {"apigatewayv2": api, "lambda": _Lambda()}, template, rows,
            account=ACCOUNT, api_id=API,
        )
    except Exception as exc:
        assert getattr(exc, "category", None) == "accepted_runtime_invalid"
    else:
        raise AssertionError("POST without exact JWT scope accepted")
