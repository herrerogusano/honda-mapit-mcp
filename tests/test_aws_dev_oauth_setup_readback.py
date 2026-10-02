from __future__ import annotations

import copy
import uuid
from datetime import datetime, timezone

import pytest

from scripts.aws_dev_oauth_setup_readback import check_oauth_setup_readback

ACCOUNT = "123456789012"
STACK_UUID = "01234567-89ab-cdef-0123-456789abcdef"
STACK_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev/{STACK_UUID}"
RUN_ID = "fedcba98-7654-3210-fedc-ba9876543210"
API_ID = "abcdefghij"
POOL_ID = "eu-west-1_Abcdefghi"
CLIENT_ID = "SyntheticClient123"
CALLBACK = "http://127.0.0.1:39031/callback"
RESOURCE_URI = f"https://{API_ID}.execute-api.eu-west-1.amazonaws.com/mcp"


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def _next(self, method, **kwargs):
        self.calls.append((method, kwargs))
        if not self.responses:
            raise AssertionError("unexpected client call")
        expected_method, response = self.responses.pop(0)
        assert method == expected_method
        if isinstance(response, BaseException):
            raise response
        result = copy.deepcopy(response)
        if isinstance(result, dict):
            result.setdefault("ResponseMetadata", {"HTTPStatusCode": 200})
        return result

    def __getattr__(self, method):
        return lambda **kwargs: self._next(method, **kwargs)


def _stack_response():
    return {"Stacks": [{
        "StackId": STACK_ARN,
        "StackName": "honda-mapit-mcp-dev",
        "CreationTime": datetime(2026, 10, 2, tzinfo=timezone.utc),
        "StackStatus": "UPDATE_COMPLETE",
        "Tags": [{"Key": "ClosedRehearsalRunId", "Value": RUN_ID}],
        "Outputs": [
            {"OutputKey": "ApiId", "OutputValue": API_ID},
            {"OutputKey": "UserPoolId", "OutputValue": POOL_ID},
            {"OutputKey": "McpClientId", "OutputValue": CLIENT_ID},
        ],
    }]}


def _resource_response():
    ids = {
        "McpApi": API_ID,
        "McpApiStage": "$default",
        "McpUserPool": POOL_ID,
        "McpHandlerRole": "honda-mapit-mcp-dev-handler-role",
        "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-handler",
        "McpHandler": "honda-mapit-mcp-dev-handler",
        "McpUserPoolDomain": "opaque-domain-physical-id",
        "McpResourceServer": "opaque-resource-server-physical-id",
        "McpUserPoolClient": CLIENT_ID,
        "McpManagedLoginBranding": "opaque-branding-physical-id",
    }
    return {"StackResources": [
        {"LogicalResourceId": name, "PhysicalResourceId": physical_id, "ResourceStatus": "UPDATE_COMPLETE",
         "Timestamp": datetime(2026, 10, 2, tzinfo=timezone.utc),
         "ResourceType": {
             "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
             "McpUserPool": "AWS::Cognito::UserPool", "McpHandlerRole": "AWS::IAM::Role",
             "McpHandlerLogGroup": "AWS::Logs::LogGroup", "McpHandler": "AWS::Lambda::Function",
             "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
             "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
             "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
             "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
         }[name]}
        for name, physical_id in ids.items()
    ]}


def _valid_clients():
    described = {
        "UserPoolId": POOL_ID,
        "ClientId": CLIENT_ID,
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": [f"{RESOURCE_URI}/use"],
        "CallbackURLs": [CALLBACK],
        "DefaultRedirectURI": CALLBACK,
        "SupportedIdentityProviders": ["COGNITO"],
        "EnableTokenRevocation": True,
        "PreventUserExistenceErrors": "ENABLED",
        "AccessTokenValidity": 5,
        "IdTokenValidity": 5,
        "RefreshTokenValidity": 1,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
    }
    return [
        ("list_users", {"Users": []}),
        ("list_user_pool_clients", {"UserPoolClients": [{"ClientId": CLIENT_ID}]}),
        ("describe_user_pool_client", {"UserPoolClient": described}),
        ("describe_resource_server", {"ResourceServer": {
            "UserPoolId": POOL_ID,
            "Identifier": RESOURCE_URI,
            "Scopes": [{"ScopeName": "use", "ScopeDescription": "Call the protected MCP endpoint."}],
        }}),
        ("describe_user_pool_domain", {"DomainDescription": {
            "Domain": "hm-dev-honda-mapit-mcp-dev",
            "UserPoolId": POOL_ID,
            "AWSAccountId": ACCOUNT,
            "Status": "ACTIVE",
            "ManagedLoginVersion": 2,
        }}),
    ]


def _clients(*, mutate=None):
    cognito_responses = _valid_clients()
    if mutate:
        mutate(cognito_responses)
    return (
        FakeClient([("describe_stacks", _stack_response()), ("describe_stack_resources", _resource_response())]),
        FakeClient([("get_api", {"ApiId": API_ID, "Name": "honda-mapit-mcp-dev-api", "DisableExecuteApiEndpoint": True}),
                    ("get_routes", {"Items": []})]),
        FakeClient([("get_function_concurrency", {"ReservedConcurrentExecutions": 0})]),
        FakeClient(cognito_responses),
    )


def _check(clients):
    cf, api, lam, cognito = clients
    return check_oauth_setup_readback(
        cf, api, lam, cognito,
        account_id=ACCOUNT,
        stack_arn=STACK_ARN,
        run_id=RUN_ID,
        api_id=API_ID,
        user_pool_id=POOL_ID,
        callback_url=CALLBACK,
    )


def test_complete_readback_is_bounded_and_hides_client_id_from_safe_projection():
    clients = _clients()
    result = _check(clients)
    assert result.verified is True
    assert result.category == "oauth_setup_verified"
    assert result.calls == 10
    assert result.client_id == CLIENT_ID
    assert "client_id" not in result.safe_projection()
    assert CLIENT_ID not in repr(result)
    assert [len(client.calls) for client in clients] == [2, 2, 1, 5]
    assert clients[0].calls[0] == ("describe_stacks", {"StackName": STACK_ARN})
    assert clients[0].calls[1] == ("describe_stack_resources", {"StackName": STACK_ARN})
    assert clients[3].calls[-1] == ("describe_user_pool_domain", {"Domain": "hm-dev-honda-mapit-mcp-dev"})
    assert clients[3].calls[1] == ("list_user_pool_clients", {"UserPoolId": POOL_ID, "MaxResults": 1})


@pytest.mark.parametrize("field,value", [
    ("AllowedOAuthFlows", ["implicit"]),
    ("AllowedOAuthScopes", [f"{RESOURCE_URI}/admin"]),
    ("CallbackURLs", ["http://localhost:9999/elsewhere"]),
    ("DefaultRedirectURI", "http://localhost:9999/elsewhere"),
    ("AccessTokenValidity", True),
    ("RefreshTokenValidity", 90),
    ("EnableTokenRevocation", False),
])
def test_client_policy_mismatch_fails_closed(field, value):
    def mutate(rows):
        rows[2][1]["UserPoolClient"][field] = value

    result = _check(_clients(mutate=mutate))
    assert result.verified is False
    assert result.category == "client_policy_mismatch"
    assert result.calls == 8


@pytest.mark.parametrize("kwargs", [
    {"account_id": "000000000000"},
    {"stack_arn": f"arn:aws:cloudformation:us-east-1:{ACCOUNT}:stack/honda-mapit-mcp-dev/{STACK_UUID}"},
    {"stack_arn": STACK_ARN + ":suffix"},
    {"run_id": "not-a-run-id"},
    {"api_id": "ABCdefghij"},
    {"user_pool_id": "eu-west-1_bad"},
    {"callback_url": "https://example.invalid/callback"},
])
def test_invalid_private_bindings_make_no_calls(kwargs):
    clients = _clients()
    cf, api, lam, cognito = clients
    values = dict(
        account_id=ACCOUNT, stack_arn=STACK_ARN, run_id=RUN_ID, api_id=API_ID,
        user_pool_id=POOL_ID, callback_url=CALLBACK,
    )
    values.update(kwargs)
    result = check_oauth_setup_readback(cf, api, lam, cognito, **values)
    assert result.verified is False
    assert result.category == "readback_inputs_invalid"
    assert result.calls == 0
    assert sum(map(lambda client: len(client.calls), clients)) == 0


def test_stack_run_tag_and_duplicate_logical_ids_are_not_accepted():
    clients = _clients()
    clients[0].responses[0][1]["Stacks"][0]["Tags"] = []
    result = _check(clients)
    assert result.category == "stack_ownership_unverified"
    assert result.calls == 1
    assert result.client_id is None

    clients = _clients()
    response = clients[0].responses[1][1]
    response["StackResources"].append(copy.deepcopy(response["StackResources"][0]))
    result = _check(clients)
    assert result.category == "stack_resources_invalid"
    assert result.calls == 2

    clients = _clients()
    clients[0].responses[1][1]["StackResources"][0]["ResourceType"] = "AWS::Lambda::Function"
    assert _check(clients).category == "stack_resources_invalid"


def test_client_secret_and_unexpected_domain_or_route_fail_closed():
    def secret(rows):
        rows[2][1]["UserPoolClient"]["ClientSecret"] = "synthetic-secret-canary"

    result = _check(_clients(mutate=secret))
    assert result.category == "client_secret_present"
    assert "synthetic-secret-canary" not in repr(result)

    clients = _clients()
    clients[1].responses[1][1]["Items"] = [{"RouteKey": "POST /mcp"}]
    assert _check(clients).category == "routes_unexpected"

    def domain(rows):
        rows[4][1]["DomainDescription"]["UserPoolId"] = "eu-west-1_otherpool"

    assert _check(_clients(mutate=domain)).category == "domain_mismatch"


def test_provider_exception_is_sanitized_and_stops_without_retry():
    clients = _clients()
    clients[2].responses[0] = ("get_function_concurrency", RuntimeError("secret-id-canary"))
    result = _check(clients)
    assert result.category == "function_concurrency_invalid"
    assert result.calls == 5
    assert len(clients[2].calls) == 1
    assert "secret-id-canary" not in repr(result)


def test_non_200_response_metadata_and_analytics_are_rejected():
    clients = _clients()
    clients[0].responses[0][1]["ResponseMetadata"] = {"HTTPStatusCode": 202}
    result = _check(clients)
    assert result.category == "stack_readback_invalid"
    assert result.calls == 1

    def analytics(rows):
        rows[2][1]["UserPoolClient"]["AnalyticsConfiguration"] = {"ApplicationId": "canary"}

    result = _check(_clients(mutate=analytics))
    assert result.category == "client_analytics_present"
    assert result.client_id is None


def test_pinned_botocore_stubber_shapes_without_network():
    boto3 = pytest.importorskip("boto3")
    stub_module = pytest.importorskip("botocore.stub")
    session = boto3.Session(
        aws_access_key_id="synthetic",
        aws_secret_access_key="synthetic",
        aws_session_token="synthetic",
        region_name="eu-west-1",
    )
    clients = {
        "cloudformation": session.client("cloudformation"),
        "apigatewayv2": session.client("apigatewayv2"),
        "lambda": session.client("lambda"),
        "cognito-idp": session.client("cognito-idp"),
    }
    stubs = {name: stub_module.Stubber(client) for name, client in clients.items()}

    def add_response(stub, operation, response, params):
        response = copy.deepcopy(response)
        response["ResponseMetadata"] = {"HTTPStatusCode": 200}
        stub.add_response(operation, response, params)

    try:
        cf = stubs["cloudformation"]
        add_response(cf, "describe_stacks", _stack_response(), {"StackName": STACK_ARN})
        add_response(cf, "describe_stack_resources", _resource_response(), {"StackName": STACK_ARN})
        api = stubs["apigatewayv2"]
        add_response(api, "get_api", {"ApiId": API_ID, "Name": "honda-mapit-mcp-dev-api", "DisableExecuteApiEndpoint": True}, {"ApiId": API_ID})
        add_response(api, "get_routes", {"Items": []}, {"ApiId": API_ID, "MaxResults": "100"})
        add_response(stubs["lambda"],
            "get_function_concurrency", {"ReservedConcurrentExecutions": 0},
            {"FunctionName": "honda-mapit-mcp-dev-handler"},
        )
        cognito = stubs["cognito-idp"]
        for method, result, params in [
            ("list_users", {"Users": []}, {"UserPoolId": POOL_ID, "Limit": 1}),
            ("list_user_pool_clients", {"UserPoolClients": [{"ClientId": CLIENT_ID}]}, {"UserPoolId": POOL_ID, "MaxResults": 1}),
            ("describe_user_pool_client", _valid_clients()[2][1], {"UserPoolId": POOL_ID, "ClientId": CLIENT_ID}),
            ("describe_resource_server", _valid_clients()[3][1], {"UserPoolId": POOL_ID, "Identifier": RESOURCE_URI}),
            ("describe_user_pool_domain", _valid_clients()[4][1], {"Domain": "hm-dev-honda-mapit-mcp-dev"}),
        ]:
            add_response(cognito, method, result, params)
        for stub in stubs.values():
            stub.activate()
        result = check_oauth_setup_readback(
            clients["cloudformation"], clients["apigatewayv2"], clients["lambda"], clients["cognito-idp"],
            account_id=ACCOUNT, stack_arn=STACK_ARN, run_id=RUN_ID, api_id=API_ID,
            user_pool_id=POOL_ID, callback_url=CALLBACK,
        )
        assert result.verified is True
        assert result.calls == 10
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    finally:
        for stub in stubs.values():
            stub.deactivate()
