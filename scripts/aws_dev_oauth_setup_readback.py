"""Injected, read-only verification of the closed dev OAuth setup stage.

This module does not construct SDK clients, load credentials, retry, or write
cloud state. Callers must supply the exact stack and resource identifiers from
their already-verified private ownership record. The generated client ID is
kept only on the private result object; :meth:`safe_projection` omits it.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from scripts.build_aws_dev_oauth_template import _validate_callback

_REGION = "eu-west-1"
_STACK_NAME = "honda-mapit-mcp-dev"
_RUN_TAG = "ClosedRehearsalRunId"
_API_NAME = "honda-mapit-mcp-dev-api"
_FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
_HANDLER_ROLE = "honda-mapit-mcp-dev-handler-role"
_LOG_GROUP = "/aws/lambda/honda-mapit-mcp-dev-handler"
_DOMAIN_PREFIX = "hm-dev-honda-mapit-mcp-dev"
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_RESOURCE_NAMES = frozenset({
    "McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
    "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding",
})
_RESOURCE_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpUserPool": "AWS::Cognito::UserPool",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function",
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
}


class CloudFormationClient(Protocol):
    def describe_stacks(self, *, StackName: str) -> Mapping[str, Any]: ...

    def describe_stack_resources(self, *, StackName: str) -> Mapping[str, Any]: ...


class ApiGatewayClient(Protocol):
    def get_api(self, *, ApiId: str) -> Mapping[str, Any]: ...

    def get_routes(self, *, ApiId: str, MaxResults: str) -> Mapping[str, Any]: ...


class LambdaClient(Protocol):
    def get_function_concurrency(self, *, FunctionName: str) -> Mapping[str, Any]: ...


class CognitoClient(Protocol):
    def list_users(self, *, UserPoolId: str, Limit: int) -> Mapping[str, Any]: ...

    def list_user_pool_clients(self, *, UserPoolId: str, MaxResults: int) -> Mapping[str, Any]: ...

    def describe_user_pool_client(self, *, UserPoolId: str, ClientId: str) -> Mapping[str, Any]: ...

    def describe_resource_server(self, *, UserPoolId: str, Identifier: str) -> Mapping[str, Any]: ...

    def describe_user_pool_domain(self, *, Domain: str) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class OAuthSetupReadback:
    """Readback facts; client_id is private and excluded from repr/safe output."""

    verified: bool
    category: str
    calls: int
    stack_verified: bool = False
    resources_verified: bool = False
    api_closed: bool = False
    routes_empty: bool = False
    function_reserved_zero: bool = False
    users_empty: bool = False
    client_verified: bool = False
    resource_server_verified: bool = False
    domain_verified: bool = False
    client_id: str | None = field(default=None, repr=False)

    def safe_projection(self) -> dict[str, Any]:
        """Return a closed projection with no identifiers or provider payloads."""
        return {
            "verified": self.verified,
            "category": self.category,
            "calls": self.calls,
            "stack_verified": self.stack_verified,
            "resources_verified": self.resources_verified,
            "api_closed": self.api_closed,
            "routes_empty": self.routes_empty,
            "function_reserved_zero": self.function_reserved_zero,
            "users_empty": self.users_empty,
            "client_verified": self.client_verified,
            "resource_server_verified": self.resource_server_verified,
            "domain_verified": self.domain_verified,
        }


def _input_valid(account_id: Any, stack_arn: Any, run_id: Any, api_id: Any, pool_id: Any, callback_url: Any) -> bool:
    if type(account_id) is not str or not _ACCOUNT_ID.fullmatch(account_id):
        return False
    if type(api_id) is not str or not _API_ID.fullmatch(api_id):
        return False
    if type(pool_id) is not str or not _POOL_ID.fullmatch(pool_id):
        return False
    if type(run_id) is not str:
        return False
    try:
        parsed_run = uuid.UUID(run_id)
    except (ValueError, AttributeError):
        return False
    if str(parsed_run) != run_id or parsed_run.int == 0:
        return False
    expected_prefix = f"arn:aws:cloudformation:{_REGION}:{account_id}:stack/{_STACK_NAME}/"
    if type(stack_arn) is not str or not stack_arn.startswith(expected_prefix):
        return False
    stack_uuid = stack_arn[len(expected_prefix):]
    try:
        parsed_stack = uuid.UUID(stack_uuid)
    except (ValueError, AttributeError):
        return False
    if str(parsed_stack) != stack_uuid or parsed_stack.int == 0:
        return False
    try:
        _validate_callback(callback_url)
    except Exception:
        return False
    return True


def _result(category: str, calls: int, **facts: Any) -> OAuthSetupReadback:
    return OAuthSetupReadback(
        verified=category == "oauth_setup_verified",
        category=category,
        calls=calls,
        **facts,
    )


def check_oauth_setup_readback(
    cloudformation_client: CloudFormationClient,
    api_client: ApiGatewayClient,
    lambda_client: LambdaClient,
    cognito_client: CognitoClient,
    *,
    account_id: str,
    stack_arn: str,
    run_id: str,
    api_id: str,
    user_pool_id: str,
    callback_url: str,
) -> OAuthSetupReadback:
    """Verify the exact closed OAuth setup, with at most ten injected reads.

    The function deliberately stops at the first failed or malformed readback.
    It verifies configuration only; it does not establish OAuth interoperability,
    owner authorization, callback listener availability, or runtime readiness.
    """
    if not _input_valid(account_id, stack_arn, run_id, api_id, user_pool_id, callback_url):
        return _result("readback_inputs_invalid", 0)

    facts: dict[str, Any] = {}
    calls = 0

    def call(client: Any, method: str, **kwargs: Any) -> Mapping[str, Any] | None:
        nonlocal calls
        calls += 1
        try:
            response = getattr(client, method)(**kwargs)
        except Exception:
            return None
        if not isinstance(response, Mapping):
            return None
        metadata = response.get("ResponseMetadata")
        if not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int:
            return None
        if metadata["HTTPStatusCode"] != 200:
            return None
        return response

    # 1. Exact stack ownership, completion state, run tag and bounded outputs.
    response = call(cloudformation_client, "describe_stacks", StackName=stack_arn)
    stacks = response.get("Stacks") if response is not None else None
    if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
        return _result("stack_readback_invalid", calls)
    stack = stacks[0]
    if (
        stack.get("StackId") != stack_arn
        or stack.get("StackName") != _STACK_NAME
        or type(stack.get("StackStatus")) is not str
        or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
    ):
        return _result("stack_identity_invalid", calls)
    tags = stack.get("Tags")
    if type(tags) is not list or not any(
        isinstance(tag, Mapping) and tag.get("Key") == _RUN_TAG and tag.get("Value") == run_id
        for tag in tags
    ):
        return _result("stack_ownership_unverified", calls)
    outputs = stack.get("Outputs")
    if type(outputs) is not list:
        return _result("stack_outputs_invalid", calls)
    output_map: dict[str, Any] = {}
    for item in outputs:
        if not isinstance(item, Mapping) or type(item.get("OutputKey")) is not str or item["OutputKey"] in output_map:
            return _result("stack_outputs_invalid", calls)
        output_map[item["OutputKey"]] = item.get("OutputValue")
    if set(output_map) != {"ApiId", "UserPoolId", "McpClientId"}:
        return _result("stack_outputs_invalid", calls)
    client_id = output_map.get("McpClientId")
    if (
        output_map.get("ApiId") != api_id
        or output_map.get("UserPoolId") != user_pool_id
        or type(client_id) is not str
        or not _CLIENT_ID.fullmatch(client_id)
    ):
        return _result("stack_outputs_mismatch", calls)
    facts.update(stack_verified=True)

    # 2. All ten expected logical resources, no duplicates or unknowns.
    response = call(cloudformation_client, "describe_stack_resources", StackName=stack_arn)
    records = response.get("StackResources") if response is not None else None
    if type(records) is not list or len(records) != len(_RESOURCE_NAMES):
        return _result("stack_resources_invalid", calls, **facts)
    resource_map: dict[str, Mapping[str, Any]] = {}
    for record in records:
        if not isinstance(record, Mapping) or type(record.get("LogicalResourceId")) is not str:
            return _result("stack_resources_invalid", calls, **facts)
        logical_id = record["LogicalResourceId"]
        if logical_id in resource_map or logical_id not in _RESOURCE_NAMES:
            return _result("stack_resources_invalid", calls, **facts)
        physical_id = record.get("PhysicalResourceId")
        if type(physical_id) is not str or not physical_id or len(physical_id) > 1024:
            return _result("stack_resources_invalid", calls, **facts)
        if type(record.get("ResourceStatus")) is not str or record.get("ResourceStatus") not in {
            "CREATE_COMPLETE", "UPDATE_COMPLETE"
        }:
            return _result("stack_resources_incomplete", calls, **facts)
        if record.get("ResourceType") != _RESOURCE_TYPES[logical_id]:
            return _result("stack_resources_invalid", calls, **facts)
        resource_map[logical_id] = record
    if set(resource_map) != _RESOURCE_NAMES:
        return _result("stack_resources_invalid", calls, **facts)
    fixed_physical = {
        "McpApi": api_id,
        "McpUserPool": user_pool_id,
        "McpHandler": _FUNCTION_NAME,
        "McpHandlerRole": _HANDLER_ROLE,
        "McpHandlerLogGroup": _LOG_GROUP,
    }
    if any(resource_map[key].get("PhysicalResourceId") != value for key, value in fixed_physical.items()):
        return _result("stack_resource_identity_mismatch", calls, **facts)
    if resource_map["McpUserPoolClient"].get("PhysicalResourceId") != client_id:
        return _result("stack_client_identity_mismatch", calls, **facts)
    facts["resources_verified"] = True

    # 3. API still closed and has no routes.
    response = call(api_client, "get_api", ApiId=api_id)
    if response is None or response.get("ApiId") != api_id or response.get("Name") != _API_NAME:
        return _result("api_readback_invalid", calls, **facts)
    if response.get("DisableExecuteApiEndpoint") is not True:
        return _result("api_not_closed", calls, **facts)
    facts["api_closed"] = True
    response = call(api_client, "get_routes", ApiId=api_id, MaxResults="100")
    if response is None or type(response.get("Items")) is not list:
        return _result("routes_readback_invalid", calls, **facts)
    if response["Items"] or response.get("NextToken") not in (None, ""):
        return _result("routes_unexpected", calls, **facts)
    facts["routes_empty"] = True

    # 4. Reserved concurrency remains zero; no user has been created.
    response = call(lambda_client, "get_function_concurrency", FunctionName=_FUNCTION_NAME)
    reserved = response.get("ReservedConcurrentExecutions") if response is not None else None
    if type(reserved) is not int:
        return _result("function_concurrency_invalid", calls, **facts)
    if reserved != 0:
        return _result("function_not_reserved_zero", calls, **facts)
    facts["function_reserved_zero"] = True
    response = call(cognito_client, "list_users", UserPoolId=user_pool_id, Limit=1)
    if response is None or type(response.get("Users")) is not list:
        return _result("users_readback_invalid", calls, **facts)
    if response["Users"] or response.get("PaginationToken") not in (None, ""):
        return _result("users_unexpected", calls, **facts)
    facts["users_empty"] = True

    # 5. One public app client and its effective OAuth configuration.
    response = call(cognito_client, "list_user_pool_clients", UserPoolId=user_pool_id, MaxResults=1)
    client_list = response.get("UserPoolClients") if response is not None else None
    if type(client_list) is not list or response.get("NextToken") not in (None, ""):
        return _result("clients_readback_invalid", calls, **facts)
    if len(client_list) != 1 or not isinstance(client_list[0], Mapping) or client_list[0].get("ClientId") != client_id:
        return _result("clients_unexpected", calls, **facts)
    response = call(cognito_client, "describe_user_pool_client", UserPoolId=user_pool_id, ClientId=client_id)
    described = response.get("UserPoolClient") if response is not None else None
    if not isinstance(described, Mapping):
        return _result("client_readback_invalid", calls, **facts)
    if described.get("ClientSecret") not in (None, ""):
        return _result("client_secret_present", calls, **facts)
    analytics = described.get("AnalyticsConfiguration")
    if analytics not in (None, {}):
        return _result("client_analytics_present", calls, **facts)
    resource_uri = f"https://{api_id}.execute-api.{_REGION}.amazonaws.com/mcp"
    expected_client = {
        "UserPoolId": user_pool_id,
        "ClientId": client_id,
        "AllowedOAuthFlowsUserPoolClient": True,
        "AllowedOAuthFlows": ["code"],
        "AllowedOAuthScopes": [f"{resource_uri}/use"],
        "CallbackURLs": [callback_url],
        "DefaultRedirectURI": callback_url,
        "SupportedIdentityProviders": ["COGNITO"],
        "EnableTokenRevocation": True,
        "PreventUserExistenceErrors": "ENABLED",
        "AccessTokenValidity": 5,
        "IdTokenValidity": 5,
        "RefreshTokenValidity": 1,
        "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"},
    }
    if any(described.get(key) != value for key, value in expected_client.items()):
        return _result("client_policy_mismatch", calls, **facts)
    if any(type(described.get(key)) is not type(value) for key, value in expected_client.items()):
        return _result("client_policy_mismatch", calls, **facts)
    facts["client_verified"] = True

    # 6. Exact resource-server scope and the fixed AWS-managed login domain.
    response = call(
        cognito_client, "describe_resource_server", UserPoolId=user_pool_id, Identifier=resource_uri,
    )
    server = response.get("ResourceServer") if response is not None else None
    if not isinstance(server, Mapping) or (
        server.get("UserPoolId") != user_pool_id
        or server.get("Identifier") != resource_uri
        or server.get("Scopes") != [{"ScopeName": "use", "ScopeDescription": "Call the protected MCP endpoint."}]
    ):
        return _result("resource_server_mismatch", calls, **facts)
    facts["resource_server_verified"] = True
    response = call(cognito_client, "describe_user_pool_domain", Domain=_DOMAIN_PREFIX)
    domain = response.get("DomainDescription") if response is not None else None
    if not isinstance(domain, Mapping) or (
        domain.get("Domain") != _DOMAIN_PREFIX
        or domain.get("UserPoolId") != user_pool_id
        or domain.get("AWSAccountId") != account_id
        or domain.get("Status") != "ACTIVE"
        or type(domain.get("ManagedLoginVersion")) is not int
        or domain.get("ManagedLoginVersion") != 2
        or domain.get("CustomDomainConfig") not in (None, {})
    ):
        return _result("domain_mismatch", calls, **facts)
    facts["domain_verified"] = True
    return _result("oauth_setup_verified", calls, client_id=client_id, **facts)


__all__ = [
    "ApiGatewayClient", "CloudFormationClient", "CognitoClient", "LambdaClient",
    "OAuthSetupReadback", "check_oauth_setup_readback",
]
