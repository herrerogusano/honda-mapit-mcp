"""Injected, read-only readback for the closed 16-resource dev runtime.

The caller supplies a fixed-factory template and private ownership snapshot.
This module creates no clients, performs no writes/retries, and returns runtime
child identifiers only on its private result object (never in safe_projection).
"""

from __future__ import annotations

import base64
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Mapping

_REGION = "eu-west-1"
_STACK = "honda-mapit-mcp-dev"
_RUN_TAG = "ClosedRehearsalRunId"
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_OWNER_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_NAMES = {
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
    "McpJwtAuthorizer": "AWS::ApiGatewayV2::Authorizer",
    "McpLambdaIntegration": "AWS::ApiGatewayV2::Integration",
    "McpPostRoute": "AWS::ApiGatewayV2::Route",
    "McpLambdaInvokePermission": "AWS::Lambda::Permission",
    "McpProtectedResourceMetadataRoute": "AWS::ApiGatewayV2::Route",
    "McpProtectedResourceMetadataInvokePermission": "AWS::Lambda::Permission",
}
_SHARED_IDENTITY_NAMES = {
    name: resource_type for name, resource_type in _NAMES.items()
    if name not in {"McpUserPool", "McpUserPoolDomain"}
}
_METADATA_PATH = "/.well-known/oauth-protected-resource/mcp"


@dataclass(frozen=True)
class RuntimeReadback:
    verified: bool
    category: str
    calls: int
    stack_verified: bool = False
    resources_verified: bool = False
    api_closed: bool = False
    routes_verified: bool = False
    authorizer_verified: bool = False
    integration_verified: bool = False
    lambda_hash_verified: bool = False
    lambda_environment_verified: bool = False
    invoke_permissions_verified: bool = False
    authorizer_id: str | None = field(default=None, repr=False)
    integration_id: str | None = field(default=None, repr=False)
    post_route_id: str | None = field(default=None, repr=False)
    metadata_route_id: str | None = field(default=None, repr=False)

    def safe_projection(self) -> dict[str, Any]:
        return {
            "verified": self.verified, "category": self.category, "calls": self.calls,
            "stack_verified": self.stack_verified, "resources_verified": self.resources_verified,
            "api_closed": self.api_closed, "routes_verified": self.routes_verified,
            "authorizer_verified": self.authorizer_verified, "integration_verified": self.integration_verified,
            "lambda_hash_verified": self.lambda_hash_verified,
            "lambda_environment_verified": self.lambda_environment_verified,
            "invoke_permissions_verified": self.invoke_permissions_verified,
        }


def _duplicate_reject(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _metadata_ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata["HTTPStatusCode"] == 200


def _parse_json_object(value: Any, limit: int = 128 * 1024) -> Mapping[str, Any] | None:
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value) > limit:
        return None
    try:
        parsed = json.loads(value, object_pairs_hook=_duplicate_reject)
    except (ValueError, RecursionError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def _input_valid(state: Any, account: Any, template: Any, resource_names: Mapping[str, str]) -> bool:
    if not isinstance(state, Mapping) or type(account) is not str or not re.fullmatch(r"[0-9]{12}", account):
        return False
    if state.get("account_id") != account or state.get("region") != _REGION or state.get("oauth_setup_verified") is not True:
        return False
    stack_arn = state.get("app_stack_id")
    prefix = f"arn:aws:cloudformation:{_REGION}:{account}:stack/{_STACK}/"
    if type(stack_arn) is not str or not stack_arn.startswith(prefix):
        return False
    suffix = stack_arn[len(prefix):]
    try:
        parsed_stack = uuid.UUID(suffix)
        parsed_run = uuid.UUID(state.get("run_id"))
    except (ValueError, TypeError, AttributeError):
        return False
    if str(parsed_stack) != suffix or parsed_stack.int == 0 or state.get("stack_uuid") != suffix:
        return False
    if str(parsed_run) != state.get("run_id") or parsed_run.int == 0:
        return False
    if type(state.get("api_id")) is not str or not _API_ID.fullmatch(state["api_id"]):
        return False
    if type(state.get("user_pool_id")) is not str or not _POOL_ID.fullmatch(state["user_pool_id"]):
        return False
    if type(state.get("oauth_setup_client_id")) is not str or not _CLIENT_ID.fullmatch(state["oauth_setup_client_id"]):
        return False
    callback = state.get("oauth_setup_callback_url")
    try:
        from scripts.build_aws_dev_oauth_template import _validate_callback
        _validate_callback(callback)
    except Exception:
        return False
    if not isinstance(template, Mapping) or type(template.get("Resources")) is not dict or set(template["Resources"]) != set(resource_names):
        return False
    resources = template["Resources"]
    if any(not isinstance(resources[name], Mapping) or resources[name].get("Type") != kind for name, kind in resource_names.items()):
        return False
    api = resources["McpApi"].get("Properties", {})
    function = resources["McpHandler"].get("Properties", {})
    if api.get("DisableExecuteApiEndpoint") is not True or type(function.get("ReservedConcurrentExecutions")) is not int or function["ReservedConcurrentExecutions"] != 0:
        return False
    code = function.get("Code")
    if not isinstance(code, Mapping) or type(code.get("S3Key")) is not str:
        return False
    key_match = re.fullmatch(r"runtime/([0-9a-f]{64})\.zip", code["S3Key"])
    if not key_match:
        return False
    if function.get("Handler") != "mapit.aws_dev_entrypoint.handler":
        return False
    variables = function.get("Environment", {}).get("Variables")
    expected_uri = f"https://{state['api_id']}.execute-api.{_REGION}.amazonaws.com/mcp"
    parameters = template.get("Parameters")
    if (
        not isinstance(variables, Mapping)
        or variables.get("MAPIT_MCP_ENV") != "dev"
        or variables.get("MAPIT_API_ID") != state["api_id"]
        or variables.get("MAPIT_COGNITO_USER_POOL_ID") != state["user_pool_id"]
        or variables.get("MAPIT_COGNITO_CLIENT_ID") != state["oauth_setup_client_id"]
        or type(variables.get("MAPIT_COGNITO_JWKS_SHA256")) is not str
        or not _SHA.fullmatch(variables["MAPIT_COGNITO_JWKS_SHA256"])
        or type(variables.get("MAPIT_OWNER_SUBJECT")) is not str
        or not _OWNER_UUID.fullmatch(variables["MAPIT_OWNER_SUBJECT"])
        or set(variables) != {
            "MAPIT_MCP_ENV", "MAPIT_COGNITO_USER_POOL_ID", "MAPIT_API_ID", "MAPIT_COGNITO_CLIENT_ID",
            "MAPIT_OWNER_SUBJECT", "MAPIT_COGNITO_JWKS_SHA256", "MAPIT_DEV_EXECUTION_START_EPOCH",
            "MAPIT_DEV_EXECUTION_END_EPOCH",
        }
        or type(variables.get("MAPIT_DEV_EXECUTION_START_EPOCH")) is not str
        or not 1 <= len(variables["MAPIT_DEV_EXECUTION_START_EPOCH"]) <= 12
        or not variables["MAPIT_DEV_EXECUTION_START_EPOCH"].isdecimal()
        or type(variables.get("MAPIT_DEV_EXECUTION_END_EPOCH")) is not str
        or not 1 <= len(variables["MAPIT_DEV_EXECUTION_END_EPOCH"]) <= 12
        or not variables["MAPIT_DEV_EXECUTION_END_EPOCH"].isdecimal()
        or not isinstance(parameters, Mapping)
        or parameters.get("McpResourceUri", {}).get("Default") != expected_uri
        or parameters.get("McpResourceUri", {}).get("AllowedValues") != [expected_uri]
        or parameters.get("OAuthCallbackURL", {}).get("Default") != state.get("oauth_setup_callback_url")
        or parameters.get("OAuthCallbackURL", {}).get("AllowedValues") != [state.get("oauth_setup_callback_url")]
    ):
        return False
    start = int(variables["MAPIT_DEV_EXECUTION_START_EPOCH"])
    end = int(variables["MAPIT_DEV_EXECUTION_END_EPOCH"])
    if (
        start <= 0 or end <= 0 or str(start) != variables["MAPIT_DEV_EXECUTION_START_EPOCH"]
        or str(end) != variables["MAPIT_DEV_EXECUTION_END_EPOCH"] or not 1 <= end - start <= 300
    ):
        return False
    return True


def _resources_valid(response: Mapping[str, Any], resource_names: Mapping[str, str]) -> dict[str, Mapping[str, Any]] | None:
    rows = response.get("StackResources")
    if type(rows) is not list or len(rows) != len(resource_names):
        return None
    found: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            return None
        name = row.get("LogicalResourceId")
        if type(name) is not str or name not in resource_names or name in found:
            return None
        if row.get("ResourceType") != resource_names[name] or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
            return None
        physical = row.get("PhysicalResourceId")
        if type(physical) is not str or not physical or len(physical) > 1024:
            return None
        found[name] = row
    return found if set(found) == set(resource_names) else None


def _permission_statement_valid(statement: Any, *, account: str, api_id: str, source_path: str, function_arn: str) -> bool:
    if not isinstance(statement, Mapping):
        return False
    arn = f"arn:aws:execute-api:{_REGION}:{account}:{api_id}/$default/{source_path}"
    principal = statement.get("Principal")
    condition = statement.get("Condition")
    return (
        set(statement) == {"Sid", "Effect", "Action", "Resource", "Principal", "Condition"}
        and type(statement.get("Sid")) is str and bool(statement["Sid"])
        and statement.get("Effect") == "Allow"
        and statement.get("Action") == "lambda:InvokeFunction"
        and statement.get("Resource") == function_arn
        and principal == {"Service": "apigateway.amazonaws.com"}
        and condition == {"StringEquals": {"AWS:SourceAccount": account}, "ArnLike": {"AWS:SourceArn": arn}}
    )


def check_dev_runtime_readback(
    clients: Mapping[str, Any],
    *,
    state: Mapping[str, Any],
    expected_account_id: str,
    expected_template: Mapping[str, Any],
    resource_contract: str = "standalone16",
) -> RuntimeReadback:
    """Check a fixed runtime contract with at most ten reads.

    ``standalone16`` is the unchanged default. ``shared_identity14`` is an
    explicit alternative that omits only the dev-owned pool and domain; it
    still requires the caller's validated literal pool/client binding.
    """
    required = {"cloudformation", "apigatewayv2", "lambda"}
    if resource_contract == "standalone16":
        resource_names = _NAMES
    elif resource_contract == "shared_identity14":
        resource_names = _SHARED_IDENTITY_NAMES
    else:
        return RuntimeReadback(False, "runtime_readback_inputs_invalid", 0)
    if not _input_valid(state, expected_account_id, expected_template, resource_names) or not isinstance(clients, Mapping) or not required <= clients.keys():
        return RuntimeReadback(False, "runtime_readback_inputs_invalid", 0)
    calls = 0

    def call(service: str, method: str, **kwargs: Any) -> Mapping[str, Any] | None:
        nonlocal calls
        calls += 1
        try:
            result = getattr(clients[service], method)(**kwargs)
        except Exception:
            raise
        if not _metadata_ok(result):
            raise ValueError("readback_response_invalid")
        return result

    try:
        stack_arn = state["app_stack_id"]
        stack_reply = call("cloudformation", "describe_stacks", StackName=stack_arn)
        stacks = stack_reply.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            return RuntimeReadback(False, "stack_readback_invalid", calls)
        stack = stacks[0]
        tags = stack.get("Tags")
        if (
            stack.get("StackId") != stack_arn or stack.get("StackName") != _STACK
            or stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or type(tags) is not list
            or not any(isinstance(tag, Mapping) and tag.get("Key") == _RUN_TAG and tag.get("Value") == state["run_id"] for tag in tags)
            or stack.get("RoleARN") not in (None, "")
        ):
            return RuntimeReadback(False, "stack_identity_unverified", calls)
        outputs = stack.get("Outputs")
        output_map = {item.get("OutputKey"): item.get("OutputValue") for item in outputs if isinstance(item, Mapping)} if type(outputs) is list else None
        if output_map != {"ApiId": state["api_id"], "UserPoolId": state["user_pool_id"], "McpClientId": state["oauth_setup_client_id"]}:
            return RuntimeReadback(False, "stack_outputs_mismatch", calls)

        resource_reply = call("cloudformation", "describe_stack_resources", StackName=stack_arn)
        resources = _resources_valid(resource_reply, resource_names)
        if resources is None:
            return RuntimeReadback(False, "stack_resources_invalid", calls, stack_verified=True)
        if (
            resources["McpApi"].get("PhysicalResourceId") != state["api_id"]
            or ("McpUserPool" in resources and resources["McpUserPool"].get("PhysicalResourceId") != state["user_pool_id"])
            or resources["McpUserPoolClient"].get("PhysicalResourceId") != state["oauth_setup_client_id"]
            or resources["McpHandler"].get("PhysicalResourceId") != "honda-mapit-mcp-dev-handler"
            or resources["McpHandlerRole"].get("PhysicalResourceId") != "honda-mapit-mcp-dev-handler-role"
            or resources["McpHandlerLogGroup"].get("PhysicalResourceId") != "/aws/lambda/honda-mapit-mcp-dev-handler"
        ):
            return RuntimeReadback(False, "resource_identity_mismatch", calls, True)

        template_reply = call("cloudformation", "get_template", StackName=stack_arn, TemplateStage="Original")
        actual_template = _parse_json_object(template_reply.get("TemplateBody"))
        if actual_template is None or _json_bytes(actual_template) != _json_bytes(expected_template):
            return RuntimeReadback(False, "template_readback_mismatch", calls, True, True)

        api_id = state["api_id"]
        api_reply = call("apigatewayv2", "get_api", ApiId=api_id)
        if api_reply.get("ApiId") != api_id or api_reply.get("Name") != "honda-mapit-mcp-dev-api":
            return RuntimeReadback(False, "api_readback_invalid", calls, True, True)
        if api_reply.get("DisableExecuteApiEndpoint") is not True:
            return RuntimeReadback(False, "api_not_closed", calls, True, True)

        authorizer_reply = call("apigatewayv2", "get_authorizers", ApiId=api_id, MaxResults="100")
        authorizers = authorizer_reply.get("Items")
        if type(authorizers) is not list or authorizer_reply.get("NextToken") not in (None, "") or len(authorizers) != 1 or not isinstance(authorizers[0], Mapping):
            return RuntimeReadback(False, "authorizer_readback_invalid", calls, True, True, True)
        authorizer = authorizers[0]
        authorizer_id = authorizer.get("AuthorizerId")
        resource_uri = expected_template.get("Parameters", {}).get("McpResourceUri", {}).get("Default")
        expected_issuer = f"https://cognito-idp.{_REGION}.amazonaws.com/{state['user_pool_id']}"
        if (
            type(authorizer_id) is not str or not authorizer_id or len(authorizer_id) > 128
            or authorizer.get("AuthorizerType") != "JWT"
            or authorizer.get("IdentitySource") != ["$request.header.Authorization"]
            or authorizer.get("JwtConfiguration") != {"Issuer": expected_issuer, "Audience": [resource_uri]}
        ):
            return RuntimeReadback(False, "authorizer_mismatch", calls, True, True, True)
        if resources["McpJwtAuthorizer"].get("PhysicalResourceId") != authorizer_id:
            return RuntimeReadback(False, "authorizer_resource_mismatch", calls, True, True, True)

        integration_reply = call("apigatewayv2", "get_integrations", ApiId=api_id, MaxResults="100")
        integrations = integration_reply.get("Items")
        if type(integrations) is not list or integration_reply.get("NextToken") not in (None, "") or len(integrations) != 1 or not isinstance(integrations[0], Mapping):
            return RuntimeReadback(False, "integration_readback_invalid", calls, True, True, True, authorizer_verified=True)
        integration = integrations[0]
        integration_id = integration.get("IntegrationId")
        fn_reply = call("lambda", "get_function", FunctionName="honda-mapit-mcp-dev-handler")
        configuration = fn_reply.get("Configuration")
        function_arn = configuration.get("FunctionArn") if isinstance(configuration, Mapping) else None
        expected_function_arn = (
            f"arn:aws:lambda:{_REGION}:{expected_account_id}:function:honda-mapit-mcp-dev-handler"
        )
        if type(integration_id) is not str or not integration_id or (
            integration.get("IntegrationType") != "AWS_PROXY"
            or integration.get("IntegrationMethod") != "POST"
            or integration.get("PayloadFormatVersion") != "2.0"
            or integration.get("TimeoutInMillis") != 20000
            or function_arn != expected_function_arn
            or integration.get("IntegrationUri") != (
                f"arn:aws:apigateway:{_REGION}:lambda:path/2015-03-31/functions/{expected_function_arn}/invocations"
            )
            or resources["McpLambdaIntegration"].get("PhysicalResourceId") != integration_id
        ):
            return RuntimeReadback(False, "integration_mismatch", calls, True, True, True, authorizer_verified=True)

        routes_reply = call("apigatewayv2", "get_routes", ApiId=api_id, MaxResults="100")
        routes = routes_reply.get("Items")
        if type(routes) is not list or routes_reply.get("NextToken") not in (None, "") or len(routes) != 2:
            return RuntimeReadback(False, "routes_readback_invalid", calls, True, True, True, authorizer_verified=True, integration_verified=True)
        by_key = {route.get("RouteKey"): route for route in routes if isinstance(route, Mapping)}
        post = by_key.get("POST /mcp")
        metadata = by_key.get(f"GET {_METADATA_PATH}")
        post_id = post.get("RouteId") if isinstance(post, Mapping) else None
        metadata_id = metadata.get("RouteId") if isinstance(metadata, Mapping) else None
        if (
            len(by_key) != 2 or type(post_id) is not str or type(metadata_id) is not str or post_id == metadata_id
            or post.get("AuthorizationType") != "JWT" or post.get("AuthorizerId") != authorizer_id
            or post.get("AuthorizationScopes") != [f"{resource_uri}/use"]
            or post.get("Target") != f"integrations/{integration_id}"
            or metadata.get("AuthorizationType") != "NONE"
            or metadata.get("Target") != f"integrations/{integration_id}"
            or resources["McpPostRoute"].get("PhysicalResourceId") != post_id
            or resources["McpProtectedResourceMetadataRoute"].get("PhysicalResourceId") != metadata_id
        ):
            return RuntimeReadback(False, "routes_mismatch", calls, True, True, True, authorizer_verified=True, integration_verified=True)

        function_props = expected_template["Resources"]["McpHandler"]["Properties"]
        expected_code = function_props["Code"]["S3Key"]
        digest_hex = expected_code[len("runtime/"):-len(".zip")]
        expected_code_sha = base64.b64encode(bytes.fromhex(digest_hex)).decode("ascii")
        if (
            configuration.get("Handler") != function_props.get("Handler")
            or configuration.get("CodeSha256") != expected_code_sha
            or configuration.get("Environment") != function_props.get("Environment")
        ):
            return RuntimeReadback(False, "lambda_binding_mismatch", calls, True, True, True, True, True)
        concurrency = call("lambda", "get_function_concurrency", FunctionName="honda-mapit-mcp-dev-handler")
        if type(concurrency.get("ReservedConcurrentExecutions")) is not int or concurrency["ReservedConcurrentExecutions"] != 0:
            return RuntimeReadback(False, "lambda_concurrency_not_closed", calls, True, True, True, True, True, True, True, False)
        policy_reply = call("lambda", "get_policy", FunctionName="honda-mapit-mcp-dev-handler")
        policy = _parse_json_object(policy_reply.get("Policy"), 64 * 1024)
        statements = policy.get("Statement") if policy is not None else None
        if type(statements) is not list or len(statements) != 2:
            return RuntimeReadback(False, "invoke_permissions_invalid", calls, True, True, True, True, True, True, True, True)
        post_path = "POST/mcp"
        metadata_path = f"GET/{_METADATA_PATH.lstrip('/')}"
        valid = [
            _permission_statement_valid(item, account=expected_account_id, api_id=api_id, source_path=post_path, function_arn=function_arn)
            for item in statements
        ]
        valid_meta = [
            _permission_statement_valid(item, account=expected_account_id, api_id=api_id, source_path=metadata_path, function_arn=function_arn)
            for item in statements
        ]
        if sum(valid) != 1 or sum(valid_meta) != 1:
            return RuntimeReadback(False, "invoke_permissions_mismatch", calls, True, True, True, True, True, True, True, True)
        return RuntimeReadback(
            True, "runtime_readback_verified", calls, True, True, True, True, True, True, True, True, True,
            authorizer_id, integration_id, post_id, metadata_id,
        )
    except Exception:
        return RuntimeReadback(False, "runtime_readback_failed", calls)


__all__ = ["RuntimeReadback", "check_dev_runtime_readback"]
