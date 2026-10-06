"""Pure, injected readback checks for the retained-dev multi-user roles.

This module deliberately does not construct SDK clients.  A caller supplies a
reviewed four-resource IAM template and an injected IAM client.  The verifier
performs only bounded GET-style reads and returns a fixed, redacted result.
It is a readback helper, not an activation or deployment operator.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any

from scripts.aws_retained_dev_role_bootstrap import _canonical, _document
from scripts.build_aws_dev_oauth_template import _validate_callback

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained-cd-delivery"
EXECUTOR_ROLE_NAME = "honda-mapit-mcp-dev-retained-cd-executor"
CFN_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
_ROLE_LOGICALS = {
    "RetainedDevCdExecutorRole": EXECUTOR_ROLE_NAME,
    "RetainedDevCdCloudFormationRole": CFN_ROLE_NAME,
}
_BOUNDARY_LOGICALS = {
    "RetainedDevCdExecutorBoundary": f"{EXECUTOR_ROLE_NAME}-boundary",
    "RetainedDevCdCloudFormationBoundary": f"{CFN_ROLE_NAME}-boundary",
}
_RESOURCE_TYPES = {
    **{name: "AWS::IAM::Role" for name in _ROLE_LOGICALS},
    **{name: "AWS::IAM::ManagedPolicy" for name in _BOUNDARY_LOGICALS},
}
_ACCOUNT_RE = re.compile(r"[0-9]{12}\Z")
_VERSION_RE = re.compile(r"v[1-9][0-9]{0,2}\Z")
_STACK_RE = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/"
    rf"{re.escape(STACK_NAME)}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}\Z"
)
_SETUP_STACK_RE = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/"
    rf"honda-mapit-mcp-dev-retained/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}}\Z"
)
_CATEGORIES = frozenset({
    "clients_invalid", "template_invalid", "binding_invalid", "budget_exceeded",
    "aws_call_failed", "aws_response_invalid", "role_readback_mismatch",
    "boundary_readback_mismatch", "role_pair_verified",
})
MAX_CALLS = 32


class DevMultiuserReadbackError(ValueError):
    """Stable, non-sensitive readback category."""

    def __init__(self, category: str) -> None:
        self.category = category if category in _CATEGORIES else "aws_response_invalid"
        super().__init__(self.category)


def _ok(response: Any) -> bool:
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    return (
        isinstance(metadata, Mapping)
        and type(metadata.get("HTTPStatusCode")) is int
        and metadata.get("HTTPStatusCode") == 200
    )


def _no_pagination(response: Mapping[str, Any]) -> bool:
    if response.get("NextToken") not in (None, "") or response.get("Marker") not in (None, ""):
        return False
    if "IsTruncated" in response and response["IsTruncated"] is not False:
        return False
    return True


def _exact_tags(value: Any, expected: Mapping[str, str]) -> bool:
    if isinstance(value, Mapping):
        return all(type(key) is str and type(item) is str for key, item in value.items()) and dict(value) == dict(expected)
    if not isinstance(value, list) or len(value) != len(expected):
        return False
    seen: dict[str, str] = {}
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {"Key", "Value"}:
            return False
        if type(row["Key"]) is not str or type(row["Value"]) is not str:
            return False
        if row["Key"] in seen:
            return False
        seen[row["Key"]] = row["Value"]
    return seen == dict(expected)


def _stack_tags(*, run_id: int) -> dict[str, str]:
    """Return the exact user-managed tags exposed by IAM ListRoleTags.

    CloudFormation system tags are not returned for these IAM roles, so they
    are intentionally not treated as part of the role ownership proof.
    """
    return {
        "Project": "honda-mapit-mcp",
        "Environment": "dev",
        "Purpose": "CDDeliveryRetainedDev",
        "OperatorRunId": str(run_id),
    }


def _validate_template(template: Any) -> dict[str, Mapping[str, Any]]:
    if not isinstance(template, Mapping) or not isinstance(template.get("Resources"), Mapping):
        raise DevMultiuserReadbackError("template_invalid")
    resources = template["Resources"]
    if set(resources) != set(_RESOURCE_TYPES):
        raise DevMultiuserReadbackError("template_invalid")
    out: dict[str, Mapping[str, Any]] = {}
    for logical, resource_type in _RESOURCE_TYPES.items():
        resource = resources.get(logical)
        if not isinstance(resource, Mapping) or resource.get("Type") != resource_type:
            raise DevMultiuserReadbackError("template_invalid")
        props = resource.get("Properties")
        if not isinstance(props, Mapping):
            raise DevMultiuserReadbackError("template_invalid")
        if resource_type == "AWS::IAM::Role":
            required = {"RoleName", "Description", "MaxSessionDuration", "PermissionsBoundary", "AssumeRolePolicyDocument", "Policies", "Tags"}
            if set(props) != required or props.get("RoleName") != _ROLE_LOGICALS[logical]:
                raise DevMultiuserReadbackError("template_invalid")
            if props.get("MaxSessionDuration") != 3600:
                raise DevMultiuserReadbackError("template_invalid")
            boundary = props.get("PermissionsBoundary")
            expected_boundary = "RetainedDevCdExecutorBoundary" if logical.endswith("ExecutorRole") else "RetainedDevCdCloudFormationBoundary"
            if boundary != {"Fn::GetAtt": [expected_boundary, "PolicyArn"]}:
                raise DevMultiuserReadbackError("template_invalid")
            policies = props.get("Policies")
            if not isinstance(policies, list) or len(policies) != 1 or not isinstance(policies[0], Mapping):
                raise DevMultiuserReadbackError("template_invalid")
            if set(policies[0]) != {"PolicyName", "PolicyDocument"} or policies[0].get("PolicyName") != f"{_ROLE_LOGICALS[logical]}-policy":
                raise DevMultiuserReadbackError("template_invalid")
            if _document(props.get("AssumeRolePolicyDocument")) is None or _document(policies[0].get("PolicyDocument")) is None:
                raise DevMultiuserReadbackError("template_invalid")
            if not _exact_tags(props.get("Tags"), {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "CDDeliveryRetainedDev"}):
                raise DevMultiuserReadbackError("template_invalid")
        else:
            required = {"ManagedPolicyName", "Description", "PolicyDocument"}
            if set(props) != required or props.get("ManagedPolicyName") != _BOUNDARY_LOGICALS[logical]:
                raise DevMultiuserReadbackError("template_invalid")
            if _document(props.get("PolicyDocument")) is None:
                raise DevMultiuserReadbackError("template_invalid")
        out[logical] = resource
    return out


class _Reader:
    def __init__(self, client: Any, account: str, *, max_calls: int = MAX_CALLS) -> None:
        if client is None:
            raise DevMultiuserReadbackError("clients_invalid")
        if type(max_calls) is not int or isinstance(max_calls, bool) or max_calls <= 0 or max_calls > MAX_CALLS:
            raise DevMultiuserReadbackError("budget_exceeded")
        self.client = client
        self.account = account
        self.max_calls = max_calls
        self.calls = 0

    def get(self, method: str, **kwargs: Any) -> Mapping[str, Any]:
        if self.calls >= self.max_calls:
            raise DevMultiuserReadbackError("budget_exceeded")
        function = getattr(self.client, method, None)
        if not callable(function):
            raise DevMultiuserReadbackError("clients_invalid")
        self.calls += 1
        try:
            response = function(**kwargs)
        except Exception:
            raise DevMultiuserReadbackError("aws_call_failed") from None
        if not _ok(response) or not _no_pagination(response):
            raise DevMultiuserReadbackError("aws_response_invalid")
        return response


def verify_role_pair(
    clients: Mapping[str, Any],
    template: Mapping[str, Any],
    *,
    account: str,
    roles_stack_arn: str,
    original_creation_run_id: int,
    max_calls: int = MAX_CALLS,
) -> dict[str, Any]:
    """Verify both retained-dev IAM roles and their two boundaries.

    All identifiers are inputs to strict comparisons only; they are never
    included in the returned result or exception text.
    """
    calls = 0
    reader: _Reader | None = None
    try:
        if not isinstance(clients, Mapping) or set(clients) != {"iam"}:
            raise DevMultiuserReadbackError("clients_invalid")
        if type(account) is not str or _ACCOUNT_RE.fullmatch(account) is None or account == "000000000000":
            raise DevMultiuserReadbackError("binding_invalid")
        if type(roles_stack_arn) is not str or _STACK_RE.fullmatch(roles_stack_arn) is None or roles_stack_arn.split(":")[4] != account:
            raise DevMultiuserReadbackError("binding_invalid")
        if type(original_creation_run_id) is not int or isinstance(original_creation_run_id, bool) or original_creation_run_id <= 0:
            raise DevMultiuserReadbackError("binding_invalid")
        resources = _validate_template(template)
        reader = _Reader(clients["iam"], account, max_calls=max_calls)
        for logical, role_name in _ROLE_LOGICALS.items():
            properties = resources[logical]["Properties"]
            expected_arn = f"arn:aws:iam::{account}:role/{role_name}"
            role_response = reader.get("get_role", RoleName=role_name)
            role = role_response.get("Role")
            if not isinstance(role, Mapping) or role.get("RoleName") != role_name or role.get("Arn") != expected_arn or role.get("Path") != "/" or role.get("MaxSessionDuration") != 3600:
                raise DevMultiuserReadbackError("role_readback_mismatch")
            if _canonical(_document(role.get("AssumeRolePolicyDocument"))) != _canonical(_document(properties["AssumeRolePolicyDocument"])):
                raise DevMultiuserReadbackError("role_readback_mismatch")
            boundary = role.get("PermissionsBoundary")
            boundary_name = _BOUNDARY_LOGICALS["RetainedDevCdExecutorBoundary" if logical.endswith("ExecutorRole") else "RetainedDevCdCloudFormationBoundary"]
            expected_boundary = f"arn:aws:iam::{account}:policy/{boundary_name}"
            if not isinstance(boundary, Mapping) or boundary.get("PermissionsBoundaryArn") != expected_boundary or boundary.get("PermissionsBoundaryType") not in {"Policy", "PermissionsBoundaryPolicy"}:
                raise DevMultiuserReadbackError("role_readback_mismatch")
            policies = reader.get("list_role_policies", RoleName=role_name).get("PolicyNames")
            policy_name = f"{role_name}-policy"
            if policies != [policy_name]:
                raise DevMultiuserReadbackError("role_readback_mismatch")
            inline = reader.get("get_role_policy", RoleName=role_name, PolicyName=policy_name)
            expected_doc = properties["Policies"][0]["PolicyDocument"]
            if inline.get("RoleName") != role_name or inline.get("PolicyName") != policy_name or _canonical(_document(inline.get("PolicyDocument"))) != _canonical(_document(expected_doc)):
                raise DevMultiuserReadbackError("role_readback_mismatch")
            attached = reader.get("list_attached_role_policies", RoleName=role_name)
            if attached.get("AttachedPolicies") != []:
                raise DevMultiuserReadbackError("role_readback_mismatch")
            tags = reader.get("list_role_tags", RoleName=role_name).get("Tags")
            if not _exact_tags(tags, _stack_tags(run_id=original_creation_run_id)):
                raise DevMultiuserReadbackError("role_readback_mismatch")
        for logical, boundary_name in _BOUNDARY_LOGICALS.items():
            policy_arn = f"arn:aws:iam::{account}:policy/{boundary_name}"
            policy = reader.get("get_policy", PolicyArn=policy_arn).get("Policy")
            properties = resources[logical]["Properties"]
            default_version = policy.get("DefaultVersionId") if isinstance(policy, Mapping) else None
            if not isinstance(policy, Mapping) or policy.get("PolicyName") != boundary_name or policy.get("Path") != "/" or policy.get("Arn") != policy_arn or policy.get("IsAttachable") is not True or type(policy.get("AttachmentCount")) is not int or isinstance(policy.get("AttachmentCount"), bool) or policy.get("AttachmentCount") != 0 or type(policy.get("PermissionsBoundaryUsageCount")) is not int or isinstance(policy.get("PermissionsBoundaryUsageCount"), bool) or policy.get("PermissionsBoundaryUsageCount") != 1 or type(default_version) is not str or _VERSION_RE.fullmatch(default_version) is None:
                raise DevMultiuserReadbackError("boundary_readback_mismatch")
            version = reader.get("get_policy_version", PolicyArn=policy_arn, VersionId=default_version).get("PolicyVersion")
            if not isinstance(version, Mapping) or version.get("VersionId", default_version) != default_version or version.get("IsDefaultVersion") is not True or _canonical(_document(version.get("Document"))) != _canonical(_document(properties["PolicyDocument"])):
                raise DevMultiuserReadbackError("boundary_readback_mismatch")
        calls = reader.calls
        return {"success": True, "category": "role_pair_verified", "calls": calls}
    except DevMultiuserReadbackError as exc:
        return {"success": False, "category": exc.category, "calls": reader.calls if reader is not None else calls}
    except Exception:
        return {"success": False, "category": "aws_response_invalid", "calls": reader.calls if reader is not None else calls}


_SETUP_RESOURCE_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerRole": "AWS::IAM::Role", "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandler": "AWS::Lambda::Function", "McpUserPool": "AWS::Cognito::UserPool",
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
    "McpTenantsTable": "AWS::DynamoDB::Table",
}
_TABLE_NAME = "honda-mapit-mcp-dev-tenants"
_API_NAME = "honda-mapit-mcp-dev-retained-api"
_FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
_ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
_LOG_GROUP = "/aws/lambda/honda-mapit-mcp-dev-retained-handler"
_POOL_RE = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_API_RE = re.compile(r"[a-z0-9]{10}\Z")
_CLIENT_RE = re.compile(r"[A-Za-z0-9]{1,128}\Z")
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def _branding_id_matches(physical: Any, pool_id: str, returned: Any) -> bool:
    if type(returned) is not str or _UUID_RE.fullmatch(returned) is None:
        return False
    return physical == returned or physical == f"{pool_id}|{returned}"


def _setup_result(category: str, calls: int, **facts: Any) -> dict[str, Any]:
    return {"success": category == "setup_readback_verified", "category": category, "calls": calls, **facts}


def verify_closed_setup(
    clients: Mapping[str, Any], *, account: str, stack_arn: str, api_id: str,
    user_pool_id: str, client_id: str, callback_url: str,
    original_creation_run_id: int, table_arn: str | None = None,
    max_calls: int = 24,
    verified_rollback: bool = False,
) -> dict[str, Any]:
    """Verify the closed eleven-resource multi-user setup using injected reads.

    This is intentionally separate from the IAM role verifier.  It never lists
    users/clients, reads secrets, discovers resources, or invokes a write API.
    """
    calls = 0
    try:
        if type(verified_rollback) is not bool:
            return _setup_result("binding_invalid", 0)
        if not isinstance(clients, Mapping) or set(clients) != {"cloudformation", "cognito", "apigateway", "dynamodb"} or any(clients[key] is None for key in clients):
            return _setup_result("clients_invalid", 0)
        if type(max_calls) is not int or isinstance(max_calls, bool) or max_calls <= 0 or max_calls > 24:
            return _setup_result("binding_invalid", 0)
        if type(account) is not str or _ACCOUNT_RE.fullmatch(account) is None or account == "000000000000":
            return _setup_result("binding_invalid", 0)
        try:
            callback_url = _validate_callback(callback_url)
        except Exception:
            return _setup_result("binding_invalid", 0)
        if type(api_id) is not str or _API_RE.fullmatch(api_id) is None or type(user_pool_id) is not str or _POOL_RE.fullmatch(user_pool_id) is None or type(client_id) is not str or _CLIENT_RE.fullmatch(client_id) is None:
            return _setup_result("binding_invalid", 0)
        stack_match = _SETUP_STACK_RE.fullmatch(stack_arn) if type(stack_arn) is str else None
        expected_table_arn = table_arn or f"arn:aws:dynamodb:{REGION}:{account}:table/{_TABLE_NAME}"
        if stack_match is None or stack_match.group(1) != account or type(expected_table_arn) is not str or expected_table_arn != f"arn:aws:dynamodb:{REGION}:{account}:table/{_TABLE_NAME}":
            return _setup_result("binding_invalid", 0)
        if type(original_creation_run_id) is not int or isinstance(original_creation_run_id, bool) or original_creation_run_id <= 0:
            return _setup_result("binding_invalid", 0)
        resource_uri = f"https://{api_id}.execute-api.{REGION}.amazonaws.com/mcp"
        expected_domain = f"honda-mapit-mcp-dev-multiuser-{account}"

        def call(client: Any, method: str, **kwargs: Any) -> Mapping[str, Any] | None:
            nonlocal calls
            if calls >= max_calls:
                raise DevMultiuserReadbackError("budget_exceeded")
            function = getattr(client, method, None)
            if not callable(function):
                raise DevMultiuserReadbackError("clients_invalid")
            calls += 1
            try:
                response = function(**kwargs)
            except Exception:
                raise DevMultiuserReadbackError("aws_call_failed") from None
            if not _ok(response) or not _no_pagination(response):
                raise DevMultiuserReadbackError("aws_response_invalid")
            return response

        stack_response = call(clients["cloudformation"], "describe_stacks", StackName=stack_arn)
        stacks = stack_response.get("Stacks")
        if not isinstance(stacks, list) or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            return _setup_result("setup_stack_mismatch", calls)
        stack = stacks[0]
        allowed_statuses = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
        if verified_rollback:
            allowed_statuses.add("UPDATE_ROLLBACK_COMPLETE")
        if stack.get("StackId") != stack_arn or stack.get("StackName") != "honda-mapit-mcp-dev-retained" or stack.get("StackStatus") not in allowed_statuses:
            return _setup_result("setup_stack_mismatch", calls)
        stack_tags = stack.get("Tags")
        required_stack_tags = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": str(original_creation_run_id)}
        if not isinstance(stack_tags, list) or not all(any(isinstance(row, Mapping) and row.get("Key") == key and row.get("Value") == value for row in stack_tags) for key, value in required_stack_tags.items()):
            return _setup_result("setup_ownership_mismatch", calls)

        records = call(clients["cloudformation"], "describe_stack_resources", StackName=stack_arn).get("StackResources")
        if not isinstance(records, list) or len(records) != 11:
            return _setup_result("setup_resources_mismatch", calls)
        resource_map: dict[str, Mapping[str, Any]] = {}
        for row in records:
            if not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str or row["LogicalResourceId"] in resource_map or row["LogicalResourceId"] not in _SETUP_RESOURCE_TYPES or row.get("ResourceType") != _SETUP_RESOURCE_TYPES[row["LogicalResourceId"]] or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]:
                return _setup_result("setup_resources_mismatch", calls)
            resource_map[row["LogicalResourceId"]] = row
        expected_resource_ids = {
            "McpApi": api_id,
            # The deployed default stage is represented by its literal stage
            # name, not an arbitrary API/stage-looking identifier.
            "McpApiStage": "$default",
            "McpHandlerRole": _ROLE_NAME,
            "McpHandlerLogGroup": _LOG_GROUP,
            "McpHandler": _FUNCTION_NAME,
            "McpUserPool": user_pool_id,
            "McpUserPoolDomain": expected_domain,
            # CloudFormation's primary identifier may be surfaced either as
            # the Cognito identifier or as UserPoolId|Identifier.  Both are
            # bound to this exact pool and resource URI; arbitrary physical
            # identifiers remain rejected.
            "McpResourceServer": {resource_uri, f"{user_pool_id}|{resource_uri}"},
            "McpUserPoolClient": client_id,
            "McpTenantsTable": _TABLE_NAME,
        }
        if (set(resource_map) != set(_SETUP_RESOURCE_TYPES)
            or any(
                resource_map[key].get("PhysicalResourceId") not in value
                if isinstance(value, set)
                else resource_map[key].get("PhysicalResourceId") != value
                for key, value in expected_resource_ids.items()
            )):
            return _setup_result("setup_resource_identity_mismatch", calls)

        api = call(clients["apigateway"], "get_api", ApiId=api_id)
        if api.get("ApiId") != api_id or api.get("Name") != _API_NAME or api.get("DisableExecuteApiEndpoint") is not True:
            return _setup_result("api_readback_mismatch", calls)
        routes = call(clients["apigateway"], "get_routes", ApiId=api_id, MaxResults="100")
        if routes.get("Items") != [] or routes.get("NextToken") not in (None, ""):
            return _setup_result("api_routes_mismatch", calls)

        pool = call(clients["cognito"], "describe_user_pool", UserPoolId=user_pool_id).get("UserPool")
        admin_config = pool.get("AdminCreateUserConfig") if isinstance(pool, Mapping) else None
        email_config = pool.get("EmailConfiguration") if isinstance(pool, Mapping) else None
        pool_tags = pool.get("UserPoolTags") if isinstance(pool, Mapping) else None
        pool_tag_expected = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": str(original_creation_run_id), "aws:cloudformation:stack-id": stack_arn, "aws:cloudformation:stack-name": "honda-mapit-mcp-dev-retained", "aws:cloudformation:logical-id": "McpUserPool"}
        admin_safe = isinstance(admin_config, Mapping) and admin_config.get("AllowAdminCreateUserOnly") is True and set(admin_config).issubset({"AllowAdminCreateUserOnly", "UnusedAccountValidityDays", "InviteMessageTemplate"}) and ("UnusedAccountValidityDays" not in admin_config or (type(admin_config["UnusedAccountValidityDays"]) is int and not isinstance(admin_config["UnusedAccountValidityDays"], bool) and 1 <= admin_config["UnusedAccountValidityDays"] <= 365)) and ("InviteMessageTemplate" not in admin_config or (isinstance(admin_config["InviteMessageTemplate"], Mapping) and all(type(value) is str and len(value) <= 4096 for value in admin_config["InviteMessageTemplate"].values())))
        pool_tier_safe = isinstance(pool, Mapping) and pool.get("UserPoolTier") == "ESSENTIALS"
        pool_addons = pool.get("UserPoolAddOns") if isinstance(pool, Mapping) else None
        pool_addons_safe = isinstance(pool, Mapping) and (
            "UserPoolAddOns" not in pool or pool_addons == {"AdvancedSecurityMode": "OFF"}
        )
        if not isinstance(pool, Mapping) or pool.get("Id") != user_pool_id or pool.get("Name") != "honda-mapit-mcp-dev-multiuser" or pool.get("MfaConfiguration") != "OFF" or not pool_tier_safe or not pool_addons_safe or not admin_safe or not _exact_tags(pool_tags, pool_tag_expected) or (email_config not in (None, {"EmailSendingAccount": "COGNITO_DEFAULT"})) or pool.get("SmsConfiguration") not in (None, {}):
            return _setup_result("cognito_pool_mismatch", calls)
        described = call(clients["cognito"], "describe_user_pool_client", UserPoolId=user_pool_id, ClientId=client_id).get("UserPoolClient")
        expected_client = {"UserPoolId": user_pool_id, "ClientId": client_id, "AllowedOAuthFlowsUserPoolClient": True, "AllowedOAuthFlows": ["code"], "AllowedOAuthScopes": [resource_uri + "/use"], "CallbackURLs": [callback_url], "DefaultRedirectURI": callback_url, "SupportedIdentityProviders": ["COGNITO"], "EnableTokenRevocation": True, "PreventUserExistenceErrors": "ENABLED", "AccessTokenValidity": 60, "IdTokenValidity": 60, "RefreshTokenValidity": 30, "TokenValidityUnits": {"AccessToken": "minutes", "IdToken": "minutes", "RefreshToken": "days"}}
        if not isinstance(described, Mapping) or "ClientSecret" in described or "GenerateSecret" in described or described.get("AnalyticsConfiguration") not in (None, {}) or any(described.get(key) != value for key, value in expected_client.items()):
            return _setup_result("cognito_client_mismatch", calls)
        server = call(clients["cognito"], "describe_resource_server", UserPoolId=user_pool_id, Identifier=resource_uri).get("ResourceServer")
        if not isinstance(server, Mapping) or server.get("UserPoolId") != user_pool_id or server.get("Identifier") != resource_uri or server.get("Scopes") != [{"ScopeName": "use", "ScopeDescription": "Read-only MCP access."}]:
            return _setup_result("cognito_resource_server_mismatch", calls)
        domain = call(clients["cognito"], "describe_user_pool_domain", Domain=expected_domain).get("DomainDescription")
        if not isinstance(domain, Mapping) or domain.get("Domain") != expected_domain or domain.get("UserPoolId") != user_pool_id or domain.get("AWSAccountId") != account or domain.get("Status") != "ACTIVE" or domain.get("ManagedLoginVersion") != 2 or domain.get("CustomDomainConfig") not in (None, {}):
            return _setup_result("cognito_domain_mismatch", calls)
        branding = call(clients["cognito"], "describe_managed_login_branding_by_client", UserPoolId=user_pool_id, ClientId=client_id).get("ManagedLoginBranding")
        if not isinstance(branding, Mapping) or branding.get("UserPoolId") != user_pool_id or branding.get("UseCognitoProvidedValues") is not True or not _branding_id_matches(resource_map["McpManagedLoginBranding"].get("PhysicalResourceId"), user_pool_id, branding.get("ManagedLoginBrandingId")):
            return _setup_result("cognito_branding_mismatch", calls)

        table = call(clients["dynamodb"], "describe_table", TableName=_TABLE_NAME).get("Table")
        billing = table.get("BillingModeSummary") if isinstance(table, Mapping) else None
        ondemand = table.get("OnDemandThroughput") if isinstance(table, Mapping) else None
        stream = table.get("StreamSpecification") if isinstance(table, Mapping) else None
        if not isinstance(table, Mapping) or table.get("TableName") != _TABLE_NAME or table.get("TableArn") != expected_table_arn or table.get("TableStatus") != "ACTIVE" or not isinstance(billing, Mapping) or billing.get("BillingMode") != "PAY_PER_REQUEST" or not isinstance(ondemand, Mapping) or ondemand.get("MaxReadRequestUnits") != 10 or ondemand.get("MaxWriteRequestUnits") != 1 or table.get("KeySchema") != [{"AttributeName": "key", "KeyType": "HASH"}] or table.get("AttributeDefinitions") != [{"AttributeName": "key", "AttributeType": "S"}] or table.get("GlobalSecondaryIndexes") not in (None, []) or table.get("LocalSecondaryIndexes") not in (None, []) or table.get("SSEDescription") is not None or (stream is not None and (not isinstance(stream, Mapping) or stream.get("StreamEnabled") is not False)):
            return _setup_result("dynamodb_table_mismatch", calls)
        tags = call(clients["dynamodb"], "list_tags_of_resource", ResourceArn=expected_table_arn).get("Tags")
        expected_tags = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "multiuser-authorization", "OperatorRunId": str(original_creation_run_id)}
        if not _exact_tags(tags, expected_tags):
            return _setup_result("dynamodb_tags_mismatch", calls)
        ttl = call(clients["dynamodb"], "describe_time_to_live", TableName=_TABLE_NAME).get("TimeToLiveDescription")
        if not isinstance(ttl, Mapping) or ttl.get("TimeToLiveStatus") != "DISABLED":
            return _setup_result("dynamodb_ttl_mismatch", calls)
        backups = call(clients["dynamodb"], "describe_continuous_backups", TableName=_TABLE_NAME).get("ContinuousBackupsDescription")
        if not isinstance(backups, Mapping) or backups.get("ContinuousBackupsStatus") != "ENABLED" or backups.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") != "DISABLED":
            return _setup_result("dynamodb_backups_mismatch", calls)
        return _setup_result("setup_readback_verified", calls, resources_verified=True, api_closed=True, cognito_verified=True, dynamodb_verified=True)
    except DevMultiuserReadbackError as exc:
        return _setup_result(exc.category, calls)
    except Exception:
        return _setup_result("aws_response_invalid", calls)


__all__ = ["verify_role_pair", "verify_closed_setup", "DevMultiuserReadbackError", "_document"]
