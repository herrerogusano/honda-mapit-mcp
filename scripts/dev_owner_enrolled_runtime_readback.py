"""Bounded current-state adapter for owner-enrolled DEV delivery.

This module is intentionally read-only. It composes the accepted owner OAuth,
MAPIT bootstrap/key-publication and invitation evidence with fresh AWS
readbacks; no receipt digest or caller-supplied boolean is treated as a live
readback. The accepted historical OAuth context is checked unchanged before
delivery. After delivery a new context digest is captured, while the owner
OAuth stack/client candidate is independently revalidated.

The adapter needs a registered ``DeliveryClientBundle`` and the established
runtime/namespace verifiers. It does not construct clients, publish artifacts,
update stacks, open the API, or establish MAPIT guest login acceptance.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from dataclasses import asdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Callable

from scripts.dev_owner_enrolled_delivery import (
    _CHECKS,
    _PRE_CHECKS,
    _SHA256,
    _STATE_FIELDS,
    _canonical,
    _strict_state,
    _validate_accepted,
    _validate_authority,
    _template_sha,
)
from scripts.dev_owner_enrolled_runtime import build_owner_enrolled_dev_runtime_target
from scripts.dev_owner_enrolled_delivery_sdk import (
    DeliveryClientBundle,
    _is_registered_client_bundle,
    _validate_clients,
)
from scripts.dev_owner_login_context import (
    AcceptedOwnerLoginContext,
    _ACCEPTED as _ACCEPTED_OWNER_CONTEXTS,
    verify_current_context,
)
from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings
from scripts.dev_owner_enrolled_namespace_readback import verify_published_namespace
from scripts.dev_mapit_runtime_evidence import (
    _load_bundle as _load_mapit_evidence_bundle,
    _validate_bundle as _validate_mapit_evidence_bundle,
    _validate_historical_bootstrap as _validate_historical_mapit_bootstrap,
    make_mapit_runtime_evidence_verifier,
    runtime_evidence_digest as _mapit_runtime_evidence_digest,
)
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_retained_dev_bootstrap import validate_private_location
from scripts.run_dev_mapit_binding_key_setup import _load_accepted_bootstrap
from scripts.dev_owner_enrolled_namespace_readback import _FIELDS as _PUBLICATION_FIELDS
from scripts.dev_owner_enrolled_observation import (
    make_capsule as _make_observation_capsule,
    progress_digest as _observation_progress_digest,
    runtime_evidence_digest as _runtime_evidence_digest_v2,
    sha256_json as _observation_sha256_json,
    validate_capsule_for_accepted_update as _validate_capsule_for_update,
    validate_observation_window as _validate_observation_window,
)


_REGION = "eu-west-1"
_STACK_NAME = "honda-mapit-mcp-dev-retained"
_ARTIFACT_STACK = "honda-mapit-mcp-dev-retained-runtime-artifacts"
_HANDLER = "honda-mapit-mcp-dev-retained-handler"
_ROLE = "honda-mapit-mcp-dev-retained-handler-role"
_AUTH_TABLE = "honda-mapit-mcp-dev-tenants"
_MAX_READS = 256
_MAX_SECONDS = 90.0
_LOGICAL_TYPES = {
    "McpApi": "AWS::ApiGatewayV2::Api",
    "McpApiStage": "AWS::ApiGatewayV2::Stage",
    "McpHandlerLogGroup": "AWS::Logs::LogGroup",
    "McpHandlerRole": "AWS::IAM::Role",
    "McpHandler": "AWS::Lambda::Function",
    "McpUserPool": "AWS::Cognito::UserPool",
    "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
    "McpUserPoolDomain": "AWS::Cognito::UserPoolDomain",
    "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
    "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
    "McpTenantsTable": "AWS::DynamoDB::Table",
    "McpJwtAuthorizer": "AWS::ApiGatewayV2::Authorizer",
    "McpLambdaIntegration": "AWS::ApiGatewayV2::Integration",
    "McpPostRoute": "AWS::ApiGatewayV2::Route",
    "McpProtectedResourceMetadataRoute": "AWS::ApiGatewayV2::Route",
    "McpAuthorizationServerMetadataRoute": "AWS::ApiGatewayV2::Route",
    "McpLambdaInvokePermission": "AWS::Lambda::Permission",
    "McpProtectedResourceMetadataInvokePermission": "AWS::Lambda::Permission",
    "McpAuthorizationServerMetadataInvokePermission": "AWS::Lambda::Permission",
}
_OPS = {
    "sts": {"get_caller_identity": frozenset()},
    "cloudformation": {
        "describe_stacks": frozenset({"StackName"}),
        "get_template": frozenset({"StackName", "TemplateStage"}),
        "describe_stack_resources": frozenset({"StackName"}),
        "list_stack_resources": frozenset({"StackName", "NextToken"}),
        "describe_stack_events": frozenset({"StackName", "NextToken"}),
    },
    "apigatewayv2": {
        "get_api": frozenset({"ApiId"}),
        "get_authorizers": frozenset({"ApiId", "MaxResults", "NextToken"}),
        "get_routes": frozenset({"ApiId", "MaxResults", "NextToken"}),
        "get_integrations": frozenset({"ApiId", "MaxResults", "NextToken"}),
    },
    "lambda": {
        "get_function": frozenset({"FunctionName"}),
        "get_function_configuration": frozenset({"FunctionName"}),
        "get_function_concurrency": frozenset({"FunctionName"}),
        "get_account_settings": frozenset(),
        "list_tags": frozenset({"Resource"}),
        "get_policy": frozenset({"FunctionName"}),
    },
    "iam": {
        "get_role": frozenset({"RoleName"}),
        "list_role_policies": frozenset({"RoleName", "Marker"}),
        "list_attached_role_policies": frozenset({"RoleName", "Marker"}),
        "get_role_policy": frozenset({"RoleName", "PolicyName"}),
        "get_policy": frozenset({"PolicyArn"}),
        "get_policy_version": frozenset({"PolicyArn", "VersionId"}),
    },
    "cognito": {
        "describe_user_pool": frozenset({"UserPoolId"}),
        "get_user_pool_mfa_config": frozenset({"UserPoolId"}),
        "list_user_pool_clients": frozenset({"UserPoolId", "MaxResults", "NextToken"}),
        "describe_user_pool_client": frozenset({"UserPoolId", "ClientId"}),
        "describe_resource_server": frozenset({"UserPoolId", "Identifier"}),
        "describe_user_pool_domain": frozenset({"Domain"}),
        "describe_managed_login_branding_by_client": frozenset({"UserPoolId", "ClientId", "ReturnMergedResources"}),
    },
    "dynamodb": {
        "get_item": frozenset({"TableName", "Key", "ConsistentRead", "ReturnConsumedCapacity"}),
        "describe_table": frozenset({"TableName"}),
        "describe_time_to_live": frozenset({"TableName"}),
        "describe_continuous_backups": frozenset({"TableName"}),
        "list_tags_of_resource": frozenset({"ResourceArn", "NextToken"}),
    },
    "ssm": {
        "describe_parameters": frozenset({"ParameterFilters", "MaxResults", "NextToken"}),
        "get_parameter": frozenset({"Name", "WithDecryption"}),
    },
    "kms": {"describe_key": frozenset({"KeyId"})},
    "s3": {
        "get_public_access_block": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_encryption": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_ownership_controls": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_versioning": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_location": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_policy_status": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_tagging": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_lifecycle_configuration": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "get_bucket_policy": frozenset({"Bucket", "ExpectedBucketOwner"}),
        "head_object": frozenset({"Bucket", "Key", "ChecksumMode", "ExpectedBucketOwner"}),
    },
}
_POLICY_NAMES = frozenset({
    "honda-mapit-mcp-dev-retained-owned-log-writes",
    "honda-mapit-mcp-dev-retained-tenant-read",
    "honda-mapit-mcp-dev-identity-bindings-runtime-read",
    "honda-mapit-mcp-dev-mapit-identity-bindings-runtime-read",
})
_SYNTHETIC_POLICY_NAME = "honda-mapit-mcp-dev-identity-bindings-runtime-read"


class OwnerEnrolledReadbackError(ValueError):
    """Fixed-category readback failure; never contains provider output."""

    def __init__(self, category: str = "current_state_unverified"):
        self.category = category if category in {"binding_invalid", "current_state_unverified", "read_budget_exhausted"} else "current_state_unverified"
        super().__init__(self.category)


def _fail(category: str = "current_state_unverified") -> None:
    raise OwnerEnrolledReadbackError(category)


def _status(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return (isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int
            and metadata["HTTPStatusCode"] == 200)


class _ReadBudget:
    def __init__(self, *, authority: Mapping[str, Any], clock, monotonic, max_calls: int,
                 observation_window: Mapping[str, Any] | None = None):
        self.authority = authority
        self.observation_window = observation_window
        self.clock, self.monotonic = clock, monotonic
        self.max_calls = max_calls
        self.calls = 0
        self.started = self.last = self._mono()
        self.last_wall = self._wall()

    def _wall(self) -> float:
        value = self.clock()
        if (type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value)):
            _fail("current_state_unverified")
        return float(value)

    def _mono(self) -> float:
        value = self.monotonic()
        if (type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value)):
            _fail("current_state_unverified")
        return float(value)

    def check(self):
        wall, mono = self._wall(), self._mono()
        start = (self.observation_window["authorized_from_epoch"]
                 if self.observation_window is not None else self.authority["authorized_from_epoch"])
        end = (self.observation_window["authorized_until_epoch"]
               if self.observation_window is not None else self.authority["authorized_until_epoch"])
        if (wall < self.last_wall or mono < self.last or mono - self.started >= _MAX_SECONDS
                or not start <= wall < end):
            _fail("current_state_unverified")
        self.last_wall, self.last = wall, mono

    def call(self, service: str, method: str, **kwargs):
        self.check()
        allowed = _OPS.get(service, {}).get(method)
        if allowed is None or not set(kwargs) <= allowed:
            _fail("current_state_unverified")
        if self.calls >= self.max_calls:
            _fail("read_budget_exhausted")
        self.calls += 1
        try:
            result = getattr(self.clients[service], method)(**kwargs)
        except Exception as exc:
            self.check()
            error = getattr(exc, "response", None)
            expected_path = (f"/honda-mapit-mcp/dev/tenants/"
                             f"{self.authority['owner_tenant_key']}/mapit-refresh-token")
            if (service == "ssm" and method == "get_parameter"
                    and kwargs == {"Name": expected_path, "WithDecryption": False}
                    and isinstance(error, Mapping)
                    and isinstance(error.get("Error"), Mapping)
                    and error["Error"].get("Code") == "ParameterNotFound"
                    and isinstance(error.get("ResponseMetadata"), Mapping)
                    and type(error["ResponseMetadata"].get("HTTPStatusCode")) is int
                    and error["ResponseMetadata"]["HTTPStatusCode"] == 400):
                # The owning namespace verifier must validate absence itself.
                # Preserve only this exact expected read exception, not a
                # generic provider failure or a decrypted secret response.
                raise
            _fail("current_state_unverified")
        self.check()
        if not _status(result):
            _fail("current_state_unverified")
        for marker in ("NextToken", "NextMarker", "Marker"):
            if marker in result and result[marker] not in (None, ""):
                # The only exception is the one capped first-page event scan,
                # which is validated for an exact root completion below.
                if service != "cloudformation" or method != "describe_stack_events":
                    _fail("current_state_unverified")
        return result


class _ClientView:
    def __init__(self, budget: _ReadBudget, service: str):
        self.budget, self.service = budget, service

    def __getattr__(self, method: str):
        if method == "meta":
            # Historical accepted-state parsers inspect pinned SDK metadata but
            # do not dispatch a request. All actual SDK methods still pass
            # through the shared read budget below.
            return self.budget.clients[self.service].meta
        if method not in _OPS.get(self.service, {}):
            _fail("current_state_unverified")
        return lambda **kwargs: self.budget.call(self.service, method, **kwargs)


class _ClientsView:
    def __init__(self, budget: _ReadBudget, clients):
        self._views = {name: _ClientView(budget, name) for name in clients}
        self._budget = budget

    def __getitem__(self, service):
        return self._views[service]


def _json_document(value: Any) -> dict[str, Any] | None:
    try:
        def unique(pairs):
            result = {}
            for key, item in pairs:
                if type(key) is not str or len(key) > 64 * 1024 or key in result:
                    raise ValueError
                result[key] = item
            return result

        nodes = 0
        encoded_bytes = 0

        def charge(size):
            nonlocal encoded_bytes
            encoded_bytes += size
            if encoded_bytes > 64 * 1024:
                raise ValueError

        def charge_scalar(node):
            if type(node) is int and node.bit_length() > 262144:
                raise ValueError
            charge(len(json.dumps(node, ensure_ascii=True, allow_nan=False,
                                  separators=(",", ":"))))

        def normalize(node, depth=0):
            nonlocal nodes
            nodes += 1
            if nodes > 32768 or depth > 64:
                raise ValueError
            if isinstance(node, Mapping):
                charge(2)
                result = {}
                for key, item in node.items():
                    if type(key) is not str or len(key) > 64 * 1024 or key in result:
                        raise ValueError
                    charge_scalar(key)
                    charge(1 + bool(result))
                    result[key] = normalize(item, depth + 1)
                return result
            if type(node) is list:
                charge(2)
                result = []
                for item in node:
                    charge(bool(result))
                    result.append(normalize(item, depth + 1))
                return result
            if type(node) is str:
                if len(node) > 64 * 1024:
                    raise ValueError
                charge_scalar(node)
                return node
            if node is None or type(node) in (bool, int):
                charge_scalar(node)
                return node
            if type(node) is float and math.isfinite(node):
                charge_scalar(node)
                return node
            raise ValueError

        if isinstance(value, Mapping):
            # Botocore returns nested OrderedDict for GetTemplate JSON values.
            # Normalize the entire document, not just its outermost mapping;
            # keep the exact-type checks in the downstream template verifier.
            parsed = normalize(value)
        elif type(value) is str and len(value.encode("utf-8")) <= 64 * 1024:
            parsed = normalize(json.loads(value, object_pairs_hook=unique,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError())))
        else:
            return None
        if type(parsed) is not dict or len(_canonical(parsed)) > 64 * 1024:
            return None
        return parsed
    except Exception:
        return None


def _resolve(node: Any, *, account: str, rows: Mapping[str, Mapping[str, Any]], table_arn: str):
    if type(node) is list:
        return [_resolve(v, account=account, rows=rows, table_arn=table_arn) for v in node]
    if isinstance(node, Mapping):
        if set(node) == {"Ref"}:
            name = node["Ref"]
            if name == "AWS::AccountId":
                return account
            if name == "AWS::Region":
                return _REGION
            if name == "AWS::Partition":
                return "aws"
            if name in rows:
                return rows[name]["PhysicalResourceId"]
            if name == "ObservedApiId":
                return rows["McpApi"]["PhysicalResourceId"]
            if name == "McpResourceIdentifier":
                return f"https://{rows['McpApi']['PhysicalResourceId']}.execute-api.{_REGION}.amazonaws.com/mcp"
            if name == "McpTenantsTable":
                return _AUTH_TABLE
            raise ValueError
        if set(node) == {"Fn::GetAtt"}:
            attribute = node["Fn::GetAtt"]
            if attribute == ["McpTenantsTable", "Arn"]:
                return table_arn
            if attribute == ["McpHandler", "Arn"]:
                return f"arn:aws:lambda:{_REGION}:{account}:function:{_HANDLER}"
            raise ValueError
        if set(node) == {"Fn::Sub"}:
            specification = node["Fn::Sub"]
            variables = {}
            if type(specification) is list and len(specification) == 2 and type(specification[0]) is str and isinstance(specification[1], Mapping):
                template, variables = specification
            else:
                template = specification
            if type(template) is not str:
                raise ValueError
            replacements = {"${AWS::AccountId}": account, "${AWS::Region}": _REGION,
                            "${AWS::Partition}": "aws",
                            "${McpApi}": rows["McpApi"]["PhysicalResourceId"],
                            "${McpUserPool}": rows["McpUserPool"]["PhysicalResourceId"],
                            "${McpResourceIdentifier}": f"https://{rows['McpApi']['PhysicalResourceId']}.execute-api.{_REGION}.amazonaws.com/mcp",
                            "${McpHandler.Arn}": f"arn:aws:lambda:{_REGION}:{account}:function:{_HANDLER}",
                            "${McpTenantsTable.Arn}": table_arn}
            for key, value in variables.items():
                if type(key) is not str or "${" in key:
                    raise ValueError
                replacements["${" + key + "}"] = _resolve(value, account=account, rows=rows, table_arn=table_arn)
            for key, value in replacements.items():
                template = template.replace(key, value)
            if "${" in template:
                raise ValueError
            return template
        if any(type(key) is str and (key == "Ref" or key.startswith("Fn::")) for key in node):
            raise ValueError
        return {key: _resolve(value, account=account, rows=rows, table_arn=table_arn)
                for key, value in node.items()}
    return node


def _stack_and_resources(view: _ClientsView, authority, expected_template):
    cfn = view["cloudformation"]
    stack_reply = cfn.describe_stacks(StackName=authority["stack_id"])
    stacks = stack_reply.get("Stacks")
    if type(stacks) is not list or len(stacks) != 1:
        _fail()
    stack = stacks[0]
    if (stack.get("StackId") != authority["stack_id"] or stack.get("StackName") != _STACK_NAME
            or stack.get("StackStatus") != "UPDATE_COMPLETE" or stack.get("EnableTerminationProtection") is not True
            or stack.get("RoleARN") != authority["service_role_arn"]):
        _fail()
    template_reply = cfn.get_template(StackName=authority["stack_id"], TemplateStage="Original")
    body = _json_document(template_reply.get("TemplateBody"))
    if body is None or body != expected_template:
        _fail()
    rows_reply = cfn.describe_stack_resources(StackName=authority["stack_id"])
    rows = rows_reply.get("StackResources")
    if type(rows) is not list or len(rows) != 19:
        _fail()
    by_name = {}
    for row in rows:
        if (not isinstance(row, Mapping) or row.get("StackId") != authority["stack_id"]
                or row.get("StackName") != _STACK_NAME or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                or type(row.get("LogicalResourceId")) is not str
                or type(row.get("PhysicalResourceId")) is not str or not row["PhysicalResourceId"]
                or row.get("ResourceType") != _LOGICAL_TYPES.get(row.get("LogicalResourceId"))
                or row["LogicalResourceId"] in by_name):
            _fail()
        by_name[row["LogicalResourceId"]] = dict(row)
    if set(by_name) != set(_LOGICAL_TYPES):
        _fail()
    if any(by_name[name]["PhysicalResourceId"] == "" for name in by_name):
        _fail()
    return stack, by_name


def _response_body(row, key):
    if not isinstance(row, Mapping) or not isinstance(row.get(key), Mapping):
        _fail()
    return row[key]


def _verify_api_and_lambda(view, authority, template, rows, zip_sha, *, accepted):
    props = template["Resources"]
    api_id = rows["McpApi"]["PhysicalResourceId"]
    api = view["apigatewayv2"].get_api(ApiId=api_id)
    expected_endpoint = f"https://{api_id}.execute-api.{_REGION}.amazonaws.com"
    if (api.get("ApiId") != api_id or api.get("DisableExecuteApiEndpoint") is not True
            or api.get("ApiEndpoint") != expected_endpoint):
        _fail()
    concurrency = view["lambda"].get_function_concurrency(FunctionName=_HANDLER)
    if (type(concurrency.get("ReservedConcurrentExecutions")) is not int
            or concurrency["ReservedConcurrentExecutions"] != 0):
        _fail()
    function = view["lambda"].get_function_configuration(FunctionName=_HANDLER)
    expected_handler = props["McpHandler"]["Properties"]
    if (rows["McpHandler"]["PhysicalResourceId"] != _HANDLER
            or function.get("FunctionArn") != f"arn:aws:lambda:{_REGION}:{authority['account_id']}:function:{_HANDLER}"
            or function.get("Role") != f"arn:aws:iam::{authority['account_id']}:role/{_ROLE}"
            or function.get("State") != "Active" or function.get("LastUpdateStatus") != "Successful"
            or function.get("Handler") != expected_handler["Handler"]
            or function.get("Runtime") != expected_handler["Runtime"]
            or function.get("Architectures") != expected_handler.get("Architectures")
            or function.get("Timeout") != expected_handler["Timeout"]
            or function.get("MemorySize") != expected_handler["MemorySize"]):
        _fail()
    expected_code_sha = base64.b64encode(bytes.fromhex(zip_sha)).decode("ascii")
    if function.get("CodeSha256") != expected_code_sha:
        _fail()
    env = function.get("Environment")
    expected_env = _resolve(expected_handler["Environment"]["Variables"], account=authority["account_id"],
                            rows=rows, table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
    if not isinstance(env, Mapping) or env.get("Variables") != expected_env:
        _fail()
    # Route and authorizer state is verified against exact synthesized
    # properties. Pagination is rejected; no unobserved route can be ignored.
    api_view = view["apigatewayv2"]
    auth_reply = api_view.get_authorizers(ApiId=api_id, MaxResults="100")
    auth_items = auth_reply.get("Items")
    if type(auth_items) is not list or len(auth_items) != 1:
        _fail()
    auth = auth_items[0]
    auth_props = props["McpJwtAuthorizer"]["Properties"]
    expected_jwt = _resolve(auth_props["JwtConfiguration"], account=authority["account_id"],
        rows=rows, table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
    if (auth.get("AuthorizerId") != rows["McpJwtAuthorizer"]["PhysicalResourceId"]
            or auth.get("AuthorizerType") != "JWT"
            or auth.get("Name") != auth_props["Name"]
            or auth.get("IdentitySource") != auth_props["IdentitySource"]
            or auth.get("JwtConfiguration") != expected_jwt):
        _fail()
    route_reply = api_view.get_routes(ApiId=api_id, MaxResults="100")
    routes = route_reply.get("Items")
    integration_reply = api_view.get_integrations(ApiId=api_id, MaxResults="100")
    integrations = integration_reply.get("Items")
    if type(routes) is not list or len(routes) != 3 or type(integrations) is not list or len(integrations) != 1:
        _fail()
    int_by_id = {item.get("IntegrationId"): item for item in integrations if isinstance(item, Mapping)}
    if len(int_by_id) != 1:
        _fail()
    logical_routes = ("McpPostRoute", "McpProtectedResourceMetadataRoute",
                      "McpAuthorizationServerMetadataRoute")
    for logical in logical_routes:
        p = props[logical]["Properties"]
        actual = [item for item in routes if isinstance(item, Mapping) and item.get("RouteKey") == p["RouteKey"]]
        if len(actual) != 1:
            _fail()
        route = actual[0]
        target = route.get("Target")
        auth_type = p["AuthorizationType"]
        scopes = _resolve(p.get("AuthorizationScopes"), account=authority["account_id"], rows=rows,
            table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
        auth_ok = (route.get("AuthorizerId") == rows["McpJwtAuthorizer"]["PhysicalResourceId"]
                   and route.get("AuthorizationScopes") == scopes) if auth_type == "JWT" else (
                   route.get("AuthorizerId") in (None, "")
                   and route.get("AuthorizationScopes") in (None, []))
        if (route.get("RouteId") != rows[logical]["PhysicalResourceId"]
                or route.get("AuthorizationType") != auth_type or not auth_ok
                or target != f"integrations/{rows['McpLambdaIntegration']['PhysicalResourceId']}"):
            _fail()
        integration = int_by_id.get(target.split("/", 1)[1])
        int_logical = "McpLambdaIntegration"
        expected_integration = _resolve(props[int_logical]["Properties"], account=authority["account_id"],
            rows=rows, table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
        expected_function = f"arn:aws:lambda:{_REGION}:{authority['account_id']}:function:{_HANDLER}"
        if (integration is None
                or integration.get("IntegrationId") != rows[int_logical]["PhysicalResourceId"]
                or integration.get("IntegrationUri") not in {expected_integration["IntegrationUri"], expected_function}
                or any(integration.get(key) != val for key, val in expected_integration.items()
                       if key not in {"ApiId", "IntegrationUri"})):
            _fail()
    # Explicit Lambda invoke permission is checked through the Lambda resource
    # policy; no function invocation occurs.
    policy_reply = view["lambda"].get_policy(FunctionName=_HANDLER)
    policy = _json_document(policy_reply.get("Policy"))
    if type(policy) is not dict:
        _fail()
    # The template's exact permission statement is the authority; resolve its
    # source API ARN from the freshly observed API identifier.
    permission_logicals = ("McpLambdaInvokePermission", "McpProtectedResourceMetadataInvokePermission",
                           "McpAuthorizationServerMetadataInvokePermission")
    expected_function = f"arn:aws:lambda:{_REGION}:{authority['account_id']}:function:{_HANDLER}"
    statements = policy.get("Statement")
    if type(statements) is not list or len(statements) != len(permission_logicals):
        _fail()
    expected_statements = []
    for logical in permission_logicals:
        permission = _resolve(props[logical]["Properties"], account=authority["account_id"], rows=rows,
            table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
        expected_statements.append({
            "Effect": "Allow", "Action": permission["Action"], "Resource": expected_function,
            "Principal": {"Service": permission["Principal"]},
            "Condition": {"ArnLike": {"AWS:SourceArn": permission["SourceArn"]},
                          "StringEquals": {"AWS:SourceAccount": permission["SourceAccount"]}},
        })
    observed_statements = []
    for statement in statements:
        if (not isinstance(statement, Mapping) or type(statement.get("Sid")) is not str
                or not statement["Sid"]):
            _fail()
        observed_statements.append({key: statement.get(key) for key in
            ("Effect", "Action", "Resource", "Principal", "Condition")})
    if sorted(map(_canonical, observed_statements)) != sorted(map(_canonical, expected_statements)):
        _fail()
    return expected_env


def _verify_role(view, authority, template, rows, *, accepted: bool, synthetic_policy: Mapping[str, Any] | None):
    role = view["iam"].get_role(RoleName=_ROLE).get("Role")
    if (not isinstance(role, Mapping)
            or rows["McpHandlerRole"]["PhysicalResourceId"] != _ROLE
            or role.get("Arn") != f"arn:aws:iam::{authority['account_id']}:role/{_ROLE}"
            or role.get("PermissionsBoundary") not in (None, {})):
        _fail()
    props = template["Resources"]["McpHandlerRole"]["Properties"]
    if _json_document(role.get("AssumeRolePolicyDocument")) != _resolve(props["AssumeRolePolicyDocument"],
            account=authority["account_id"], rows=rows,
            table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}"):
        _fail()
    listed = view["iam"].list_role_policies(RoleName=_ROLE)
    names = listed.get("PolicyNames")
    base_expected = {item["PolicyName"]: _resolve(item["PolicyDocument"], account=authority["account_id"],
            rows=rows, table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
            for item in props["Policies"]}
    expected_names = set(base_expected) | {_SYNTHETIC_POLICY_NAME}
    mapit_name = "honda-mapit-mcp-dev-mapit-identity-bindings-runtime-read"
    expected_names.add(mapit_name)
    if (expected_names != _POLICY_NAMES or type(names) is not list
            or set(names) != expected_names or len(names) != len(expected_names)):
        _fail()
    if listed.get("IsTruncated") is not False or listed.get("Marker") not in (None, ""):
        _fail()
    attached = view["iam"].list_attached_role_policies(RoleName=_ROLE)
    attached_rows = attached.get("AttachedPolicies")
    if type(attached_rows) is not list or attached_rows:
        _fail()
    if attached.get("IsTruncated") is not False or attached.get("Marker") not in (None, ""):
        _fail()
    expected = dict(base_expected)
    mapit = template.get("__mapit_runtime_policy")
    if (not isinstance(mapit, Mapping) or mapit.get("PolicyName") != mapit_name
            or mapit.get("Roles") != [_ROLE]):
        _fail()
    expected[mapit_name] = _resolve(mapit["PolicyDocument"], account=authority["account_id"],
        rows=rows, table_arn=f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}")
    if not isinstance(synthetic_policy, Mapping):
        _fail()
    expected[_SYNTHETIC_POLICY_NAME] = dict(synthetic_policy)
    observed = {}
    for name in sorted(expected_names):
        result = view["iam"].get_role_policy(RoleName=_ROLE, PolicyName=name)
        document = _json_document(result.get("PolicyDocument"))
        if (result.get("RoleName") != _ROLE or result.get("PolicyName") != name
                or document is None):
            _fail()
        observed[name] = document
    if (observed != expected or expected.get(_SYNTHETIC_POLICY_NAME) != dict(synthetic_policy)):
        _fail()
    return synthetic_policy


def _verify_owner_row(view, authority):
    reply = view["dynamodb"].get_item(TableName=_AUTH_TABLE,
        Key={"key": {"S": authority["owner_tenant_key"]}}, ConsistentRead=True,
        ReturnConsumedCapacity="NONE")
    item = reply.get("Item")
    if (type(item) is not dict or set(item) != {"key", "status", "revision"}
            or item.get("key") != {"S": authority["owner_tenant_key"]}
            or item.get("status") != {"S": "active"}
            or item.get("revision") != {"N": "1"}):
        _fail()


def _read_tenant_row(view, tenant_key):
    reply = view["dynamodb"].get_item(TableName=_AUTH_TABLE,
        Key={"key": {"S": tenant_key}}, ConsistentRead=True, ReturnConsumedCapacity="NONE")
    item = reply.get("Item")
    if item is None:
        return None
    if (type(item) is not dict or set(item) != {"key", "status", "revision"}
            or item.get("key") != {"S": tenant_key}
            or type(item.get("status")) is not dict or set(item["status"]) != {"S"}
            or type(item["status"].get("S")) is not str
            or type(item.get("revision")) is not dict or set(item["revision"]) != {"N"}
            or type(item["revision"].get("N")) is not str
            or not re.fullmatch(r"[1-9][0-9]{0,17}", item["revision"]["N"])):
        _fail()
    return dict(item)


def _verify_artifact(view, authority, zip_sha, archive_size=None):
    bucket = authority["artifact_bucket"]
    # The content object is verified by checksum and owner. Bucket privacy is
    # checked using the same narrow controls as the retained DEV artifact
    # bootstrap; no object bodies or MAPIT data are fetched.
    s3 = view["s3"]
    owner = authority["account_id"]
    pab = s3.get_public_access_block(Bucket=bucket, ExpectedBucketOwner=owner).get("PublicAccessBlockConfiguration")
    if pab != {"BlockPublicAcls": True, "IgnorePublicAcls": True,
               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}:
        _fail()
    encryption = s3.get_bucket_encryption(Bucket=bucket, ExpectedBucketOwner=owner).get("ServerSideEncryptionConfiguration")
    if (type(encryption) is not dict or set(encryption) != {"Rules"} or type(encryption["Rules"]) is not list
            or len(encryption["Rules"]) != 1 or encryption["Rules"][0].get("ApplyServerSideEncryptionByDefault") != {"SSEAlgorithm": "AES256"}):
        _fail()
    ownership = s3.get_bucket_ownership_controls(Bucket=bucket, ExpectedBucketOwner=owner).get("OwnershipControls")
    if ownership != {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}:
        _fail()
    versioning = s3.get_bucket_versioning(Bucket=bucket, ExpectedBucketOwner=owner)
    if set(versioning) - {"ResponseMetadata", "Status"} or versioning.get("Status") not in (None, ""):
        _fail()
    location = s3.get_bucket_location(Bucket=bucket, ExpectedBucketOwner=owner).get("LocationConstraint")
    if location != _REGION:
        _fail()
    public = s3.get_bucket_policy_status(Bucket=bucket, ExpectedBucketOwner=owner).get("PolicyStatus")
    if not isinstance(public, Mapping) or public.get("IsPublic") is not False:
        _fail()
    policy_reply = s3.get_bucket_policy(Bucket=bucket, ExpectedBucketOwner=owner)
    policy = _json_document(policy_reply.get("Policy"))
    expected_policy = {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny", "Principal": "*",
        "Action": "s3:*", "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
    if policy != expected_policy:
        _fail()
    tags_reply = s3.get_bucket_tagging(Bucket=bucket, ExpectedBucketOwner=owner)
    tag_rows = tags_reply.get("TagSet")
    if type(tag_rows) is not list or any(not isinstance(row, Mapping) or set(row) != {"Key", "Value"} for row in tag_rows):
        _fail()
    tags = {row["Key"]: row["Value"] for row in tag_rows}
    core_tags = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev-artifacts"}
    if (len(tags) != len(tag_rows)
            or any(tags.get(key) != value for key, value in core_tags.items())
            or not re.fullmatch(r"[1-9][0-9]{0,18}", tags.get("OperatorRunId", ""))):
        _fail()
    artifact_stack = view["cloudformation"].describe_stacks(StackName=_ARTIFACT_STACK).get("Stacks")
    if type(artifact_stack) is not list or len(artifact_stack) != 1:
        _fail()
    owning_stack = artifact_stack[0]
    stack_id = owning_stack.get("StackId")
    if (type(stack_id) is not str
            or not stack_id.startswith(f"arn:aws:cloudformation:{_REGION}:{owner}:stack/{_ARTIFACT_STACK}/")
            or owning_stack.get("StackName") != _ARTIFACT_STACK
            or owning_stack.get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
            or owning_stack.get("EnableTerminationProtection") is not True):
        _fail()
    resource_reply = view["cloudformation"].describe_stack_resources(StackName=stack_id)
    artifact_resources = resource_reply.get("StackResources")
    if (type(artifact_resources) is not list or len(artifact_resources) != 2
            or any(not isinstance(row, Mapping) or row.get("StackId") != stack_id
                   or row.get("StackName") != _ARTIFACT_STACK
                   or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
                   for row in artifact_resources)):
        _fail()
    by_logical = {row.get("LogicalResourceId"): row for row in artifact_resources}
    if (set(by_logical) != {"RuntimeArtifactBucket", "RuntimeArtifactBucketPolicy"}
            or by_logical["RuntimeArtifactBucket"].get("ResourceType") != "AWS::S3::Bucket"
            or by_logical["RuntimeArtifactBucketPolicy"].get("ResourceType") != "AWS::S3::BucketPolicy"
            or any(by_logical[name].get("PhysicalResourceId") != bucket for name in by_logical)):
        _fail()
    optional_tags = {
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:stack-name": _ARTIFACT_STACK,
        "aws:cloudformation:logical-id": "RuntimeArtifactBucket",
    }
    if any(key not in {**core_tags, "OperatorRunId": tags["OperatorRunId"], **optional_tags} for key in tags):
        _fail()
    if any(tags[key] != value for key, value in optional_tags.items() if key in tags):
        _fail()
    lifecycle = s3.get_bucket_lifecycle_configuration(Bucket=bucket, ExpectedBucketOwner=owner)
    expected_rule = {"ID": "DevTerminalJournalRetention", "Status": "Enabled",
        "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}},
        "Expiration": {"Days": 30}}
    if lifecycle.get("Rules") != [expected_rule]:
        _fail()
    head = s3.head_object(Bucket=bucket, Key=f"runtime/{zip_sha}.zip", ChecksumMode="ENABLED",
        ExpectedBucketOwner=owner)
    checksum = base64.b64encode(bytes.fromhex(zip_sha)).decode("ascii")
    if (type(head.get("ContentLength")) is not int or head["ContentLength"] <= 0
            or head["ContentLength"] > 50 * 1024 * 1024
            or archive_size is not None and head["ContentLength"] != archive_size
            or head.get("ChecksumSHA256") != checksum or head.get("ServerSideEncryption") != "AES256"
            or head.get("ContentType") != "application/zip"):
        _fail()


def _verify_authorization_table(view, authority, template, rows, *, expected_run_id):
    if type(expected_run_id) is not int or expected_run_id <= 0:
        _fail()
    table_arn = f"arn:aws:dynamodb:{_REGION}:{authority['account_id']}:table/{_AUTH_TABLE}"
    table = view["dynamodb"].describe_table(TableName=_AUTH_TABLE).get("Table")
    props = template["Resources"]["McpTenantsTable"]["Properties"]
    if (not isinstance(table, Mapping) or table.get("TableName") != _AUTH_TABLE
            or table.get("TableArn") != table_arn or table.get("TableStatus") != "ACTIVE"
            or table.get("BillingModeSummary", {}).get("BillingMode") != props.get("BillingMode")
            or table.get("OnDemandThroughput") != props.get("OnDemandThroughput")
            or table.get("KeySchema") != props.get("KeySchema")
            or table.get("AttributeDefinitions") != props.get("AttributeDefinitions")
            or table.get("DeletionProtectionEnabled") is not True
            or table.get("SSEDescription") is not None
            or table.get("GlobalSecondaryIndexes") not in (None, [])
            or table.get("LocalSecondaryIndexes") not in (None, [])):
        _fail()
    table_id = table.get("TableId")
    if type(table_id) is not str or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", table_id):
        _fail()
    if rows["McpTenantsTable"]["PhysicalResourceId"] != _AUTH_TABLE:
        _fail()
    tags_reply = view["dynamodb"].list_tags_of_resource(ResourceArn=table_arn)
    tag_rows = tags_reply.get("Tags")
    expected = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "multiuser-authorization",
                "OperatorRunId": str(expected_run_id)}
    if type(tag_rows) is not list or any(not isinstance(row, Mapping) or set(row) != {"Key", "Value"} for row in tag_rows):
        _fail()
    tags = {row["Key"]: row["Value"] for row in tag_rows}
    if len(tags) != len(tag_rows) or any(tags.get(key) != value for key, value in expected.items()):
        _fail()
    optional = {"aws:cloudformation:stack-id": authority["stack_id"],
        "aws:cloudformation:stack-name": _STACK_NAME, "aws:cloudformation:logical-id": "McpTenantsTable"}
    if any(key not in set(expected) | set(optional) for key in tags) or any(
            tags.get(key) != value for key, value in optional.items() if key in tags):
        _fail()
    return table_id


def _verify_completion(view, authority, binding):
    token = f"owner-enrolled-{authority['run_id']}"
    reply = view["cloudformation"].describe_stack_events(StackName=authority["stack_id"])
    events = reply.get("StackEvents")
    if type(events) is not list or len(events) > 100:
        _fail()
    matches = []
    for event in events:
        if (isinstance(event, Mapping) and event.get("ClientRequestToken") == token
                and event.get("StackId") == authority["stack_id"]
                and event.get("StackName") == _STACK_NAME
                and event.get("LogicalResourceId") == _STACK_NAME
                and event.get("PhysicalResourceId") == authority["stack_id"]
                and event.get("ResourceType") == "AWS::CloudFormation::Stack"
                and event.get("ResourceStatus") == "UPDATE_COMPLETE"):
            timestamp = event.get("Timestamp")
            if not hasattr(timestamp, "timestamp"):
                _fail()
            when = timestamp.timestamp()
            if not authority["execution_start_epoch"] <= when < authority["execution_end_epoch"]:
                _fail()
            matches.append(event)
    if len(matches) != 1:
        _fail()
    return {"stack_id": authority["stack_id"], "resource_type": "AWS::CloudFormation::Stack",
            "status": "UPDATE_COMPLETE", "client_request_token": token,
            "timestamp_epoch": int(matches[0]["Timestamp"].timestamp()), "response_http_status": 200,
            "matching_completion_events": 1}


def _load_accepted_publication(state_dir: Path, *, acl_checker, expected_receipt_sha256: str):
    """Load one accepted publication journal and bind canonical state metadata."""
    try:
        directory = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        journal = FileJournal(directory)
        state_path = validate_private_location(journal.path, acl_checker=acl_checker)
        if (not state_path.is_file() or state_path.stat().st_size <= 0
                or state_path.stat().st_size > 32 * 1024):
            raise ValueError
        raw = state_path.read_bytes()
        if len(raw) != state_path.stat().st_size:
            raise ValueError
        value = journal.load()
        if (type(value) is not dict or set(value) != _PUBLICATION_FIELDS
                or value.get("phase") != "accepted"
                or json.loads(_canonical(value)) != value
                or hashlib.sha256(_canonical(value)).hexdigest() != expected_receipt_sha256):
            raise ValueError
        return value
    except Exception:
        _fail("binding_invalid")


class OwnerEnrolledCurrentState:
    """Callable, registered-bundle adapter for delivery coordinator phases."""

    def __init__(self, *, client_bundle: DeliveryClientBundle, authority: Mapping[str, Any],
                 accepted: Mapping[str, Any], prior_template: Mapping[str, Any],
                 manifest_raw: bytes, invitation_jwks: bytes, mapit_jwks: bytes, archive_bytes: bytes,
                 archive_size: int, owner_oauth_context: AcceptedOwnerLoginContext,
                 mapit_bootstrap_authority_path: Path, mapit_bootstrap_state_dir: Path,
                 mapit_publication_state_dir: Path,
                 mapit_evidence_path: Path, synthetic_binding_path: Path,
                 synthetic_authorization_path: Path, synthetic_state_dir: Path,
                 accepted_observation_capsule: Mapping[str, Any] | None = None,
                 accepted_update_state: Mapping[str, Any] | None = None,
                 observation_window: Mapping[str, Any] | None = None,
                 accepted_runtime_evidence_sha256: str | None = None,
                 observation_source_check: Callable[[Mapping[str, Any]], Any] | None = None,
                 observation_protection_check: Callable[[Mapping[str, Any]], Any] | None = None,
                 acl_checker: Callable[[Path], bool] | None = None,
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic):
        try:
            self.authority = _validate_authority(dict(authority))
            self.accepted = _validate_accepted(dict(accepted), self.authority)
            if (not _is_registered_client_bundle(client_bundle)
                    or type(owner_oauth_context) is not AcceptedOwnerLoginContext
                    or _ACCEPTED_OWNER_CONTEXTS.get(id(owner_oauth_context)) is not owner_oauth_context
                    or any(not isinstance(path, (Path, str)) for path in (
                        mapit_bootstrap_authority_path, mapit_bootstrap_state_dir,
                        mapit_publication_state_dir, mapit_evidence_path,
                        synthetic_binding_path, synthetic_authorization_path, synthetic_state_dir))
                    or (acl_checker is not None and not callable(acl_checker))):
                raise ValueError
            if (owner_oauth_context.account != self.authority["account_id"]
                    or owner_oauth_context.operator != self.authority["operator_arn"]
                    or owner_oauth_context.context_digest != self.authority["owner_context_sha256"]
                    or owner_oauth_context.readback_digest != self.authority["owner_oauth_receipt_sha256"]
                    or owner_oauth_context.policy.user_pool_id != self.authority["owner_pool_id"]
                    or owner_oauth_context.policy.client_id != self.authority["owner_client_id"]
                    or owner_oauth_context.policy.resource_url != self.authority["owner_resource_uri"]):
                raise ValueError
            self.bundle, self.clients = client_bundle, client_bundle.clients
            _validate_clients(self.clients)
            self.prior = json.loads(_canonical(dict(prior_template)))
            prior_keys = [row["key"] for row in self.prior["Metadata"]["ManifestContract"]["tenants"]]
            prior_code = self.prior["Resources"]["McpHandler"]["Properties"]["Code"]
            if (prior_keys != self.authority["historical_tenant_keys"]
                    or prior_code.get("S3Key") != f"runtime/{self.authority['prior_zip_sha256']}.zip"
                    or prior_code.get("S3Bucket") != self.authority["artifact_bucket"]):
                raise ValueError
            self.mapit_bootstrap_authority_path = Path(mapit_bootstrap_authority_path)
            self.mapit_bootstrap_state_dir = Path(mapit_bootstrap_state_dir)
            self.mapit_publication_state_dir = Path(mapit_publication_state_dir)
            bootstrap_clients = {name: self.clients[name] for name in (
                "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
                "apigatewayv2", "lambda", "kms")}
            (self.bootstrap_authority, self.bootstrap_source, self.bootstrap_github,
             bootstrap_state, self.bootstrap_plan, self.bootstrap_receipt_sha) = _load_accepted_bootstrap(
                self.mapit_bootstrap_authority_path, self.mapit_bootstrap_state_dir,
                bootstrap_clients, acl_checker=acl_checker, clock=clock, monotonic=monotonic)
            if (self.bootstrap_authority.account_id != self.authority["account_id"]
                    or self.bootstrap_authority.expected_caller_arn != self.authority["operator_arn"]
                    or self.bootstrap_authority._binding_sha256 != self.authority["mapit_bootstrap_authority_sha256"]
                    or self.bootstrap_authority.runtime_evidence_sha256 != self.authority["runtime_evidence_sha256"]
                    or self.authority["owner_tenant_key"] not in self.bootstrap_authority._tenant_keys
                    or not set(self.authority["historical_tenant_keys"]).issubset(
                        set(self.bootstrap_authority._excluded_tenant_keys))):
                raise ValueError
            if self.bootstrap_receipt_sha != self.authority["mapit_bootstrap_receipt_sha256"]:
                raise ValueError
            self.bootstrap_template = self.bootstrap_plan.template
            self.archive = archive_bytes
            self.archive_size = archive_size
            if (type(self.archive) is not bytes or type(archive_size) is not int
                    or len(self.archive) != archive_size or hashlib.sha256(self.archive).hexdigest() == "0" * 64
                    or type(manifest_raw) is not bytes or type(invitation_jwks) is not bytes
                    or type(mapit_jwks) is not bytes):
                raise ValueError
            self.zip_sha = hashlib.sha256(self.archive).hexdigest()
            self.manifest_raw, self.invitation_jwks, self.mapit_jwks = manifest_raw, invitation_jwks, mapit_jwks
            self.context = owner_oauth_context
            self.bootstrap_state = json.loads(_canonical(dict(bootstrap_state)))
            self.publication = _load_accepted_publication(
                self.mapit_publication_state_dir, acl_checker=acl_checker,
                expected_receipt_sha256=self.authority["key_publication_receipt_sha256"])
            self.mapit_evidence_path = Path(mapit_evidence_path)
            self.synthetic_binding_path = Path(synthetic_binding_path)
            self.synthetic_authorization_path = Path(synthetic_authorization_path)
            self.synthetic_state_dir = Path(synthetic_state_dir)
            self.acl_checker = acl_checker
            runtime_bundle, _runtime_raw = _load_mapit_evidence_bundle(
                self.mapit_evidence_path, acl_checker=acl_checker)
            if _mapit_runtime_evidence_digest(runtime_bundle) != self.bootstrap_authority.runtime_evidence_sha256:
                raise ValueError
            runtime_binding = _validate_mapit_evidence_bundle(
                runtime_bundle, self.bootstrap_authority, self.bootstrap_template)
            self._app_run_id = runtime_binding["app_run_id"]
            if type(self._app_run_id) is not int or self._app_run_id <= 0:
                raise ValueError
            self.pre_runtime_verifier = make_mapit_runtime_evidence_verifier(
                self.mapit_evidence_path,
                synthetic_binding_path=self.synthetic_binding_path,
                synthetic_authorization_path=self.synthetic_authorization_path,
                synthetic_state_dir=self.synthetic_state_dir,
                acl_checker=acl_checker,
                monotonic=monotonic,
            )
            self.clock, self.monotonic = clock, monotonic
            self.target = build_owner_enrolled_dev_runtime_target(
                prior_template=self.prior, mapit_bootstrap_template=self.bootstrap_template,
                manifest_raw=manifest_raw, invitation_jwks=invitation_jwks, mapit_jwks=mapit_jwks,
                manifest_sha256=self.authority["manifest_sha256"], account_id=self.authority["account_id"],
                source_sha=self.authority["source_sha"], zip_sha256=self.zip_sha,
                execution_start_epoch=self.authority["execution_start_epoch"],
                execution_end_epoch=self.authority["execution_end_epoch"])
            if (_template_sha(self.prior) != self.authority["prior_template_sha256"]
                    or hashlib.sha256(manifest_raw).hexdigest() != self.authority["manifest_sha256"]
                    or hashlib.sha256(invitation_jwks).hexdigest() != self.authority["invitation_jwks_sha256"]
                    or hashlib.sha256(mapit_jwks).hexdigest() != self.authority["mapit_jwks_sha256"]):
                raise ValueError
            self.target_sha = _template_sha(self.target)
            self.delivery_binding = {
                "schema": 1, "kind": "dev-owner-enrolled-delivery",
                "authority": json.loads(_canonical(self.authority)),
                "accepted": json.loads(_canonical(self.accepted)),
                "prior_template_sha256": self.authority["prior_template_sha256"],
                "target_template_sha256": self.target_sha,
                "artifact_sha256": self.zip_sha, "artifact_size": self.archive_size,
                "client_request_token": f"owner-enrolled-{self.authority['run_id']}",
            }
            self._resource_ids = None
            self._historical_rows = None
            self._historical_row_sha256 = None
            self._synthetic_policy = None
            self._authorization_table_id = None
            self._accepted_capsule = None
            self._accepted_update_state = None
            self._observation_window = None
            self._accepted_runtime_evidence_sha256 = accepted_runtime_evidence_sha256
            self._last_accepted_observation = None
            self._last_successful_state = None
            self._last_read_call_count = 0
            self._observation_source_check = observation_source_check
            self._observation_protection_check = observation_protection_check
            if (accepted_observation_capsule is not None or observation_window is not None
                    or accepted_update_state is not None):
                if (accepted_observation_capsule is None or observation_window is None
                        or accepted_update_state is None
                        or not _SHA256.fullmatch(accepted_runtime_evidence_sha256 or "")
                        or not callable(observation_source_check)
                        or not callable(observation_protection_check)):
                    raise ValueError
                now = clock()
                self._observation_window = _validate_observation_window(
                    dict(observation_window), account_id=self.authority["account_id"],
                    operator_arn=self.authority["operator_arn"],
                    github_owner_id=self.authority["github_owner_id"],
                    github_repository_id=self.authority["github_repository_id"], now=now)
                self._accepted_update_state = dict(accepted_update_state)
                self._accepted_capsule = _validate_capsule_for_update(
                    dict(accepted_observation_capsule), delivery_binding=self.delivery_binding,
                    accepted_update_state=self._accepted_update_state)
                if (self._accepted_capsule["runtime_evidence_sha256"]
                        != accepted_runtime_evidence_sha256):
                    raise ValueError
                progress = self._accepted_capsule["progress"]
                if (set(progress["resource_ids"]) != set(_LOGICAL_TYPES)
                        or set(progress["historical_row_sha256"])
                            != {"tenant_a", "tenant_b"}
                        or type(self.authority.get("historical_tenant_keys")) is not list
                        or len(self.authority["historical_tenant_keys"]) != 2
                        or len(set(self.authority["historical_tenant_keys"])) != 2):
                    raise ValueError
                self._resource_ids = dict(progress["resource_ids"])
                self._historical_row_sha256 = {
                    key: progress["historical_row_sha256"][f"tenant_{'a' if index == 0 else 'b'}"]
                    for index, key in enumerate(self.authority["historical_tenant_keys"])
                }
                self._authorization_table_id = progress["authorization_table_id"]
                self._progress_digest = self._accepted_capsule["progress_sha256"]
                if (self._accepted_capsule["target_template_sha256"] != self.target_sha
                        or self._accepted_capsule["artifact_sha256"] != self.zip_sha
                        or self._accepted_capsule["owner_context_sha256"] == self.context.context_digest):
                    raise ValueError
                # Reconstruct the expected historical policy from its owning
                # private evidence; the capsule stores only its digest.
                self._synthetic_policy = self._historical_synthetic_policy()
                if _observation_sha256_json(self._synthetic_policy) != progress["synthetic_policy_sha256"]:
                    raise ValueError
            self._input_objects = (self.bundle, self.clients, self.context,
                self.bootstrap_authority, self.clock, self.monotonic, self.pre_runtime_verifier,
                self.acl_checker, self._observation_source_check, self._observation_protection_check)
            self._input_digest = self._fixed_input_digest()
            if self._accepted_capsule is None:
                self._progress_digest = None
        except Exception:
            _fail("binding_invalid")

    def __repr__(self):
        return "OwnerEnrolledCurrentState(<redacted>)"

    def _fixed_input_digest(self):
        value = {
            "authority": self.authority, "accepted": self.accepted,
            "prior": self.prior, "target": self.target, "target_sha": self.target_sha,
            "delivery_binding": self.delivery_binding,
            "zip_sha": self.zip_sha, "archive_size": self.archive_size,
            "archive_sha": hashlib.sha256(self.archive).hexdigest(),
            "manifest_sha": hashlib.sha256(self.manifest_raw).hexdigest(),
            "invitation_sha": hashlib.sha256(self.invitation_jwks).hexdigest(),
            "mapit_sha": hashlib.sha256(self.mapit_jwks).hexdigest(),
            "context": asdict(self.context), "bootstrap_authority": asdict(self.bootstrap_authority),
            "bootstrap_source": self.bootstrap_source, "bootstrap_github": self.bootstrap_github,
            "bootstrap_state": self.bootstrap_state, "bootstrap_template": self.bootstrap_template,
            "bootstrap_plan_template": self.bootstrap_plan.template,
            "bootstrap_plan_sha": self.bootstrap_plan.template_sha256,
            "bootstrap_receipt": self.bootstrap_receipt_sha, "publication": self.publication,
            "app_run_id": self._app_run_id,
            "paths": [str(path) for path in (self.mapit_bootstrap_authority_path,
                self.mapit_bootstrap_state_dir, self.mapit_publication_state_dir,
                self.mapit_evidence_path, self.synthetic_binding_path,
                self.synthetic_authorization_path, self.synthetic_state_dir)],
            "observation_window": self._observation_window,
            "observation_capsule": self._accepted_capsule,
            "accepted_update_state": self._accepted_update_state,
            "accepted_runtime_evidence_sha256": self._accepted_runtime_evidence_sha256,
        }
        return hashlib.sha256(_canonical(value)).hexdigest()

    def _phase_progress_digest(self):
        return _observation_progress_digest(self._phase_progress_projection())

    def _phase_progress_projection(self):
        history_hashes = self._historical_row_sha256
        if self._historical_rows is not None:
            history_hashes = {key: _observation_sha256_json(row)
                              for key, row in sorted(self._historical_rows.items())}
        if type(self._synthetic_policy) is not dict:
            raise ValueError
        if type(history_hashes) is not dict or type(self.authority.get("historical_tenant_keys")) is not list:
            raise ValueError
        tenant_keys = self.authority["historical_tenant_keys"]
        if len(tenant_keys) != 2 or set(history_hashes) != set(tenant_keys):
            raise ValueError
        # Fixed slot labels preserve the historical-key order from the trusted
        # authority without writing those opaque keys into the capsule.
        history_slots = {
            f"tenant_{'a' if index == 0 else 'b'}": history_hashes[key]
            for index, key in enumerate(tenant_keys)
        }
        return {
            "resource_ids": dict(sorted(self._resource_ids.items())) if type(self._resource_ids) is dict else None,
            "historical_row_sha256": history_slots,
            "authorization_table_id": self._authorization_table_id,
            "synthetic_policy_sha256": _observation_sha256_json(self._synthetic_policy),
        }

    def export_accepted_observation_capsule(self) -> dict[str, Any]:
        """Export the validated, secret-free restart baseline after accepted readback."""
        try:
            if (self._last_accepted_observation is None or self._last_successful_state is None
                    or self._last_successful_state.get("phase") != "accepted"):
                raise ValueError
            self._assert_integrity()
            capsule = _make_observation_capsule(
                delivery_binding=self.delivery_binding,
                progress=self._phase_progress_projection(),
                target_template_sha256=self.target_sha,
                artifact_sha256=self.zip_sha,
                owner_context_sha256=self._last_accepted_observation["owner_context_sha256"],
                accepted_read_call_count=self._last_accepted_observation["calls"],
            )
            if capsule["runtime_evidence_sha256"] != self._last_accepted_observation["runtime_evidence_sha256"]:
                raise ValueError
            return capsule
        except Exception:
            _fail("current_state_unverified")

    @property
    def last_read_call_count(self) -> int:
        """Bounded SDK calls attempted in the most recent phase, including failures."""
        return self._last_read_call_count

    def owner_login_projections(self, readback: Mapping[str, Any]):
        """Return same-snapshot projections for the pure lineage validator."""
        try:
            if (self._last_successful_state is not readback or type(readback) is not dict
                    or readback.get("phase") != "accepted" or not _is_registered_client_bundle(self.bundle)):
                raise ValueError
            policy = self.context.policy
            identity = {
                "account_id": self.authority["account_id"],
                "owner_pool_id": policy.user_pool_id,
                "client_id": policy.client_id,
                "owner_subject": policy.owner_subject,
                "api_id": policy.api_id,
                "issuer": policy.issuer_url,
                "resource_uri": policy.resource_url,
                "audience": policy.audience,
                "scope": policy.required_scope,
            }
            snapshot = self.bundle.credential_snapshot
            digest = readback["owner_context_sha256"]
            return (
                {"state": readback, "owner_identity": identity,
                 "current_context_sha256": digest, "credential_snapshot": snapshot},
                {"owner_identity": identity, "current_context_sha256": digest,
                 "credential_snapshot": snapshot},
            )
        except Exception:
            _fail("current_state_unverified")

    def _check_observation_gates(self):
        if self._observation_window is None:
            return
        try:
            _validate_observation_window(self._observation_window,
                account_id=self.authority["account_id"], operator_arn=self.authority["operator_arn"],
                github_owner_id=self.authority["github_owner_id"],
                github_repository_id=self.authority["github_repository_id"], now=self.clock())
            source = self._observation_source_check(dict(self._observation_window))
            if (type(source) is not dict or set(source) != {
                    "source_sha", "ci_run_id", "head_sha", "checks_passed"}
                    or source != {"source_sha": self._observation_window["source_sha"],
                        "ci_run_id": self._observation_window["ci_run_id"],
                        "head_sha": self._observation_window["source_sha"],
                        "checks_passed": True}):
                raise ValueError
            protections = self._observation_protection_check(dict(self._observation_window))
            if (type(protections) is not dict or set(protections) != {
                    "owner_id", "repository_id", "dev_environment_protected"}
                    or protections != {"owner_id": self._observation_window["github_owner_id"],
                        "repository_id": self._observation_window["github_repository_id"],
                        "dev_environment_protected": True}):
                raise ValueError
        except Exception:
            _fail("current_state_unverified")

    def _assert_integrity(self):
        objects = (self.bundle, self.clients, self.context, self.bootstrap_authority,
                   self.clock, self.monotonic, self.pre_runtime_verifier, self.acl_checker,
                   self._observation_source_check, self._observation_protection_check)
        if (not _is_registered_client_bundle(self.bundle)
                or self.clients is not self.bundle.clients
                or _ACCEPTED_OWNER_CONTEXTS.get(id(self.context)) is not self.context
                or any(current is not original for current, original in zip(objects, self._input_objects))
                or self._fixed_input_digest() != self._input_digest
                or (self._progress_digest is not None
                    and self._phase_progress_digest() != self._progress_digest)):
            _fail("current_state_unverified")

    def _reload_bootstrap_lineage(self) -> None:
        clients = {name: self.clients[name] for name in (
            "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
            "apigatewayv2", "lambda", "kms")}
        # This owning coordinator is instantiated solely to parse immutable
        # accepted evidence. Pin its parser clock inside the old authorization
        # window; never call run_step, renew, or save the consumed authority.
        parser_clock = lambda: self.bootstrap_authority.authorized_from_epoch + 1
        parser_monotonic = lambda: 0.0
        authority, source, github, state, plan, receipt = _load_accepted_bootstrap(
            self.mapit_bootstrap_authority_path, self.mapit_bootstrap_state_dir,
            clients, acl_checker=self.acl_checker, clock=parser_clock, monotonic=parser_monotonic)
        if (authority._binding_sha256 != self.bootstrap_authority._binding_sha256
                or authority != self.bootstrap_authority
                or source != self.bootstrap_source or github != self.bootstrap_github
                or state != self.bootstrap_state
                or plan.template_sha256 != self.bootstrap_plan.template_sha256
                or receipt != self.bootstrap_receipt_sha):
            _fail("current_state_unverified")

    def __call__(self, phase: str, delivery_binding: Mapping[str, Any]) -> dict[str, Any]:
        if phase not in {"preflight", "pre_publish", "pre_update", "accepted"}:
            _fail("binding_invalid")
        if self._accepted_capsule is not None and phase != "accepted":
            _fail("binding_invalid")
        budget = None
        try:
            self._assert_integrity()
            self._check_observation_gates()
            authority = self.authority
            if (not isinstance(delivery_binding, Mapping)
                    or dict(delivery_binding) != self.delivery_binding):
                raise ValueError
            self._reload_bootstrap_lineage()
            publication = _load_accepted_publication(
                self.mapit_publication_state_dir, acl_checker=self.acl_checker,
                expected_receipt_sha256=authority["key_publication_receipt_sha256"])
            if publication != self.publication:
                raise ValueError
            budget = _ReadBudget(authority=authority, clock=self.clock, monotonic=self.monotonic,
                                 max_calls=_MAX_READS, observation_window=self._observation_window)
            budget.clients = self.clients
            view = _ClientsView(budget, self.clients)
            identity = view["sts"].get_caller_identity()
            if identity.get("Account") != authority["account_id"] or identity.get("Arn") != authority["operator_arn"]:
                raise ValueError
            accepted = phase == "accepted"
            template = self.target if accepted else self.prior
            stack, rows = _stack_and_resources(view, authority, template)
            expected_ids = {name: row["PhysicalResourceId"] for name, row in rows.items()}
            if self._resource_ids is None:
                if accepted:
                    raise ValueError
                self._resource_ids = expected_ids
            elif self._resource_ids != expected_ids:
                raise ValueError
            authorization_table_id = _verify_authorization_table(view, authority, template, rows,
                expected_run_id=self._app_run_id)
            if self._authorization_table_id is None:
                if accepted:
                    raise ValueError
                self._authorization_table_id = authorization_table_id
            elif self._authorization_table_id != authorization_table_id:
                raise ValueError
            # Both phases require a fresh owner Cognito readback. Pre-update
            # compares the historical snapshot; post-update records a new one.
            oauth = OwnerOAuthSdkBindings(
                {"cloudformation": view["cloudformation"], "cognito": view["cognito"],
                "apigatewayv2": view["apigatewayv2"], "lambda": view["lambda"], "sts": view["sts"]},
                account_id=authority["account_id"], operator_user_arn=authority["operator_arn"],
                until_epoch=(self._observation_window["authorized_until_epoch"]
                    if self._observation_window is not None else authority["authorized_until_epoch"]), wall_clock=self.clock,
                monotonic=self.monotonic, max_calls=64)
            if not accepted:
                if not verify_current_context(self.context, oauth):
                    raise ValueError
                owner_context_sha = self.context.context_digest
            else:
                captured = oauth.capture_context(exclude_client_id=self.context.policy.client_id)
                if (captured != {"verified": True, "account_id": authority["account_id"],
                        "owner_pool_id": authority["owner_pool_id"],
                        "api_id": self.context.policy.api_id,
                        "context_sha256": captured.get("context_sha256")}
                        or type(captured.get("context_sha256")) is not str
                        or _SHA256.fullmatch(captured["context_sha256"]) is None
                        or captured["context_sha256"] == self.context.context_digest):
                    raise ValueError
                from scripts.build_aws_dev_owner_oauth import build_dev_owner_oauth_template
                owner_rows, owner_stack = oauth._stack("honda-mapit-mcp-dev-owner-oauth", 3)
                if (owner_stack.get("stack_id") != self.context.stack_id
                        or owner_stack.get("template_sha256") != self.context.template_digest):
                    raise ValueError
                candidate = oauth.validate_candidate(self.context.stack_id,
                    build_dev_owner_oauth_template(
                        account_id=self.context.account, api_id=self.context.policy.api_id,
                        owner_pool_id=self.context.policy.user_pool_id,
                        callback_url="http://127.0.0.1:8787/callback"),
                    self.context.run_id, self.context.start, self.context.end,
                    {name: item["PhysicalResourceId"] for name, item in owner_rows.items()})
                if (not isinstance(candidate, Mapping) or candidate.get("verified") is not True
                        or candidate.get("client_id") != self.context.policy.client_id
                        or type(candidate.get("readback_sha256")) is not str
                        or _SHA256.fullmatch(candidate["readback_sha256"]) is None):
                    raise ValueError
                owner_context_sha = captured["context_sha256"]
            _verify_api_and_lambda(view, authority, template, rows,
                self.zip_sha if accepted else authority["prior_zip_sha256"], accepted=accepted)
            _verify_owner_row(view, authority)
            history = {key: _read_tenant_row(view, key) for key in authority["historical_tenant_keys"]}
            if any(value is None for value in history.values()):
                raise ValueError
            historical_a, historical_b = authority["historical_tenant_keys"]
            if (history[historical_a]["status"] != {"S": "revoked"}
                    or history[historical_b]["status"] != {"S": "active"}):
                raise ValueError
            observed_history_hashes = {key: _observation_sha256_json(row)
                                       for key, row in sorted(history.items())}
            if self._historical_rows is None and self._historical_row_sha256 is None:
                if accepted:
                    raise ValueError
                self._historical_rows = json.loads(_canonical(history))
                self._historical_row_sha256 = observed_history_hashes
            elif (self._historical_row_sha256 != observed_history_hashes
                    or (self._historical_rows is not None and history != self._historical_rows)):
                raise ValueError
            if accepted:
                synthetic_policy = self._historical_synthetic_policy()
                expected_role_template = dict(template)
                mapit_policy = self.bootstrap_template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
                expected_role_template["__mapit_runtime_policy"] = mapit_policy
                self._synthetic_policy = _verify_role(view, authority, expected_role_template, rows,
                    accepted=True, synthetic_policy=synthetic_policy)
                if self._synthetic_policy is None:
                    raise ValueError
                namespace_clients = {name: view._views[name] for name in (
                    "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
                    "apigatewayv2", "lambda", "kms")}
                namespace = verify_published_namespace(namespace_clients, self.bootstrap_authority,
                    self.bootstrap_state, self.bootstrap_plan, self.bootstrap_receipt_sha,
                    publication, [budget.calls], budget.started,
                    budget.started + _MAX_SECONDS, self.monotonic)
                if (namespace.get("verified") is not True or namespace.get("config_version") != 1
                        or namespace.get("table_id") != authority["mapit_table_id"]
                        or namespace.get("binding_empty") is not True
                        or namespace.get("sessions_absent") is not True):
                    raise ValueError
                _verify_artifact(view, authority, self.zip_sha, self.archive_size)
                completion = _verify_completion(view, authority, delivery_binding)
                runtime_checks = {name: True for name in _CHECKS}
                issuer = self.target["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"]
                mapit_table_id = authority["mapit_table_id"]
                config_path = authority["mapit_config_path"]
                mapit_version = authority["mapit_config_version"]
                zip_sha = self.zip_sha
                template_sha = self.target_sha
                leading = [*authority["historical_tenant_keys"], authority["owner_tenant_key"]]
                mapit_digest = authority["mapit_bootstrap_receipt_sha256"]
                invitation_digest = authority["invitation_receipt_sha256"]
                key_digest = authority["key_publication_receipt_sha256"]
                runtime_evidence_sha = None  # finalized after closure and final STS readback
            else:
                _verify_artifact(view, authority, authority["prior_zip_sha256"])
                runtime_clients = {name: view._views[name] for name in (
                    "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
                    "apigatewayv2", "lambda", "kms")}
                evidence = self.pre_runtime_verifier(runtime_clients, self.bootstrap_authority,
                    self.bootstrap_template, phase="readback")
                if (not isinstance(evidence, Mapping) or set(evidence) != {
                        "verified", "calls", "phase", "account_id", "source_sha", "run_id", "caller_arn",
                        "evidence_sha256", "resource_count", "api_closed", "reserve_zero", "mapit_policy_attached"}
                        or evidence.get("verified") is not True
                        or evidence.get("account_id") != authority["account_id"]
                        or evidence.get("source_sha") != self.bootstrap_authority.source_sha
                        or type(evidence.get("calls")) is not int
                        or not 1 <= evidence["calls"] <= 64
                        or evidence.get("phase") != "readback"
                        or evidence.get("run_id") != self.bootstrap_authority.run_id
                        or evidence.get("caller_arn") != authority["operator_arn"]
                        or evidence.get("evidence_sha256") != self.bootstrap_authority.runtime_evidence_sha256
                        or evidence.get("resource_count") != 19
                        or evidence.get("api_closed") is not True
                        or evidence.get("reserve_zero") is not True
                        or evidence.get("mapit_policy_attached") is not True):
                    raise ValueError
                synthetic_policy = self._historical_synthetic_policy()
                expected_role_template = dict(template)
                expected_role_template["__mapit_runtime_policy"] = self.bootstrap_template["Resources"][
                    "RuntimeIdentityBindingPolicy"]["Properties"]
                self._synthetic_policy = _verify_role(view, authority, expected_role_template, rows,
                    accepted=False, synthetic_policy=synthetic_policy)
                namespace_clients = {name: view._views[name] for name in (
                    "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
                    "apigatewayv2", "lambda", "kms")}
                namespace = verify_published_namespace(namespace_clients, self.bootstrap_authority,
                    self.bootstrap_state, self.bootstrap_plan, self.bootstrap_receipt_sha,
                    self.publication, [budget.calls], budget.started,
                    budget.started + _MAX_SECONDS, self.monotonic)
                if (namespace.get("verified") is not True or namespace.get("config_version") != 1
                        or namespace.get("table_id") != authority["mapit_table_id"]
                        or namespace.get("binding_empty") is not True
                        or namespace.get("sessions_absent") is not True):
                    raise ValueError
                completion = None
                runtime_checks = dict(_PRE_CHECKS)
                issuer = self.prior["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"]
                mapit_table_id = authority["mapit_table_id"]
                config_path = authority["mapit_config_path"]
                mapit_version = 1
                zip_sha = authority["prior_zip_sha256"]
                template_sha = authority["prior_template_sha256"]
                leading = list(authority["historical_tenant_keys"])
                mapit_digest = authority["mapit_bootstrap_receipt_sha256"]
                invitation_digest = authority["invitation_receipt_sha256"]
                key_digest = authority["key_publication_receipt_sha256"]
                runtime_evidence_sha = authority["runtime_evidence_sha256"]
            value = {
                "phase": phase, "account_id": authority["account_id"], "caller_arn": authority["operator_arn"],
                "stack_id": authority["stack_id"], "stack_status": stack["StackStatus"],
                "template_sha256": template_sha, "resource_count": 19,
                "api_disabled": True, "lambda_reserved_concurrency": 0, "handler_zip_sha256": zip_sha,
                "owner_issuer": issuer, "owner_client_id": authority["owner_client_id"],
                "owner_tenant_key": authority["owner_tenant_key"], "authorization_table": _AUTH_TABLE,
                "authorization_row_status": "active", "authorization_row_revision": 1,
                "authorization_row_key": authority["owner_tenant_key"], "mapit_table_id": mapit_table_id,
                "mapit_config_path": config_path, "mapit_config_version": mapit_version,
                "mapit_parameter_version": 1, "leading_keys": leading,
                "owner_context_sha256": owner_context_sha,
                "owner_oauth_receipt_sha256": authority["owner_oauth_receipt_sha256"],
                "mapit_bootstrap_receipt_sha256": mapit_digest,
                "invitation_receipt_sha256": invitation_digest,
                "key_publication_receipt_sha256": key_digest,
                "runtime_evidence_sha256": runtime_evidence_sha,
                "runtime_checks": runtime_checks, "completion_event": completion,
            }
            final_api = view["apigatewayv2"].get_api(ApiId=self.context.policy.api_id)
            final_concurrency = view["lambda"].get_function_concurrency(FunctionName=_HANDLER)
            if (final_api.get("ApiId") != self.context.policy.api_id
                    or final_api.get("DisableExecuteApiEndpoint") is not True
                    or type(final_concurrency.get("ReservedConcurrentExecutions")) is not int
                    or final_concurrency["ReservedConcurrentExecutions"] != 0):
                raise ValueError
            final_identity = view["sts"].get_caller_identity()
            if (final_identity.get("Account") != authority["account_id"]
                    or final_identity.get("Arn") != authority["operator_arn"]):
                raise ValueError
            self._check_observation_gates()
            if accepted:
                progress = self._phase_progress_projection()
                progress_sha = _observation_progress_digest(progress)
                if self._accepted_capsule is not None:
                    if (progress_sha != self._accepted_capsule["progress_sha256"]
                            or owner_context_sha != self._accepted_capsule["owner_context_sha256"]):
                        raise ValueError
                    runtime_evidence_sha = self._accepted_capsule["runtime_evidence_sha256"]
                else:
                    runtime_evidence_sha = _runtime_evidence_digest_v2(
                        target_template_sha256=template_sha, artifact_sha256=zip_sha,
                        owner_context_sha256=owner_context_sha, progress_sha256=progress_sha,
                        accepted_read_call_count=budget.calls)
                value["runtime_evidence_sha256"] = runtime_evidence_sha
            self._assert_integrity()
            _strict_state(value, phase=phase, binding=authority,
                prior_sha=authority["prior_template_sha256"], target_sha=self.target_sha,
                zip_sha=self.zip_sha, leading_keys=[*authority["historical_tenant_keys"], authority["owner_tenant_key"]],
                issuer=template["Resources"]["McpJwtAuthorizer"]["Properties"]["JwtConfiguration"]["Issuer"])
            if self._progress_digest is None:
                self._progress_digest = self._phase_progress_digest()
            if accepted:
                self._last_accepted_observation = {
                    "owner_context_sha256": owner_context_sha,
                    "runtime_evidence_sha256": runtime_evidence_sha,
                    "calls": budget.calls,
                }
            self._last_successful_state = value
            self._last_read_call_count = budget.calls
            return value
        except OwnerEnrolledReadbackError:
            if budget is not None:
                self._last_read_call_count = budget.calls
            raise
        except Exception:
            if budget is not None:
                self._last_read_call_count = budget.calls
            _fail("current_state_unverified")

    def _historical_synthetic_policy(self) -> dict[str, Any]:
        """Rebuild the synthetic runtime policy from immutable private lineage."""
        try:
            bundle, _raw = _load_mapit_evidence_bundle(
                self.mapit_evidence_path, acl_checker=self.acl_checker)
            if (_mapit_runtime_evidence_digest(bundle)
                    != self.bootstrap_authority.runtime_evidence_sha256):
                raise ValueError
            runtime_binding = _validate_mapit_evidence_bundle(
                bundle, self.bootstrap_authority, self.bootstrap_template)
            if (runtime_binding.get("account_id") != self.bootstrap_authority.account_id
                    or runtime_binding.get("operator_user_arn") != self.bootstrap_authority.expected_caller_arn):
                raise ValueError
            clients = {name: self.clients[name] for name in (
                "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
                "apigatewayv2", "lambda", "kms")}
            policy = _validate_historical_mapit_bootstrap(
                clients=clients, binding_path=self.synthetic_binding_path,
                authorization_path=self.synthetic_authorization_path,
                state_dir=self.synthetic_state_dir, bundle=bundle,
                authority=self.bootstrap_authority, acl_checker=self.acl_checker)
            if (type(policy) is not dict or set(policy) != {"policy_name", "policy_document"}
                    or policy["policy_name"] != "honda-mapit-mcp-dev-identity-bindings-runtime-read"
                    or type(policy["policy_document"]) is not dict):
                raise ValueError
            return policy["policy_document"]
        except Exception:
            _fail("current_state_unverified")


def make_owner_enrolled_current_state(**kwargs):
    """Create a read-only callback for ``OwnerEnrolledClosedDelivery``.

    This factory is deliberately keyword-only through its implementation
    constructor. It requires genuine accepted OAuth context and namespace
    evidence objects, plus the established pre-update runtime verifier.
    """
    try:
        return OwnerEnrolledCurrentState(**kwargs)
    except OwnerEnrolledReadbackError:
        raise
    except Exception:
        _fail("binding_invalid")


def make_owner_enrolled_accepted_observer(**kwargs):
    """Construct accepted-only fresh readback from a verified restart capsule.

    This read-only mode never runs pre-update phases or renews the expired
    delivery authority. It requires the accepted runtime hash from the exact
    accepted update-journal receipt and a fresh ≤600-second observation window
    with fresh source/protection callbacks.
    """
    try:
        required = {"accepted_observation_capsule", "observation_window",
                    "accepted_update_state",
                    "accepted_runtime_evidence_sha256", "observation_source_check",
                    "observation_protection_check"}
        if not required.issubset(kwargs):
            raise ValueError
        return OwnerEnrolledCurrentState(**kwargs)
    except OwnerEnrolledReadbackError:
        raise
    except Exception:
        _fail("binding_invalid")


__all__ = ["OwnerEnrolledCurrentState", "OwnerEnrolledReadbackError",
           "make_owner_enrolled_accepted_observer", "make_owner_enrolled_current_state"]
