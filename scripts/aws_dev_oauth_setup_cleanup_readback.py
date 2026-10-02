"""Read-only deletion readback for an owned dev OAuth setup stack.

Clients and the private journal snapshot are supplied by the operator. This
module never creates SDK clients, loads credentials, retries, or performs AWS
writes. A positive result covers the ten setup-stack resources and Cognito
parent/domain only; the rehearsal runner separately verifies the original six
app resources and controls before deleting controls.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

_REGION = "eu-west-1"
_STACK_NAME = "honda-mapit-mcp-dev"
_RUN_TAG = "ClosedRehearsalRunId"
_DOMAIN = "hm-dev-honda-mapit-mcp-dev"
_API_ID = re.compile(r"^[a-z0-9]{10}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")
_CLIENT_ID = re.compile(r"^[A-Za-z0-9]{1,128}$")
_ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
_RESOURCES = {
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


@dataclass(frozen=True)
class OAuthSetupCleanupReadback:
    verified: bool
    category: str
    calls: int
    stack_delete_complete: bool = False
    setup_resources_deleted: bool = False
    user_pool_absent: bool = False
    domain_absent: bool = False
    user_pool_client_absent: bool = False

    def safe_projection(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "category": self.category,
            "calls": self.calls,
            "stack_delete_complete": self.stack_delete_complete,
            "setup_resources_deleted": self.setup_resources_deleted,
            "user_pool_absent": self.user_pool_absent,
            "domain_absent": self.domain_absent,
            "user_pool_client_absent": self.user_pool_client_absent,
        }


def _valid_state(state: Any, expected_account_id: Any) -> bool:
    if not isinstance(state, Mapping) or type(expected_account_id) is not str or not _ACCOUNT_ID.fullmatch(expected_account_id):
        return False
    if state.get("account_id") != expected_account_id or state.get("region") != _REGION:
        return False
    if state.get("oauth_setup_verified") is not True:
        return False
    fallback_delete = state.get("app_delete_attempted") is True
    scheduled_delete = False
    started = state.get("resource_started_epoch")
    expression = state.get("oauth_setup_cleanup_schedule_expression")
    if state.get("oauth_setup_controls_verified") is True and type(started) is int and started > 0:
        try:
            stamp = datetime.fromtimestamp(started + 2700, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            scheduled_delete = expression == f"at({stamp})"
        except (OverflowError, OSError, ValueError):
            scheduled_delete = False
    if not (fallback_delete or scheduled_delete):
        return False
    if type(state.get("api_id")) is not str or not _API_ID.fullmatch(state["api_id"]):
        return False
    if type(state.get("user_pool_id")) is not str or not _POOL_ID.fullmatch(state["user_pool_id"]):
        return False
    if type(state.get("oauth_setup_client_id")) is not str or not _CLIENT_ID.fullmatch(state["oauth_setup_client_id"]):
        return False
    run_id = state.get("run_id")
    if type(run_id) is not str:
        return False
    try:
        run_uuid = uuid.UUID(run_id)
    except (ValueError, AttributeError):
        return False
    if str(run_uuid) != run_id or run_uuid.int == 0:
        return False
    stack_arn = state.get("app_stack_id")
    prefix = f"arn:aws:cloudformation:{_REGION}:{expected_account_id}:stack/{_STACK_NAME}/"
    if type(stack_arn) is not str or not stack_arn.startswith(prefix):
        return False
    suffix = stack_arn[len(prefix):]
    try:
        stack_uuid = uuid.UUID(suffix)
    except (ValueError, AttributeError):
        return False
    return (
        str(stack_uuid) == suffix and stack_uuid.int != 0
        and state.get("stack_uuid") == suffix
    )


def _metadata_ok(response: Any) -> bool:
    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
    return (
        isinstance(metadata, Mapping)
        and type(metadata.get("HTTPStatusCode")) is int
        and metadata["HTTPStatusCode"] == 200
    )


def _known_not_found(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    error = response.get("Error")
    metadata = response.get("ResponseMetadata")
    return (
        isinstance(error, Mapping)
        and error.get("Code") == "ResourceNotFoundException"
        and isinstance(metadata, Mapping)
        and type(metadata.get("HTTPStatusCode")) is int
        and metadata["HTTPStatusCode"] == 400
    )


def check_oauth_setup_cleanup(
    clients: Mapping[str, Any],
    *,
    state: Mapping[str, Any],
    expected_account_id: str,
) -> OAuthSetupCleanupReadback:
    """Verify deletion of the owned ten-resource OAuth setup stack.

    The supplied state must be the already-private journal snapshot. Child
    Cognito resources are considered absent only after both all ten CloudFormation
    resources report DELETE_COMPLETE and the exact pool and fixed domain readbacks
    confirm absence. No user/client identifiers are returned.
    """
    required = {"cloudformation", "cognito"}
    if not _valid_state(state, expected_account_id) or not isinstance(clients, Mapping) or not required <= clients.keys():
        return OAuthSetupCleanupReadback(False, "cleanup_inputs_invalid", 0)

    calls = 0

    def call(service: str, method: str, **kwargs: Any) -> Mapping[str, Any] | None:
        nonlocal calls
        calls += 1
        try:
            response = getattr(clients[service], method)(**kwargs)
        except Exception:
            raise
        if not _metadata_ok(response):
            raise ValueError("readback_response_invalid")
        return response

    stack_arn = state["app_stack_id"]
    try:
        stack_response = call("cloudformation", "describe_stacks", StackName=stack_arn)
        stacks = stack_response.get("Stacks")
        if type(stacks) is not list or len(stacks) != 1 or not isinstance(stacks[0], Mapping):
            return OAuthSetupCleanupReadback(False, "stack_delete_readback_invalid", calls)
        stack = stacks[0]
        tags = stack.get("Tags")
        if (
            stack.get("StackId") != stack_arn
            or stack.get("StackName") != _STACK_NAME
            or stack.get("StackStatus") != "DELETE_COMPLETE"
            or type(tags) is not list
            or not any(isinstance(tag, Mapping) and tag.get("Key") == _RUN_TAG and tag.get("Value") == state["run_id"] for tag in tags)
        ):
            return OAuthSetupCleanupReadback(False, "stack_delete_unverified", calls)

        resources_response = call("cloudformation", "describe_stack_resources", StackName=stack_arn)
        rows = resources_response.get("StackResources")
        if type(rows) is not list or len(rows) != len(_RESOURCES):
            return OAuthSetupCleanupReadback(False, "setup_resources_invalid", calls, stack_delete_complete=True)
        found: set[str] = set()
        for row in rows:
            if not isinstance(row, Mapping):
                return OAuthSetupCleanupReadback(False, "setup_resources_invalid", calls, stack_delete_complete=True)
            logical = row.get("LogicalResourceId")
            if type(logical) is not str or logical not in _RESOURCES or logical in found:
                return OAuthSetupCleanupReadback(False, "setup_resources_invalid", calls, stack_delete_complete=True)
            if row.get("ResourceType") != _RESOURCES[logical] or row.get("ResourceStatus") != "DELETE_COMPLETE":
                return OAuthSetupCleanupReadback(False, "setup_resources_not_deleted", calls, stack_delete_complete=True)
            found.add(logical)
        if found != set(_RESOURCES):
            return OAuthSetupCleanupReadback(False, "setup_resources_invalid", calls, stack_delete_complete=True)

        pool_absent = False
        try:
            call("cognito", "describe_user_pool", UserPoolId=state["user_pool_id"])
        except Exception as exc:
            if not _known_not_found(exc):
                raise
            pool_absent = True
        else:
            return OAuthSetupCleanupReadback(False, "user_pool_still_present", calls, True, True)

        domain_absent = False
        try:
            domain_response = call("cognito", "describe_user_pool_domain", Domain=_DOMAIN)
        except Exception as exc:
            if not _known_not_found(exc):
                raise
            domain_absent = True
        else:
            description = domain_response.get("DomainDescription")
            if not isinstance(description, Mapping):
                return OAuthSetupCleanupReadback(False, "domain_readback_invalid", calls, True, True, pool_absent, False, pool_absent)
            domain_absent = not description
            if not domain_absent:
                return OAuthSetupCleanupReadback(False, "domain_still_present", calls, True, True, pool_absent, False, pool_absent)
        return OAuthSetupCleanupReadback(
            pool_absent and domain_absent,
            "oauth_setup_deleted_verified" if pool_absent and domain_absent else "oauth_setup_delete_unverified",
            calls, True, True, pool_absent, domain_absent, pool_absent,
        )
    except Exception:
        return OAuthSetupCleanupReadback(False, "cleanup_readback_failed", calls)


__all__ = ["OAuthSetupCleanupReadback", "check_oauth_setup_cleanup"]
