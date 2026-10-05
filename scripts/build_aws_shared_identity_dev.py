"""Compose a closed dev runtime against the separate retained identity pool."""

from __future__ import annotations

import copy
import re
from typing import Any

from mapit.aws_dev_runtime import CognitoDevPolicy
from scripts.build_aws_dev_oauth_template import build_dev_oauth_setup_template, build_dev_oauth_template
from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template

_REMOVED = {"McpUserPool", "McpUserPoolDomain"}
_EXPECTED_RESOURCE_COUNT = 16
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")


class SharedIdentityTemplateError(ValueError):
    """Safe error for the shared-pool dev composition."""


def build_shared_identity_bootstrap_template() -> dict[str, Any]:
    """Build the fixed five-resource closed dev bootstrap without a pool."""
    template = fixed_bootstrap_template()
    resources = template.get("Resources")
    outputs = template.get("Outputs")
    if (
        not isinstance(resources, dict)
        or set(resources) != {"McpApi", "McpApiStage", "McpUserPool", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"}
        or not isinstance(outputs, dict)
        or set(outputs) != {"ApiId", "UserPoolId"}
    ):
        raise SharedIdentityTemplateError("shared_identity_bootstrap_invalid")
    resources.pop("McpUserPool")
    outputs.pop("UserPoolId")
    if _contains_pool_ref(template):
        raise SharedIdentityTemplateError("shared_identity_bootstrap_reference_invalid")
    template["Metadata"].update({
        "Readiness": "SHARED_IDENTITY_BOOTSTRAP_NOT_DEPLOY_READY",
        "UsesSeparatelyRetainedIdentityPool": True,
        "NoPoolResourceOrPoolOutput": True,
        "PersistentPoolOwnershipAndReadbackRequired": True,
    })
    return template


def build_shared_identity_oauth_setup_template(api_id: str, user_pool_id: str, *, callback_url: str) -> dict[str, Any]:
    """Build the fixed eight-resource OAuth setup bound to an observed pool ID."""
    if type(user_pool_id) is not str or not _POOL_ID.fullmatch(user_pool_id):
        raise SharedIdentityTemplateError("shared_identity_pool_id_invalid")
    try:
        template = build_dev_oauth_setup_template(api_id, callback_url=callback_url)
    except Exception:
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid") from None
    resources = template.get("Resources")
    if not isinstance(resources, dict) or len(resources) != 10 or not _REMOVED <= set(resources):
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid")
    resources.pop("McpUserPool")
    resources.pop("McpUserPoolDomain")
    for name, resource in tuple(resources.items()):
        if not isinstance(resource, dict):
            raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid")
        template["Resources"][name] = _bind_pool_refs(resource, user_pool_id)
    client = resources.get("McpUserPoolClient")
    branding = resources.get("McpManagedLoginBranding")
    if not isinstance(client, dict) or not isinstance(branding, dict):
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid")
    if client.get("DependsOn") != ["McpResourceServer", "McpUserPoolDomain"]:
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid")
    client["DependsOn"] = ["McpResourceServer"]
    if branding.get("DependsOn") != ["McpUserPoolDomain"]:
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid")
    branding.pop("DependsOn")
    outputs = template.get("Outputs")
    if not isinstance(outputs, dict) or not isinstance(outputs.get("UserPoolId"), dict):
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_invalid")
    outputs["UserPoolId"]["Value"] = user_pool_id
    if _contains_pool_ref(template):
        raise SharedIdentityTemplateError("shared_identity_oauth_setup_reference_invalid")
    template["Metadata"].update({
        "Readiness": "SHARED_IDENTITY_OAUTH_SETUP_NOT_DEPLOY_READY",
        "UsesSeparatelyRetainedIdentityPool": True,
        "PoolIDIsValidatedLiteralBinding": True,
        "NoPoolOrDomainResources": True,
        "PersistentPoolOwnershipAndReadbackRequired": True,
    })
    return template


def _retain_shared_pool_children(template: dict[str, Any]) -> dict[str, Any]:
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise SharedIdentityTemplateError("shared_identity_retention_contract_invalid")
    expected_types = {
        "McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
        "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
        "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding",
    }
    for name, expected_type in expected_types.items():
        resource = resources.get(name)
        if not isinstance(resource, dict) or resource.get("Type") != expected_type:
            raise SharedIdentityTemplateError("shared_identity_retention_contract_invalid")
        resource["DeletionPolicy"] = "Retain"
        resource["UpdateReplacePolicy"] = "Retain"
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise SharedIdentityTemplateError("shared_identity_retention_contract_invalid")
    metadata.update({
        "SharedPoolDevChildrenRetained": True,
        "SharedPoolDevChildrenRequireSeparateOperatorRetirement": True,
        "NoAutomaticPoolChildDeletion": True,
    })
    return template


def build_shared_identity_oauth_setup_retained_template(
    api_id: str, user_pool_id: str, *, callback_url: str,
) -> dict[str, Any]:
    """OAuth setup variant retaining its three shared-pool child resources."""
    return _retain_shared_pool_children(
        build_shared_identity_oauth_setup_template(api_id, user_pool_id, callback_url=callback_url)
    )


def _bind_pool_refs(value: Any, pool_id: str) -> Any:
    if isinstance(value, dict):
        if set(value) == {"Ref"} and value.get("Ref") == "McpUserPool":
            return pool_id
        result = {}
        for key, child in value.items():
            if key == "Fn::Sub" and type(child) is str and "${McpUserPool}" in child:
                result[key] = child.replace("${McpUserPool}", pool_id)
            else:
                result[key] = _bind_pool_refs(child, pool_id)
        return result
    if isinstance(value, list):
        return [_bind_pool_refs(item, pool_id) for item in value]
    return value


def _contains_pool_ref(value: Any) -> bool:
    if isinstance(value, dict):
        return (
            value == {"Ref": "McpUserPool"}
            or ("Fn::Sub" in value and type(value["Fn::Sub"]) is str and "${McpUserPool}" in value["Fn::Sub"])
            or any(_contains_pool_ref(child) for child in value.values())
        )
    if isinstance(value, list):
        return any(_contains_pool_ref(item) for item in value)
    return False


def build_shared_identity_dev_template(
    policy: CognitoDevPolicy,
    *,
    bucket: str,
    zip_sha256: str,
    jwks_sha256: str,
    callback_url: str,
    execution_start: int,
    execution_end: int,
) -> dict[str, Any]:
    """Build the existing dev runtime with a separately retained Cognito pool.

    The original standalone OAuth/runtime factory is not modified. This wrapper
    removes only the dev-owned pool/domain and binds their references to the
    validated persistent pool ID; it leaves the dev app client and `use` scope
    in the dev compute stack. Operationally, use the staged setup/readback flow:
    create and verify the dev client first, then compose the runtime with the
    observed client ID in ``policy``. The Lambda binding remains that validated
    literal; this factory does not infer or substitute a generated client ID.
    """
    if type(policy) is not CognitoDevPolicy:
        raise SharedIdentityTemplateError("shared_identity_policy_invalid")
    try:
        template = build_dev_oauth_template(
            policy,
            bucket=bucket,
            zip_sha256=zip_sha256,
            jwks_sha256=jwks_sha256,
            callback_url=callback_url,
            execution_start=execution_start,
            execution_end=execution_end,
        )
    except Exception:
        raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid") from None
    resources = template.get("Resources")
    if not isinstance(resources, dict) or len(resources) != _EXPECTED_RESOURCE_COUNT or not _REMOVED <= set(resources):
        raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid")
    pool_id = policy.user_pool_id
    resources.pop("McpUserPool")
    resources.pop("McpUserPoolDomain")
    for name, resource in tuple(resources.items()):
        if not isinstance(resource, dict):
            raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid")
        template["Resources"][name] = _bind_pool_refs(resource, pool_id)
    client = resources.get("McpUserPoolClient")
    branding = resources.get("McpManagedLoginBranding")
    if not isinstance(client, dict) or not isinstance(branding, dict):
        raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid")
    client_dependencies = client.get("DependsOn")
    if client_dependencies != ["McpResourceServer", "McpUserPoolDomain"]:
        raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid")
    client["DependsOn"] = ["McpResourceServer"]
    if branding.get("DependsOn") != ["McpUserPoolDomain"]:
        raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid")
    branding.pop("DependsOn")
    outputs = template.get("Outputs")
    if not isinstance(outputs, dict) or not isinstance(outputs.get("UserPoolId"), dict):
        raise SharedIdentityTemplateError("shared_identity_runtime_candidate_invalid")
    outputs["UserPoolId"]["Value"] = pool_id
    if _contains_pool_ref(template):
        raise SharedIdentityTemplateError("shared_identity_pool_reference_unbound")
    template["Metadata"].update({
        "SharedPersistentIdentityPool": True,
        "IdentityStackName": "honda-mapit-mcp-identity",
        "NoPoolOrDomainResourcesInDevStack": True,
        "DevOwnsOnlyItsResourceServerClientAndBranding": True,
        "PersistentPoolMustExistAndBeReadBackBeforeDevStackUpdate": True,
        "DevClientMustBeCreatedAndReadBackBeforeRuntimeComposition": True,
        "RuntimeClientIdIsValidatedLiteralBinding": True,
    })
    return template


def build_shared_identity_dev_retained_template(
    policy: CognitoDevPolicy,
    *,
    bucket: str,
    zip_sha256: str,
    jwks_sha256: str,
    callback_url: str,
    execution_start: int,
    execution_end: int,
) -> dict[str, Any]:
    """Runtime variant retaining shared-pool client/resource-server/branding."""
    return _retain_shared_pool_children(build_shared_identity_dev_template(
        policy, bucket=bucket, zip_sha256=zip_sha256, jwks_sha256=jwks_sha256,
        callback_url=callback_url, execution_start=execution_start, execution_end=execution_end,
    ))


__all__ = [
    "SharedIdentityTemplateError",
    "build_shared_identity_bootstrap_template",
    "build_shared_identity_oauth_setup_template",
    "build_shared_identity_oauth_setup_retained_template",
    "build_shared_identity_dev_template",
    "build_shared_identity_dev_retained_template",
]
