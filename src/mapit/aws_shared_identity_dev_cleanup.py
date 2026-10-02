"""Exact cleanup for dev OAuth children on a retained shared identity pool."""

from __future__ import annotations

from typing import Any

from .aws_dev_oauth_cleanup import build_dev_oauth_cleanup
from .aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup
from .aws_dev_shutdown import AwsDevShutdownPolicy


def build_shared_identity_dev_cleanup(
    policy: AwsDevShutdownPolicy,
    user_pool_id: str,
    stack_uuid: str,
    schedule_at_utc: str,
    *,
    authorizer_id: str,
    integration_id: str,
    post_route_id: str,
    metadata_route_id: str,
) -> dict[str, Any]:
    """Keep exact dev-child cleanup while forbidding shared-pool deletion.

    The persistent identity pool/domain are not deleted by this role. Cognito
    child-delete permissions are scoped to the pool ARN, not individual child
    IDs, so they may affect any resource server, app client, or branding in
    that pool. This draft is not deploy-ready until that blast radius is
    explicitly accepted and the owned workflow's child bindings are verified.
    """
    try:
        template = build_dev_oauth_cleanup(
            policy, user_pool_id, stack_uuid, schedule_at_utc,
            authorizer_id=authorizer_id,
            integration_id=integration_id,
            post_route_id=post_route_id,
            metadata_route_id=metadata_route_id,
        )
    except Exception:
        raise ValueError("shared_identity_cleanup_inputs_invalid") from None
    resources = template.get("Resources")
    role = resources.get("BootstrapDeletionRole") if isinstance(resources, dict) else None
    props = role.get("Properties") if isinstance(role, dict) else None
    policies = props.get("Policies") if isinstance(props, dict) else None
    document = policies[0].get("PolicyDocument") if isinstance(policies, list) and len(policies) == 1 and isinstance(policies[0], dict) else None
    statements = document.get("Statement") if isinstance(document, dict) else None
    if not isinstance(statements, list) or len(statements) != 7:
        raise ValueError("shared_identity_cleanup_contract_invalid")
    pool_arn = {"Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{user_pool_id}"}
    if (
        statements[1].get("Resource") != pool_arn
        or statements[1].get("Action") != [
            "cognito-idp:DeleteUserPool",
            "cognito-idp:DeleteUserPoolDomain",
            "cognito-idp:DeleteResourceServer",
            "cognito-idp:DeleteUserPoolClient",
            "cognito-idp:DeleteManagedLoginBranding",
        ]
        or statements[2] != {
            "Effect": "Allow",
            "Action": "cognito-idp:DescribeUserPoolDomain",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}},
        }
    ):
        raise ValueError("shared_identity_cleanup_contract_invalid")
    statements[1]["Action"] = [
        "cognito-idp:DeleteResourceServer",
        "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DeleteManagedLoginBranding",
    ]
    statements.pop(2)
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("shared_identity_cleanup_contract_invalid")
    metadata.update({
        "Readiness": "SHARED_IDENTITY_DEV_CLEANUP_NOT_DEPLOY_READY",
        "PersistentPoolAndDomainPreserved": True,
        "CognitoChildDeletesAreScopedToPoolNotIndividualChildren": True,
        "SharedPoolChildDeletionBlastRadiusRequiresExplicitAcceptance": True,
        "ExactWorkflowChildBindingsMustBeVerifiedBeforeUse": True,
        "OptionalProviderPermissionBranchesPending": True,
        "KmsPermissionsIncluded": False,
        "MissingPrerequisites": [
            "exact persistent pool identity and all dev child IDs read back",
            "explicit acceptance and minimization of shared-pool child-delete blast radius",
            "shared-pool-preserving cleanup rehearsal independently reviewed",
            "runtime S3 artifact retirement completed separately",
        ],
    })
    return template


def build_shared_identity_bootstrap_cleanup(
    policy: AwsDevShutdownPolicy,
    user_pool_id: str,
    stack_uuid: str,
    schedule_at_utc: str,
) -> dict[str, Any]:
    """Build fixed bootstrap cleanup without any Cognito pool deletion grant."""
    try:
        template = build_dev_bootstrap_cleanup(policy, user_pool_id, stack_uuid, schedule_at_utc)
    except Exception:
        raise ValueError("shared_identity_bootstrap_cleanup_inputs_invalid") from None
    resources = template.get("Resources")
    role = resources.get("BootstrapDeletionRole") if isinstance(resources, dict) else None
    props = role.get("Properties") if isinstance(role, dict) else None
    policies = props.get("Policies") if isinstance(props, dict) else None
    document = policies[0].get("PolicyDocument") if isinstance(policies, list) and len(policies) == 1 and isinstance(policies[0], dict) else None
    statements = document.get("Statement") if isinstance(document, dict) else None
    expected_pool_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{user_pool_id}"
    }
    if (
        not isinstance(statements, list) or len(statements) != 6
        or statements[1] != {"Effect": "Allow", "Action": "cognito-idp:DeleteUserPool", "Resource": expected_pool_arn}
    ):
        raise ValueError("shared_identity_bootstrap_cleanup_contract_invalid")
    statements.pop(1)
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("shared_identity_bootstrap_cleanup_contract_invalid")
    metadata.update({
        "Readiness": "SHARED_IDENTITY_BOOTSTRAP_CLEANUP_NOT_DEPLOY_READY",
        "PersistentIdentityPoolDeletionPermissionExcluded": True,
        "PoolARNChildPermissionNotIncluded": True,
        "ExactBootstrapOwnershipAndReadbackRequired": True,
    })
    return template


def build_shared_identity_dev_cleanup_operator_retired(
    policy: AwsDevShutdownPolicy,
    user_pool_id: str,
    stack_uuid: str,
    schedule_at_utc: str,
    *,
    authorizer_id: str,
    integration_id: str,
    post_route_id: str,
    metadata_route_id: str,
) -> dict[str, Any]:
    """Build dev-stack cleanup with Cognito children retained for operator retirement.

    This schedule role has no Cognito actions. Retained child resources require
    a separate operator process using exact observed IDs and ownership checks.
    """
    template = build_shared_identity_dev_cleanup(
        policy, user_pool_id, stack_uuid, schedule_at_utc,
        authorizer_id=authorizer_id, integration_id=integration_id,
        post_route_id=post_route_id, metadata_route_id=metadata_route_id,
    )
    resources = template.get("Resources")
    role = resources.get("BootstrapDeletionRole") if isinstance(resources, dict) else None
    props = role.get("Properties") if isinstance(role, dict) else None
    policies = props.get("Policies") if isinstance(props, dict) else None
    document = policies[0].get("PolicyDocument") if isinstance(policies, list) and len(policies) == 1 and isinstance(policies[0], dict) else None
    statements = document.get("Statement") if isinstance(document, dict) else None
    expected_pool_arn = {
        "Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{user_pool_id}"
    }
    if (
        not isinstance(statements, list) or len(statements) != 6
        or statements[1].get("Resource") != expected_pool_arn
        or statements[1].get("Action") != [
            "cognito-idp:DeleteResourceServer", "cognito-idp:DeleteUserPoolClient",
            "cognito-idp:DeleteManagedLoginBranding",
        ]
    ):
        raise ValueError("shared_identity_operator_cleanup_contract_invalid")
    statements.pop(1)
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("shared_identity_operator_cleanup_contract_invalid")
    metadata.pop("CognitoChildDeletesAreScopedToPoolNotIndividualChildren", None)
    metadata.pop("SharedPoolChildDeletionBlastRadiusRequiresExplicitAcceptance", None)
    metadata.update({
        "Readiness": "SHARED_IDENTITY_DEV_OPERATOR_CHILD_RETIREMENT_NOT_DEPLOY_READY",
        "NoAutomaticPoolChildDeletion": True,
        "RetainedChildrenRequireSeparateOperatorRetirement": True,
        "ExactObservedChildIDsAndOwnershipRequired": True,
        "MissingPrerequisites": [
            "verify exact dev-owned retained child IDs and ownership after compute closure",
            "perform separately reviewed operator retirement and readback",
            "runtime S3 artifact retirement completed separately",
        ],
    })
    return template


__all__ = [
    "build_shared_identity_dev_cleanup",
    "build_shared_identity_bootstrap_cleanup",
    "build_shared_identity_dev_cleanup_operator_retired",
]
