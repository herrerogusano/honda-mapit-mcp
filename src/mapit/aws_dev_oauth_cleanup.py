"""Offline draft for exact-scope cleanup of dev OAuth child resources.

The generated role is not deployment-ready. It must be paired with observed
resource ownership, a complete closed-stack deletion rehearsal, and separate
runtime-artifact retirement. Optional provider permission branches remain a
review gate; no KMS or broader IAM permissions are included here.
"""

from __future__ import annotations

import re
from typing import Any

from .aws_dev_bootstrap_cleanup import build_dev_bootstrap_cleanup
from .aws_dev_shutdown import AwsDevShutdownPolicy

_REGION = "eu-west-1"
_OBSERVED_RESOURCE_ID = re.compile(r"^[a-z0-9]{1,64}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,45}$")
_HANDLER_FUNCTION_NAME = "honda-mapit-mcp-dev-handler"
_BASE_CLEANUP_RESOURCES = frozenset({"BootstrapDeletionRole", "BootstrapCleanupScheduleGroup", "BootstrapCleanupSchedulerRole", "BootstrapCleanupSchedule"})


def _validated_bootstrap_cleanup(policy, user_pool_id: str, stack_uuid: str, schedule_at_utc: str):
    """Build and verify the shared exact six-statement bootstrap cleanup role."""
    try:
        template = build_dev_bootstrap_cleanup(policy, user_pool_id, stack_uuid, schedule_at_utc)
    except Exception:
        raise ValueError("bootstrap cleanup contract invalid") from None
    resources = template.get("Resources")
    role = resources.get("BootstrapDeletionRole") if isinstance(resources, dict) else None
    properties = role.get("Properties") if isinstance(role, dict) else None
    policies = properties.get("Policies") if isinstance(properties, dict) else None
    document = policies[0].get("PolicyDocument") if isinstance(policies, list) and len(policies) == 1 and isinstance(policies[0], dict) else None
    statements = document.get("Statement") if isinstance(document, dict) else None
    if not isinstance(resources, dict) or set(resources) != _BASE_CLEANUP_RESOURCES:
        raise ValueError("bootstrap cleanup contract invalid")
    if not isinstance(statements, list) or len(statements) != 6:
        raise ValueError("bootstrap cleanup contract invalid")

    api_root = {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}"}
    api_stage = {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}/stages/$default"}
    expected = [
        {"Effect": "Allow", "Action": ["apigateway:GET", "apigateway:DELETE"], "Resource": [api_root, api_stage]},
        {"Effect": "Allow", "Action": "cognito-idp:DeleteUserPool", "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{user_pool_id}"}},
        {"Effect": "Allow", "Action": ["lambda:DeleteFunction", "lambda:GetFunction"], "Resource": {"Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{_HANDLER_FUNCTION_NAME}"}},
        {"Effect": "Allow", "Action": [
            "iam:DeleteRole", "iam:DetachRolePolicy", "iam:DeleteRolePolicy", "iam:GetRole",
            "iam:ListAttachedRolePolicies", "iam:ListRolePolicies", "iam:TagRole", "iam:UntagRole",
        ], "Resource": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/honda-mapit-mcp-dev-handler-role"}},
        {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": "*", "Condition": {"StringEquals": {"aws:RequestedRegion": _REGION}}},
        {"Effect": "Allow", "Action": ["logs:DeleteLogGroup", "logs:DeleteDataProtectionPolicy"], "Resource": [
            {"Fn::Sub": f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/{_HANDLER_FUNCTION_NAME}"},
            {"Fn::Sub": f"arn:${{AWS::Partition}}:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/{_HANDLER_FUNCTION_NAME}:*"},
        ]},
    ]
    if statements != expected:
        raise ValueError("bootstrap cleanup contract invalid")
    return template, statements


def _validate_id(value: str) -> str:
    if type(value) is not str or not _OBSERVED_RESOURCE_ID.fullmatch(value):
        raise ValueError("invalid observed OAuth resource identifier")
    return value


def build_dev_oauth_cleanup(
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
    """Extend the fixed bootstrap cleanup schedule for observed OAuth children.

    This is a pure template factory: it does not inspect AWS, deploy a role, or
    infer ownership from identifier shape. All supplied child IDs must have
    been read back and independently matched to this closed dev API.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")
    policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    if policy.region != _REGION:
        raise ValueError("unsupported development region")
    if type(user_pool_id) is not str or not _POOL_ID.fullmatch(user_pool_id):
        raise ValueError("invalid observed OAuth pool identifier")
    authorizer_id = _validate_id(authorizer_id)
    integration_id = _validate_id(integration_id)
    post_route_id = _validate_id(post_route_id)
    metadata_route_id = _validate_id(metadata_route_id)
    if post_route_id == metadata_route_id:
        raise ValueError("OAuth routes must have distinct observed identifiers")

    template, statements = _validated_bootstrap_cleanup(policy, user_pool_id, stack_uuid, schedule_at_utc)
    resources = template["Resources"]
    api_root = {"Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}"}
    api_arn = lambda suffix: {
        "Fn::Sub": f"arn:${{AWS::Partition}}:apigateway:${{AWS::Region}}::/apis/{policy.api_id}/{suffix}"
    }
    api_statement = statements[0]
    expected_api_resources = [api_root, api_arn("stages/$default")]

    expected_api_resources.extend([
        api_arn(f"authorizers/{authorizer_id}"),
        api_arn(f"integrations/{integration_id}"),
        api_arn(f"routes/{post_route_id}"),
        api_arn(f"routes/{metadata_route_id}"),
    ])
    api_statement["Resource"] = expected_api_resources
    statements[1]["Action"] = [
        "cognito-idp:DeleteUserPool",
        "cognito-idp:DeleteUserPoolDomain",
        "cognito-idp:DeleteResourceServer",
        "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DeleteManagedLoginBranding",
    ]
    statements.insert(2, {
        "Effect": "Allow",
        "Action": "cognito-idp:DescribeUserPoolDomain",
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": _REGION}},
    })
    lambda_statement = statements[3]
    if (
        lambda_statement.get("Effect") != "Allow"
        or lambda_statement.get("Action") != ["lambda:DeleteFunction", "lambda:GetFunction"]
        or lambda_statement.get("Resource") != {"Fn::Sub": f"arn:${{AWS::Partition}}:lambda:${{AWS::Region}}:${{AWS::AccountId}}:function:{_HANDLER_FUNCTION_NAME}"}
    ):
        raise ValueError("bootstrap cleanup contract invalid")
    lambda_statement["Action"] = ["lambda:DeleteFunction", "lambda:GetFunction", "lambda:RemovePermission"]
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("bootstrap cleanup contract invalid")
    metadata.update({
        "Readiness": "OAUTH_CLEANUP_NOT_DEPLOY_READY",
        "ReplacesBootstrapOnlyCleanupScope": True,
        "ObservedOAuthChildOwnershipRequired": True,
        "FullClosedOAuthStackDeletionRehearsalRequired": True,
        "RuntimeArtifactRetirementAndEmptyBucketVerificationRequired": True,
        "OptionalProviderPermissionBranchesPending": True,
        "KmsPermissionsIncluded": False,
        "MissingPrerequisites": [
            "observed child-resource ownership independently matched to this exact dev API/pool",
            "all optional Cognito-provider deletion branches reviewed against actual configuration",
            "full closed OAuth stack deletion rehearsal and absence readback",
            "runtime artifact retirement and empty-bucket verification remain separate",
        ],
    })
    return template


def build_dev_oauth_setup_cleanup(
    policy: AwsDevShutdownPolicy,
    user_pool_id: str,
    stack_uuid: str,
    schedule_at_utc: str,
) -> dict[str, Any]:
    """Build exact cleanup for the closed Cognito setup stage only.

    The setup stage adds no API child routes. Permissions remain scoped to the
    known pool and fixed bootstrap resources; schedules stay disabled.
    """
    if type(policy) is not AwsDevShutdownPolicy:
        raise ValueError("a validated development shutdown policy is required")
    policy = AwsDevShutdownPolicy(policy.api_id, region=policy.region)
    if policy.region != _REGION or type(user_pool_id) is not str or not _POOL_ID.fullmatch(user_pool_id):
        raise ValueError("bootstrap cleanup contract invalid")
    template, statements = _validated_bootstrap_cleanup(policy, user_pool_id, stack_uuid, schedule_at_utc)
    pool_statement = statements[1]
    if pool_statement["Resource"] != {
        "Fn::Sub": f"arn:${{AWS::Partition}}:cognito-idp:${{AWS::Region}}:${{AWS::AccountId}}:userpool/{user_pool_id}"
    }:
        raise ValueError("bootstrap cleanup contract invalid")
    pool_statement["Action"] = [
        "cognito-idp:DeleteUserPool",
        "cognito-idp:DeleteUserPoolDomain",
        "cognito-idp:DeleteResourceServer",
        "cognito-idp:DeleteUserPoolClient",
        "cognito-idp:DeleteManagedLoginBranding",
    ]
    statements.insert(2, {
        "Effect": "Allow",
        "Action": "cognito-idp:DescribeUserPoolDomain",
        "Resource": "*",
        "Condition": {"StringEquals": {"aws:RequestedRegion": _REGION}},
    })
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise ValueError("bootstrap cleanup contract invalid")
    metadata.update({
        "Readiness": "OAUTH_SETUP_CLEANUP_NOT_DEPLOY_READY",
        "FixedTargetCognitoSetupOnly": True,
        "ObservedBootstrapOwnershipRequired": True,
        "FullSetupDeletionRehearsalRequired": True,
        "NoApiChildPermissions": True,
        "NoRuntimeArtifactPermissions": True,
        "OptionalProviderPermissionBranchesPending": True,
        "KmsPermissionsIncluded": False,
        "MissingPrerequisites": [
            "exact bootstrap stack ownership and pool/API bindings independently read back",
            "cleanup role policy and enabled one-time 45-minute app deletion schedule read back before app update",
            "full Cognito setup stack deletion and resource absence rehearsed",
            "runtime OAuth, owner binding, and enrollment remain separate gates",
        ],
    })
    return template


__all__ = ["build_dev_oauth_cleanup", "build_dev_oauth_setup_cleanup"]
