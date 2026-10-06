"""Closed retained-dev V2 CloudFormation role extension.

This module reuses the reviewed retained-dev OIDC/executor role factory and
changes only the CloudFormation service-role policy and its boundary.  It is
an offline policy factory: it never constructs an SDK client or performs an
AWS operation.  The bootstrap form permits the unavoidable Cognito wildcard
while the new user-pool ID is unknown; the recurrent form requires the exact
observed pool ID and removes that wildcard.
"""

from __future__ import annotations

import copy
import hashlib
import re
from typing import Any

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.build_cd_delivery_roles import _permissions_boundary
from scripts.build_cd_retained_dev_roles import (
    CFN_ROLE_NAME,
    EXECUTOR_ROLE_NAME,
    RetainedDevRoleError,
    build_cd_retained_dev_roles,
)


REGION = "eu-west-1"
TABLE_NAME = "honda-mapit-mcp-dev-tenants"
_ACCOUNT = re.compile(r"^[0-9]{12}$")
_POOL_ID = re.compile(r"^eu-west-1_[A-Za-z0-9]{9,64}$")


class RetainedDevMultiuserRoleError(RetainedDevRoleError):
    """Closed input category for the multi-user role extension."""

    def __init__(self, category: str = "invalid_configuration") -> None:
        allowed = {
            "invalid_configuration", "subject_digest_mismatch", "artifact_binding_invalid",
            "multiuser_user_pool_binding_invalid", "multiuser_executor_changed",
            "multiuser_boundary_too_large",
            "multiuser_environment_key_unsupported",
        }
        self.category = category if category in allowed else "invalid_configuration"
        super(RetainedDevRoleError, self).__init__(self.category)


def _fail(category: str = "invalid_configuration") -> None:
    raise RetainedDevMultiuserRoleError(category)


def _policy(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def _cognito_pool_arn(account_id: str, pool_id: str) -> str:
    return f"arn:aws:cognito-idp:{REGION}:{account_id}:userpool/{pool_id}"


def _table_arn(account_id: str) -> str:
    return f"arn:aws:dynamodb:{REGION}:{account_id}:table/{TABLE_NAME}"


def _cognito_statements(*, account_id: str, pool_id: str | None) -> list[dict[str, Any]]:
    """Return exactly the Cognito lifecycle used by the V2 template.

    CloudFormation must create the pool before its ID exists.  In that one
    bootstrap phase, pool-scoped children therefore use ``*``.  A recurrent
    delivery receives the observed pool ID and scopes every action to the
    corresponding pool ARN.  No user, password, message, identity-pool, or
    federation action is included.
    """
    resource = _cognito_pool_arn(account_id, pool_id) if pool_id is not None else "*"
    tag_condition = {
        "StringEquals": {
            "aws:RequestTag/Project": "honda-mapit-mcp",
            "aws:RequestTag/Environment": "dev",
        },
        # The retained parent stack propagates its ownership tags to nested
        # CloudFormation resources.  Purpose is fixed; OperatorRunId is the
        # bounded operator binding and is validated by the coordinator/journal
        # rather than hard-coded into this reusable policy factory.
        "StringEqualsIfExists": {
            "aws:RequestTag/Purpose": "retained-dev",
        },
        # CloudFormation may add its three reserved stack tags to a tagged
        # resource request.  Keep the request fail-closed while allowing only
        # those documented system keys in addition to the two application
        # ownership tags.
        "ForAllValues:StringLike": {
            "aws:TagKeys": [
                "Project", "Environment", "Purpose", "OperatorRunId",
                "aws:cloudformation:*",
            ],
        },
    }
    resource_tag_condition = {
        "StringEquals": {
            "aws:ResourceTag/Project": "honda-mapit-mcp",
            "aws:ResourceTag/Environment": "dev",
        }
    }
    statements: list[dict[str, Any]] = []
    if pool_id is None:
        statements.append({
            "Sid": "CreateOnlyTaggedDevUserPool",
            "Effect": "Allow",
            "Action": "cognito-idp:CreateUserPool",
            "Resource": "*",
            "Condition": tag_condition,
        })
    statements.append({
        "Sid": "ManageTaggedDevUserPool",
        "Effect": "Allow",
        "Action": [
            "cognito-idp:DescribeUserPool", "cognito-idp:UpdateUserPool",
            "cognito-idp:DeleteUserPool", "cognito-idp:TagResource",
            "cognito-idp:UntagResource", "cognito-idp:ListTagsForResource",
            "cognito-idp:SetUserPoolMfaConfig", "cognito-idp:GetUserPoolMfaConfig",
        ],
        "Resource": resource,
        **({"Condition": resource_tag_condition} if pool_id is None else {}),
    })
    child_actions = {
        "UserPoolDomain": [
            "cognito-idp:CreateUserPoolDomain", "cognito-idp:UpdateUserPoolDomain",
            "cognito-idp:DeleteUserPoolDomain",
        ],
        "ResourceServer": [
            "cognito-idp:CreateResourceServer", "cognito-idp:DescribeResourceServer",
            "cognito-idp:UpdateResourceServer", "cognito-idp:DeleteResourceServer",
        ],
        "UserPoolClient": [
            "cognito-idp:CreateUserPoolClient", "cognito-idp:DescribeUserPoolClient",
            "cognito-idp:UpdateUserPoolClient", "cognito-idp:DeleteUserPoolClient",
        ],
        "ManagedLoginBranding": [
            "cognito-idp:CreateManagedLoginBranding", "cognito-idp:DescribeManagedLoginBranding",
            "cognito-idp:DescribeManagedLoginBrandingByClient",
            "cognito-idp:UpdateManagedLoginBranding", "cognito-idp:DeleteManagedLoginBranding",
            "cognito-idp:ListUserPoolClientSecrets",
        ],
    }
    for suffix, actions in child_actions.items():
        statements.append({
            "Sid": f"ManageDev{suffix}", "Effect": "Allow", "Action": actions,
            "Resource": resource,
            **({"Condition": resource_tag_condition} if pool_id is None else {}),
        })
    # DescribeUserPoolDomain is the one required Cognito read that has no
    # userpool resource type in the service authorization reference.  Keep it
    # as a standalone read-only wildcard; all domain writes remain pool scoped.
    statements.append({
        "Sid": "ReadDevUserPoolDomain",
        "Effect": "Allow",
        "Action": "cognito-idp:DescribeUserPoolDomain",
        "Resource": "*",
    })
    return statements


def _multiuser_cfn_statements(*, account_id: str, api_arn: str,
                              handler_arn: str, execution_role_arn: str,
                              pool_id: str | None) -> list[dict[str, Any]]:
    api_prefix = api_arn.rstrip("/")
    # Do not grant the generic ``/apis/{id}/*`` namespace: that would also
    # cover stages, deployments, exports, and other API Gateway resources
    # outside the V2 template's authorizer/integration/route lifecycle.
    api_children = [
        f"{api_prefix}/authorizers", f"{api_prefix}/authorizers/*",
        f"{api_prefix}/integrations", f"{api_prefix}/integrations/*",
        f"{api_prefix}/routes", f"{api_prefix}/routes/*",
    ]
    table_arn = _table_arn(account_id)
    statements = _cognito_statements(account_id=account_id, pool_id=pool_id)
    statements.extend([
        {
            "Sid": "ManageRetainedDevApiChildren",
            "Effect": "Allow",
            "Action": ["apigateway:GET", "apigateway:POST", "apigateway:PATCH", "apigateway:DELETE"],
            "Resource": api_children,
        },
        {
            "Sid": "ReadRetainedDevApi",
            "Effect": "Allow",
            "Action": "apigateway:GET",
            "Resource": api_arn,
        },
        {
            "Sid": "ManageRetainedDevLambdaPermissions",
            "Effect": "Allow",
            "Action": ["lambda:AddPermission", "lambda:RemovePermission", "lambda:GetPolicy"],
            "Resource": handler_arn,
        },
        {
            "Sid": "UpdateRetainedDevHandlerRolePolicy",
            "Effect": "Allow",
            "Action": ["iam:PutRolePolicy", "iam:DeleteRolePolicy"],
            "Resource": execution_role_arn,
        },
        {
            "Sid": "ManageRetainedDevTenantTable",
            "Effect": "Allow",
            "Action": [
                "dynamodb:CreateTable", "dynamodb:DescribeTable", "dynamodb:UpdateTable",
                "dynamodb:DeleteTable", "dynamodb:TagResource", "dynamodb:UntagResource",
                "dynamodb:ListTagsOfResource", "dynamodb:DescribeContinuousBackups",
                "dynamodb:DescribeContributorInsights", "dynamodb:DescribeKinesisStreamingDestination",
                "dynamodb:GetResourcePolicy", "dynamodb:DescribeTimeToLive",
            ],
            "Resource": table_arn,
        },
    ])
    return statements


def _compact_boundary(policy: dict[str, Any]) -> dict[str, Any]:
    """Compact equivalent statements to stay below IAM's 6144-byte limit.

    Sids are informational.  Statements with identical authorization context
    (effect/resource/conditions and any other non-Action fields) can safely
    share one statement with the union of their actions.  The deny
    ``NotAction`` statement is retained as-is; no permission is removed or
    added by this transformation.
    """
    statements = policy.get("Statement") if isinstance(policy, dict) else None
    if not isinstance(statements, list):
        _fail("invalid_configuration")
    output: list[dict[str, Any]] = []
    by_context: dict[str, int] = {}
    for statement in statements:
        if not isinstance(statement, dict):
            _fail("invalid_configuration")
        action = statement.get("Action")
        context = {key: value for key, value in statement.items()
                   if key not in {"Sid", "Action"}}
        context_key = _canonical(context).decode("ascii")
        if action is not None and context_key in by_context:
            target = output[by_context[context_key]]
            old_action = target.get("Action")
            old_values = old_action if isinstance(old_action, list) else [old_action]
            new_values = action if isinstance(action, list) else [action]
            if all(type(value) is str for value in (*old_values, *new_values)):
                target["Action"] = sorted(set((*old_values, *new_values)))
                continue
        compacted = dict(context)
        if action is not None:
            actions = sorted(set(action if isinstance(action, list) else [action]))
            compacted["Action"] = actions[0] if len(actions) == 1 else actions
        output.append(compacted)
        by_context[context_key] = len(output) - 1
    compacted_policy = {"Version": policy.get("Version"), "Statement": output}
    if len(_canonical(compacted_policy)) > 6144:
        _fail("multiuser_boundary_too_large")
    return compacted_policy


def build_cd_retained_dev_multiuser_roles(
    *,
    account_id: str,
    provider_arn: str,
    owner_id: str,
    repository_id: str,
    observed_dev_subject_format: str,
    observed_dev_subject_sha256: str,
    stack_arn: str,
    artifact_stack_arn: str,
    handler_arn: str,
    api_arn: str,
    shutdown_state_machine_arn: str,
    artifact_bucket_arn: str,
    execution_role_arn: str,
    lambda_environment_key_arn: str | None = None,
    observed_user_pool_id: str | None = None,
) -> dict[str, Any]:
    """Extend the exact retained-dev role pair for the multi-user V2 stack.

    ``observed_user_pool_id=None`` is only for the first closed setup, when the
    pool ID does not exist yet.  It retains the same four role/boundary
    resources and uses the tag-scoped bootstrap wildcard.  Passing an observed
    pool ID produces the recurrent, pool-ARN-scoped policy.
    """
    if lambda_environment_key_arn is not None:
        # This opt-in DEV contract excludes the optional customer-managed
        # environment-key variant in both bootstrap and recurrent phases.
        _fail("multiuser_environment_key_unsupported")
    if observed_user_pool_id is not None and (
        type(observed_user_pool_id) is not str or _POOL_ID.fullmatch(observed_user_pool_id) is None
    ):
        _fail("multiuser_user_pool_binding_invalid")
    base = build_cd_retained_dev_roles(
        account_id=account_id, provider_arn=provider_arn, owner_id=owner_id,
        repository_id=repository_id, observed_dev_subject_format=observed_dev_subject_format,
        observed_dev_subject_sha256=observed_dev_subject_sha256, stack_arn=stack_arn,
        artifact_stack_arn=artifact_stack_arn, handler_arn=handler_arn, api_arn=api_arn,
        shutdown_state_machine_arn=shutdown_state_machine_arn, artifact_bucket_arn=artifact_bucket_arn,
        execution_role_arn=execution_role_arn, lambda_environment_key_arn=lambda_environment_key_arn,
    )
    template = copy.deepcopy(base)
    cfn_role_id = "RetainedDevCdCloudFormationRole"
    cfn_boundary_id = "RetainedDevCdCloudFormationBoundary"
    cfn_policy = template["Resources"][cfn_role_id]["Properties"]["Policies"][0]["PolicyDocument"]
    cfn_policy["Statement"].extend(_multiuser_cfn_statements(
        account_id=account_id, api_arn=api_arn, handler_arn=handler_arn,
        execution_role_arn=execution_role_arn, pool_id=observed_user_pool_id,
    ))
    template["Resources"][cfn_boundary_id]["Properties"]["PolicyDocument"] = _compact_boundary(
        _permissions_boundary(
            cfn_policy,
            environment_key=lambda_environment_key_arn,
            handler_arn=handler_arn,
        )
    )
    metadata = template.setdefault("Metadata", {})
    metadata.update({
        "Readiness": "RETAINED_DEV_MULTIUSER_ROLES_NOT_DEPLOY_READY",
        "RetainedNamespace": "honda-mapit-mcp-dev-retained",
        "MultiuserRoleVersion": 2,
        "MultiuserSetupPhase": "bootstrap" if observed_user_pool_id is None else "recurrent",
        "ObservedUserPoolIdBound": observed_user_pool_id is not None,
        "CfnOnlyExtension": True,
        "NoProdNamesOrBindings": True,
        "NoUserCreation": True,
        "NoMapitCredentials": True,
        "NoRuntimeTenantWrites": True,
        "NoIamMutation": False,
        "NoApiPatch": False,
        "CanonicalTemplateSha256": hashlib.sha256(_canonical(template["Resources"])).hexdigest(),
    })
    # The executor role, its trust, and its boundary must remain byte-identical
    # to the reviewed retained-dev factory.  The assertion is intentionally
    # performed here so future edits cannot silently broaden it.
    if template["Resources"]["RetainedDevCdExecutorRole"] != base["Resources"]["RetainedDevCdExecutorRole"]:
        _fail("multiuser_executor_changed")
    if template["Resources"]["RetainedDevCdExecutorBoundary"] != base["Resources"]["RetainedDevCdExecutorBoundary"]:
        _fail("multiuser_executor_changed")
    return template


__all__ = ["RetainedDevMultiuserRoleError", "build_cd_retained_dev_multiuser_roles"]
