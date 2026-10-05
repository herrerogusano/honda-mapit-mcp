"""Pure, offline policy factory for a narrowly scoped production CD role pair.

This module builds review material only; it creates no AWS clients/resources.
The caller must privately source exact current resource bindings and the
observed GitHub OIDC subject digest before using the result.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from scripts.build_cd_identity_bootstrap import AUDIENCE, ISSUER_HOST, OWNER, REPOSITORY
from scripts.build_aws_dev_runtime_template import _validate_bucket_name


class DeliveryRoleError(ValueError):
    """Closed input category; never includes resource identifiers."""

    def __init__(self, category: str = "invalid_configuration") -> None:
        self.category = category if category in {"invalid_configuration", "subject_digest_mismatch"} else "invalid_configuration"
        super().__init__(self.category)


_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_DECIMAL_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
_SUBJECT_FORMATS = {"legacy_environment", "immutable_environment"}
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_ROLE_PATH = re.compile(r"(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+\Z")
_PROD_STACK = "honda-mapit-mcp-prod"
_FUNCTION = "honda-mapit-mcp-prod-handler"
_STATE_MACHINE = "honda-mapit-mcp-prod-shutdown"
_ARTIFACT_STACK_BUCKET_PREFIX = "honda-mapit-mcp-prod-runtime-artifacts-"
_ALARM = "honda-mapit-mcp-prod-request-tripwire"
_RULE = "honda-mapit-mcp-prod-request-tripwire-alarm-rule"
_EXECUTOR_ROLE = "honda-mapit-mcp-prod-cd-executor"
_CFN_ROLE = "honda-mapit-mcp-prod-cfn-update"


def _subject(subject_format: str, owner_id: str, repository_id: str) -> str:
    if subject_format == "legacy_environment":
        return f"repo:{OWNER}/{REPOSITORY}:environment:prod"
    if subject_format == "immutable_environment":
        return f"repo:{OWNER}@{owner_id}/{REPOSITORY}@{repository_id}:environment:prod"
    raise DeliveryRoleError()


def _account(account_id: str) -> None:
    if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or account_id == "000000000000":
        raise DeliveryRoleError()


def _exact(value: Any, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise DeliveryRoleError()
    return value


def _policy(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def _permissions_boundary(policy: dict[str, Any]) -> dict[str, Any]:
    allowed_actions: list[str] = []
    for statement in policy["Statement"]:
        actions = statement["Action"]
        for action in actions if isinstance(actions, list) else [actions]:
            if action not in allowed_actions:
                allowed_actions.append(action)
    # Reuse the scoped action/resource/condition grants as the boundary's
    # ceiling; the explicit NotAction deny additionally blocks future grants.
    statements = [dict(statement) for statement in policy["Statement"]]
    statements.append({"Sid": "DenyEveryUnlistedAction", "Effect": "Deny",
                       "NotAction": allowed_actions, "Resource": "*"})
    return _policy(statements)


def _tagset(target: str) -> list[dict[str, str]]:
    return [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": target},
        {"Key": "Purpose", "Value": "CDDelivery"},
    ]


def build_cd_delivery_roles(
    *,
    account_id: str,
    provider_arn: str,
    owner_id: str,
    repository_id: str,
    observed_prod_subject_format: str,
    observed_prod_subject_sha256: str,
    stack_arn: str,
    handler_arn: str,
    api_arn: str,
    shutdown_state_machine_arn: str,
    artifact_bucket_arn: str,
    execution_role_arn: str,
    tripwire_alarm_arn: str,
    tripwire_rule_arn: str,
    allow_execution_role_passrole: bool,
) -> dict[str, Any]:
    """Build four IAM resources; identifiers must come from private readbacks.

    No direct Lambda code/config writes or artifact publication are granted to
    GitHub. The optional Lambda execution-role PassRole is explicit and off by
    default only in the sense that callers must supply an exact bool decision.
    """
    _account(account_id)
    if (
        type(owner_id) is not str or _DECIMAL_ID.fullmatch(owner_id) is None
        or type(repository_id) is not str or _DECIMAL_ID.fullmatch(repository_id) is None
        or type(observed_prod_subject_format) is not str
        or observed_prod_subject_format not in _SUBJECT_FORMATS
        or type(observed_prod_subject_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", observed_prod_subject_sha256) is None
        or type(allow_execution_role_passrole) is not bool
    ):
        raise DeliveryRoleError()
    expected_subject = _subject(observed_prod_subject_format, owner_id, repository_id)
    expected_digest = hashlib.sha256(expected_subject.encode("ascii")).hexdigest()
    if not hmac.compare_digest(expected_digest, observed_prod_subject_sha256):
        raise DeliveryRoleError("subject_digest_mismatch")

    _exact(provider_arn, f"arn:aws:iam::{account_id}:oidc-provider/{ISSUER_HOST}")
    stack_prefix = f"arn:aws:cloudformation:eu-west-1:{account_id}:stack/{_PROD_STACK}/"
    if type(stack_arn) is not str or not stack_arn.startswith(stack_prefix) or _UUID.fullmatch(stack_arn[len(stack_prefix):]) is None:
        raise DeliveryRoleError()
    _exact(handler_arn, f"arn:aws:lambda:eu-west-1:{account_id}:function:{_FUNCTION}")
    api_match = re.fullmatch(r"arn:aws:apigateway:eu-west-1::/apis/([a-z0-9]{10})", api_arn) if type(api_arn) is str else None
    if api_match is None:
        raise DeliveryRoleError()
    _exact(shutdown_state_machine_arn, f"arn:aws:states:eu-west-1:{account_id}:stateMachine:{_STATE_MACHINE}")
    bucket_match = re.fullmatch(r"arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", artifact_bucket_arn) if type(artifact_bucket_arn) is str else None
    if bucket_match is None:
        raise DeliveryRoleError()
    try:
        bucket_name = _validate_bucket_name(bucket_match.group(1))
    except Exception:
        raise DeliveryRoleError() from None
    if not bucket_name.startswith(_ARTIFACT_STACK_BUCKET_PREFIX):
        raise DeliveryRoleError()
    if type(execution_role_arn) is not str:
        raise DeliveryRoleError()
    execution_match = re.fullmatch(rf"arn:aws:iam::{account_id}:role/(.+)", execution_role_arn)
    if execution_match is None or _ROLE_PATH.fullmatch(execution_match.group(1)) is None:
        raise DeliveryRoleError()
    _exact(tripwire_alarm_arn, f"arn:aws:cloudwatch:eu-west-1:{account_id}:alarm:{_ALARM}")
    _exact(tripwire_rule_arn, f"arn:aws:events:eu-west-1:{account_id}:rule/{_RULE}")

    cfn_role_arn = f"arn:aws:iam::{account_id}:role/{_CFN_ROLE}"
    stack_read = ["cloudformation:GetTemplate", "cloudformation:DescribeStacks", "cloudformation:DescribeStackResources"]
    executor_statements: list[dict[str, Any]] = [
        {"Sid": "ReadCallerIdentity", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
        {"Sid": "UpdateOnlyOwnedStackWithFixedServiceRole", "Effect": "Allow",
         "Action": "cloudformation:UpdateStack", "Resource": stack_arn,
         "Condition": {"StringEquals": {"cloudformation:RoleArn": cfn_role_arn}}},
        {"Sid": "ReadOnlyOwnedStack", "Effect": "Allow", "Action": stack_read, "Resource": stack_arn},
        {"Sid": "PassOnlyFixedCloudFormationRole", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": cfn_role_arn,
         "Condition": {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}}},
        {"Sid": "StartOnlyFixedShutdownWorkflow", "Effect": "Allow",
         "Action": "states:StartExecution", "Resource": shutdown_state_machine_arn},
        {"Sid": "InspectOnlyFixedShutdownWorkflow", "Effect": "Allow",
         "Action": "states:DescribeStateMachine", "Resource": shutdown_state_machine_arn},
        {"Sid": "InspectOnlyFixedShutdownExecutions", "Effect": "Allow",
         "Action": "states:DescribeExecution",
         "Resource": f"arn:aws:states:eu-west-1:{account_id}:execution:{_STATE_MACHINE}:*"},
        {"Sid": "UpdateOnlyFixedApiEndpoint", "Effect": "Allow", "Action": "apigateway:PATCH", "Resource": api_arn},
        {"Sid": "ReadOnlyFixedApi", "Effect": "Allow", "Action": "apigateway:GET", "Resource": api_arn},
        {"Sid": "RestoreOnlyFixedFunctionConcurrency", "Effect": "Allow",
         "Action": ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionConcurrency",
                    "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency"],
         "Resource": handler_arn},
        {"Sid": "ReadRegionalConcurrencyCeiling", "Effect": "Allow", "Action": "lambda:GetAccountSettings", "Resource": "*"},
        {"Sid": "ReadOnlyTripwire", "Effect": "Allow", "Action": "cloudwatch:DescribeAlarms", "Resource": tripwire_alarm_arn},
        {"Sid": "ReadOnlyTripwireRule", "Effect": "Allow",
         "Action": ["events:DescribeRule", "events:ListTargetsByRule"], "Resource": tripwire_rule_arn},
    ]
    executor_policy = _policy(executor_statements)

    cfn_actions = ["lambda:GetFunction", "lambda:GetFunctionConfiguration",
                   "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration"]
    cfn_statements: list[dict[str, Any]] = [
        {"Sid": "UpdateAndReadOnlyFixedHandler", "Effect": "Allow",
         "Action": cfn_actions, "Resource": handler_arn},
        {"Sid": "ReadOnlyRuntimePackagePrefix", "Effect": "Allow", "Action": "s3:GetObject",
         "Resource": f"{artifact_bucket_arn}/runtime/*"},
        {"Sid": "ReadExactExistingExecutionRoleDependencies", "Effect": "Allow",
         "Action": ["iam:GetRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies",
                    "iam:GetRolePolicy", "iam:ListRoleTags"],
         "Resource": execution_role_arn},
    ]
    if allow_execution_role_passrole:
        cfn_statements.append({
            "Sid": "PassOnlyFixedHandlerExecutionRole", "Effect": "Allow", "Action": "iam:PassRole",
            "Resource": execution_role_arn,
            "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
        })
    cfn_policy = _policy(cfn_statements)

    resources: dict[str, Any] = {}
    for title, role_name, principal, policy, purpose in (
        ("Executor", _EXECUTOR_ROLE, {"Federated": provider_arn}, executor_policy, "CDDeliveryExecutor"),
        ("CloudFormation", _CFN_ROLE, {"Service": "cloudformation.amazonaws.com"}, cfn_policy, "CDCloudFormationService"),
    ):
        boundary_name = f"honda-mapit-mcp-prod-cd-{title.lower()}-boundary"
        boundary_id = f"ProdCd{title}Boundary"
        role_id = f"ProdCd{title}Role"
        if title == "Executor":
            trust_condition: dict[str, Any] = {"StringEquals": {
                f"{ISSUER_HOST}:aud": AUDIENCE,
                f"{ISSUER_HOST}:sub": expected_subject,
            }}
        else:
            trust_condition = {}
        trust_statement: dict[str, Any] = {
            "Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole",
        }
        if title == "Executor":
            trust_statement["Action"] = "sts:AssumeRoleWithWebIdentity"
            trust_statement["Condition"] = trust_condition
        resources[boundary_id] = {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {"ManagedPolicyName": boundary_name,
                           "Description": "Maximum permissions boundary for one fixed production CD role.",
                           "PolicyDocument": _permissions_boundary(policy)},
        }
        resources[role_id] = {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "Description": "Narrow production CD capability; offline review artifact only.",
                "MaxSessionDuration": 3600,
                "PermissionsBoundary": {"Fn::GetAtt": [boundary_id, "PolicyArn"]},
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [trust_statement]},
                "Policies": [{"PolicyName": f"{role_name}-policy", "PolicyDocument": policy}],
                "Tags": _tagset("prod"),
            },
        }
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Offline production CD role/boundary draft; not deploy-ready.",
        "Metadata": {
            "Readiness": "NOT_DEPLOY_READY",
            "Environment": "prod",
            "ExistingIdentityRolesChanged": False,
            "DirectLambdaCodeOrConfigWritesForExecutor": False,
            "ArtifactPublicationForExecutor": False,
            "ExecutionRolePassRoleForCloudFormation": allow_execution_role_passrole,
            "ServiceRoleAssociationIsPersistent": True,
            "ApiGatewayHttpApiResourceScopePendingClosedValidation": True,
            "ApiGatewayPropertyChangeGuardIsTemplateOnly": True,
            "RequiresIndependentPolicyAndResourceReadback": True,
        },
        "Resources": resources,
    }


__all__ = ["DeliveryRoleError", "build_cd_delivery_roles"]
