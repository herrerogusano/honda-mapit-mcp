"""Pure offline factory for the retained-development CD role pair.

This is review material only.  It constructs no AWS clients and does not
create, update, activate, or read any account resource.  Every resource name
and binding is fixed to the retained ``dev`` namespace; callers must supply
the exact private readbacks before any separately reviewed deployment gate.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any

from scripts.aws_retained_dev_bootstrap import _canonical
from scripts.build_aws_dev_runtime_template import _validate_bucket_name
from scripts.build_cd_delivery_roles import _permissions_boundary
from scripts.build_cd_identity_bootstrap import AUDIENCE, ISSUER_HOST, OWNER, REPOSITORY


class RetainedDevRoleError(ValueError):
    """Stable input category without interpolated identifiers or provider text."""

    def __init__(self, category: str = "invalid_configuration") -> None:
        allowed = {"invalid_configuration", "subject_digest_mismatch", "artifact_binding_invalid"}
        self.category = category if category in allowed else "invalid_configuration"
        super().__init__(self.category)


REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained"
FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
EXECUTOR_ROLE_NAME = "honda-mapit-mcp-dev-retained-cd-executor"
CFN_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
SHUTDOWN_MACHINE_NAME = "honda-mapit-mcp-dev-retained-shutdown"
ALARM_NAME = "honda-mapit-mcp-dev-retained-request-tripwire"
RULE_NAME = "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"
ARTIFACT_STACK_NAME = "honda-mapit-mcp-dev-retained-runtime-artifacts"
SUBJECT_FORMATS = {"legacy_environment", "immutable_environment"}
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_DECIMAL_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_STACK = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/"
    rf"{re.escape(STACK_NAME)}/([0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}})\Z"
)
_ARTIFACT_STACK = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/"
    rf"{re.escape(ARTIFACT_STACK_NAME)}/([0-9a-f]{{8}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{4}}-[0-9a-f]{{12}})\Z"
)


def _subject(format_name: str, owner_id: str, repository_id: str) -> str:
    if format_name == "legacy_environment":
        return f"repo:{OWNER}/{REPOSITORY}:environment:dev"
    if format_name == "immutable_environment":
        return f"repo:{OWNER}@{owner_id}/{REPOSITORY}@{repository_id}:environment:dev"
    raise RetainedDevRoleError()


def _account(value: Any) -> str:
    if type(value) is not str or _ACCOUNT.fullmatch(value) is None or value == "000000000000":
        raise RetainedDevRoleError()
    return value


def _exact(value: Any, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise RetainedDevRoleError()
    return value


def _policy(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def _stack_arn(value: Any, account_id: str, name: str) -> str:
    pattern = _STACK if name == STACK_NAME else _ARTIFACT_STACK
    match = pattern.fullmatch(value) if type(value) is str else None
    if match is None or match.group(1) != account_id:
        raise RetainedDevRoleError("artifact_binding_invalid" if name != STACK_NAME else "invalid_configuration")
    return value


def _build_executor_policy(
    *, account_id: str, stack_arn: str, api_arn: str, shutdown_arn: str,
    artifact_bucket_arn: str, cfn_role_arn: str, handler_arn: str,
    allow_environment_key: str | None = None,
) -> dict[str, Any]:
    execution_arns = f"arn:aws:states:{REGION}:{account_id}:execution:{SHUTDOWN_MACHINE_NAME}:*"
    alarm_arn = f"arn:aws:cloudwatch:{REGION}:{account_id}:alarm:{ALARM_NAME}"
    rule_arn = f"arn:aws:events:{REGION}:{account_id}:rule/{RULE_NAME}"
    stack_read = ["cloudformation:GetTemplate", "cloudformation:DescribeStacks", "cloudformation:DescribeStackResources"]
    statements: list[dict[str, Any]] = [
        {"Sid": "ReadCallerIdentity", "Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"},
        {"Sid": "UpdateOnlyOwnedRetainedStack", "Effect": "Allow", "Action": "cloudformation:UpdateStack",
         "Resource": stack_arn, "Condition": {"StringEquals": {"cloudformation:RoleArn": cfn_role_arn}}},
        {"Sid": "ReadOnlyOwnedRetainedStack", "Effect": "Allow", "Action": stack_read, "Resource": stack_arn},
        {"Sid": "PassOnlyRetainedCloudFormationRole", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": cfn_role_arn, "Condition": {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}}},
        {"Sid": "StartOnlyRetainedShutdown", "Effect": "Allow", "Action": "states:StartExecution", "Resource": shutdown_arn},
        {"Sid": "InspectRetainedShutdown", "Effect": "Allow", "Action": "states:DescribeStateMachine", "Resource": shutdown_arn},
        {"Sid": "InspectRetainedShutdownExecutions", "Effect": "Allow", "Action": "states:DescribeExecution", "Resource": execution_arns},
        {"Sid": "ReadOnlyRetainedApi", "Effect": "Allow", "Action": "apigateway:GET", "Resource": api_arn},
        {"Sid": "ReadOnlyRetainedTripwire", "Effect": "Allow", "Action": "cloudwatch:DescribeAlarms", "Resource": alarm_arn},
        {"Sid": "ReadOnlyRetainedTripwireRule", "Effect": "Allow",
         "Action": ["events:DescribeRule", "events:ListTargetsByRule"], "Resource": rule_arn},
        {"Sid": "ReadOnlyRetainedFunction", "Effect": "Allow", "Action": [
            "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionConcurrency", "lambda:ListTags",
        ], "Resource": handler_arn},
        {"Sid": "ReadRegionalConcurrencyCeiling", "Effect": "Allow", "Action": "lambda:GetAccountSettings", "Resource": "*"},
        {"Sid": "ReadRuntimePackages", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{artifact_bucket_arn}/runtime/*"},
        {"Sid": "PublishRuntimePackagesWithoutOverwrite", "Effect": "Allow", "Action": "s3:PutObject",
         "Resource": f"{artifact_bucket_arn}/runtime/*", "Condition": {"StringEquals": {"s3:if-none-match": "*"}}},
        {"Sid": "ReadDeliveryJournals", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{artifact_bucket_arn}/journals/*"},
        {"Sid": "CreateDeliveryJournalWithoutOverwrite", "Effect": "Allow", "Action": "s3:PutObject",
         "Resource": f"{artifact_bucket_arn}/journals/*", "Condition": {"StringEquals": {"s3:if-none-match": "*"}}},
        {"Sid": "ReviseDeliveryJournalWithObservedEtag", "Effect": "Allow", "Action": "s3:PutObject",
         "Resource": f"{artifact_bucket_arn}/journals/*", "Condition": {"Null": {"s3:if-match": "false"}}},
        {"Sid": "ReadDeliveryJournalTags", "Effect": "Allow", "Action": "s3:GetObjectTagging", "Resource": f"{artifact_bucket_arn}/journals/*"},
        {"Sid": "MarkOnlyTerminalDeliveryJournals", "Effect": "Allow", "Action": "s3:PutObjectTagging",
         "Resource": f"{artifact_bucket_arn}/journals/*", "Condition": {
             "ForAllValues:StringEquals": {"s3:RequestObjectTagKeys": ["cd-terminal"]},
             "StringEquals": {"s3:RequestObjectTag/cd-terminal": "true"},
             "Null": {"s3:RequestObjectTagKeys": "false"},
         }},
        {"Sid": "ReadExactArtifactBucketSecurityMetadata", "Effect": "Allow", "Action": [
            "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketOwnershipControls", "s3:GetEncryptionConfiguration", "s3:GetBucketTagging",
            "s3:GetBucketPolicyStatus", "s3:GetBucketPolicy",
        ], "Resource": artifact_bucket_arn},
    ]
    if allow_environment_key is not None:
        statements.append({"Sid": "FixedLambdaEnvironmentKey", "Effect": "Allow", "Action": "kms:Decrypt",
                           "Resource": allow_environment_key,
                           "Condition": {"StringEquals": {
                               "kms:CallerAccount": account_id,
                               "kms:ViaService": "lambda.eu-west-1.amazonaws.com",
                               "kms:EncryptionContext:aws:lambda:FunctionArn": handler_arn,
                           }}})
    return _policy(statements)


def _build_cfn_policy(*, artifact_bucket_arn: str, handler_arn: str, execution_role_arn: str,
                      allow_environment_key: str | None = None) -> dict[str, Any]:
    statements: list[dict[str, Any]] = [
        {"Sid": "UpdateOnlyRetainedHandler", "Effect": "Allow", "Action": [
            "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig",
            "lambda:ListTags", "lambda:TagResource", "lambda:UntagResource",
            "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
        ], "Resource": handler_arn},
        {"Sid": "ReadOnlyRuntimePackagePrefix", "Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{artifact_bucket_arn}/runtime/*"},
        {"Sid": "ReadExactExecutionRoleDependencies", "Effect": "Allow", "Action": [
            "iam:GetRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetRolePolicy", "iam:ListRoleTags",
        ], "Resource": execution_role_arn},
        {"Sid": "PassOnlyRetainedLambdaExecutionRole", "Effect": "Allow", "Action": "iam:PassRole",
         "Resource": execution_role_arn, "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
    ]
    if allow_environment_key is not None:
        statements.append({"Sid": "FixedLambdaEnvironmentKey", "Effect": "Allow",
                           "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
                           "Resource": allow_environment_key,
                           "Condition": {"StringEquals": {
                               "kms:CallerAccount": execution_role_arn.split(":")[4],
                               "kms:ViaService": "lambda.eu-west-1.amazonaws.com",
                               "kms:EncryptionContext:aws:lambda:FunctionArn": handler_arn,
                           }}})
    return _policy(statements)


def build_cd_retained_dev_roles(
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
) -> dict[str, Any]:
    """Return exactly two dev CD roles and their restrictive boundaries."""
    account_id = _account(account_id)
    if (
        type(owner_id) is not str or _DECIMAL_ID.fullmatch(owner_id) is None
        or type(repository_id) is not str or _DECIMAL_ID.fullmatch(repository_id) is None
        or type(observed_dev_subject_format) is not str or observed_dev_subject_format not in SUBJECT_FORMATS
        or type(observed_dev_subject_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", observed_dev_subject_sha256) is None
    ):
        raise RetainedDevRoleError()
    subject = _subject(observed_dev_subject_format, owner_id, repository_id)
    expected_digest = hashlib.sha256(subject.encode("ascii")).hexdigest()
    if not hmac.compare_digest(expected_digest, observed_dev_subject_sha256):
        raise RetainedDevRoleError("subject_digest_mismatch")

    _exact(provider_arn, f"arn:aws:iam::{account_id}:oidc-provider/{ISSUER_HOST}")
    stack_arn = _stack_arn(stack_arn, account_id, STACK_NAME)
    artifact_stack_arn = _stack_arn(artifact_stack_arn, account_id, ARTIFACT_STACK_NAME)
    _exact(handler_arn, f"arn:aws:lambda:{REGION}:{account_id}:function:{FUNCTION_NAME}")
    api_match = re.fullmatch(rf"arn:aws:apigateway:{REGION}::/apis/([a-z0-9]{{10}})", api_arn) if type(api_arn) is str else None
    if api_match is None:
        raise RetainedDevRoleError()
    _exact(shutdown_state_machine_arn, f"arn:aws:states:{REGION}:{account_id}:stateMachine:{SHUTDOWN_MACHINE_NAME}")
    bucket_match = re.fullmatch(r"arn:aws:s3:::([a-z0-9][a-z0-9.-]*[a-z0-9])", artifact_bucket_arn) if type(artifact_bucket_arn) is str else None
    if bucket_match is None:
        raise RetainedDevRoleError("artifact_binding_invalid")
    try:
        bucket_name = _validate_bucket_name(bucket_match.group(1))
    except Exception:
        raise RetainedDevRoleError("artifact_binding_invalid") from None
    if bucket_name != f"honda-mapit-mcp-dev-retained-{account_id}-{REGION}":
        raise RetainedDevRoleError("artifact_binding_invalid")
    if type(execution_role_arn) is not str:
        raise RetainedDevRoleError()
    if execution_role_arn != f"arn:aws:iam::{account_id}:role/honda-mapit-mcp-dev-retained-handler-role":
        raise RetainedDevRoleError()
    if lambda_environment_key_arn is not None:
        key_prefix = f"arn:aws:kms:{REGION}:{account_id}:key/"
        if (type(lambda_environment_key_arn) is not str
                or not lambda_environment_key_arn.startswith(key_prefix)
                or _UUID.fullmatch(lambda_environment_key_arn[len(key_prefix):]) is None
                or lambda_environment_key_arn.endswith("00000000-0000-0000-0000-000000000000")):
            raise RetainedDevRoleError()

    cfn_role_arn = f"arn:aws:iam::{account_id}:role/{CFN_ROLE_NAME}"
    executor_policy = _build_executor_policy(
        account_id=account_id, stack_arn=stack_arn, api_arn=api_arn,
        shutdown_arn=shutdown_state_machine_arn, artifact_bucket_arn=artifact_bucket_arn,
        cfn_role_arn=cfn_role_arn, handler_arn=handler_arn,
        allow_environment_key=lambda_environment_key_arn,
    )
    cfn_policy = _build_cfn_policy(
        artifact_bucket_arn=artifact_bucket_arn, handler_arn=handler_arn,
        execution_role_arn=execution_role_arn, allow_environment_key=lambda_environment_key_arn,
    )

    def role_resource(logical: str, role_name: str, policy: dict[str, Any], principal: dict[str, str]) -> tuple[str, dict[str, Any]]:
        boundary_id = f"RetainedDevCd{logical}Boundary"
        role_id = f"RetainedDevCd{logical}Role"
        trust: dict[str, Any] = {"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {f"{ISSUER_HOST}:aud": AUDIENCE, f"{ISSUER_HOST}:sub": subject}},
        }]}
        if logical == "CloudFormation":
            trust = {"Version": "2012-10-17", "Statement": [{
                "Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole",
            }]}
        return role_id, {
            "role_id": role_id,
            "boundary_id": boundary_id,
            "boundary": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {
                "ManagedPolicyName": f"{role_name}-boundary", "Description": "Maximum permissions boundary for retained dev CD.",
                "PolicyDocument": _permissions_boundary(policy, environment_key=lambda_environment_key_arn,
                                                         handler_arn=handler_arn),
            }},
            "role": {"Type": "AWS::IAM::Role", "Properties": {
                "RoleName": role_name, "Description": "Retained dev CD role; offline review artifact only.",
                "MaxSessionDuration": 3600, "PermissionsBoundary": {"Fn::GetAtt": [boundary_id, "PolicyArn"]},
                "AssumeRolePolicyDocument": trust,
                "Policies": [{"PolicyName": f"{role_name}-policy", "PolicyDocument": policy}],
                "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
                         {"Key": "Purpose", "Value": "CDDeliveryRetainedDev"}],
            }},
        }

    resources: dict[str, Any] = {}
    for logical, role_name, policy, principal in (
        ("Executor", EXECUTOR_ROLE_NAME, executor_policy, {"Federated": provider_arn}),
        ("CloudFormation", CFN_ROLE_NAME, cfn_policy, {"Service": "cloudformation.amazonaws.com"}),
    ):
        role_id, material = role_resource(logical, role_name, policy, principal)
        resources[material["boundary_id"]] = material["boundary"]
        resources[role_id] = material["role"]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Offline retained-development CD role/boundary draft; not deploy-ready.",
        "Metadata": {
            "Readiness": "NOT_DEPLOY_READY", "Environment": "dev", "ExpectedEnvironment": "dev",
            "RetainedNamespace": "honda-mapit-mcp-dev-retained", "ObservedSubjectFormat": observed_dev_subject_format,
            "ObservedSubjectSha256": observed_dev_subject_sha256, "ArtifactStackArn": artifact_stack_arn,
            "ArtifactBucketDerivedFromExactAccountAndRegion": True, "ExecutorRoleName": EXECUTOR_ROLE_NAME,
            "CloudFormationRoleName": CFN_ROLE_NAME, "NoProdNamesOrBindings": True,
            "NoStackCreateDelete": True, "NoIamMutation": True, "NoApiPatch": True,
            "NoLambdaConcurrencyWrite": True, "RequiresIndependentResourceReadback": True,
            "CanonicalTemplateSha256": hashlib.sha256(_canonical(resources)).hexdigest(),
        },
        "Resources": resources,
    }


__all__ = ["RetainedDevRoleError", "build_cd_retained_dev_roles"]
