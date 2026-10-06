"""Pure offline factory for the retained-dev read-only proof role.

This is review material only.  It creates no AWS clients and does not mutate
the already accepted four-role factory.  The role is intentionally limited to
fresh owner/control readbacks; it cannot publish, update, invoke, pass a role,
read S3 objects or start the shutdown state machine.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from scripts.build_cd_identity_bootstrap import AUDIENCE, ISSUER_HOST, OWNER, REPOSITORY

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained-readonly-proof"
ROLE_NAME = "honda-mapit-mcp-dev-retained-readonly-proof"
BOUNDARY_NAME = ROLE_NAME + "-boundary"
FUNCTION_NAME = "honda-mapit-mcp-dev-retained-handler"
CFN_ROLE_NAME = "honda-mapit-mcp-dev-retained-cfn-update"
EXECUTION_ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
EXECUTOR_ROLE_NAME = "honda-mapit-mcp-dev-retained-cd-executor"
CONTROL_ROLE_NAMES = (
    "honda-mapit-mcp-dev-retained-shutdown-workflow",
    "honda-mapit-mcp-dev-retained-request-tripwire",
)
MAX_POLICY_BYTES = 6144
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_DECIMAL_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_STACK_NAMES = {"app": "honda-mapit-mcp-dev-retained", "artifact": "honda-mapit-mcp-dev-retained-runtime-artifacts", "controls": "honda-mapit-mcp-dev-retained-controls"}


class RetainedDevProofRoleError(ValueError):
    def __init__(self, category: str = "invalid_configuration") -> None:
        self.category = category if category in {"invalid_configuration", "subject_digest_mismatch", "policy_too_large"} else "invalid_configuration"
        super().__init__(self.category)


def _canonical(value: Any) -> bytes:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise RetainedDevProofRoleError() from None
    return raw


def _account(value: Any) -> str:
    if type(value) is not str or _ACCOUNT.fullmatch(value) is None or value == "000000000000":
        raise RetainedDevProofRoleError()
    return value


def _arn(value: Any, pattern: str) -> str:
    if type(value) is not str or re.fullmatch(pattern, value) is None:
        raise RetainedDevProofRoleError()
    return value


def _stack(value: Any, account: str, name: str) -> str:
    return _arn(value, rf"arn:aws:cloudformation:{REGION}:{account}:stack/{re.escape(name)}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}")


def _subject(owner_id: str, repository_id: str) -> str:
    return f"repo:{OWNER}@{owner_id}/{REPOSITORY}@{repository_id}:environment:dev"


def _statement(sid: str, action: str | list[str], resource: str | list[str]) -> dict[str, Any]:
    return {"Sid": sid, "Effect": "Allow", "Action": action, "Resource": resource}


def _read_policy(*, account: str, app_stack_arn: str, artifact_stack_arn: str, controls_stack_arn: str, bucket_arn: str, api_arn: str, handler_arn: str, cfn_role_arn: str, execution_role_arn: str, cfn_boundary_arn: str, executor_boundary_arn: str, shutdown_state_machine_arn: str, tripwire_alarm_arn: str, tripwire_rule_arn: str, proof_role_arn: str, proof_boundary_arn: str) -> dict[str, Any]:
    stacks = [app_stack_arn, artifact_stack_arn, controls_stack_arn]
    api_routes_arn = api_arn + "/routes"
    role_arns = [proof_role_arn, f"arn:aws:iam::{account}:role/{EXECUTOR_ROLE_NAME}", cfn_role_arn, execution_role_arn] + [f"arn:aws:iam::{account}:role/{name}" for name in CONTROL_ROLE_NAMES]
    boundary_arns = [proof_boundary_arn, executor_boundary_arn, cfn_boundary_arn]
    alarm_arn = tripwire_alarm_arn
    rule_arn = tripwire_rule_arn
    statements = [
        _statement("ReadCallerIdentity", "sts:GetCallerIdentity", "*"),
        {**_statement("ReadRetainedStacks", ["cloudformation:DescribeStacks", "cloudformation:DescribeStackResources", "cloudformation:GetTemplate", "cloudformation:DescribeStackEvents"], stacks), "Condition": {"StringEquals": {"aws:RequestedRegion": REGION}}},
        _statement("ReadArtifactBucketSecurity", ["s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls", "s3:GetEncryptionConfiguration", "s3:GetBucketTagging", "s3:GetBucketPolicyStatus", "s3:GetBucketPolicy", "s3:GetLifecycleConfiguration"], bucket_arn),
        _statement("ReadRetainedApiAndRoutes", "apigateway:GET", [api_arn, api_routes_arn]),
        _statement("ReadRetainedHandler", ["lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionConcurrency", "lambda:ListTags"], handler_arn),
        _statement("ReadRetainedRoles", ["iam:GetRole", "iam:ListRolePolicies", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies", "iam:ListRoleTags"], role_arns),
        _statement("ReadRetainedBoundaries", ["iam:GetPolicy", "iam:GetPolicyVersion"], boundary_arns),
        _statement("ReadRetainedShutdown", ["states:DescribeStateMachine", "states:ListTagsForResource"], shutdown_state_machine_arn),
        _statement("ReadRetainedTripwireRule", ["events:DescribeRule", "events:ListTargetsByRule", "events:ListTagsForResource"], rule_arn),
        _statement("ReadRetainedTripwireAlarm", ["cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource"], alarm_arn),
    ]
    return {"Version": "2012-10-17", "Statement": statements}


def _boundary(policy: dict[str, Any]) -> dict[str, Any]:
    actions: list[str] = []
    for statement in policy["Statement"]:
        values = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        for action in values:
            if action not in actions:
                actions.append(action)
    result = {"Version": "2012-10-17", "Statement": [dict(statement) for statement in policy["Statement"]]}
    result["Statement"].append({"Sid": "DenyEveryUnlistedAction", "Effect": "Deny", "NotAction": actions, "Resource": "*"})
    return result


def _assert_size(policy: dict[str, Any]) -> None:
    if len(_canonical(policy)) > MAX_POLICY_BYTES:
        raise RetainedDevProofRoleError("policy_too_large")


def build_cd_retained_dev_proof_role(*, account_id: str, provider_arn: str, owner_id: str, repository_id: str, observed_dev_subject_sha256: str, app_stack_arn: str, artifact_stack_arn: str, controls_stack_arn: str, artifact_bucket_arn: str, api_arn: str, handler_arn: str, cfn_role_arn: str, execution_role_arn: str, cfn_boundary_arn: str, executor_boundary_arn: str, shutdown_state_machine_arn: str, tripwire_alarm_arn: str, tripwire_rule_arn: str) -> dict[str, Any]:
    account_id = _account(account_id)
    if type(owner_id) is not str or _DECIMAL_ID.fullmatch(owner_id) is None or type(repository_id) is not str or _DECIMAL_ID.fullmatch(repository_id) is None or type(observed_dev_subject_sha256) is not str or _SHA256.fullmatch(observed_dev_subject_sha256) is None:
        raise RetainedDevProofRoleError()
    subject = _subject(owner_id, repository_id)
    if not hmac.compare_digest(hashlib.sha256(subject.encode("ascii")).hexdigest(), observed_dev_subject_sha256):
        raise RetainedDevProofRoleError("subject_digest_mismatch")
    _arn(provider_arn, rf"arn:aws:iam::{account_id}:oidc-provider/{re.escape(ISSUER_HOST)}")
    app_stack_arn = _stack(app_stack_arn, account_id, _STACK_NAMES["app"])
    artifact_stack_arn = _stack(artifact_stack_arn, account_id, _STACK_NAMES["artifact"])
    controls_stack_arn = _stack(controls_stack_arn, account_id, _STACK_NAMES["controls"])
    bucket_arn = _arn(artifact_bucket_arn, rf"arn:aws:s3:::[a-z0-9][a-z0-9.-]*[a-z0-9]")
    expected_bucket = f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{account_id}-{REGION}"
    if bucket_arn != expected_bucket:
        raise RetainedDevProofRoleError()
    api_arn = _arn(api_arn, rf"arn:aws:apigateway:{REGION}::/apis/[a-z0-9]{{10}}")
    handler_arn = _arn(handler_arn, rf"arn:aws:lambda:{REGION}:{account_id}:function:{FUNCTION_NAME}")
    cfn_role_arn = _arn(cfn_role_arn, rf"arn:aws:iam::{account_id}:role/{CFN_ROLE_NAME}")
    execution_role_arn = _arn(execution_role_arn, rf"arn:aws:iam::{account_id}:role/{EXECUTION_ROLE_NAME}")
    cfn_boundary_arn = _arn(cfn_boundary_arn, rf"arn:aws:iam::{account_id}:policy/{re.escape(CFN_ROLE_NAME)}-boundary")
    executor_boundary_arn = _arn(executor_boundary_arn, rf"arn:aws:iam::{account_id}:policy/{re.escape(EXECUTOR_ROLE_NAME)}-boundary")
    shutdown_state_machine_arn = _arn(shutdown_state_machine_arn, rf"arn:aws:states:{REGION}:{account_id}:stateMachine:honda-mapit-mcp-dev-retained-shutdown")
    tripwire_alarm_arn = _arn(tripwire_alarm_arn, rf"arn:aws:cloudwatch:{REGION}:{account_id}:alarm:honda-mapit-mcp-dev-retained-request-tripwire")
    tripwire_rule_arn = _arn(tripwire_rule_arn, rf"arn:aws:events:{REGION}:{account_id}:rule/honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule")
    proof_role_arn = f"arn:aws:iam::{account_id}:role/{ROLE_NAME}"
    proof_boundary_arn = f"arn:aws:iam::{account_id}:policy/{BOUNDARY_NAME}"
    policy = _read_policy(account=account_id, app_stack_arn=app_stack_arn, artifact_stack_arn=artifact_stack_arn, controls_stack_arn=controls_stack_arn, bucket_arn=bucket_arn, api_arn=api_arn, handler_arn=handler_arn, cfn_role_arn=cfn_role_arn, execution_role_arn=execution_role_arn, cfn_boundary_arn=cfn_boundary_arn, executor_boundary_arn=executor_boundary_arn, shutdown_state_machine_arn=shutdown_state_machine_arn, tripwire_alarm_arn=tripwire_alarm_arn, tripwire_rule_arn=tripwire_rule_arn, proof_role_arn=proof_role_arn, proof_boundary_arn=proof_boundary_arn)
    boundary = _boundary(policy)
    _assert_size(policy)
    _assert_size(boundary)
    trust = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Federated": provider_arn}, "Action": "sts:AssumeRoleWithWebIdentity", "Condition": {"StringEquals": {f"{ISSUER_HOST}:aud": AUDIENCE, f"{ISSUER_HOST}:sub": subject}}}]}
    tags = [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "CDReadOnlyProof"}]
    condition = {"Fn::And": [{"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]}, {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]}]}
    return {"AWSTemplateFormatVersion": "2010-09-09", "Description": "Offline retained-dev read-only proof role; not deploy-ready.", "Conditions": {"SupportedDeployment": condition}, "Metadata": {"Readiness": "NOT_DEPLOY_READY", "StackName": STACK_NAME, "Environment": "dev", "ObservedSubjectSha256": observed_dev_subject_sha256, "NoWrites": True, "NoPassRole": True, "NoInvoke": True, "NoObjectRead": True, "PolicyBytes": len(_canonical(policy)), "BoundaryBytes": len(_canonical(boundary)), "PolicySha256": hashlib.sha256(_canonical(policy)).hexdigest(), "BoundarySha256": hashlib.sha256(_canonical(boundary)).hexdigest()}, "Resources": {"RetainedDevReadOnlyProofBoundary": {"Type": "AWS::IAM::ManagedPolicy", "Condition": "SupportedDeployment", "Properties": {"ManagedPolicyName": BOUNDARY_NAME, "Description": "Read-only retained-dev proof boundary.", "PolicyDocument": boundary}}, "RetainedDevReadOnlyProofRole": {"Type": "AWS::IAM::Role", "Condition": "SupportedDeployment", "Properties": {"RoleName": ROLE_NAME, "Description": "Read-only retained-dev owner-proof role; offline review artifact only.", "MaxSessionDuration": 3600, "PermissionsBoundary": {"Fn::GetAtt": ["RetainedDevReadOnlyProofBoundary", "PolicyArn"]}, "AssumeRolePolicyDocument": trust, "Policies": [{"PolicyName": ROLE_NAME + "-policy", "PolicyDocument": policy}], "Tags": tags}}}}


__all__ = ["MAX_POLICY_BYTES", "STACK_NAME", "ROLE_NAME", "BOUNDARY_NAME", "RetainedDevProofRoleError", "build_cd_retained_dev_proof_role"]
