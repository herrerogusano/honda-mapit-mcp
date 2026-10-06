from __future__ import annotations

import hashlib
import json

import pytest

from scripts.build_cd_retained_dev_proof_role import RetainedDevProofRoleError, build_cd_retained_dev_proof_role

ACCOUNT = "123456789012"
OWNER = "1234567"
REPOSITORY = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER}/honda-mapit-mcp@{REPOSITORY}:environment:dev"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
APP = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4333-8444-555555555555"
CONTROLS = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-controls/33333333-4444-4333-8444-555555555555"
BUCKET = f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
API = "arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
CFN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"
CFN_BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-cfn-update-boundary"
EXECUTION_BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-handler-role-boundary"
EXECUTOR_BOUNDARY = f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
ALARM = f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-dev-retained-request-tripwire"
RULE = f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"


def _build(**overrides):
    values = {"account_id": ACCOUNT, "provider_arn": PROVIDER, "owner_id": OWNER, "repository_id": REPOSITORY, "observed_dev_subject_sha256": hashlib.sha256(SUBJECT.encode()).hexdigest(), "app_stack_arn": APP, "artifact_stack_arn": ARTIFACT, "controls_stack_arn": CONTROLS, "artifact_bucket_arn": BUCKET, "api_arn": API, "handler_arn": HANDLER, "cfn_role_arn": CFN_ROLE, "execution_role_arn": EXECUTION_ROLE, "cfn_boundary_arn": CFN_BOUNDARY, "executor_boundary_arn": EXECUTOR_BOUNDARY, "shutdown_state_machine_arn": SHUTDOWN, "tripwire_alarm_arn": ALARM, "tripwire_rule_arn": RULE}
    values.update(overrides)
    return build_cd_retained_dev_proof_role(**values)


def _policy(template):
    return template["Resources"]["RetainedDevReadOnlyProofRole"]["Properties"]["Policies"][0]["PolicyDocument"]


def test_factory_has_exact_two_resources_and_bounded_policies():
    template = _build()
    assert set(template["Resources"]) == {"RetainedDevReadOnlyProofRole", "RetainedDevReadOnlyProofBoundary"}
    assert template["Metadata"]["PolicyBytes"] <= 6144
    assert template["Metadata"]["BoundaryBytes"] <= 6144
    statements = _policy(template)["Statement"]
    actions = {action for row in statements for action in (row["Action"] if isinstance(row["Action"], list) else [row["Action"]])}
    assert not actions & {"cloudformation:UpdateStack", "s3:PutObject", "lambda:InvokeFunction", "iam:PassRole", "sts:AssumeRole", "states:StartExecution"}


def test_factory_has_exact_stack_bucket_api_and_iam_read_resources():
    statements = _policy(_build())["Statement"]
    by_sid = {row["Sid"]: row for row in statements}
    assert by_sid["ReadRetainedStacks"]["Resource"] == [APP, ARTIFACT, CONTROLS]
    assert by_sid["ReadArtifactBucketSecurity"]["Resource"] == BUCKET
    assert by_sid["ReadRetainedApiAndRoutes"]["Resource"] == [API, API + "/routes"]
    assert by_sid["ReadRetainedBoundaries"]["Resource"] == ["arn:aws:iam::123456789012:policy/honda-mapit-mcp-dev-retained-readonly-proof-boundary", EXECUTOR_BOUNDARY, CFN_BOUNDARY]


def test_factory_scopes_template_without_unsupported_iam_stack_condition():
    template = _build()
    assert template["Conditions"]["SupportedDeployment"] == {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev-retained-readonly-proof"]},
        ]
    }
    assert all(resource["Condition"] == "SupportedDeployment" for resource in template["Resources"].values())
    stack_statement = next(row for row in _policy(template)["Statement"] if row["Sid"] == "ReadRetainedStacks")
    assert stack_statement["Condition"] == {"StringEquals": {"aws:RequestedRegion": "eu-west-1"}}


@pytest.mark.parametrize("field,value", [("provider_arn", "arn:aws:iam::123456789012:oidc-provider/evil.example"), ("controls_stack_arn", APP), ("artifact_bucket_arn", "arn:aws:s3:::other-bucket"), ("execution_role_arn", CFN_ROLE), ("cfn_boundary_arn", EXECUTION_BOUNDARY), ("executor_boundary_arn", CFN_BOUNDARY), ("shutdown_state_machine_arn", "arn:aws:states:eu-west-1:123456789012:stateMachine/other")])
def test_factory_rejects_wrong_namespace_or_binding(field, value):
    with pytest.raises(RetainedDevProofRoleError):
        _build(**{field: value})


def test_factory_rejects_subject_digest_mismatch():
    with pytest.raises(RetainedDevProofRoleError, match="subject_digest_mismatch"):
        _build(observed_dev_subject_sha256="a" * 64)


def test_factory_output_is_bounded_and_deterministic():
    template = _build()
    assert len(json.dumps(template, separators=(",", ":"))) < 30000
    assert template == _build()
