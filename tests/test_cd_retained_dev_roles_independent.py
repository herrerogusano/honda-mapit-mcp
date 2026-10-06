from __future__ import annotations

import hashlib

import pytest

from scripts.build_cd_retained_dev_roles import RetainedDevRoleError, build_cd_retained_dev_roles


ACCOUNT = "123456789012"
OWNER = "1234567"
REPOSITORY = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER}/honda-mapit-mcp@{REPOSITORY}:environment:dev"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4444-8555-666666666666"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
API = "arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
BUCKET = "arn:aws:s3:::honda-mapit-mcp-dev-retained-123456789012-eu-west-1"
EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"


def _build(**overrides):
    args = {
        "account_id": ACCOUNT,
        "provider_arn": PROVIDER,
        "owner_id": OWNER,
        "repository_id": REPOSITORY,
        "observed_dev_subject_format": "immutable_environment",
        "observed_dev_subject_sha256": hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
        "stack_arn": STACK,
        "artifact_stack_arn": ARTIFACT_STACK,
        "handler_arn": HANDLER,
        "api_arn": API,
        "shutdown_state_machine_arn": SHUTDOWN,
        "artifact_bucket_arn": BUCKET,
        "execution_role_arn": EXECUTION_ROLE,
    }
    args.update(overrides)
    return build_cd_retained_dev_roles(**args)


def _role_statements(template, role_id):
    return template["Resources"][role_id]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def _actions(statements):
    return {
        action
        for statement in statements
        for action in (statement.get("Action", []) if isinstance(statement.get("Action", []), list) else [statement.get("Action")])
        if isinstance(action, str)
    }


def test_independent_exact_dev_resources_and_trust_bindings():
    template = _build()
    assert set(template["Resources"]) == {
        "RetainedDevCdExecutorBoundary", "RetainedDevCdExecutorRole",
        "RetainedDevCdCloudFormationBoundary", "RetainedDevCdCloudFormationRole",
    }
    executor = template["Resources"]["RetainedDevCdExecutorRole"]["Properties"]
    cfn = template["Resources"]["RetainedDevCdCloudFormationRole"]["Properties"]
    assert executor["RoleName"] == "honda-mapit-mcp-dev-retained-cd-executor"
    assert cfn["RoleName"] == "honda-mapit-mcp-dev-retained-cfn-update"
    assert executor["AssumeRolePolicyDocument"] == {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow", "Principal": {"Federated": PROVIDER},
            "Action": "sts:AssumeRoleWithWebIdentity",
            "Condition": {"StringEquals": {
                "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                "token.actions.githubusercontent.com:sub": SUBJECT,
            }},
        }],
    }
    assert cfn["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }]


def test_independent_executor_has_no_direct_lambda_or_prod_mutation_actions():
    actions = _actions(_role_statements(_build(), "RetainedDevCdExecutorRole"))
    assert "cloudformation:UpdateStack" in actions
    forbidden = {
        "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
        "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency",
        "apigateway:PATCH", "iam:CreateRole", "iam:PutRolePolicy",
        "secretsmanager:GetSecretValue", "ssm:GetParameter", "bedrock:InvokeModel",
        "cloudformation:CreateStack", "cloudformation:DeleteStack",
    }
    assert actions.isdisjoint(forbidden)
    assert not any("prod" in str(resource).casefold() for resource in _build()["Resources"].values())


def test_independent_s3_cas_and_terminal_tagging_are_exact_bucket_scoped():
    statements = _role_statements(_build(), "RetainedDevCdExecutorRole")
    bucket_resources = {
        resource
        for statement in statements
        for resource in (statement.get("Resource", []) if isinstance(statement.get("Resource", []), list) else [statement.get("Resource")])
        if isinstance(resource, str) and resource.startswith("arn:aws:s3:::")
    }
    assert bucket_resources == {BUCKET, f"{BUCKET}/runtime/*", f"{BUCKET}/journals/*"}
    by_sid = {statement["Sid"]: statement for statement in statements}
    assert by_sid["PublishRuntimePackagesWithoutOverwrite"]["Condition"] == {
        "StringEquals": {"s3:if-none-match": "*"}
    }
    assert by_sid["CreateDeliveryJournalWithoutOverwrite"]["Condition"] == {
        "StringEquals": {"s3:if-none-match": "*"}
    }
    assert by_sid["ReviseDeliveryJournalWithObservedEtag"]["Condition"] == {
        "Null": {"s3:if-match": "false"}
    }
    assert by_sid["MarkOnlyTerminalDeliveryJournals"]["Condition"] == {
        "ForAllValues:StringEquals": {"s3:RequestObjectTagKeys": ["cd-terminal"]},
        "StringEquals": {"s3:RequestObjectTag/cd-terminal": "true"},
        "Null": {"s3:RequestObjectTagKeys": "false"},
    }


def test_independent_optional_kms_context_is_exact_for_both_roles_and_boundaries():
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    template = _build(lambda_environment_key_arn=key)
    expected = {
        "StringEquals": {
            "kms:CallerAccount": ACCOUNT,
            "kms:ViaService": "lambda.eu-west-1.amazonaws.com",
            "kms:EncryptionContext:aws:lambda:FunctionArn": HANDLER,
        }
    }
    for role_id in ("RetainedDevCdExecutorRole", "RetainedDevCdCloudFormationRole"):
        statement = next(s for s in _role_statements(template, role_id) if s["Sid"] == "FixedLambdaEnvironmentKey")
        assert statement["Resource"] == key
        assert statement["Condition"] == expected
        boundary = template["Resources"][role_id.replace("Role", "Boundary")]["Properties"]["PolicyDocument"]["Statement"]
        assert any(s.get("Condition") == {"StringNotEquals": {
            "kms:EncryptionContext:aws:lambda:FunctionArn": HANDLER
        }} for s in boundary)


@pytest.mark.parametrize("bad", [
    "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com/extra",
    "arn:aws:s3:::honda-mapit-mcp-prod-123456789012-eu-west-1",
    "arn:aws:s3:::honda-mapit-mcp-dev-retained-123456789012-us-east-1",
    "arn:aws:s3:::honda-mapit-mcp-dev-retained-123456789012-eu-west-1-extra",
    "arn:aws:iam::123456789013:role/honda-mapit-mcp-dev-retained-handler-role",
    "arn:aws:lambda:us-east-1:123456789012:function:honda-mapit-mcp-dev-retained-handler",
])
def test_independent_cross_environment_or_provider_binding_fails_closed(bad):
    field = (
        "provider_arn" if ":oidc-provider/" in bad
        else "artifact_bucket_arn" if ":s3:::" in bad
        else "execution_role_arn" if ":role/" in bad
        else "handler_arn"
    )
    with pytest.raises(RetainedDevRoleError):
        _build(**{field: bad})
