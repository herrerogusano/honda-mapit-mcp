from __future__ import annotations

import hashlib

import pytest

from scripts.build_cd_retained_dev_roles import RetainedDevRoleError, build_cd_retained_dev_roles


ACCOUNT = "123456789012"
OWNER_ID = "1234567"
REPOSITORY_ID = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPOSITORY_ID}:environment:dev"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4444-8555-666666666666"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
API = f"arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
BUCKET = "arn:aws:s3:::honda-mapit-mcp-dev-retained-123456789012-eu-west-1"
EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"


def _build(**overrides):
    args = {
        "account_id": ACCOUNT,
        "provider_arn": PROVIDER,
        "owner_id": OWNER_ID,
        "repository_id": REPOSITORY_ID,
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


def _statements(template, role_id):
    return template["Resources"][role_id]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def test_factory_is_exactly_two_retained_dev_roles_and_boundaries():
    template = _build()
    assert set(template["Resources"]) == {
        "RetainedDevCdExecutorBoundary", "RetainedDevCdExecutorRole",
        "RetainedDevCdCloudFormationBoundary", "RetainedDevCdCloudFormationRole",
    }
    assert template["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
    assert template["Metadata"]["ExpectedEnvironment"] == "dev"
    assert template["Metadata"]["NoProdNamesOrBindings"] is True
    for logical, role_name in (("Executor", "honda-mapit-mcp-dev-retained-cd-executor"),
                               ("CloudFormation", "honda-mapit-mcp-dev-retained-cfn-update")):
        role = template["Resources"][f"RetainedDevCd{logical}Role"]
        boundary = template["Resources"][f"RetainedDevCd{logical}Boundary"]
        assert role["Type"] == "AWS::IAM::Role"
        assert role["Properties"]["RoleName"] == role_name
        assert role["Properties"]["Tags"] == [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "CDDeliveryRetainedDev"},
        ]
        assert boundary["Type"] == "AWS::IAM::ManagedPolicy"
        assert role["Properties"]["PermissionsBoundary"] == {
            "Fn::GetAtt": [f"RetainedDevCd{logical}Boundary", "PolicyArn"]
        }


def test_executor_has_only_read_controls_and_atomic_dev_publication():
    statements = _statements(_build(), "RetainedDevCdExecutorRole")
    by_sid = {statement["Sid"]: statement for statement in statements}
    assert by_sid["UpdateOnlyOwnedRetainedStack"]["Resource"] == STACK
    assert by_sid["UpdateOnlyOwnedRetainedStack"]["Condition"] == {
        "StringEquals": {"cloudformation:RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"}
    }
    assert by_sid["PassOnlyRetainedCloudFormationRole"]["Condition"] == {
        "StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}
    }
    assert by_sid["ReadOnlyRetainedApi"]["Action"] == "apigateway:GET"
    assert by_sid["ReadOnlyRetainedTripwire"]["Action"] == "cloudwatch:DescribeAlarms"
    assert by_sid["ReadOnlyRetainedTripwireRule"]["Action"] == ["events:DescribeRule", "events:ListTargetsByRule"]
    assert by_sid["PublishRuntimePackagesWithoutOverwrite"]["Condition"] == {
        "StringEquals": {"s3:if-none-match": "*"}
    }
    assert by_sid["CreateDeliveryJournalWithoutOverwrite"]["Condition"] == {
        "StringEquals": {"s3:if-none-match": "*"}
    }
    assert by_sid["ReviseDeliveryJournalWithObservedEtag"]["Condition"] == {"Null": {"s3:if-match": "false"}}
    assert by_sid["MarkOnlyTerminalDeliveryJournals"]["Condition"]["StringEquals"] == {
        "s3:RequestObjectTag/cd-terminal": "true"
    }
    encoded = repr(statements)
    for forbidden in ("cloudformation:CreateStack", "cloudformation:DeleteStack", "s3:DeleteObject",
                      "s3:ListBucket", "lambda:PutFunctionConcurrency", "lambda:DeleteFunctionConcurrency",
                      "apigateway:PATCH", "iam:CreateRole", "iam:PutRolePolicy", "secretsmanager"):
        assert forbidden not in encoded


def test_cfn_role_is_the_only_lambda_writer_and_passes_only_existing_execution_role():
    statements = _statements(_build(), "RetainedDevCdCloudFormationRole")
    updates = next(statement for statement in statements if statement["Sid"] == "UpdateOnlyRetainedHandler")
    assert updates["Resource"] == HANDLER
    assert "lambda:UpdateFunctionCode" in updates["Action"]
    assert "lambda:UpdateFunctionConfiguration" in updates["Action"]
    assert not any(action in repr(statements) for action in ("iam:CreateRole", "iam:PutRolePolicy", "cloudformation:UpdateStack"))
    passrole = next(statement for statement in statements if statement["Sid"] == "PassOnlyRetainedLambdaExecutionRole")
    assert passrole["Resource"] == EXECUTION_ROLE
    assert passrole["Condition"] == {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}


@pytest.mark.parametrize(("field", "value"), [
    ("account_id", "123456789013"),
    ("provider_arn", "arn:aws:iam::123456789013:oidc-provider/token.actions.githubusercontent.com"),
    ("owner_id", "0"),
    ("repository_id", "not-a-number"),
    ("stack_arn", STACK.replace("dev-retained", "other")),
    ("artifact_stack_arn", ARTIFACT_STACK.replace("artifacts", "other-artifacts")),
    ("handler_arn", HANDLER.replace("dev-retained-handler", "other")),
    ("api_arn", API.replace("eu-west-1", "us-east-1")),
    ("shutdown_state_machine_arn", SHUTDOWN.replace("dev-retained-shutdown", "other")),
    ("artifact_bucket_arn", "arn:aws:s3:::other-project-artifacts-a1b2c3d4"),
    ("artifact_bucket_arn", "arn:aws:s3:::honda-mapit-mcp-dev-retained-artifacts-a1b2c3d4"),
    ("execution_role_arn", f"arn:aws:iam::{ACCOUNT}:role/*"),
    ("execution_role_arn", f"arn:aws:iam::{ACCOUNT}:role/another-project-handler"),
    ("artifact_bucket_arn", "arn:aws:s3:::honda-mapit-mcp-dev-retained-123456789012-us-east-1"),
])
def test_bad_binding_fails_closed(field, value):
    with pytest.raises(RetainedDevRoleError):
        _build(**{field: value})


def test_subject_digest_and_environment_are_bound():
    with pytest.raises(RetainedDevRoleError, match="subject_digest_mismatch"):
        _build(observed_dev_subject_sha256="0" * 64)
    with pytest.raises(RetainedDevRoleError):
        _build(observed_dev_subject_format="legacy_environment", observed_dev_subject_sha256=hashlib.sha256(
            b"repo:herrerogusano/honda-mapit-mcp:environment:prod"
        ).hexdigest())


def test_optional_kms_policy_is_narrow_and_does_not_change_namespace():
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    template = _build(lambda_environment_key_arn=key)
    for role_id in ("RetainedDevCdExecutorRole", "RetainedDevCdCloudFormationRole"):
        assert any(statement["Sid"] == "FixedLambdaEnvironmentKey" for statement in _statements(template, role_id))
    assert template["Metadata"]["RetainedNamespace"] == "honda-mapit-mcp-dev-retained"
