from __future__ import annotations

import hashlib
import json

import pytest

from scripts.build_cd_retained_dev_multiuser_roles import (
    KMS_METADATA_BINDING_MARKER,
    RetainedDevMultiuserRoleError,
    build_cd_retained_dev_multiuser_roles,
)


ACCOUNT = "123456789012"
OWNER_ID = "1234567"
REPOSITORY_ID = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPOSITORY_ID}:environment:dev"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4444-8555-666666666666"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
API = "arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"
BUCKET = f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"
POOL_ID = "eu-west-1_AbCdEf123"
POOL_ARN = f"arn:aws:cognito-idp:eu-west-1:{ACCOUNT}:userpool/{POOL_ID}"


def _build(**overrides):
    values = {
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
    values.update(overrides)
    return build_cd_retained_dev_multiuser_roles(**values)


def _cfn_statements(template):
    return template["Resources"]["RetainedDevCdCloudFormationRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def _actions(statements):
    return {
        action
        for statement in statements
        for action in (statement.get("Action", []) if isinstance(statement.get("Action", []), list) else [statement.get("Action")])
        if isinstance(action, str)
    }


def test_exact_four_roles_and_executor_is_unchanged():
    template = _build()
    assert set(template["Resources"]) == {
        "RetainedDevCdExecutorBoundary", "RetainedDevCdExecutorRole",
        "RetainedDevCdCloudFormationBoundary", "RetainedDevCdCloudFormationRole",
    }
    from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles
    base = build_cd_retained_dev_roles(
        account_id=ACCOUNT, provider_arn=PROVIDER, owner_id=OWNER_ID,
        repository_id=REPOSITORY_ID, observed_dev_subject_format="immutable_environment",
        observed_dev_subject_sha256=hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
        stack_arn=STACK, artifact_stack_arn=ARTIFACT_STACK, handler_arn=HANDLER,
        api_arn=API, shutdown_state_machine_arn=SHUTDOWN, artifact_bucket_arn=BUCKET,
        execution_role_arn=EXECUTION_ROLE,
    )
    assert template["Resources"]["RetainedDevCdExecutorRole"] == base["Resources"]["RetainedDevCdExecutorRole"]
    assert template["Resources"]["RetainedDevCdExecutorBoundary"] == base["Resources"]["RetainedDevCdExecutorBoundary"]
    assert template["Metadata"]["MultiuserSetupPhase"] == "bootstrap"


def test_bootstrap_wildcard_is_limited_to_cognito_before_pool_id_exists():
    statements = _cfn_statements(_build())
    by_sid = {item["Sid"]: item for item in statements}
    create = by_sid["CreateOnlyTaggedDevUserPool"]
    assert create["Resource"] == "*"
    assert create["Condition"] == {
        "StringEquals": {
            "aws:RequestTag/Project": "honda-mapit-mcp",
            "aws:RequestTag/Environment": "dev",
        },
        "StringEqualsIfExists": {"aws:RequestTag/Purpose": "retained-dev"},
        "ForAllValues:StringLike": {
            "aws:TagKeys": [
                "Project", "Environment", "Purpose", "OperatorRunId",
                "aws:cloudformation:*",
            ]
        },
    }
    assert by_sid["ManageTaggedDevUserPool"]["Resource"] == "*"
    assert by_sid["ManageTaggedDevUserPool"]["Condition"] == {
        "StringEquals": {
            "aws:ResourceTag/Project": "honda-mapit-mcp",
            "aws:ResourceTag/Environment": "dev",
        }
    }
    cognito = [item for item in statements if item["Sid"].startswith(("CreateOnlyTaggedDev", "ManageTaggedDev", "ManageDev"))]
    assert cognito
    assert not any("cognito-idp:Admin" in repr(item) for item in cognito)


def test_recurrent_pool_binding_removes_cognito_wildcard():
    statements = _cfn_statements(_build(observed_user_pool_id=POOL_ID))
    cognito = [item for item in statements if item["Sid"].startswith(("ManageTaggedDev", "ManageDev"))]
    assert cognito
    assert all(item["Resource"] == POOL_ARN for item in cognito)
    assert not any(item.get("Resource") == "*" for item in cognito)
    assert [item for item in statements if item["Sid"] == "ReadDevUserPoolDomain"][0]["Resource"] == "*"
    assert not any(item["Sid"] == "CreateOnlyTaggedDevUserPool" for item in statements)
    assert _build(observed_user_pool_id=POOL_ID)["Metadata"]["ObservedUserPoolIdBound"] is True


def test_v2_writes_are_exactly_scoped_to_api_handler_role_and_table():
    statements = _cfn_statements(_build())
    by_sid = {item["Sid"]: item for item in statements}
    assert by_sid["ManageRetainedDevApiChildren"]["Resource"] == [
        f"{API}/authorizers", f"{API}/authorizers/*",
        f"{API}/integrations", f"{API}/integrations/*",
        f"{API}/routes", f"{API}/routes/*",
    ]
    assert f"{API}/*" not in by_sid["ManageRetainedDevApiChildren"]["Resource"]
    assert by_sid["ReadRetainedDevApi"]["Resource"] == API
    assert by_sid["ManageRetainedDevLambdaPermissions"]["Resource"] == HANDLER
    assert by_sid["UpdateRetainedDevHandlerRolePolicy"]["Resource"] == EXECUTION_ROLE
    assert by_sid["ManageRetainedDevTenantTable"]["Resource"] == (
        f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-tenants"
    )
    assert _actions(statements).isdisjoint({
        "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan",
        "iam:CreateRole", "iam:PutRole", "iam:AttachRolePolicy", "cognito-idp:AdminCreateUser",
        "secretsmanager:GetSecretValue", "ssm:GetParameter",
    })


def test_cloudformation_schema_readbacks_are_scoped_without_user_or_secret_mutation():
    actions = _actions(_cfn_statements(_build()))
    assert {
        "cognito-idp:SetUserPoolMfaConfig", "cognito-idp:GetUserPoolMfaConfig",
        "cognito-idp:ListUserPoolClientSecrets", "cognito-idp:DescribeManagedLoginBrandingByClient",
        "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeContributorInsights",
        "dynamodb:DescribeKinesisStreamingDestination", "dynamodb:GetResourcePolicy",
        "dynamodb:DescribeTimeToLive",
    }.issubset(actions)
    assert actions.isdisjoint({
        "cognito-idp:AdminCreateUser", "cognito-idp:CreateUserImportJob",
        "cognito-idp:CreateIdentityProvider", "cognito-idp:CreateUserPoolClientSecret",
        "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Scan",
    })


def test_boundary_contains_new_cfn_actions_but_executor_does_not():
    template = _build()
    cfn_statements = _cfn_statements(template)
    boundary = template["Resources"]["RetainedDevCdCloudFormationBoundary"]["Properties"]["PolicyDocument"]["Statement"]
    executor = template["Resources"]["RetainedDevCdExecutorRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert "cognito-idp:CreateUserPool" in _actions(cfn_statements)
    assert "dynamodb:CreateTable" in _actions(cfn_statements)
    assert "lambda:AddPermission" in _actions(cfn_statements)
    assert "iam:PutRolePolicy" in _actions(cfn_statements)
    assert _actions(cfn_statements).issubset(_actions(boundary) | {"iam:PassRole"})
    assert _actions(executor).isdisjoint({"cognito-idp:CreateUserPool", "dynamodb:CreateTable", "lambda:AddPermission", "iam:PutRolePolicy"})


def test_v2_boundary_is_compact_and_preserves_authorization_context():
    template = _build()
    boundary = template["Resources"]["RetainedDevCdCloudFormationBoundary"]["Properties"]["PolicyDocument"]
    assert len(json.dumps(boundary, separators=(",", ":")).encode("utf-8")) <= 6144
    contexts = {}
    for statement in boundary["Statement"]:
        context = {key: value for key, value in statement.items() if key != "Action"}
        key = json.dumps(context, sort_keys=True, separators=(",", ":"))
        actions = statement.get("Action", [])
        if not isinstance(actions, list):
            actions = [actions]
        assert key not in contexts
        contexts[key] = set(actions)
    assert _actions(boundary["Statement"]).issuperset(_actions(_cfn_statements(template)))
    assert any(statement.get("NotAction") for statement in boundary["Statement"])


@pytest.mark.parametrize("pool", [None, "eu-west-1_ABCDEFGHI"])
def test_optional_lambda_environment_key_is_cf_only_and_bounded(pool):
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    template = _build(lambda_environment_key_arn=key, observed_user_pool_id=pool)
    cfn = _cfn_statements(template)
    boundary = template["Resources"]["RetainedDevCdCloudFormationBoundary"]["Properties"]["PolicyDocument"]
    boundary_bytes = len(json.dumps(boundary, separators=(",", ":")).encode("utf-8"))
    assert boundary_bytes <= 6144
    cfn_policy = template["Resources"]["RetainedDevCdCloudFormationRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    assert len(json.dumps(cfn_policy, separators=(",", ":")).encode("utf-8")) <= 10240
    kms_allow = next(item for item in cfn if item.get("Sid") == "UseExactRetainedDevLambdaEnvironmentKey")
    assert kms_allow["Action"] == ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    assert kms_allow["Resource"] == key
    assert kms_allow["Condition"] == {"StringEquals": {
        "kms:CallerAccount": ACCOUNT,
        "kms:ViaService": "lambda.eu-west-1.amazonaws.com",
        "kms:EncryptionContext:aws:lambda:FunctionArn": HANDLER,
    }}
    # The allow is CFN-only: neither executor policy nor boundary may acquire
    # a KMS action from this opt-in.
    base_executor = _build()["Resources"]["RetainedDevCdExecutorRole"]
    assert template["Resources"]["RetainedDevCdExecutorRole"] == base_executor
    assert not any(action.startswith("kms:") for action in _actions(
        template["Resources"]["RetainedDevCdExecutorBoundary"]["Properties"]["PolicyDocument"]["Statement"]
    ))
    assert any(action.startswith("kms:") for action in _actions(boundary["Statement"]))
    assert any(item.get("Sid") == "DenyEveryUnlistedAction" for item in cfn)
    assert not any(item.get("Sid") == "DenyEveryUnlistedAction" for item in boundary["Statement"])


def test_kms_wrong_key_service_context_and_action_remain_denied():
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    template = _build(lambda_environment_key_arn=key, observed_user_pool_id=POOL_ID)
    cfn = _cfn_statements(template)
    boundary = template["Resources"]["RetainedDevCdCloudFormationBoundary"]["Properties"]["PolicyDocument"]["Statement"]
    kms_denies = [item for item in boundary if item.get("Effect") == "Deny" and "kms:Encrypt" in item.get("Action", [])]
    wrong_key = next(item for item in kms_denies if "NotResource" in item)
    wrong_service = next(item for item in kms_denies if item.get("Condition", {}).get("StringNotEquals", {}).get("kms:ViaService"))
    wrong_context = next(item for item in kms_denies if item.get("Condition", {}).get("StringNotEquals", {}).get("kms:EncryptionContext:aws:lambda:FunctionArn"))
    assert wrong_key["NotResource"] == key
    assert wrong_service["Resource"] == key
    assert wrong_service["Condition"] == {"StringNotEquals": {"kms:ViaService": "lambda.eu-west-1.amazonaws.com"}}
    assert wrong_context["Resource"] == key
    assert wrong_context["Condition"] == {"StringNotEquals": {
        "kms:EncryptionContext:aws:lambda:FunctionArn": HANDLER,
    }}
    catchall = next(item for item in cfn if item.get("Sid") == "DenyEveryUnlistedAction")
    not_actions = set(catchall["NotAction"])
    assert {"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"}.issubset(not_actions)
    assert "kms:ScheduleKeyDeletion" not in not_actions
    assert not any(
        isinstance(action, str) and action == "kms:*"
        for statement in [*cfn, *boundary]
        for action in (statement.get("Action", []) if isinstance(statement.get("Action", []), list) else [statement.get("Action")])
    )


def test_describe_key_metadata_mode_is_exact_and_keeps_crypto_context_grants():
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    legacy = _build(lambda_environment_key_arn=key, observed_user_pool_id=POOL_ID)
    template = _build(
        lambda_environment_key_arn=key,
        lambda_environment_key_describe=True,
        observed_user_pool_id=POOL_ID,
    )
    cfn = _cfn_statements(template)
    boundary = template["Resources"]["RetainedDevCdCloudFormationBoundary"]["Properties"]["PolicyDocument"]["Statement"]
    metadata = [item for item in cfn if item.get("Sid") == "ReadExactRetainedDevLambdaEnvironmentKeyMetadata"]
    assert metadata == [{
        "Sid": "ReadExactRetainedDevLambdaEnvironmentKeyMetadata",
        "Effect": "Allow",
        "Action": "kms:DescribeKey",
        "Resource": key,
        "Condition": {"StringEquals": {"kms:CallerAccount": ACCOUNT}},
    }]
    boundary_metadata = [item for item in boundary if item.get("Action") == "kms:DescribeKey"]
    assert boundary_metadata == [{
        "Effect": "Allow",
        "Action": "kms:DescribeKey",
        "Resource": key,
        "Condition": {"StringEquals": {"kms:CallerAccount": ACCOUNT}},
    }]
    assert all("kms:ViaService" not in item.get("Condition", {}).get("StringEquals", {})
               for item in metadata + boundary_metadata)
    assert all("kms:EncryptionContext:aws:lambda:FunctionArn" not in item.get("Condition", {}).get("StringEquals", {})
               for item in metadata + boundary_metadata)
    # The three existing context-specific denies remain crypto-only; they must
    # not turn a DescribeKey request into a context-bearing request.
    assert all("kms:DescribeKey" not in item.get("Action", [])
               for item in boundary if item.get("Effect") == "Deny")
    assert {"kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"}.issubset(_actions(cfn))
    assert template["Metadata"]["KmsMetadataBinding"] == KMS_METADATA_BINDING_MARKER
    assert "KmsMetadataBinding" not in legacy["Metadata"]
    assert template["Resources"]["RetainedDevCdExecutorRole"] == legacy["Resources"]["RetainedDevCdExecutorRole"]
    assert template["Resources"]["RetainedDevCdExecutorBoundary"] == legacy["Resources"]["RetainedDevCdExecutorBoundary"]


def test_describe_key_metadata_mode_is_strictly_opt_in():
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    with pytest.raises(RetainedDevMultiuserRoleError, match="multiuser_environment_key_invalid"):
        _build(lambda_environment_key_describe=True)
    with pytest.raises(RetainedDevMultiuserRoleError, match="multiuser_environment_key_invalid"):
        _build(lambda_environment_key_describe=1, lambda_environment_key_arn=key)
    # The pre-existing key variant remains unchanged unless the new explicit
    # marker is supplied.
    old = _build(lambda_environment_key_arn=key)
    assert "KmsMetadataBinding" not in old["Metadata"]
    assert not any(item.get("Action") == "kms:DescribeKey" for item in _cfn_statements(old))


@pytest.mark.parametrize("key", [
    "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555",
    "arn:aws:kms:eu-west-1:123456789012:key/not-a-uuid",
    "arn:aws:kms:eu-west-1:000000000000:key/11111111-2222-4333-8444-555555555555",
])
def test_environment_key_binding_is_exact_and_fail_closed(key):
    with pytest.raises(RetainedDevMultiuserRoleError, match="multiuser_environment_key_invalid"):
        _build(lambda_environment_key_arn=key)


@pytest.mark.parametrize("pool_id", ["", "us-east-1_bad", "eu-west-1_bad!", True])
def test_invalid_observed_pool_fails_closed(pool_id):
    with pytest.raises(RetainedDevMultiuserRoleError, match="multiuser_user_pool_binding_invalid"):
        _build(observed_user_pool_id=pool_id)
