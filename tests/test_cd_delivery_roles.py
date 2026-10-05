from __future__ import annotations

import hashlib

import pytest

from scripts.build_cd_delivery_roles import DeliveryRoleError, build_cd_delivery_roles


ACCOUNT = "123456789012"  # Synthetic fixture only.
OWNER_ID = "1234567"
REPOSITORY_ID = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPOSITORY_ID}:environment:prod"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-prod/11111111-2222-4333-8444-555555555555"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-prod-handler"
API = "a1b2c3d4e5"
API_ARN = f"arn:aws:apigateway:eu-west-1::/apis/{API}"
MACHINE = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-prod-shutdown"
BUCKET = "arn:aws:s3:::honda-mapit-mcp-prod-runtime-artifacts-a1b2c3d4abcd"
EXECUTION_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-runtime"
ALARM = f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-prod-request-tripwire"
RULE = f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/honda-mapit-mcp-prod-request-tripwire-alarm-rule"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"


def _build(**overrides):
    args = {
        "account_id": ACCOUNT,
        "provider_arn": PROVIDER,
        "owner_id": OWNER_ID,
        "repository_id": REPOSITORY_ID,
        "observed_prod_subject_format": "immutable_environment",
        "observed_prod_subject_sha256": hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
        "stack_arn": STACK,
        "handler_arn": HANDLER,
        "api_arn": API_ARN,
        "shutdown_state_machine_arn": MACHINE,
        "artifact_bucket_arn": BUCKET,
        "execution_role_arn": EXECUTION_ROLE,
        "tripwire_alarm_arn": ALARM,
        "tripwire_rule_arn": RULE,
        "allow_execution_role_passrole": True,
    }
    args.update(overrides)
    return build_cd_delivery_roles(**args)


def _role_policy(resource, role_id):
    return resource[role_id]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]


def test_factory_returns_two_separate_bound_roles_and_boundaries():
    template = _build()
    resources = template["Resources"]
    assert set(resources) == {
        "ProdCdExecutorBoundary", "ProdCdExecutorRole",
        "ProdCdCloudFormationBoundary", "ProdCdCloudFormationRole",
    }
    assert template["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
    assert template["Metadata"]["ExistingIdentityRolesChanged"] is False
    assert template["Metadata"]["ServiceRoleAssociationIsPersistent"] is True
    assert template["Metadata"]["ApiGatewayHttpApiResourceScopePendingClosedValidation"] is True
    assert template["Metadata"]["LambdaProviderTagMaintenanceScopedToHandler"] is True
    assert template["Metadata"]["LambdaProviderReadDependenciesScopedToHandler"] is True
    assert template["Metadata"]["ExecutorS3Prefixes"] == ["runtime/*", "journals/*"]
    assert template["Metadata"]["ExecutorS3ListOrDelete"] is False
    assert template["Metadata"]["JournalRetentionDays"] == 30
    assert template["Metadata"]["JournalRetentionLifecycleFilter"] == {
        "Prefix": "journals/", "Tag": {"Key": "cd-terminal", "Value": "true"}
    }
    assert template["Metadata"]["JournalTerminalTagConfiguredByFactory"] is False
    assert template["Metadata"]["JournalLifecycleConfiguredByFactory"] is False
    assert template["Metadata"]["JournalAuthorizationEnvelopeMaxSeconds"] == 3600
    assert template["Metadata"]["ExpiredJournalActionable"] is False
    for title in ("Executor", "CloudFormation"):
        role = resources[f"ProdCd{title}Role"]
        boundary = resources[f"ProdCd{title}Boundary"]
        assert role["Type"] == "AWS::IAM::Role"
        assert role["Properties"]["MaxSessionDuration"] == 3600
        assert role["Properties"]["PermissionsBoundary"] == {
            "Fn::GetAtt": [f"ProdCd{title}Boundary", "PolicyArn"]
        }
        bstatements = boundary["Properties"]["PolicyDocument"]["Statement"]
        rstatements = role["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
        assert bstatements[:-1] == rstatements
        assert bstatements[-1]["Effect"] == "Deny"
        assert bstatements[-1]["NotAction"]


def test_opt_in_default_lambda_key_is_exact_service_context_and_role_capability():
    key = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-2222-4333-8444-555555555555"
    base = _build()
    updated = _build(lambda_environment_key_arn=key)
    assert base["Metadata"] == updated["Metadata"]
    assert set(base["Resources"]) == set(updated["Resources"])
    for title, actions in (("Executor", ["kms:Decrypt"]),
                           ("CloudFormation", ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"])):
        role_id, boundary_id = f"ProdCd{title}Role", f"ProdCd{title}Boundary"
        original = _role_policy(base["Resources"], role_id)
        current = _role_policy(updated["Resources"], role_id)
        assert current[:-1] == original
        assert current[-1] == {
            "Sid": "FixedLambdaEnvironmentKey", "Effect": "Allow", "Action": actions, "Resource": key,
            "Condition": {"StringEquals": {"kms:CallerAccount": ACCOUNT,
                "kms:ViaService": "lambda.eu-west-1.amazonaws.com",
                "kms:EncryptionContext:aws:lambda:FunctionArn": HANDLER}}}
        boundary = updated["Resources"][boundary_id]["Properties"]["PolicyDocument"]["Statement"]
        assert boundary[:-4] == [{k: v for k, v in statement.items() if k != "Sid"} for statement in current]
        assert boundary[-4:-1] == [
            {"Effect": "Deny", "Action": actions, "NotResource": key},
            {"Effect": "Deny", "Action": actions, "Resource": key,
             "Condition": {"StringNotEquals": {"kms:ViaService": "lambda.eu-west-1.amazonaws.com"}}},
            {"Effect": "Deny", "Action": actions, "Resource": key,
             "Condition": {"StringNotEquals": {"kms:EncryptionContext:aws:lambda:FunctionArn": HANDLER}}},
        ]
        assert set(boundary[-1]["NotAction"]) == set(base["Resources"][boundary_id]["Properties"]["PolicyDocument"]["Statement"][-1]["NotAction"]) | set(actions)
        assert updated["Resources"][role_id]["Properties"]["AssumeRolePolicyDocument"] == base["Resources"][role_id]["Properties"]["AssumeRolePolicyDocument"]
        import json
        assert len(json.dumps(updated["Resources"][boundary_id]["Properties"]["PolicyDocument"], separators=(",", ":"))) <= 6144


@pytest.mark.parametrize("key", ["*", "arn:aws:kms:eu-west-1:123456789012:alias/aws/lambda",
    "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-4333-8444-555555555555",
    "arn:aws:kms:eu-west-1:999999999999:key/11111111-2222-4333-8444-555555555555",
    "arn:aws:kms:eu-west-1:123456789012:key/00000000-0000-0000-0000-000000000000", False, 1])
def test_default_lambda_key_rejects_unbound_region_account_alias_or_wildcard(key):
    with pytest.raises(DeliveryRoleError):
        _build(lambda_environment_key_arn=key)


def test_executor_trust_is_exact_observed_prod_subject_and_no_direct_code_write():
    resources = _build()["Resources"]
    trust = resources["ProdCdExecutorRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
    assert trust == [{
        "Effect": "Allow",
        "Principal": {"Federated": PROVIDER},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {"StringEquals": {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
            "token.actions.githubusercontent.com:sub": SUBJECT,
        }},
    }]
    statements = _role_policy(resources, "ProdCdExecutorRole")
    encoded = repr(statements)
    assert "lambda:UpdateFunctionCode" not in encoded
    assert "lambda:UpdateFunctionConfiguration" not in encoded
    assert "iam:CreateRole" not in encoded and "iam:PutRolePolicy" not in encoded
    assert not any("mapit-refresh-token" in str(stmt) for stmt in statements)


def test_executor_s3_grants_are_prefix_scoped_and_require_atomic_conditions():
    statements = _role_policy(_build()["Resources"], "ProdCdExecutorRole")
    s3 = [s for s in statements if any(
        action.startswith("s3:") for action in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
    )]
    assert {s["Sid"] for s in s3} == {
        "ReadRuntimePackages", "PublishRuntimePackagesWithoutOverwrite",
        "ReadOnlyDeliveryJournals", "CreateDeliveryJournalWithoutOverwrite",
        "ReviseDeliveryJournalWithObservedEtag", "ReadDeliveryJournalTags",
        "MarkOnlyTerminalDeliveryJournals", "ReadExactArtifactBucketSecurityMetadata",
    }
    assert all(s["Effect"] == "Allow" for s in s3)
    assert all(
        action in {
            "s3:GetObject", "s3:PutObject", "s3:GetObjectTagging", "s3:PutObjectTagging",
            "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls",
            "s3:GetEncryptionConfiguration", "s3:GetBucketTagging", "s3:GetBucketPolicyStatus", "s3:GetBucketPolicy",
        }
        for s in s3 for action in (s["Action"] if isinstance(s["Action"], list) else [s["Action"]])
    )
    assert all(s["Resource"] in {BUCKET, f"{BUCKET}/runtime/*", f"{BUCKET}/journals/*"} for s in s3)
    by_sid = {s["Sid"]: s for s in s3}
    assert by_sid["PublishRuntimePackagesWithoutOverwrite"]["Condition"] == {
        "StringEquals": {"s3:if-none-match": "*"}
    }
    assert by_sid["CreateDeliveryJournalWithoutOverwrite"]["Condition"] == {
        "StringEquals": {"s3:if-none-match": "*"}
    }
    assert by_sid["ReviseDeliveryJournalWithObservedEtag"]["Condition"] == {
        "Null": {"s3:if-match": "false"}
    }
    assert by_sid["ReadDeliveryJournalTags"]["Action"] == "s3:GetObjectTagging"
    assert by_sid["MarkOnlyTerminalDeliveryJournals"]["Action"] == "s3:PutObjectTagging"
    assert by_sid["MarkOnlyTerminalDeliveryJournals"]["Condition"] == {
        "ForAllValues:StringEquals": {"s3:RequestObjectTagKeys": ["cd-terminal"]},
        "StringEquals": {"s3:RequestObjectTag/cd-terminal": "true"},
        "Null": {"s3:RequestObjectTagKeys": "false"},
    }
    bucket_read = by_sid["ReadExactArtifactBucketSecurityMetadata"]
    assert set(bucket_read["Action"]) == {
        "s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:GetBucketPublicAccessBlock", "s3:GetBucketOwnershipControls",
        "s3:GetEncryptionConfiguration", "s3:GetBucketTagging", "s3:GetBucketPolicyStatus", "s3:GetBucketPolicy",
    }
    assert bucket_read["Resource"] == BUCKET
    assert not any("s3:List" in str(s["Action"]) or "s3:Delete" in str(s["Action"]) for s in statements)


def test_factory_accepts_only_owned_artifact_bucket_namespaces():
    stack_bucket = "honda-mapit-mcp-prod-runtime-runtimeartifactbucket-a1b2c3d4e5f6"
    template = _build(artifact_bucket_arn=f"arn:aws:s3:::{stack_bucket}")
    executor = _role_policy(template["Resources"], "ProdCdExecutorRole")
    assert next(s for s in executor if s["Sid"] == "ReadRuntimePackages")["Resource"] == (
        f"arn:aws:s3:::{stack_bucket}/runtime/*"
    )
    for invalid in (
        "other-project-prod-runtime-runtimeartifactbucket-a1b2c3d4e5f6",
        "honda-mapit-mcp-prod-runtime-runtimeartifactbucket-a1b2c3d4e5f6-near-miss",
        "honda-mapit-mcp-prod-runtime-runtimeartifactbucket-A1B2C3D4E5F6",
        "honda-mapit-mcp-prod-runtime-runtimeartifactbucket-short",
    ):
        with pytest.raises(DeliveryRoleError):
            _build(artifact_bucket_arn=f"arn:aws:s3:::{invalid}")


def test_executor_scopes_update_passrole_shutdown_controls_and_tripwire_reads():
    resources = _build()["Resources"]
    statements = _role_policy(resources, "ProdCdExecutorRole")
    update = next(s for s in statements if s["Sid"] == "UpdateOnlyOwnedStackWithFixedServiceRole")
    assert update["Resource"] == STACK
    assert update["Condition"] == {"StringEquals": {
        "cloudformation:RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-cfn-update"
    }}
    passrole = next(s for s in statements if s["Sid"] == "PassOnlyFixedCloudFormationRole")
    assert passrole["Resource"] == update["Condition"]["StringEquals"]["cloudformation:RoleArn"]
    assert passrole["Condition"] == {"StringEquals": {"iam:PassedToService": "cloudformation.amazonaws.com"}}
    start = next(s for s in statements if s["Sid"] == "StartOnlyFixedShutdownWorkflow")
    assert start["Action"] == "states:StartExecution" and start["Resource"] == MACHINE
    executions = next(s for s in statements if s["Sid"] == "InspectOnlyFixedShutdownExecutions")
    assert executions["Resource"] == f"arn:aws:states:eu-west-1:{ACCOUNT}:execution:honda-mapit-mcp-prod-shutdown:*"
    assert {s["Resource"] for s in statements if s["Sid"] == "ReadOnlyTripwire"} == {ALARM}
    assert {s["Resource"] for s in statements if s["Sid"] == "ReadOnlyTripwireRule"} == {RULE}
    api_toggle = next(s for s in statements if s["Action"] == "apigateway:PATCH")
    assert api_toggle["Resource"] == API_ARN
    assert "Condition" not in api_toggle  # HTTP API property enforcement is a separate closed-validation gate.
    function_reads = next(s for s in statements if s["Sid"] == "RestoreOnlyFixedFunctionConcurrency")
    assert "lambda:ListTags" in function_reads["Action"]
    assert function_reads["Resource"] == HANDLER


def test_cfn_role_only_updates_handler_reads_runtime_prefix_and_exact_dependencies():
    resources = _build()["Resources"]
    role = resources["ProdCdCloudFormationRole"]["Properties"]
    assert role["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow", "Principal": {"Service": "cloudformation.amazonaws.com"}, "Action": "sts:AssumeRole"
    }]
    statements = _role_policy(resources, "ProdCdCloudFormationRole")
    updates = next(s for s in statements if s["Sid"] == "UpdateAndReadOnlyFixedHandler")
    assert updates["Resource"] == HANDLER
    assert set(updates["Action"]) == {
        "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:GetFunctionCodeSigningConfig",
        "lambda:ListTags", "lambda:TagResource", "lambda:UntagResource",
        "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration",
    }
    assert next(s for s in statements if s["Sid"] == "ReadOnlyRuntimePackagePrefix")["Resource"] == f"{BUCKET}/runtime/*"
    deps = next(s for s in statements if s["Sid"] == "ReadExactExistingExecutionRoleDependencies")
    assert deps["Resource"] == EXECUTION_ROLE
    assert set(deps["Action"]) == {
        "iam:GetRole", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetRolePolicy", "iam:ListRoleTags"
    }
    passrole = next(s for s in statements if s["Sid"] == "PassOnlyFixedHandlerExecutionRole")
    assert passrole["Resource"] == EXECUTION_ROLE
    assert passrole["Condition"] == {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}
    assert not any(a.startswith("iam:") and a not in set(deps["Action"]) | {"iam:PassRole"}
                   for stmt in statements for a in (stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]))


@pytest.mark.parametrize(("field", "value"), [
    ("account_id", "123456789013"),
    ("provider_arn", "arn:aws:iam::123456789013:oidc-provider/token.actions.githubusercontent.com"),
    ("stack_arn", f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/other/11111111-2222-4333-8444-555555555555"),
    ("handler_arn", f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:other"),
    ("api_arn", f"arn:aws:apigateway:us-east-1::/apis/{API}"),
    ("shutdown_state_machine_arn", f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:other"),
    ("artifact_bucket_arn", "arn:aws:s3:::other-bucket"),
    ("artifact_bucket_arn", "arn:aws:s3:::honda-mapit-mcp-prod-runtime-artifacts-a..b"),
    ("artifact_bucket_arn", "arn:aws:s3:::honda-mapit-mcp-prod-runtime-artifacts-evil--x-s3"),
    ("execution_role_arn", f"arn:aws:iam::{ACCOUNT}:role/*"),
    ("tripwire_alarm_arn", f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:other"),
    ("tripwire_rule_arn", f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/other"),
    ("allow_execution_role_passrole", 1),
])
def test_invalid_resource_bindings_fail_closed(field, value):
    with pytest.raises(DeliveryRoleError):
        _build(**{field: value})


def test_observed_subject_digest_is_required_and_bound():
    with pytest.raises(DeliveryRoleError, match="subject_digest_mismatch"):
        _build(observed_prod_subject_sha256="0" * 64)


def test_execution_role_passrole_is_not_added_when_explicitly_disabled():
    statements = _role_policy(_build(allow_execution_role_passrole=False)["Resources"], "ProdCdCloudFormationRole")
    assert not any(
        "iam:PassRole" in (stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]])
        for stmt in statements
    )
