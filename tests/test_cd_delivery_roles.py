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
    assert "s3:PutObject" not in encoded and "s3:GetObject" not in encoded
    assert "iam:CreateRole" not in encoded and "iam:PutRolePolicy" not in encoded
    assert not any("mapit-refresh-token" in str(stmt) for stmt in statements)


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
        "lambda:GetFunction", "lambda:GetFunctionConfiguration",
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
