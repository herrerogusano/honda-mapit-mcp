from __future__ import annotations

import copy
import json

import pytest

from scripts.build_aws_dev_mapit_binding_bootstrap import (
    CONFIG_PARAMETER,
    OPERATOR_BOUNDARY_NAME,
    OPERATOR_ROLE_NAME,
    RUNTIME_ROLE_NAME,
    STACK_NAME,
    MapitBindingBootstrapTemplateError,
    build_dev_mapit_binding_bootstrap,
)

ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
KMS = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"
FRESH = tuple("tenant-" + format(i, "064x") for i in range(1, 17))
HISTORICAL = tuple("tenant-" + format(i, "064x") for i in range(101, 107))
TABLE_ARN = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{STACK_NAME}"


def _build(*, count=2, excluded=HISTORICAL):
    return build_dev_mapit_binding_bootstrap(account_id=ACCOUNT, operator_user_arn=OPERATOR,
        tenant_keys=FRESH[:count], excluded_tenant_keys=excluded, ssm_key_arn=KMS)


def _actions(statement):
    value = statement["Action"]
    return set(value if type(value) is list else [value])


def test_fixed_namespace_template_has_four_retained_resources_and_owned_encryption():
    template = _build()
    resources = template["Resources"]
    assert set(resources) == {"MapitIdentityBindings", "IdentityEnrollerBoundary",
                              "IdentityEnrollerRole", "RuntimeIdentityBindingPolicy"}
    assert all(resource["Condition"] == "SupportedDeployment" for resource in resources.values())
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, ACCOUNT]},
    ]
    table = resources["MapitIdentityBindings"]
    assert table["Type"] == "AWS::DynamoDB::Table"
    assert table["DeletionPolicy"] == table["UpdateReplacePolicy"] == "Retain"
    assert table["Properties"]["TableName"] == STACK_NAME
    assert table["Properties"]["SSESpecification"] == {"SSEEnabled": False}
    assert table["Properties"]["DeletionProtectionEnabled"] is True
    assert table["Properties"]["BillingMode"] == "PAY_PER_REQUEST"
    assert table["Properties"]["OnDemandThroughput"] == {
        "MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100,
    }

    role = resources["IdentityEnrollerRole"]["Properties"]
    assert role["RoleName"] == OPERATOR_ROLE_NAME
    assert role["MaxSessionDuration"] == 3600
    assert role["AssumeRolePolicyDocument"]["Statement"] == [{
        "Effect": "Allow", "Principal": {"AWS": OPERATOR}, "Action": "sts:AssumeRole",
    }]
    assert role["PermissionsBoundary"] == {"Fn::GetAtt": ["IdentityEnrollerBoundary", "PolicyArn"]}
    boundary = resources["IdentityEnrollerBoundary"]["Properties"]
    assert boundary["ManagedPolicyName"] == OPERATOR_BOUNDARY_NAME
    operator_policy = role["Policies"][0]["PolicyDocument"]
    assert len(boundary["PolicyDocument"]["Statement"]) == 3
    assert len(json.dumps(boundary["PolicyDocument"], separators=(",", ":")).encode()) <= 6144
    assert len(json.dumps(operator_policy, separators=(",", ":")).encode()) <= 10240

    runtime = resources["RuntimeIdentityBindingPolicy"]["Properties"]
    assert runtime["Roles"] == [RUNTIME_ROLE_NAME]
    assert "*" not in runtime["PolicyDocument"].__repr__()
    assert "*" not in operator_policy.__repr__()


def test_exact_namespace_paths_and_readonly_runtime_crypto_policy():
    template = _build(count=2)
    resources = template["Resources"]
    runtime = resources["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyDocument"]["Statement"]
    operator = resources["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    paths = [f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{CONFIG_PARAMETER}"] + [
        f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
        for key in FRESH[:2]
    ]
    assert {_actions(row).pop() for row in runtime} == {
        "dynamodb:GetItem", "ssm:GetParameter", "kms:Decrypt",
    }
    assert "dynamodb:PutItem" not in set().union(*(_actions(row) for row in runtime))
    assert "ssm:PutParameter" not in set().union(*(_actions(row) for row in runtime))
    assert "kms:Encrypt" not in set().union(*(_actions(row) for row in runtime))

    ddb = next(row for row in runtime if "dynamodb:GetItem" in _actions(row))
    assert ddb["Resource"] == TABLE_ARN
    assert ddb["Condition"]["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"] == ["identity-bindings-v1"]
    runtime_ssm = next(row for row in runtime if "ssm:GetParameter" in _actions(row))
    assert runtime_ssm["Resource"] == paths
    runtime_kms = next(row for row in runtime if "kms:Decrypt" in _actions(row))
    assert runtime_kms["Resource"] == KMS
    assert runtime_kms["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"] == paths
    assert runtime_kms["Condition"]["StringEquals"]["kms:ViaService"] == "ssm.eu-west-1.amazonaws.com"
    assert runtime_kms["Condition"]["StringEquals"]["kms:CallerAccount"] == ACCOUNT

    assert set().union(*(_actions(row) for row in operator)) == {
        "dynamodb:GetItem", "dynamodb:PutItem", "ssm:GetParameter", "ssm:PutParameter",
        "kms:Encrypt", "kms:Decrypt",
    }
    assert all("*" not in row["Resource"] if type(row["Resource"]) is str
               else "*" not in row["Resource"] for row in operator)
    op_put = next(row for row in operator if "ssm:PutParameter" in _actions(row))
    assert op_put["Resource"] == paths
    assert op_put["Condition"]["StringEqualsIfExists"]["ssm:Overwrite"] == "false"
    op_kms = next(row for row in operator if "kms:Encrypt" in _actions(row))
    assert op_kms["Action"] == ["kms:Encrypt", "kms:Decrypt"]
    assert op_kms["Resource"] == KMS
    assert op_kms["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"] == paths
    boundary = template["Resources"]["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]["Statement"]
    boundary_ssm = next(row for row in boundary if "ssm:PutParameter" in _actions(row))
    assert boundary_ssm["Resource"] == paths
    assert boundary_ssm["Condition"]["StringEqualsIfExists"]["ssm:Overwrite"] == "false"
    boundary_kms = next(row for row in boundary if "kms:Encrypt" in _actions(row))
    assert boundary_kms["Resource"] == KMS
    assert boundary_kms["Condition"]["StringEquals"] == {
        "kms:ViaService": "ssm.eu-west-1.amazonaws.com",
        "kms:CallerAccount": ACCOUNT,
        "kms:EncryptionContext:PARAMETER_ARN": paths,
    }


def test_historical_keys_are_excluded_and_eight_key_policy_is_within_limits():
    template = _build(count=8)
    rendered = json.dumps(template, sort_keys=True)
    assert all(key not in rendered for key in HISTORICAL)
    fresh_arns = [f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
                  for key in FRESH[:8]]
    operator = template["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]["Statement"]
    assert all(any(arn in json.dumps(statement) for statement in operator) for arn in fresh_arns)
    boundary = template["Resources"]["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
    runtime = template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyDocument"]
    operator_policy = template["Resources"]["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    assert boundary == operator_policy
    expected_crypto_context = [
        f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{CONFIG_PARAMETER}", *fresh_arns,
    ]
    for document in (boundary, operator_policy, runtime):
        crypto = next(row for row in document["Statement"]
                      if "kms:Decrypt" in _actions(row))
        assert crypto["Condition"]["StringEquals"]["kms:EncryptionContext:PARAMETER_ARN"] == expected_crypto_context
    assert len(json.dumps(boundary, separators=(",", ":")).encode()) <= 6144
    assert len(json.dumps(operator_policy, separators=(",", ":")).encode()) <= 10240
    assert template["Metadata"]["Readiness"] == "NOT_DEPLOY_READY"
    assert template["Metadata"]["FreshKeysExcludeHistoricalTenantKeys"] is True
    assert template["Metadata"]["InitiallyAuthorizedTenantKeyLimit"] == 8
    assert template["Metadata"]["RegistryTenantRecordLimit"] == 16
    assert template["Metadata"]["AdditionalAuthorizedPathsRequireReview"] is True
    assert template["Metadata"]["ConfigSecretMaterialIncluded"] is False
    assert template["Metadata"]["ApplicationStackModified"] is False
    assert "Output" not in rendered


@pytest.mark.parametrize("changes", [
    {"account_id": "000000000000"},
    {"account_id": "12345678901x"},
    {"operator_user_arn": f"arn:aws:iam::999999999999:user/operator"},
    {"operator_user_arn": f"arn:aws:iam::{ACCOUNT}:root"},
    {"operator_user_arn": f"arn:aws:iam::{ACCOUNT}:user/*"},
    {"ssm_key_arn": f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"},
    {"tenant_keys": ()},
    {"tenant_keys": FRESH[:9]},
    {"tenant_keys": FRESH},
    {"tenant_keys": (FRESH[0], FRESH[0])},
    {"tenant_keys": (HISTORICAL[0],)},
    {"excluded_tenant_keys": ()},
    {"excluded_tenant_keys": (HISTORICAL[0], FRESH[0])},
    {"excluded_tenant_keys": (HISTORICAL[0], HISTORICAL[0])},
    {"excluded_tenant_keys": [*HISTORICAL]},
])
def test_bad_account_principal_key_set_or_key_fails_closed(changes):
    args = {"account_id": ACCOUNT, "operator_user_arn": OPERATOR,
            "tenant_keys": FRESH[:2], "excluded_tenant_keys": HISTORICAL, "ssm_key_arn": KMS}
    args.update(changes)
    with pytest.raises(MapitBindingBootstrapTemplateError,
                       match="^mapit_binding_bootstrap_invalid$"):
        build_dev_mapit_binding_bootstrap(**args)


def test_factory_returns_independent_copy_and_never_embeds_excluded_ids_or_secrets():
    first = _build()
    copy.deepcopy(first)["Resources"].clear()
    again = _build()
    assert set(again["Resources"]) == set(first["Resources"])
    rendered = json.dumps(again)
    assert "binding_mac_key" not in rendered
    assert "identity_proof_hmac_key" not in rendered
    assert all(key not in rendered for key in HISTORICAL)
