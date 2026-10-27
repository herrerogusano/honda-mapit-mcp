"""Pure DEV identity-binding infrastructure candidate; never deploys itself."""
from __future__ import annotations

import copy
import re
from typing import Any

from mapit.aws_identity_binding_infra import build_dev_identity_binding_table, dev_identity_binding_policy_draft

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-identity-bindings-bootstrap"
OPERATOR_ROLE_NAME = "honda-mapit-mcp-dev-identity-enroller"
OPERATOR_BOUNDARY_NAME = OPERATOR_ROLE_NAME + "-boundary"
RUNTIME_ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
CONFIG_PARAMETER = "/honda-mapit-mcp/dev/identity-binding-config"
CONFIG_ARN = "arn:aws:ssm:eu-west-1:{account}:parameter/honda-mapit-mcp/dev/identity-binding-config"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")


class IdentityBindingBootstrapTemplateError(ValueError):
    """Fixed local category for malformed DEV bootstrap inputs."""


def _policy_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = policy.get("Statement")
    if type(statements) is not list or not statements or any(type(row) is not dict for row in statements):
        raise IdentityBindingBootstrapTemplateError("identity_binding_bootstrap_invalid")
    return statements


def build_dev_identity_binding_bootstrap(*, account_id: str, operator_user_arn: str,
                                         tenant_keys: tuple[str, str], ssm_key_arn: str) -> dict[str, Any]:
    """Build table + narrowly scoped operator/runtime permissions.

    ``tenant_keys`` must be two fresh synthetic keys fixed in the private
    authorization. The operator performs absence/lineage checks before stack
    creation. No key material, parameter values, subjects, or credentials are
    embedded in the template.
    """
    if (type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None
        or account_id == "000000000000"
        or type(ssm_key_arn) is not str
        or re.fullmatch(rf"arn:aws:kms:{REGION}:{account_id}:key/[0-9a-f]{{8}}-(?:[0-9a-f]{{4}}-){{3}}[0-9a-f]{{12}}", ssm_key_arn) is None
        or type(operator_user_arn) is not str
        or re.fullmatch(rf"arn:aws:iam::{account_id}:user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+", operator_user_arn) is None
        or type(tenant_keys) is not tuple or len(tenant_keys) != 2
        or any(type(key) is not str or _TENANT_KEY.fullmatch(key) is None for key in tenant_keys)
        or len(set(tenant_keys)) != 2):
        raise IdentityBindingBootstrapTemplateError("identity_binding_bootstrap_invalid")

    try:
        table_scaffold = build_dev_identity_binding_table()
        table = copy.deepcopy(table_scaffold["Resources"]["MapitIdentityBindings"])
        operator_policy = dev_identity_binding_policy_draft(
            account_id=account_id, tenant_keys=tenant_keys, operator=True,
        )
        runtime_policy = dev_identity_binding_policy_draft(
            account_id=account_id, tenant_keys=tenant_keys, operator=False,
        )
    except Exception:
        raise IdentityBindingBootstrapTemplateError("identity_binding_bootstrap_invalid") from None

    table_arn = f"arn:aws:dynamodb:{REGION}:{account_id}:table/honda-mapit-mcp-dev-identity-bindings"
    config_arn = CONFIG_ARN.format(account=account_id)
    for policy in (operator_policy, runtime_policy):
        for statement in _policy_statements(policy):
            if statement.get("Action") in ("ssm:GetParameter", "ssm:PutParameter"):
                resources = statement.get("Resource")
                if type(resources) is not list:
                    raise IdentityBindingBootstrapTemplateError("identity_binding_bootstrap_invalid")
                statement["Resource"] = [*resources, config_arn]

    operator_statements = _policy_statements(operator_policy)
    operator_statements.append({"Sid": "CallerIdentityOnly", "Effect": "Allow",
                                "Action": "sts:GetCallerIdentity", "Resource": "*"})
    parameter_arns = next(row["Resource"] for row in operator_statements
                          if row.get("Action") == "ssm:GetParameter")
    crypto_actions = ["kms:Encrypt", "kms:Decrypt"]
    crypto_conditions = {
        "kms:ViaService": f"ssm.{REGION}.amazonaws.com",
        "kms:CallerAccount": account_id,
        "kms:EncryptionContext:PARAMETER_ARN": parameter_arns,
    }
    operator_statements.append({"Sid": "ExactStandardParameterCrypto", "Effect": "Allow",
        "Action": crypto_actions, "Resource": ssm_key_arn,
        "Condition": {"StringEquals": crypto_conditions}})
    operator_statements.append({"Sid": "DenyOtherCryptoKeys", "Effect": "Deny",
        "Action": crypto_actions, "NotResource": ssm_key_arn})
    for index, (key, value) in enumerate(crypto_conditions.items()):
        # Independent statements implement OR; absent context is also denied.
        operator_statements.append({"Sid": f"DenyOtherCryptoContext{index}", "Effect": "Deny",
            "Action": crypto_actions, "Resource": "*",
            "Condition": {"StringNotEqualsIfExists": {key: value}}})
    boundary = copy.deepcopy(operator_policy)
    _policy_statements(boundary).append({
        "Sid": "DenyUnlistedOperatorCapabilities", "Effect": "Deny", "NotAction": [
            "sts:GetCallerIdentity", "dynamodb:GetItem", "dynamodb:PutItem",
            "ssm:GetParameter", "ssm:PutParameter",
            "kms:Encrypt", "kms:Decrypt",
        ], "Resource": "*",
    })

    runtime_role_arn = f"arn:aws:iam::{account_id}:role/{RUNTIME_ROLE_NAME}"
    runtime_policy_resource = {
        "Version": "2012-10-17", "Statement": _policy_statements(runtime_policy),
    }
    condition = {"Fn::And": [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, account_id]},
    ]}
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "mapit-identity-bindings"},
    ]
    table["Condition"] = "SupportedDeployment"
    resources = {
        "MapitIdentityBindings": table,
        "IdentityEnrollerBoundary": {
            "Type": "AWS::IAM::ManagedPolicy", "Condition": "SupportedDeployment",
            "Properties": {"ManagedPolicyName": OPERATOR_BOUNDARY_NAME,
                "Description": "Maximum permissions for the one-purpose DEV identity enroller.",
                "Path": "/", "PolicyDocument": boundary},
        },
        "IdentityEnrollerRole": {
            "Type": "AWS::IAM::Role", "Condition": "SupportedDeployment",
            "Properties": {"RoleName": OPERATOR_ROLE_NAME,
                "Description": "DEV synthetic identity enrollment only.",
                "Path": "/", "MaxSessionDuration": 3600,
                "PermissionsBoundary": {"Fn::GetAtt": ["IdentityEnrollerBoundary", "PolicyArn"]},
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"AWS": operator_user_arn},
                    "Action": "sts:AssumeRole",
                }]},
                "Policies": [{"PolicyName": OPERATOR_ROLE_NAME + "-policy",
                              "PolicyDocument": operator_policy}],
                "Tags": tags},
        },
        "RuntimeIdentityBindingPolicy": {
            "Type": "AWS::IAM::Policy", "Condition": "SupportedDeployment",
            "Properties": {"PolicyName": "honda-mapit-mcp-dev-identity-bindings-runtime-read",
                "Roles": [RUNTIME_ROLE_NAME], "PolicyDocument": runtime_policy_resource},
        },
    }
    if not all(
        resource.get("Condition") == "SupportedDeployment"
        for resource in resources.values()
    ):
        raise IdentityBindingBootstrapTemplateError("identity_binding_bootstrap_invalid")
    # Ensure the read-only attachment has not inherited operator writes.
    for statement in runtime_policy_resource["Statement"]:
        actions = statement.get("Action")
        if actions == "dynamodb:PutItem" or actions == "ssm:PutParameter":
            raise IdentityBindingBootstrapTemplateError("identity_binding_bootstrap_invalid")
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Dedicated DEV synthetic identity binding storage and minimum permissions.",
        "Conditions": {"SupportedDeployment": condition},
        "Metadata": {
            "Readiness": "NOT_DEPLOY_READY",
            "Purpose": "Synthetic DEV enrollment preparation only; not functional-hosting acceptance.",
            "OperatorMustUseWholeFixedDdbItemCas": True,
            "ApplicationStackModified": False,
            "ConfigParameterPath": CONFIG_PARAMETER,
            "ConfigSecretMaterialIncluded": False,
            "TwoSyntheticTenantBindingsOnly": True,
            "OwnerMfaProductionAndQuotaUnchanged": True,
            "PermissionBoundaryLiveAcceptancePending": True,
        },
        "Resources": resources,
    }


__all__ = ["build_dev_identity_binding_bootstrap", "IdentityBindingBootstrapTemplateError"]
