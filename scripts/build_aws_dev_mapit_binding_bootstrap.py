"""Pure infrastructure candidate for the separate DEV MAPIT namespace.

This factory does not deploy resources or publish key material. It is isolated
from the historical synthetic binding stack and grants only fixed DEV paths.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

from mapit.aws_identity_binding_infra import build_dev_identity_binding_table

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-mapit-identity-bindings"
TABLE_NAME = STACK_NAME
OPERATOR_ROLE_NAME = "honda-mapit-mcp-dev-mapit-enroller"
OPERATOR_BOUNDARY_NAME = OPERATOR_ROLE_NAME + "-boundary"
RUNTIME_ROLE_NAME = "honda-mapit-mcp-dev-retained-handler-role"
CONFIG_PARAMETER = "/honda-mapit-mcp/dev/mapit-identity-binding-config"
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_KMS_KEY = re.compile(r"arn:aws:kms:eu-west-1:([0-9]{12}):key/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
_MAX_AUTHORIZED_TENANT_KEYS = 8


class MapitBindingBootstrapTemplateError(ValueError):
    """Fixed category for malformed namespace bootstrap inputs."""


def _paths(account_id: str, tenant_keys: tuple[str, ...]) -> list[str]:
    paths = [CONFIG_PARAMETER]
    paths.extend(f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token" for key in tenant_keys)
    return [f"arn:aws:ssm:{REGION}:{account_id}:parameter{path}" for path in paths]


def _allow_statements(account_id: str, tenant_keys: tuple[str, ...], ssm_key_arn: str,
                      *, operator: bool) -> list[dict[str, Any]]:
    table_arn = f"arn:aws:dynamodb:{REGION}:{account_id}:table/{TABLE_NAME}"
    paths = _paths(account_id, tenant_keys)
    statements: list[dict[str, Any]] = [{
        "Sid": "FixedItemCas", "Effect": "Allow",
        "Action": ["dynamodb:GetItem"] + (["dynamodb:PutItem"] if operator else []),
        "Resource": table_arn,
        "Condition": {
            "ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["identity-bindings-v1"]},
            "Null": {"dynamodb:LeadingKeys": "false"},
        },
    }]
    if operator:
        statements.append({
            "Sid": "ExactCreateOnlyParameters", "Effect": "Allow",
            "Action": ["ssm:GetParameter", "ssm:PutParameter"], "Resource": paths,
            # GetParameter has no Overwrite request context; IfExists keeps
            # reads valid while requiring every write to be create-only.
            "Condition": {"StringEqualsIfExists": {"ssm:Overwrite": "false"}},
        })
        crypto_actions = ["kms:Encrypt", "kms:Decrypt"]
    else:
        statements.append({
            "Sid": "ExactParameterRead", "Effect": "Allow", "Action": "ssm:GetParameter",
            "Resource": paths,
        })
        crypto_actions = ["kms:Decrypt"]
    crypto_condition = {
        "kms:ViaService": f"ssm.{REGION}.amazonaws.com",
        "kms:CallerAccount": account_id,
    }
    crypto_condition["kms:EncryptionContext:PARAMETER_ARN"] = paths
    statements.append({
        "Sid": "ExactSecureStringCrypto", "Effect": "Allow", "Action": crypto_actions,
        "Resource": ssm_key_arn,
        "Condition": {"StringEquals": crypto_condition},
    })
    return statements


def _policy(statements: list[dict[str, Any]]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": statements}


def build_dev_mapit_binding_bootstrap(*, account_id: str, operator_user_arn: str,
                                     tenant_keys: tuple[str, ...],
                                     excluded_tenant_keys: tuple[str, ...],
                                     ssm_key_arn: str) -> dict[str, Any]:
    """Build fixed four-resource DEV namespace template with exact access paths.

    Fresh tenant keys must be disjoint from the private historical exclusion
    set. The set itself is not copied into template metadata or outputs. This
    initial IAM authorization is deliberately limited to eight tenant keys so
    both operator policies retain exact KMS parameter-context conditions within
    AWS policy-size limits. The identity registry itself remains capped at 16;
    authorizing additional paths requires a separately reviewed policy update.
    """
    key_arn = _KMS_KEY.fullmatch(ssm_key_arn) if type(ssm_key_arn) is str else None
    if (type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None
            or account_id == "000000000000"
            or type(operator_user_arn) is not str
            or re.fullmatch(rf"arn:aws:iam::{account_id}:user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+", operator_user_arn) is None
            or key_arn is None or key_arn.group(1) != account_id
            or type(tenant_keys) is not tuple or not 1 <= len(tenant_keys) <= _MAX_AUTHORIZED_TENANT_KEYS
            or any(type(key) is not str or _TENANT_KEY.fullmatch(key) is None for key in tenant_keys)
            or len(set(tenant_keys)) != len(tenant_keys)
            or type(excluded_tenant_keys) is not tuple or not 1 <= len(excluded_tenant_keys) <= 16
            or any(type(key) is not str or _TENANT_KEY.fullmatch(key) is None for key in excluded_tenant_keys)
            or len(set(excluded_tenant_keys)) != len(excluded_tenant_keys)
            or set(tenant_keys) & set(excluded_tenant_keys)):
        raise MapitBindingBootstrapTemplateError("mapit_binding_bootstrap_invalid")

    try:
        scaffold = build_dev_identity_binding_table()
        table = copy.deepcopy(scaffold["Resources"]["MapitIdentityBindings"])
        table["Properties"]["TableName"] = TABLE_NAME
        table["Properties"]["SSESpecification"] = {"SSEEnabled": False}
        table["Properties"]["Tags"] = [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "mapit-enrolled-identity-bindings"},
        ]
        operator_policy = _policy(_allow_statements(account_id, tenant_keys, ssm_key_arn,
                                                    operator=True))
        runtime_policy = _policy(_allow_statements(account_id, tenant_keys, ssm_key_arn,
                                                    operator=False))
        boundary = _policy(_allow_statements(account_id, tenant_keys, ssm_key_arn,
            operator=True))
        boundary_size = len(json.dumps(boundary, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        operator_size = len(json.dumps(operator_policy, separators=(",", ":"), ensure_ascii=True).encode("utf-8"))
        if boundary_size > 6144 or operator_size > 10240:
            raise ValueError
    except Exception:
        raise MapitBindingBootstrapTemplateError("mapit_binding_bootstrap_invalid") from None

    table["Condition"] = "SupportedDeployment"
    condition = {"Fn::And": [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, REGION]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, STACK_NAME]},
        {"Fn::Equals": [{"Ref": "AWS::AccountId"}, account_id]},
    ]}
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "mapit-enrolled-identity-bindings"},
    ]
    resources = {
        "MapitIdentityBindings": table,
        "IdentityEnrollerBoundary": {
            "Type": "AWS::IAM::ManagedPolicy", "Condition": "SupportedDeployment",
            "Properties": {"ManagedPolicyName": OPERATOR_BOUNDARY_NAME,
                "Description": "Maximum permissions for the exact DEV MAPIT enroller.",
                "Path": "/", "PolicyDocument": boundary},
        },
        "IdentityEnrollerRole": {
            "Type": "AWS::IAM::Role", "Condition": "SupportedDeployment",
            "Properties": {"RoleName": OPERATOR_ROLE_NAME,
                "Description": "DEV MAPIT identity binding enrollment only.",
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
            "Properties": {"PolicyName": "honda-mapit-mcp-dev-mapit-identity-bindings-runtime-read",
                "Roles": [RUNTIME_ROLE_NAME], "PolicyDocument": runtime_policy},
        },
    }
    if any(resource.get("Condition") != "SupportedDeployment" for resource in resources.values()):
        raise MapitBindingBootstrapTemplateError("mapit_binding_bootstrap_invalid")
    if any(row.get("Effect") != "Allow" for row in runtime_policy["Statement"]):
        raise MapitBindingBootstrapTemplateError("mapit_binding_bootstrap_invalid")
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Dedicated DEV real-MAPIT identity binding storage and minimum permissions.",
        "Conditions": {"SupportedDeployment": condition},
        "Metadata": {
            "Readiness": "NOT_DEPLOY_READY",
            "Purpose": "Opt-in DEV MAPIT namespace; no historical synthetic binding reuse.",
            "ApplicationStackModified": False,
            "ConfigParameterPath": CONFIG_PARAMETER,
            "ConfigSecretMaterialIncluded": False,
            "FreshKeysExcludeHistoricalTenantKeys": True,
            "InitiallyAuthorizedTenantKeyLimit": _MAX_AUTHORIZED_TENANT_KEYS,
            "RegistryTenantRecordLimit": 16,
            "AdditionalAuthorizedPathsRequireReview": True,
            "OperatorInlinePolicyPinsKmsParameterContext": True,
            "OwnerMfaProductionAndQuotaUnchanged": True,
        },
        "Resources": resources,
    }


__all__ = ["build_dev_mapit_binding_bootstrap", "MapitBindingBootstrapTemplateError"]
