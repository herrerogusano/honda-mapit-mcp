"""Pure DEV-only resource/permission drafts; no SDK or deployment authority.

These drafts do not modify existing roles, boundaries, templates or journals.
Applying them needs a fresh reviewed deployment with verified closed DEV.
"""
from __future__ import annotations

import re


def build_dev_identity_binding_table() -> dict:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Dedicated retained DEV MAPIT identity binding metadata; no sessions",
        "Resources": {
            "MapitIdentityBindings": {
                "Type": "AWS::DynamoDB::Table", "DeletionPolicy": "Retain",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "TableName": "honda-mapit-mcp-dev-identity-bindings",
                    "BillingMode": "PAY_PER_REQUEST", "DeletionProtectionEnabled": True,
                    "OnDemandThroughput": {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100},
                    "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}],
                    "SSESpecification": {"SSEEnabled": True},
                    "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"},
                             {"Key": "Environment", "Value": "dev"},
                             {"Key": "Purpose", "Value": "mapit-identity-bindings"}],
                },
            },
        },
    }


def dev_identity_binding_policy_draft(*, account_id: str, tenant_keys: tuple[str, ...],
                                      operator: bool = False) -> dict:
    """Exact-resource grants, not a complete deployed role/boundary policy.

    Runtime is read-only; enrollment operator gets CAS and create-only SSM.
    No wildcard secret namespace, Scan/Delete, Cognito admin or KMS expansion.
    Actual KMS/service-role/boundary readbacks remain a separate live gate.
    """
    if (type(account_id) is not str or re.fullmatch(r"[0-9]{12}", account_id) is None
        or account_id == "000000000000" or type(operator) is not bool
        or type(tenant_keys) is not tuple or not 1 <= len(tenant_keys) <= 16
        or any(type(key) is not str or re.fullmatch(r"tenant-[0-9a-f]{64}", key) is None for key in tenant_keys)
        or len(set(tenant_keys)) != len(tenant_keys)):
        raise ValueError("identity_binding_policy_invalid")
    table = f"arn:aws:dynamodb:eu-west-1:{account_id}:table/honda-mapit-mcp-dev-identity-bindings"
    paths = [f"arn:aws:ssm:eu-west-1:{account_id}:parameter/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token" for key in tenant_keys]
    statements = [
        {"Effect": "Allow", "Action": ["dynamodb:GetItem"] + (["dynamodb:PutItem"] if operator else []),
         "Resource": table, "Condition": {"ForAllValues:StringEquals": {"dynamodb:LeadingKeys": ["identity-bindings-v1"]},
                                         "Null": {"dynamodb:LeadingKeys": "false"}}},
        {"Effect": "Allow", "Action": "ssm:GetParameter", "Resource": paths},
    ]
    if operator:
        statements.append({"Effect": "Allow", "Action": "ssm:PutParameter", "Resource": paths,
                           "Condition": {"StringEquals": {"ssm:Overwrite": "false"}}})
        statements.append({"Effect": "Deny", "Action": "ssm:PutParameter", "Resource": paths,
                           "Condition": {"StringEquals": {"ssm:Overwrite": "true"}}})
    return {"Version": "2012-10-17", "Statement": statements}


__all__ = ["build_dev_identity_binding_table", "dev_identity_binding_policy_draft"]
