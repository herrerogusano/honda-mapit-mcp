"""Independent checks for the narrowly scoped DEV SecureString KMS policy."""
from __future__ import annotations

import pytest

from scripts.build_aws_dev_identity_binding_bootstrap import (
    IdentityBindingBootstrapTemplateError,
    build_dev_identity_binding_bootstrap,
)


ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
TENANTS = ("tenant-" + "1" * 64, "tenant-" + "2" * 64)
SSM_KEY_ARN = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc"
CRYPTO = {"kms:Encrypt", "kms:Decrypt"}


def _template(*, key_arn=SSM_KEY_ARN):
    return build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=OPERATOR, tenant_keys=TENANTS,
        ssm_key_arn=key_arn,
    )


def _policy_documents(template):
    resources = template["Resources"]
    operator = resources["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
    boundary = resources["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
    runtime = resources["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyDocument"]
    return operator, boundary, runtime


def _actions(statement):
    action = statement.get("Action")
    return set(action) if type(action) is list else {action}


def test_crypto_allows_are_exact_key_and_three_parameter_contexts_in_operator_and_boundary():
    operator, boundary, runtime = _policy_documents(_template())
    paths = [
        *(f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token"
          for key in TENANTS),
        f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/identity-binding-config",
    ]
    for policy in (operator, boundary):
        allow = [row for row in policy["Statement"] if row.get("Sid") == "ExactStandardParameterCrypto"]
        assert len(allow) == 1
        row = allow[0]
        assert row["Effect"] == "Allow"
        assert _actions(row) == CRYPTO
        assert row["Resource"] == SSM_KEY_ARN
        assert row["Condition"] == {"StringEquals": {
            "kms:ViaService": "ssm.eu-west-1.amazonaws.com",
            "kms:CallerAccount": ACCOUNT,
            "kms:EncryptionContext:PARAMETER_ARN": paths,
        }}

        key_denies = [s for s in policy["Statement"] if s.get("Sid") == "DenyOtherCryptoKeys"]
        assert len(key_denies) == 1
        assert key_denies[0]["Effect"] == "Deny" and _actions(key_denies[0]) == CRYPTO
        assert key_denies[0]["NotResource"] == SSM_KEY_ARN

        context_denies = [s for s in policy["Statement"] if str(s.get("Sid", "")).startswith("DenyOtherCryptoContext")]
        assert len(context_denies) == 3
        denied = {}
        for statement in context_denies:
            assert statement["Effect"] == "Deny" and _actions(statement) == CRYPTO
            assert statement["Resource"] == "*"
            condition = statement.get("Condition", {}).get("StringNotEqualsIfExists")
            assert type(condition) is dict and len(condition) == 1
            key, value = next(iter(condition.items()))
            denied[key] = value
        assert denied == {
            "kms:ViaService": "ssm.eu-west-1.amazonaws.com",
            "kms:CallerAccount": ACCOUNT,
            "kms:EncryptionContext:PARAMETER_ARN": paths,
        }

    assert CRYPTO <= set(next(row for row in boundary["Statement"]
                              if row.get("Sid") == "DenyUnlistedOperatorCapabilities")["NotAction"])
    runtime_actions = set().union(*(_actions(s) for s in runtime["Statement"]))
    assert not any(type(action) is str and action.startswith("kms:") for action in runtime_actions)


@pytest.mark.parametrize("key_arn", [
    f"arn:aws:kms:us-east-1:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc",
    "arn:aws:kms:eu-west-1:999999999999:key/12345678-1234-1234-1234-123456789abc",
    f"arn:aws:kms:eu-west-1:{ACCOUNT}:alias/aws/ssm",
    f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/not-a-key-id",
    f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc:extra",
    None,
])
def test_crypto_policy_rejects_noncanonical_or_wrong_account_key_arns(key_arn):
    with pytest.raises(IdentityBindingBootstrapTemplateError, match="identity_binding_bootstrap_invalid"):
        _template(key_arn=key_arn)
