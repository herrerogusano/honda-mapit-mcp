from copy import deepcopy
import hashlib

import pytest

from scripts.build_cd_identity_bootstrap import (
    AUDIENCE,
    ISSUER_HOST,
    IdentityBootstrapError,
    build_cd_identity_bootstrap,
)


ACCOUNT = "123456789012"  # Synthetic fixture only.
OWNER_ID = "1234567"  # Synthetic fixture only.
REPOSITORY_ID = "7654321"  # Synthetic fixture only.
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/{ISSUER_HOST}"


def _sub(target, form):
    if form == "legacy_environment":
        return f"repo:herrerogusano/honda-mapit-mcp:environment:{target}"
    return (
        f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPOSITORY_ID}"
        f":environment:{target}"
    )


def _subjects():
    return {
        target: {
            "format": form,
            "sha256": hashlib.sha256(_sub(target, form).encode("ascii")).hexdigest(),
        }
        for target, form in (("dev", "legacy_environment"), ("prod", "immutable_environment"))
    }


def _build(**overrides):
    args = {
        "account_id": ACCOUNT,
        "provider_arn": PROVIDER,
        "owner_id": OWNER_ID,
        "repository_id": REPOSITORY_ID,
        "observed_subjects": _subjects(),
    }
    args.update(overrides)
    return build_cd_identity_bootstrap(**args)


def test_template_contains_only_separate_identity_roles_and_boundaries() -> None:
    template = _build()
    resources = template["Resources"]
    assert set(resources) == {
        "DevCdPermissionsBoundary",
        "DevCdIdentityRole",
        "ProdCdPermissionsBoundary",
        "ProdCdIdentityRole",
    }
    assert "Outputs" not in template and "Parameters" not in template

    for target in ("dev", "prod"):
        role = resources[f"{target.title()}CdIdentityRole"]
        boundary = resources[f"{target.title()}CdPermissionsBoundary"]
        role_props = role["Properties"]
        assert role["Type"] == "AWS::IAM::Role"
        assert role_props["RoleName"] == f"honda-mapit-mcp-{target}-cd"
        assert role_props["MaxSessionDuration"] == 3600
        assert role_props["Tags"] == [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": target},
            {"Key": "Purpose", "Value": "CDIdentityOwnership"},
        ]
        assert role_props["PermissionsBoundary"] == {
            "Fn::GetAtt": [f"{target.title()}CdPermissionsBoundary", "PolicyArn"]
        }
        assert boundary["Type"] == "AWS::IAM::ManagedPolicy"
        assert boundary["Properties"]["ManagedPolicyName"] == f"honda-mapit-mcp-{target}-cd-boundary"
        assert "Tags" not in boundary["Properties"]


def test_trust_is_exact_account_provider_audience_and_observed_target_subject() -> None:
    resources = _build()["Resources"]
    for target in ("dev", "prod"):
        props = resources[f"{target.title()}CdIdentityRole"]["Properties"]
        trust = props["AssumeRolePolicyDocument"]["Statement"]
        assert len(trust) == 1
        statement = trust[0]
        assert statement["Principal"] == {"Federated": PROVIDER}
        assert statement["Action"] == "sts:AssumeRoleWithWebIdentity"
        assert statement["Condition"] == {
            "StringEquals": {
                f"{ISSUER_HOST}:aud": AUDIENCE,
                f"{ISSUER_HOST}:sub": _sub(target, _subjects()[target]["format"]),
            }
        }
        assert "StringLike" not in statement["Condition"]


def test_inline_policy_and_boundary_grant_only_get_caller_identity() -> None:
    resources = _build()["Resources"]
    for target in ("dev", "prod"):
        boundary = resources[f"{target.title()}CdPermissionsBoundary"]["Properties"]["PolicyDocument"]
        assert boundary["Statement"] == [
            {
                "Sid": "AllowOnlyCallerIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            },
            {
                "Sid": "DenyEverythingExceptCallerIdentity",
                "Effect": "Deny",
                "NotAction": "sts:GetCallerIdentity",
                "Resource": "*",
            },
        ]
        role_policy = resources[f"{target.title()}CdIdentityRole"]["Properties"]["Policies"]
        assert len(role_policy) == 1
        assert role_policy[0]["PolicyDocument"]["Statement"] == [
            {
                "Sid": "AllowOnlyCallerIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            }
        ]


@pytest.mark.parametrize(
    ("field", "value", "category"),
    [
        ("account_id", "12345678901", "invalid_account"),
        ("account_id", "000000000000", "invalid_account"),
        ("account_id", True, "invalid_account"),
        ("provider_arn", "arn:aws:iam::999999999999:oidc-provider/token.actions.githubusercontent.com", "invalid_provider"),
        ("provider_arn", f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com/extra", "invalid_provider"),
        ("owner_id", "000123", "invalid_repository_binding"),
        ("repository_id", "x" * 21, "invalid_repository_binding"),
        ("observed_subjects", {"dev": {}, "prod": {}}, "invalid_repository_binding"),
    ],
)
def test_invalid_account_provider_or_binding_fails_closed(field, value, category) -> None:
    with pytest.raises(IdentityBootstrapError) as error:
        _build(**{field: value})
    assert error.value.category == category
    assert str(error.value) == category


def test_subject_digest_must_bind_exact_observed_format_and_target() -> None:
    subjects = deepcopy(_subjects())
    subjects["prod"]["sha256"] = subjects["dev"]["sha256"]
    with pytest.raises(IdentityBootstrapError) as error:
        _build(observed_subjects=subjects)
    assert error.value.category == "subject_digest_mismatch"

    subjects = _subjects()
    subjects["prod"]["format"] = "legacy_environment"
    with pytest.raises(IdentityBootstrapError) as error:
        _build(observed_subjects=subjects)
    assert error.value.category == "subject_digest_mismatch"


def test_input_observation_is_not_mutated_and_template_has_no_deployer_permissions() -> None:
    subjects = _subjects()
    before = deepcopy(subjects)
    template = _build(observed_subjects=subjects)
    assert subjects == before
    serialized = str(template)
    assert "CreateStack" not in serialized
    assert "UpdateStack" not in serialized
    assert "iam:PassRole" not in serialized
    assert "AWS::IAM::OpenIDConnectProvider" not in serialized
