"""Build a closed, target-specific GitHub OIDC identity bootstrap template.

This is a pure builder: it does not construct an AWS client, read credentials,
or deploy resources. The existing account-wide GitHub OIDC provider must be
observed separately; this template only references its exact ARN.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from typing import Any


OWNER = "herrerogusano"
REPOSITORY = "honda-mapit-mcp"
ISSUER_HOST = "token.actions.githubusercontent.com"
AUDIENCE = "sts.amazonaws.com"
TARGET_ENVIRONMENT = {"dev": "dev", "prod": "prod"}
SUBJECT_FORMATS = {"legacy_environment", "immutable_environment"}


class IdentityBootstrapError(ValueError):
    """A fixed-category input rejection without interpolated values."""

    def __init__(self, category: str) -> None:
        if category not in {
            "invalid_target", "invalid_account", "invalid_provider",
            "invalid_repository_binding", "subject_digest_mismatch",
        }:
            category = "invalid_configuration"
        self.category = category
        super().__init__(category)


def _subject(target: str, subject_format: str, owner_id: str, repository_id: str) -> str:
    if subject_format == "legacy_environment":
        return f"repo:{OWNER}/{REPOSITORY}:environment:{target}"
    if subject_format == "immutable_environment":
        return (
            f"repo:{OWNER}@{owner_id}/{REPOSITORY}@{repository_id}"
            f":environment:{target}"
        )
    raise IdentityBootstrapError("invalid_repository_binding")


def _validate_inputs(
    account_id: str,
    provider_arn: str,
    owner_id: str,
    repository_id: str,
    observed_subjects: Any,
) -> dict[str, str]:
    if (
        type(account_id) is not str
        or re.fullmatch(r"[0-9]{12}", account_id) is None
        or account_id == "000000000000"
    ):
        raise IdentityBootstrapError("invalid_account")
    provider_pattern = (
        rf"arn:aws:iam::{account_id}:oidc-provider/"
        rf"{re.escape(ISSUER_HOST)}"
    )
    if type(provider_arn) is not str or re.fullmatch(provider_pattern, provider_arn) is None:
        raise IdentityBootstrapError("invalid_provider")
    if (
        type(owner_id) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", owner_id) is None
        or type(repository_id) is not str
        or re.fullmatch(r"[1-9][0-9]{0,19}", repository_id) is None
    ):
        raise IdentityBootstrapError("invalid_repository_binding")
    if not isinstance(observed_subjects, Mapping) or set(observed_subjects) != {"dev", "prod"}:
        raise IdentityBootstrapError("invalid_repository_binding")
    subjects: dict[str, str] = {}
    for target in ("dev", "prod"):
        binding = observed_subjects[target]
        if (
            not isinstance(binding, Mapping)
            or set(binding) != {"format", "sha256"}
            or type(binding["format"]) is not str
            or binding["format"] not in SUBJECT_FORMATS
            or type(binding["sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", binding["sha256"]) is None
        ):
            raise IdentityBootstrapError("invalid_repository_binding")
        expected_subject = _subject(target, binding["format"], owner_id, repository_id)
        expected_digest = hashlib.sha256(expected_subject.encode("ascii")).hexdigest()
        if not hmac.compare_digest(expected_digest, binding["sha256"]):
            raise IdentityBootstrapError("subject_digest_mismatch")
        subjects[target] = expected_subject
    return subjects


def _identity_only_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowOnlyCallerIdentity",
                "Effect": "Allow",
                "Action": "sts:GetCallerIdentity",
                "Resource": "*",
            }
        ],
    }


def _boundary_policy() -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
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
        ],
    }


def _target_resources(target: str, provider_arn: str, subject: str) -> dict[str, Any]:
    prefix = f"honda-mapit-mcp-{target}-cd"
    boundary_logical_id = f"{target.title()}CdPermissionsBoundary"
    role_logical_id = f"{target.title()}CdIdentityRole"
    return {
        boundary_logical_id: {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": f"{prefix}-boundary",
                "Description": "Maximum permission is STS caller identity only.",
                "PolicyDocument": _boundary_policy(),
            },
        },
        role_logical_id: {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": prefix,
                "Description": "GitHub OIDC identity-only role; no deployment access.",
                "MaxSessionDuration": 3600,
                "Tags": [
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": target},
                    {"Key": "Purpose", "Value": "CDIdentityOwnership"},
                ],
                "PermissionsBoundary": {"Fn::GetAtt": [boundary_logical_id, "PolicyArn"]},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "TrustExactRepositoryEnvironmentSubject",
                            "Effect": "Allow",
                            "Principal": {"Federated": provider_arn},
                            "Action": "sts:AssumeRoleWithWebIdentity",
                            "Condition": {
                                "StringEquals": {
                                    f"{ISSUER_HOST}:aud": AUDIENCE,
                                    f"{ISSUER_HOST}:sub": subject,
                                }
                            },
                        }
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": f"{prefix}-identity-only",
                        "PolicyDocument": _identity_only_policy(),
                    }
                ],
            },
        },
    }


def build_cd_identity_bootstrap(
    *,
    account_id: str,
    provider_arn: str,
    owner_id: str,
    repository_id: str,
    observed_subjects: Mapping[str, Mapping[str, str]],
) -> dict[str, Any]:
    """Return one role and one permission boundary for each fixed target.

    Each subject is derived from fixed repository/target inputs and must match
    the digest from a separately observed claim. The builder references an
    existing provider only; it never creates the account-wide provider.
    """
    subjects = _validate_inputs(
        account_id,
        provider_arn,
        owner_id,
        repository_id,
        observed_subjects,
    )
    resources: dict[str, Any] = {}
    for target in ("dev", "prod"):
        resources.update(_target_resources(target, provider_arn, subjects[target]))
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Closed GitHub OIDC identity bootstrap; caller-identity permission only.",
        "Metadata": {
            "Readiness": "IDENTITY_BOOTSTRAP_ONLY_NOT_A_DEPLOY_ROLE",
            "Provider": "Existing account-wide GitHub OIDC provider; not created here.",
        },
        "Resources": resources,
    }
