"""Independent exact-provider identity-binding regressions; all data is synthetic."""

from datetime import timedelta

import pytest

from scripts.github_sts_identity import StsProofError, prove_github_sts_identity
from test_github_sts_identity import (
    ACCOUNT,
    ISSUER,
    NOW,
    OWNER_ID,
    REPO_ID,
    SHA,
    FakeSts,
    _token,
)


def _proof_fixture(target: str, provider):
    role_name = f"honda-mapit-mcp-{target}-cd"
    session_name = f"mapit-cd-{target}-{SHA[:12]}"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{role_name}"
    assumed_arn = f"arn:aws:sts::{ACCOUNT}:assumed-role/{role_name}/{session_name}"
    assumed_id = f"AROA1234567890EXAMPLE:{session_name}"
    token = _token(target=target)
    unsigned = FakeSts(assume={
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Provider": provider,
        "Audience": "sts.amazonaws.com",
        "SubjectFromWebIdentityToken": (
            f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPO_ID}:environment:{target}"
        ),
        "AssumedRoleUser": {"Arn": assumed_arn, "AssumedRoleId": assumed_id},
        "Credentials": {
            "AccessKeyId": "ASIA-SYNTHETIC-CANARY",
            "SecretAccessKey": "secret-synthetic-canary",
            "SessionToken": "session-synthetic-canary",
            "Expiration": NOW + timedelta(minutes=15),
        },
    })
    explicit = FakeSts(caller={
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Account": ACCOUNT,
        "Arn": assumed_arn,
        "UserId": assumed_id,
    })
    explicit_calls = []

    def explicit_factory(**kwargs):
        explicit_calls.append(kwargs)
        return explicit

    args = {
        "token": token,
        "target": target,
        "source_sha": SHA,
        "expected_account_id": ACCOUNT,
        "expected_owner_id": OWNER_ID,
        "expected_repository_id": REPO_ID,
        "role_arn": role_arn,
        "anonymous_sts": unsigned,
        "explicit_sts_factory": explicit_factory,
        "clock": lambda: NOW,
    }
    return args, unsigned, explicit, explicit_calls


@pytest.mark.parametrize("target", ["dev", "prod"])
@pytest.mark.parametrize("provider_kind", ["url", "account_arn"])
def test_exact_github_issuer_url_and_account_bound_provider_arn_succeed(target, provider_kind):
    provider = (
        ISSUER
        if provider_kind == "url"
        else f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    )
    args, unsigned, explicit, explicit_calls = _proof_fixture(target, provider)

    result = prove_github_sts_identity(**args)

    assert result.status == "aws_identity_verified"
    assert [name for name, _ in unsigned.calls] == ["assume_role_with_web_identity"]
    assert [name for name, _ in explicit.calls] == ["get_caller_identity"]
    assert len(explicit_calls) == 1


@pytest.mark.parametrize("target", ["dev", "prod"])
@pytest.mark.parametrize("provider", [
    "http://token.actions.githubusercontent.com",
    f"arn:aws:iam::999999999999:oidc-provider/token.actions.githubusercontent.com",
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com/",
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/attacker.example",
    {"iss": ISSUER},
    [ISSUER],
    None,
])
def test_provider_near_misses_fail_before_explicit_caller_identity(provider, target):
    args, unsigned, explicit, explicit_calls = _proof_fixture(target, provider)

    with pytest.raises(StsProofError, match="identity_mismatch"):
        prove_github_sts_identity(**args)

    assert [name for name, _ in unsigned.calls] == ["assume_role_with_web_identity"]
    assert explicit.calls == []
    assert explicit_calls == []


@pytest.mark.parametrize("target", ["dev", "prod"])
def test_missing_provider_is_denied_before_caller_request(target):
    account_arn = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
    args, unsigned, explicit, explicit_calls = _proof_fixture(target, account_arn)
    del unsigned.assume_reply["Provider"]

    with pytest.raises(StsProofError, match="identity_mismatch"):
        prove_github_sts_identity(**args)

    assert [name for name, _ in unsigned.calls] == ["assume_role_with_web_identity"]
    assert explicit.calls == []
    assert explicit_calls == []
