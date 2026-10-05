from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from scripts.github_sts_identity import (
    StsProofError,
    prove_github_sts_identity,
)


ACCOUNT = "123456789012"
OWNER_ID = "1234567"
REPO_ID = "7654321"
SHA = "a" * 40
ISSUER = "https://token.actions.githubusercontent.com"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPO_ID}:environment:dev"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-cd"
SESSION_NAME = f"mapit-cd-dev-{SHA[:12]}"
ASSUMED_ARN = f"arn:aws:sts::{ACCOUNT}:assumed-role/honda-mapit-mcp-dev-cd/{SESSION_NAME}"
ASSUMED_ID = f"AROAEXAMPLE:{SESSION_NAME}"
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)


def _segment(value):
    raw = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _token(*, target="dev", sub=None, repository_id=REPO_ID):
    subject = sub or f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{repository_id}:environment:{target}"
    claims = {
        "iss": ISSUER,
        "aud": "sts.amazonaws.com",
        "repository": "herrerogusano/honda-mapit-mcp",
        "repository_owner": "herrerogusano",
        "repository_id": repository_id,
        "repository_owner_id": OWNER_ID,
        "ref": "refs/heads/develop" if target == "dev" else "refs/heads/main",
        "sha": SHA,
        "environment": target,
        "sub": subject,
    }
    return f"{_segment({'alg':'RS256','kid':'synthetic'})}.{_segment(claims)}.synthetic-signature"


class FakeSts:
    def __init__(self, assume=None, caller=None, failure=None):
        self.assume_reply = assume
        self.caller_reply = caller
        self.failure = failure
        self.calls = []

    def assume_role_with_web_identity(self, **kwargs):
        self.calls.append(("assume_role_with_web_identity", kwargs))
        if self.failure:
            raise RuntimeError("credential-canary")
        return self.assume_reply

    def get_caller_identity(self):
        self.calls.append(("get_caller_identity", {}))
        return self.caller_reply


def _responses(*, provider=ISSUER, audience="sts.amazonaws.com", subject=SUBJECT,
               assumed_arn=ASSUMED_ARN, assumed_id=ASSUMED_ID,
               expiration=NOW + timedelta(minutes=15), caller_account=ACCOUNT,
               caller_arn=ASSUMED_ARN, caller_id=ASSUMED_ID):
    return (
        {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Provider": provider,
            "Audience": audience,
            "SubjectFromWebIdentityToken": subject,
            "AssumedRoleUser": {"Arn": assumed_arn, "AssumedRoleId": assumed_id},
            "Credentials": {
                "AccessKeyId": "ASIA-SYNTHETIC-CANARY",
                "SecretAccessKey": "secret-canary",
                "SessionToken": "session-canary",
                "Expiration": expiration,
            },
        },
        {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Account": caller_account,
            "Arn": caller_arn,
            "UserId": caller_id,
        },
    )


def _run(assume=None, caller=None, *, token=None, factory=None):
    assume_reply, caller_reply = _responses() if assume is None else (assume, caller)
    unsigned = FakeSts(assume=assume_reply)
    explicit_calls = []

    def explicit_factory(**kwargs):
        explicit_calls.append(kwargs)
        if factory:
            return factory(**kwargs)
        return FakeSts(caller=caller_reply)

    result = prove_github_sts_identity(
        token or _token(),
        target="dev",
        source_sha=SHA,
        expected_account_id=ACCOUNT,
        expected_owner_id=OWNER_ID,
        expected_repository_id=REPO_ID,
        role_arn=ROLE_ARN,
        anonymous_sts=unsigned,
        explicit_sts_factory=explicit_factory,
        clock=lambda: NOW,
    )
    return result, unsigned, explicit_calls


def test_success_uses_one_exchange_then_only_explicit_returned_credentials() -> None:
    result, unsigned, explicit_calls = _run()
    assert result.safe_dict() == {
        "status": "aws_identity_verified",
        "target": "dev",
        "source_sha": SHA,
        "account_verified": True,
        "role_verified": True,
    }
    assert len(unsigned.calls) == 1
    name, params = unsigned.calls[0]
    assert name == "assume_role_with_web_identity"
    assert params == {
        "RoleArn": ROLE_ARN,
        "RoleSessionName": SESSION_NAME,
        "WebIdentityToken": _token(),
        "DurationSeconds": 900,
    }
    assert explicit_calls == [{
        "aws_access_key_id": "ASIA-SYNTHETIC-CANARY",
        "aws_secret_access_key": "secret-canary",
        "aws_session_token": "session-canary",
        "region_name": "eu-west-1",
    }]
    rendered = repr(result) + json.dumps(result.safe_dict())
    for secret in ("ASIA-SYNTHETIC-CANARY", "secret-canary", "session-canary", _token()):
        assert secret not in rendered


@pytest.mark.parametrize("role_arn", [
    f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-cd",
    f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-cd/extra",
    "arn:aws:iam::123456789013:role/honda-mapit-mcp-dev-cd",
])
def test_wrong_role_binding_fails_before_any_exchange(role_arn):
    sts = FakeSts()
    with pytest.raises(StsProofError, match="invalid_input"):
        prove_github_sts_identity(
            _token(), target="dev", source_sha=SHA, expected_account_id=ACCOUNT, expected_owner_id=OWNER_ID,
            expected_repository_id=REPO_ID, role_arn=role_arn,
            anonymous_sts=sts, explicit_sts_factory=lambda **_kwargs: None, clock=lambda: NOW,
        )
    assert not sts.calls


@pytest.mark.parametrize(("field", "value"), [
    ("provider", "https://attacker.example"),
    ("provider", f"arn:aws:iam::123456789013:oidc-provider/token.actions.githubusercontent.com"),
    ("provider", f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com/"),
    ("provider", f"arn:aws:iam::{ACCOUNT}:oidc-provider/attacker.example"),
    ("provider", {"iss": ISSUER}),
    ("provider", [ISSUER]),
    ("provider", None),
    ("audience", "other-audience"),
    ("subject", "repo:other/repository:environment:dev"),
    ("assumed_arn", f"arn:aws:sts::{ACCOUNT}:assumed-role/other/{SESSION_NAME}"),
    ("assumed_id", f"AROAOTHER:{SESSION_NAME}"),
    ("caller_account", "123456789013"),
    ("caller_arn", f"arn:aws:sts::{ACCOUNT}:assumed-role/other/{SESSION_NAME}"),
    ("caller_id", f"AROAOTHER:{SESSION_NAME}"),
])
def test_mismatched_sts_bindings_fail_closed(field, value):
    args = {field: value}
    assume, caller = _responses(**args)
    with pytest.raises(StsProofError):
        _run(assume, caller)


@pytest.mark.parametrize("provider", [
    ISSUER,
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com",
])
def test_owned_oidc_provider_url_or_exact_account_arn_is_accepted(provider):
    assume, caller = _responses(provider=provider)
    result, _unsigned, _calls = _run(assume, caller)
    assert result.status == "aws_identity_verified"


def test_missing_sts_provider_is_rejected():
    assume, caller = _responses()
    del assume["Provider"]
    with pytest.raises(StsProofError, match="identity_mismatch"):
        _run(assume, caller)


@pytest.mark.parametrize("expiration", [
    NOW,
    NOW - timedelta(seconds=1),
    NOW + timedelta(minutes=17),
    "not-a-datetime",
    datetime(2026, 10, 5, 12, 15),
])
def test_invalid_or_unbounded_credentials_are_not_used(expiration):
    assume, caller = _responses(expiration=expiration)
    called = []
    with pytest.raises(StsProofError, match="credentials_invalid"):
        _run(assume, caller, factory=lambda **kwargs: called.append(kwargs))
    assert called == []


def test_malformed_claims_fail_before_sts_and_exceptions_are_sanitized():
    unsigned = FakeSts(failure=True)
    with pytest.raises(StsProofError, match="claims_mismatch") as error:
        prove_github_sts_identity(
            _token(target="prod"), target="dev", source_sha=SHA,
            expected_account_id=ACCOUNT,
            expected_owner_id=OWNER_ID, expected_repository_id=REPO_ID,
            role_arn=ROLE_ARN, anonymous_sts=unsigned,
            explicit_sts_factory=lambda **_kwargs: None, clock=lambda: NOW,
        )
    assert not unsigned.calls
    assert "credential-canary" not in repr(error.value)
    with pytest.raises(StsProofError, match="sts_exchange_failed") as error:
        prove_github_sts_identity(
            _token(), target="dev", source_sha=SHA,
            expected_account_id=ACCOUNT,
            expected_owner_id=OWNER_ID, expected_repository_id=REPO_ID,
            role_arn=ROLE_ARN, anonymous_sts=unsigned,
            explicit_sts_factory=lambda **_kwargs: None, clock=lambda: NOW,
        )
    assert "credential-canary" not in repr(error.value)


def test_proof_errors_report_fixed_stage_and_ignore_mutated_metadata():
    error = StsProofError("claims_mismatch", stage="claims_validation")
    assert error.stage == "claims_validation"
    error.category = {"secret": "canary"}
    error.stage = ["canary"]
    with pytest.raises(StsProofError) as raised:
        # Re-entering the public constructor is the same sanitization boundary
        # used by the runner when translating proof errors.
        raise StsProofError(error.category, stage=error.stage)
    assert raised.value.category == "sts_response_invalid"
    assert raised.value.stage == "proof_internal"
    assert "canary" not in repr(raised.value)


def test_botocore_stubber_checks_the_two_exact_sdk_request_shapes():
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config
    from botocore.stub import Stubber

    cfg = Config(connect_timeout=1, read_timeout=1, retries={"total_max_attempts": 1, "mode": "standard"})
    anonymous = boto3.client(
        "sts", region_name="eu-west-1", aws_access_key_id="synthetic", aws_secret_access_key="synthetic", config=cfg
    )
    expiration = NOW + timedelta(minutes=15)
    assume_response, caller_response = _responses(expiration=expiration)
    assume_stub = Stubber(anonymous)
    assume_stub.add_response("assume_role_with_web_identity", assume_response, {
        "RoleArn": ROLE_ARN,
        "RoleSessionName": SESSION_NAME,
        "WebIdentityToken": _token(),
        "DurationSeconds": 900,
    })
    assume_stub.activate()
    authenticated_clients = []

    def explicit_factory(**credentials):
        client = boto3.client("sts", config=cfg, **credentials)
        stub = Stubber(client)
        stub.add_response("get_caller_identity", caller_response, {})
        stub.activate()
        authenticated_clients.append((client, stub))
        return client

    try:
        result = prove_github_sts_identity(
            _token(), target="dev", source_sha=SHA, expected_owner_id=OWNER_ID,
            expected_account_id=ACCOUNT,
            expected_repository_id=REPO_ID, role_arn=ROLE_ARN,
            anonymous_sts=anonymous, explicit_sts_factory=explicit_factory,
            clock=lambda: NOW,
        )
        assert result.status == "aws_identity_verified"
        assume_stub.assert_no_pending_responses()
        authenticated_clients[0][1].assert_no_pending_responses()
    finally:
        assume_stub.deactivate()
        for _, stub in authenticated_clients:
            stub.deactivate()
