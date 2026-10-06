from __future__ import annotations

from datetime import datetime, timedelta, timezone
import base64
import json

import pytest

from scripts import run_aws_retained_dev_oidc_proof as runner


ACCOUNT = "123456789012"
OWNER = "1234567"
REPOSITORY_ID = "7654321"
SOURCE_SHA = "a" * 40
ROLE = f"arn:aws:iam::{ACCOUNT}:role/{runner.ROLE_NAME}"
SUBJECT = f"repo:herrerogusano@{OWNER}/honda-mapit-mcp@{REPOSITORY_ID}:environment:dev"
NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
SESSION = f"mapit-retained-dev-{SOURCE_SHA[:12]}"
ASSUMED = f"arn:aws:sts::{ACCOUNT}:assumed-role/{runner.ROLE_NAME}/{SESSION}"
ASSUMED_ID = f"AROAEXAMPLE:{SESSION}"


def _segment(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def _token():
    claims = {
        "iss": runner.ISSUER, "aud": runner.AUDIENCE, "repository": runner.REPOSITORY,
        "repository_owner": "herrerogusano", "repository_id": REPOSITORY_ID,
        "repository_owner_id": OWNER, "ref": runner.EXPECTED_REF, "sha": SOURCE_SHA,
        "environment": "dev", "sub": SUBJECT,
    }
    return f"{_segment({'alg': 'RS256', 'kid': 'synthetic'})}.{_segment(claims)}.signature"


def _env(**overrides):
    value = {
        "TARGET": "dev", "GITHUB_REF": runner.EXPECTED_REF, "GITHUB_SHA": SOURCE_SHA,
        "GITHUB_REPOSITORY": runner.REPOSITORY, "GITHUB_REPOSITORY_ID": REPOSITORY_ID,
        "GITHUB_REPOSITORY_OWNER_ID": OWNER, runner.ROLE_ENV_NAME: ROLE,
        runner.EXPECTED_ACCOUNT_ENV_NAME: ACCOUNT,
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/runner/request",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token-synthetic",
    }
    value.update(overrides)
    return value


class FakeSts:
    def __init__(self, *, assume=None, caller=None):
        self.assume = assume
        self.caller = caller
        self.calls = []
        self.closed = False

    def assume_role_with_web_identity(self, **kwargs):
        self.calls.append(("assume", kwargs))
        return self.assume

    def get_caller_identity(self):
        self.calls.append(("caller", {}))
        return self.caller

    def close(self):
        self.closed = True


def _reply_pair(*, provider=None, caller_arn=ASSUMED):
    assume = {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Provider": provider or runner.ISSUER, "Audience": runner.AUDIENCE,
        "SubjectFromWebIdentityToken": SUBJECT,
        "AssumedRoleUser": {"Arn": ASSUMED, "AssumedRoleId": ASSUMED_ID},
        "Credentials": {
            "AccessKeyId": "ASIA-SYNTHETIC", "SecretAccessKey": "secret-synthetic",
            "SessionToken": "session-synthetic", "Expiration": NOW + timedelta(minutes=15),
        },
    }
    caller = {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT, "Arn": caller_arn, "UserId": ASSUMED_ID}
    return assume, caller


def test_success_uses_exact_dev_context_single_attempt_and_closes_clients(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: _token())
    assume, caller = _reply_pair()
    unsigned, signed = FakeSts(assume=assume), FakeSts(caller=caller)
    calls = []

    def factory(**kwargs):
        calls.append(kwargs)
        return unsigned if kwargs["unsigned"] else signed

    result = runner.run_retained_dev_oidc_proof(_env(), home=tmp_path / "clean", client_factory=factory, clock=lambda: NOW)
    assert result == {"status": "aws_identity_verified", "target": "dev", "source_sha": SOURCE_SHA, "account_verified": True, "role_verified": True}
    assert calls == [{"unsigned": True, "region_name": runner.REGION}, {"unsigned": False, "credentials": {"aws_access_key_id": "ASIA-SYNTHETIC", "aws_secret_access_key": "secret-synthetic", "aws_session_token": "session-synthetic"}, "region_name": runner.REGION}]
    assert unsigned.closed and signed.closed
    assert unsigned.calls[0][1]["RoleArn"] == ROLE
    assert unsigned.calls[0][1]["DurationSeconds"] == 900
    rendered = json.dumps(result)
    assert all(secret not in rendered for secret in (ACCOUNT, ROLE, "secret-synthetic", "session-synthetic", _token()))


@pytest.mark.parametrize("overrides", [
    {"GITHUB_REF": "refs/heads/main"},
    {"GITHUB_SHA": "b" * 40, "SOURCE_SHA": SOURCE_SHA},
    {runner.EXPECTED_ACCOUNT_ENV_NAME: "000000000000"},
    {runner.ROLE_ENV_NAME: f"arn:aws:iam::{ACCOUNT}:role/other"},
])
def test_context_rejects_wrong_dev_binding_before_token(monkeypatch, tmp_path, overrides):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: pytest.fail("token requested"))
    with pytest.raises(runner.RetainedDevOidcProofError) as raised:
        runner.run_retained_dev_oidc_proof(_env(**overrides), home=tmp_path / "clean")
    assert raised.value.category in {"runner_context_invalid", "role_binding_invalid"}


def test_ambient_aws_source_is_rejected_before_token(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: pytest.fail("token requested"))
    with pytest.raises(runner.RetainedDevOidcProofError) as raised:
        runner.run_retained_dev_oidc_proof(_env(AWS_PROFILE="default"), home=tmp_path / "clean")
    assert raised.value.safe_dict()["category"] == "ambient_aws_source"


@pytest.mark.parametrize("field", ["Audience", "SubjectFromWebIdentityToken", "AssumedRoleUser"])
def test_assume_response_mismatch_is_redacted_and_clients_close(monkeypatch, tmp_path, field):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: _token())
    assume, caller = _reply_pair()
    if field == "Audience": assume[field] = "wrong"
    elif field == "SubjectFromWebIdentityToken": assume[field] = "secret-subject"
    else: assume[field] = {"Arn": "wrong", "AssumedRoleId": "wrong"}
    unsigned, signed = FakeSts(assume=assume), FakeSts(caller=caller)
    with pytest.raises(runner.RetainedDevOidcProofError) as raised:
        runner.run_retained_dev_oidc_proof(_env(), home=tmp_path / "clean", client_factory=lambda **kw: unsigned if kw["unsigned"] else signed, clock=lambda: NOW)
    assert raised.value.safe_dict()["category"] == "identity_mismatch"
    assert "secret-subject" not in repr(raised.value)
    assert unsigned.closed and signed.closed is False


def test_caller_identity_mismatch_is_fixed_category(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: _token())
    assume, caller = _reply_pair(caller_arn="wrong")
    unsigned, signed = FakeSts(assume=assume), FakeSts(caller=caller)
    with pytest.raises(runner.RetainedDevOidcProofError) as raised:
        runner.run_retained_dev_oidc_proof(_env(), home=tmp_path / "clean", client_factory=lambda **kw: unsigned if kw["unsigned"] else signed, clock=lambda: NOW)
    assert raised.value.safe_dict() == {"status": "failed", "target": "dev", "category": "identity_mismatch", "stage": "caller_identity_response_validation"}
    assert unsigned.closed and signed.closed


def test_clean_main_failure_has_no_traceback_or_secret(monkeypatch, capsys):
    monkeypatch.setattr(runner, "run_retained_dev_oidc_proof", lambda *_a, **_k: (_ for _ in ()).throw(runner.RetainedDevOidcProofError("claims_mismatch", stage="claims_validation")))
    assert runner.main() == 1
    output = capsys.readouterr()
    assert json.loads(output.out) == {"category": "claims_mismatch", "stage": "claims_validation", "status": "failed", "target": "dev"}
    assert output.err == ""
