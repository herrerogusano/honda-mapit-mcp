from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from scripts import run_github_sts_identity as runner


ACCOUNT = "123456789012"
OWNER_ID = "1234567"
REPO_ID = "7654321"
SHA = "a" * 40
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-cd"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPO_ID}:environment:dev"
NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
SESSION_NAME = f"mapit-cd-dev-{SHA[:12]}"
ASSUMED_ARN = f"arn:aws:sts::{ACCOUNT}:assumed-role/honda-mapit-mcp-dev-cd/{SESSION_NAME}"
ASSUMED_ID = f"AROAEXAMPLE:{SESSION_NAME}"


def _token():
    def segment(value):
        encoded = base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode()
        return encoded.rstrip("=")

    claims = {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "sts.amazonaws.com",
        "repository": "herrerogusano/honda-mapit-mcp",
        "repository_owner": "herrerogusano",
        "repository_id": REPO_ID,
        "repository_owner_id": OWNER_ID,
        "ref": "refs/heads/develop",
        "sha": SHA,
        "environment": "dev",
        "sub": SUBJECT,
    }
    return f"{segment({'alg':'RS256','kid':'synthetic'})}.{segment(claims)}.synthetic-signature"


def _env(**overrides):
    result = {
        "TARGET": "dev",
        "GITHUB_REF": "refs/heads/develop",
        "GITHUB_SHA": SHA,
        "GITHUB_REPOSITORY": "herrerogusano/honda-mapit-mcp",
        "GITHUB_REPOSITORY_ID": REPO_ID,
        "GITHUB_REPOSITORY_OWNER_ID": OWNER_ID,
        "ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.actions.githubusercontent.com/runner/request?x=1",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "synthetic-runner-request-token",
        "AWS_CD_IDENTITY_ROLE_ARN": ROLE_ARN,
    }
    result.update(overrides)
    return result


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


def _sdk_replies():
    return (
        {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Provider": "https://token.actions.githubusercontent.com",
            "Audience": "sts.amazonaws.com",
            "SubjectFromWebIdentityToken": SUBJECT,
            "AssumedRoleUser": {"Arn": ASSUMED_ARN, "AssumedRoleId": ASSUMED_ID},
            "Credentials": {
                "AccessKeyId": "ASIA-SYNTHETIC",
                "SecretAccessKey": "secret-synthetic",
                "SessionToken": "session-synthetic",
                "Expiration": NOW + timedelta(minutes=15),
            },
        },
        {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Account": ACCOUNT,
            "Arn": ASSUMED_ARN,
            "UserId": ASSUMED_ID,
        },
    )


def test_runner_rejects_ambient_sources_before_oidc_token_request(monkeypatch, tmp_path):
    token_requests = []
    client_requests = []
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *a, **k: token_requests.append(1))
    monkeypatch.setattr(runner, "_new_sts_client", lambda **kwargs: client_requests.append(kwargs))
    with pytest.raises(runner.RunnerProofError, match="ambient_aws_source"):
        runner.run_identity_proof(_env(AWS_PROFILE="default"), home=tmp_path)
    assert token_requests == [] and client_requests == []


@pytest.mark.parametrize("invalid_environment", [
    {"AWS_ENDPOINT_URL_STS": "https://unexpected.example"},
    {"BOTOCORE_LOG_LEVEL": "DEBUG"},
    {"AWS_SHARED_CREDENTIALS_FILE": "synthetic-path"},
])
def test_endpoint_logging_and_profile_overrides_fail_before_token(monkeypatch, tmp_path, invalid_environment):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: pytest.fail("token requested"))
    with pytest.raises(runner.RunnerProofError, match="ambient_aws_source"):
        runner.run_identity_proof(_env(**invalid_environment), home=tmp_path / "clean")


def test_invalid_private_role_binding_fails_before_token(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: pytest.fail("token requested"))
    with pytest.raises(runner.RunnerProofError, match="role_binding_invalid"):
        runner.run_identity_proof(
            _env(AWS_CD_IDENTITY_ROLE_ARN=f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-cd"),
            home=tmp_path / "clean",
        )


def test_runner_rejects_profile_files_and_wrong_branch_before_token(monkeypatch, tmp_path):
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "config").write_text("synthetic", encoding="utf-8")
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: pytest.fail("token requested"))
    with pytest.raises(runner.RunnerProofError, match="ambient_aws_source"):
        runner.run_identity_proof(_env(), home=tmp_path)
    with pytest.raises(runner.RunnerProofError, match="runner_context_invalid"):
        runner.run_identity_proof(_env(GITHUB_REF="refs/heads/main"), home=tmp_path / "clean")


def test_runner_uses_one_token_then_two_sdk_clients_and_returns_redacted_projection(monkeypatch, tmp_path):
    token_calls = []
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *a, **k: token_calls.append(1) or _token())
    assume, caller = _sdk_replies()
    unsigned = FakeSts(assume=assume)
    authenticated = FakeSts(caller=caller)
    factory_calls = []

    def factory(**kwargs):
        factory_calls.append(kwargs)
        return unsigned if kwargs["unsigned"] else authenticated

    result = runner.run_identity_proof(
        _env(), home=tmp_path / "clean", client_factory=factory, clock=lambda: NOW
    )
    assert result == {
        "status": "aws_identity_verified", "target": "dev", "source_sha": SHA,
        "account_verified": True, "role_verified": True,
    }
    assert token_calls == [1]
    assert factory_calls == [
        {"unsigned": True},
        {"unsigned": False, "credentials": {
            "aws_access_key_id": "ASIA-SYNTHETIC",
            "aws_secret_access_key": "secret-synthetic",
            "aws_session_token": "session-synthetic",
        }},
    ]
    assert unsigned.closed and authenticated.closed
    rendered = json.dumps(result)
    for secret in ("secret-synthetic", "session-synthetic", "ASIA-SYNTHETIC", _token(), ROLE_ARN, ACCOUNT):
        assert secret not in rendered


def test_sdk_client_config_is_regional_single_attempt_no_proxy_and_explicit(monkeypatch):
    pytest.importorskip("botocore")
    from botocore.credentials import CredentialResolver
    from botocore import UNSIGNED

    def no_chain(_self):
        raise AssertionError("credential provider chain must not be consulted")

    monkeypatch.setattr(CredentialResolver, "load_credentials", no_chain)
    unsigned = runner._new_sts_client(unsigned=True)
    signed = runner._new_sts_client(unsigned=False, credentials={
        "aws_access_key_id": "ASIA-SYNTHETIC",
        "aws_secret_access_key": "secret-synthetic",
        "aws_session_token": "session-synthetic",
    })
    try:
        for client in (unsigned, signed):
            assert client.meta.region_name == "eu-west-1"
            assert client.meta.endpoint_url == "https://sts.eu-west-1.amazonaws.com"
            assert client.meta.config.connect_timeout == 2
            assert client.meta.config.read_timeout == 4
            assert client.meta.config.retries["total_max_attempts"] == 1
            assert client.meta.config.proxies == {}
            assert client._endpoint.http_session._verify is True
        assert unsigned.meta.config.signature_version == UNSIGNED
        assert signed.meta.config.signature_version == "v4"
    finally:
        unsigned.close()
        signed.close()


def test_pinned_botocore_send_disables_redirect_following():
    pytest.importorskip("botocore")
    import inspect
    from botocore.httpsession import URLLib3Session

    source = inspect.getsource(URLLib3Session.send)
    assert "retries=Retry(False)" in source


def test_clean_module_invocation_fails_safely_before_token_or_sdk_import():
    environment = {"PATH": os.environ.get("PATH", "")}
    result = subprocess.run(
        [sys.executable, "-m", "scripts.run_github_sts_identity"],
        cwd=Path.cwd(),
        env=environment,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 1
    assert result.stdout.strip() == '{"status":"failed","category":"runner_context_invalid"}'
    assert result.stderr == ""


def test_error_metadata_is_revalidated_and_stage_is_allowlisted():
    error = runner.RunnerProofError("claims_mismatch", stage="claims_validation")
    assert error.safe_dict() == {
        "status": "failed", "category": "claims_mismatch", "stage": "claims_validation"
    }
    error.category = {"secret": "category-canary"}
    error.stage = ["secret", "stage-canary"]
    assert error.safe_dict() == {
        "status": "failed", "category": "proof_failed", "stage": "proof_internal"
    }
    assert "canary" not in json.dumps(error.safe_dict())


def test_oidc_token_failure_preserves_fixed_acquisition_category(monkeypatch, tmp_path):
    def fail(*_args, **_kwargs):
        raise runner.OidcClaimError("runner_request_failed")

    monkeypatch.setattr(runner, "request_runner_oidc_token", fail)
    with pytest.raises(runner.RunnerProofError) as raised:
        runner.run_identity_proof(_env(), home=tmp_path / "clean")
    assert raised.value.safe_dict() == {
        "status": "failed", "category": "runner_request_failed", "stage": "oidc_token_acquisition"
    }


def test_unexpected_token_request_error_gets_closed_acquisition_stage(monkeypatch, tmp_path):
    def fail(*_args, **_kwargs):
        raise RuntimeError("request-canary-secret")

    monkeypatch.setattr(runner, "request_runner_oidc_token", fail)
    with pytest.raises(runner.RunnerProofError) as raised:
        runner.run_identity_proof(_env(), home=tmp_path / "clean")
    assert raised.value.safe_dict() == {
        "status": "failed", "category": "proof_failed", "stage": "oidc_token_acquisition"
    }
    assert "request-canary-secret" not in repr(raised.value)


def test_proof_failure_identifies_unsigned_client_creation_without_sdk_text(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "request_runner_oidc_token", lambda *_a, **_k: _token())

    def fail(**_kwargs):
        raise RuntimeError("sdk-canary-secret")

    with pytest.raises(runner.RunnerProofError) as raised:
        runner.run_identity_proof(_env(), home=tmp_path / "clean", client_factory=fail)
    assert raised.value.safe_dict() == {
        "status": "failed", "category": "sts_client_creation_failed", "stage": "unsigned_client_creation"
    }
    assert "sdk-canary-secret" not in repr(raised.value)


def test_manual_workflow_is_target_and_source_pinned_without_credential_export():
    workflow = Path(".github/workflows/cd-sts-identity.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch:" in workflow
    assert "dev:refs/heads/develop|prod:refs/heads/main" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "persist-credentials: false" in workflow
    assert '"$(git rev-parse HEAD)" != "${SOURCE_SHA}"' in workflow
    assert "id-token: write" in workflow
    assert "AWS_CD_IDENTITY_ROLE_ARN: ${{ secrets.AWS_CD_IDENTITY_ROLE_ARN }}" in workflow
    assert workflow.count("secrets.") == 1
    for forbidden in (
        "configure-aws-credentials", "aws-actions/", "cloudformation deploy", "upload-artifact",
        "AWS_ACCESS_KEY_ID:", "GITHUB_OUTPUT", "::add-mask::",
    ):
        assert forbidden not in workflow
