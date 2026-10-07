from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from scripts.github_cd_protections import (
    REPOSITORY,
)
import scripts.run_aws_dev_identity_binding_bootstrap as runner_module
from scripts.run_aws_dev_identity_binding_bootstrap import (
    IdentityBindingBootstrapRunnerError, load_binding, run_authorized_step,
    validate_github_protections,
)


ACCOUNT = "123456789012"
OWNER_ID = 12345
REPOSITORY_ID = 67890
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"


def _binding():
    return {
        "account_id": ACCOUNT,
        "operator_user_arn": CALLER,
        "tenant_keys": ["tenant-" + "1" * 64, "tenant-" + "2" * 64],
        "ssm_key_arn": "arn:aws:kms:eu-west-1:123456789012:key/11111111-1111-1111-1111-111111111111",
        "accepted_runtime_journal_path": "C:/private/accepted/runtime.json",
        "app_stack_arn": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/12345678-1234-1234-1234-123456789abc",
        "app_run_id": 1234,
        "api_id": "abc123def4",
        "user_pool_id": "eu-west-1_Abc123",
        "client_id": "Abc123456789",
        "template_sha256": "a" * 64,
        "code_sha256": "b" * 64,
        "handler_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        "handler_trust_sha256": "c" * 64,
        "handler_policies_sha256": "d" * 64,
        "github_owner_id": OWNER_ID,
        "github_repository_id": REPOSITORY_ID,
    }


def _auth():
    return {
        "account": ACCOUNT, "source_sha": "e" * 40, "run_id": 111,
        "expected_caller_arn": CALLER, "start": 1_700_000_000,
        "end": 1_700_003_600, "ci_run_id": 222,
    }


def _write(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_binding_loader_requires_exact_private_shape_and_normalizes_two_keys(tmp_path):
    path = _write(tmp_path / "binding.json", _binding())
    value = load_binding(path, acl_checker=lambda _: True)
    assert type(value["tenant_keys"]) is tuple and len(value["tenant_keys"]) == 2
    malformed = _binding() | {"password": "canary"}
    with pytest.raises(IdentityBindingBootstrapRunnerError, match="binding_invalid"):
        load_binding(_write(tmp_path / "extra.json", malformed), acl_checker=lambda _: True)
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"account_id":"123456789012","account_id":"999999999999"}', encoding="utf-8")
    with pytest.raises(IdentityBindingBootstrapRunnerError, match="binding_invalid"):
        load_binding(duplicate, acl_checker=lambda _: True)


def test_github_source_protection_readback_uses_four_fixed_gh_reads(monkeypatch):
    payloads = [
        {"full_name": REPOSITORY, "id": REPOSITORY_ID,
         "owner": {"login": "herrerogusano", "id": OWNER_ID}},
        {"fixed": "branch"}, {"fixed": "environment", "can_admins_bypass": False}, [{"fixed": "policy"}],
    ]
    monkeypatch.setattr(runner_module, "validate_branch_protection_readback",
                        lambda name, value: name == "develop" and value == payloads[1])
    monkeypatch.setattr(runner_module, "validate_environment_readback",
                        lambda target, owner, value, rules: target == "dev" and owner == OWNER_ID
                        and value == payloads[2] and rules == payloads[3])
    monkeypatch.setattr(runner_module, "validate_admin_bypass_disabled", lambda value: value is False)
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(payloads[len(calls) - 1]).encode(), stderr=b"")

    validate_github_protections(_binding(), command_runner=runner)
    assert len(calls) == 4
    assert calls == [
        ["gh", "api", f"repos/{REPOSITORY}"],
        ["gh", "api", f"repos/{REPOSITORY}/branches/develop/protection"],
        ["gh", "api", f"repos/{REPOSITORY}/environments/dev"],
        ["gh", "api", f"repos/{REPOSITORY}/environments/dev/deployment-branch-policies?per_page=100"],
    ]


def test_wrong_github_repository_identity_fails_closed():
    payloads = [
        {"full_name": REPOSITORY, "id": REPOSITORY_ID + 1,
         "owner": {"login": "herrerogusano", "id": OWNER_ID}},
        {}, {}, [],
    ]
    calls = []

    def runner(command, **kwargs):
        calls.append(command)
        return SimpleNamespace(returncode=0, stdout=json.dumps(payloads[len(calls) - 1]).encode(), stderr=b"")

    with pytest.raises(IdentityBindingBootstrapRunnerError, match="github_protection_failed"):
        validate_github_protections(_binding(), command_runner=runner)


def test_ci_or_protection_failure_stops_before_aws_client_construction(tmp_path):
    auth_path = _write(tmp_path / "authorization.json", _auth())
    binding_path = _write(tmp_path / "binding.json", _binding())
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    calls = []

    def fail_ci(_):
        calls.append("ci")
        raise RuntimeError("secret-canary")

    result = run_authorized_step(
        auth_path, binding_path, state_dir, "preflight",
        acl_checker=lambda _: True,
        source_ci_validator=fail_ci,
        protection_validator=lambda _: calls.append("protection"),
        client_factory=lambda: calls.append("aws") or {},
        journal_factory=lambda _: pytest.fail("journal must not open before source gate"),
    )
    assert result == {"step": "preflight", "ok": False, "category": "source_ci_failed", "calls": 0}
    assert calls == ["ci"]

    calls.clear()
    result = run_authorized_step(
        auth_path, binding_path, state_dir, "preflight",
        acl_checker=lambda _: True,
        source_ci_validator=lambda _: calls.append("ci"),
        protection_validator=lambda _: (_ for _ in ()).throw(RuntimeError("token-canary")),
        client_factory=lambda: calls.append("aws") or {},
        journal_factory=lambda _: pytest.fail("journal must not open before protections"),
    )
    assert result == {"step": "preflight", "ok": False, "category": "github_protection_failed", "calls": 0}
    assert calls == ["ci"]


def test_real_aws_client_factory_is_nine_fixed_tls_single_attempt_clients(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.exceptions import ClientError
    from botocore.stub import Stubber

    for name in runner_module._PROXY_ENV:
        monkeypatch.delenv(name, raising=False)
    real_session = boto3.Session
    monkeypatch.setattr(boto3, "Session", lambda **kwargs: real_session(
        aws_access_key_id="synthetic-access", aws_secret_access_key="synthetic-secret",
        aws_session_token="synthetic-session", **kwargs))
    clients = runner_module._build_clients()
    expected = {
        "kms": ("kms", "eu-west-1", "https://kms.eu-west-1.amazonaws.com", "describe_key", {"KeyId": "alias/aws/ssm"}),
        "sts": ("sts", "eu-west-1", "https://sts.eu-west-1.amazonaws.com", "get_caller_identity", {}),
        "cloudformation": ("cloudformation", "eu-west-1", "https://cloudformation.eu-west-1.amazonaws.com", "describe_stacks", {"StackName": "honda-mapit-mcp-dev-identity-bindings-bootstrap"}),
        "iam": ("iam", "us-east-1", "https://iam.amazonaws.com", "get_role", {"RoleName": "honda-mapit-mcp-dev-identity-enroller"}),
        "dynamodb": ("dynamodb", "eu-west-1", "https://dynamodb.eu-west-1.amazonaws.com", "describe_table", {"TableName": "honda-mapit-mcp-dev-identity-bindings"}),
        "ssm": ("ssm", "eu-west-1", "https://ssm.eu-west-1.amazonaws.com", "get_parameter", {"Name": "/honda-mapit-mcp/dev/identity-binding-config", "WithDecryption": False}),
        "cognito": ("cognito-idp", "eu-west-1", "https://cognito-idp.eu-west-1.amazonaws.com", "describe_user_pool", {"UserPoolId": "eu-west-1_Abc123"}),
        "apigatewayv2": ("apigatewayv2", "eu-west-1", "https://apigateway.eu-west-1.amazonaws.com", "get_api", {"ApiId": "abc123def4"}),
        "lambda": ("lambda", "eu-west-1", "https://lambda.eu-west-1.amazonaws.com", "get_function_configuration", {"FunctionName": "honda-mapit-mcp-dev-retained-handler"}),
    }
    assert set(clients) == set(expected)
    for key, (service, region, endpoint, operation, params) in expected.items():
        client = clients[key]
        assert client.meta.service_model.service_name == service
        assert client.meta.region_name == region
        assert client.meta.endpoint_url == endpoint
        assert client.meta.config.retries["total_max_attempts"] == 1
        assert client.meta.config.connect_timeout <= 3 and client.meta.config.read_timeout <= 3
        assert client._endpoint.http_session._verify is True
        stubber = Stubber(client)
        stubber.add_client_error(operation, service_error_code="AccessDenied", http_status_code=403,
                                 expected_params=params)
        with stubber:
            with pytest.raises(ClientError):
                getattr(client, operation)(**params)
            stubber.assert_no_pending_responses()
