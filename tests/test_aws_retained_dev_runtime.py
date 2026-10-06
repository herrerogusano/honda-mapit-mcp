from __future__ import annotations

import copy

import pytest

from mapit.aws_dev_runtime import cognito_dev_policy

from scripts.build_aws_retained_dev_runtime import (
    REGION,
    RUNTIME_HANDLER,
    RetainedDevRuntimeTemplateError,
    SYNTHETIC_CLIENT_ID,
    SYNTHETIC_EXECUTION_END,
    SYNTHETIC_EXECUTION_START,
    SYNTHETIC_OWNER_SUBJECT,
    SYNTHETIC_USER_POOL_ID,
    build_retained_dev_runtime_template,
    retained_dev_artifact_bucket,
)


ACCOUNT = "123456789012"
API_ID = "abc1234567"
ZIP_SHA = "a" * 64
JWKS_SHA = "b" * 64


def _template(**kwargs):
    values = {
        "account_id": ACCOUNT,
        "api_id": API_ID,
        "zip_sha256": ZIP_SHA,
        "jwks_sha256": JWKS_SHA,
    }
    values.update(kwargs)
    return build_retained_dev_runtime_template(**values)


def test_runtime_candidate_keeps_exact_five_resource_closed_shape():
    template = _template()
    assert set(template["Resources"]) == {
        "McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
    }
    assert "McpUserPool" not in str(template)
    assert template["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    handler = template["Resources"]["McpHandler"]["Properties"]
    assert handler["Handler"] == RUNTIME_HANDLER
    assert handler["ReservedConcurrentExecutions"] == 0
    assert handler["Architectures"] == ["arm64"]
    assert handler["Code"] == {
        "S3Bucket": retained_dev_artifact_bucket(ACCOUNT),
        "S3Key": f"runtime/{ZIP_SHA}.zip",
    }


def test_runtime_environment_is_synthetic_and_non_secret():
    variables = _template()["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]
    assert variables == {
        "MAPIT_MCP_ENV": "dev",
        "MAPIT_COGNITO_USER_POOL_ID": SYNTHETIC_USER_POOL_ID,
        "MAPIT_API_ID": API_ID,
        "MAPIT_COGNITO_CLIENT_ID": SYNTHETIC_CLIENT_ID,
        "MAPIT_OWNER_SUBJECT": SYNTHETIC_OWNER_SUBJECT,
        "MAPIT_COGNITO_JWKS_SHA256": JWKS_SHA,
        "MAPIT_DEV_EXECUTION_START_EPOCH": str(SYNTHETIC_EXECUTION_START),
        "MAPIT_DEV_EXECUTION_END_EPOCH": str(SYNTHETIC_EXECUTION_END),
    }
    assert all("password" not in key.casefold() and "secret" not in key.casefold() for key in variables)


def test_runtime_role_remains_logs_only():
    role = _template()["Resources"]["McpHandlerRole"]["Properties"]
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements == [{
        "Effect": "Allow",
        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/honda-mapit-mcp-dev-retained-handler:*"},
    }]


def test_generated_environment_is_accepted_by_real_dev_runtime_policy():
    variables = _template()["Resources"]["McpHandler"]["Properties"]["Environment"]["Variables"]
    policy = cognito_dev_policy(
        user_pool_id=variables["MAPIT_COGNITO_USER_POOL_ID"],
        api_id=variables["MAPIT_API_ID"],
        client_id=variables["MAPIT_COGNITO_CLIENT_ID"],
        owner_subject=variables["MAPIT_OWNER_SUBJECT"],
    )
    assert policy.environment == "dev"
    assert policy.api_host == f"{API_ID}.execute-api.eu-west-1.amazonaws.com"
    assert "AWS_REGION" not in variables


def test_invalid_fixture_client_cannot_produce_a_template(monkeypatch):
    from scripts import build_aws_retained_dev_runtime as runtime
    monkeypatch.setattr(runtime, "SYNTHETIC_CLIENT_ID", "synthetic-invalid-client")
    with pytest.raises(RetainedDevRuntimeTemplateError, match="^synthetic_fixture_invalid$"):
        _template()


def test_bucket_is_account_and_region_derived():
    assert retained_dev_artifact_bucket(ACCOUNT) == (
        "honda-mapit-mcp-dev-retained-123456789012-eu-west-1"
    )
    with pytest.raises(RetainedDevRuntimeTemplateError) as exc:
        retained_dev_artifact_bucket("not-an-account")
    assert str(exc.value) == "account_invalid"


@pytest.mark.parametrize(
    ("field", "value", "category"),
    [
        ("api_id", "wrong", "api_id_invalid"),
        ("zip_sha256", "not-a-sha", "runtime_hash_invalid"),
        ("jwks_sha256", "not-a-sha", "jwks_hash_invalid"),
        ("execution_start_epoch", 100, "execution_window_invalid"),
    ],
)
def test_runtime_inputs_fail_closed(field, value, category):
    values = {
        "account_id": ACCOUNT,
        "api_id": API_ID,
        "zip_sha256": ZIP_SHA,
        "jwks_sha256": JWKS_SHA,
        "execution_start_epoch": SYNTHETIC_EXECUTION_START,
        "execution_end_epoch": SYNTHETIC_EXECUTION_END,
    }
    values[field] = value
    with pytest.raises(RetainedDevRuntimeTemplateError) as exc:
        build_retained_dev_runtime_template(**values)
    assert str(exc.value) == category


def test_factory_does_not_mutate_a_previous_candidate():
    first = _template()
    snapshot = copy.deepcopy(first)
    second = _template(zip_sha256="c" * 64, jwks_sha256="d" * 64)
    assert first == snapshot
    assert first["Resources"]["McpHandler"]["Properties"]["Code"] != second["Resources"]["McpHandler"]["Properties"]["Code"]
