from __future__ import annotations

from types import SimpleNamespace

import pytest

from mapit import aws_dev_shutdown_entrypoint as entrypoint


API_ID = "a1b2c3d4e5"
FUNCTION = "honda-mapit-mcp-dev-shutdown"
_PRIVATE_CANARY = "shutdown-entrypoint-private-canary"


@pytest.fixture
def valid_environment(monkeypatch):
    monkeypatch.setenv(entrypoint.ENV_MAPIT_MCP_ENV, "dev")
    monkeypatch.setenv(entrypoint.ENV_AWS_REGION, "eu-west-1")
    monkeypatch.setenv(entrypoint.ENV_API_ID, API_ID)
    monkeypatch.setenv(entrypoint.ENV_LAMBDA_FUNCTION_NAME, FUNCTION)


def _fake_sdk(monkeypatch, calls, *, failed_services=(), session_error=False):
    config_args = []
    config_instances = []
    failed = set(failed_services)

    class Config:
        def __init__(self, **kwargs):
            config_args.append(kwargs)
            config_instances.append(self)

    class APIClient:
        def update_api(self, **kwargs):
            calls.append(("update_api", kwargs))

        def get_api(self, **kwargs):
            calls.append(("get_api", kwargs))
            return {"DisableExecuteApiEndpoint": True}

    class LambdaClient:
        def put_function_concurrency(self, **kwargs):
            calls.append(("put_function_concurrency", kwargs))

        def get_function_concurrency(self, **kwargs):
            calls.append(("get_function_concurrency", kwargs))
            return {"ReservedConcurrentExecutions": 0}

    class Session:
        def __init__(self, **kwargs):
            calls.append(("Session", kwargs))
            if session_error:
                raise RuntimeError(_PRIVATE_CANARY)

        def client(self, service, **kwargs):
            calls.append(("client", service, kwargs))
            if service in failed:
                raise RuntimeError(_PRIVATE_CANARY)
            return APIClient() if service == "apigatewayv2" else LambdaClient()

    def fake_import(name):
        if name == "boto3":
            return SimpleNamespace(Session=Session)
        if name == "botocore.config":
            return SimpleNamespace(Config=Config)
        raise AssertionError(f"unexpected SDK module: {name}")

    monkeypatch.setattr(entrypoint.importlib, "import_module", fake_import)
    return config_args, config_instances


def test_malicious_event_and_credential_canaries_cannot_change_target_or_escape(
    valid_environment, monkeypatch, capsys
):
    calls = []
    config_args, config_instances = _fake_sdk(monkeypatch, calls)
    event = {
        "ApiId": "event-api-canary",
        "api_id": "other-api-canary",
        "FunctionName": "event-function-canary",
        "region": "us-east-1",
        "account": "account-canary",
        "authorization": f"Bearer {_PRIVATE_CANARY}",
        "aws_secret_access_key": _PRIVATE_CANARY,
    }
    result = entrypoint.handler(event, SimpleNamespace(secret=_PRIVATE_CANARY))
    captured = capsys.readouterr()

    assert result["verified"] is True
    assert calls == [
        ("Session", {"region_name": "eu-west-1"}),
        ("client", "apigatewayv2", {"region_name": "eu-west-1", "config": config_instances[0]}),
        ("client", "lambda", {"region_name": "eu-west-1", "config": config_instances[0]}),
        ("update_api", {"ApiId": API_ID, "DisableExecuteApiEndpoint": True}),
        ("put_function_concurrency", {"FunctionName": "honda-mapit-mcp-dev-handler", "ReservedConcurrentExecutions": 0}),
        ("get_api", {"ApiId": API_ID}),
        ("get_function_concurrency", {"FunctionName": "honda-mapit-mcp-dev-handler"}),
    ]
    assert config_args == [{
        "retries": {"mode": "standard", "total_max_attempts": 1},
        "connect_timeout": 2,
        "read_timeout": 3,
    }]
    serialized = repr(result) + captured.out + captured.err
    for canary in (_PRIVATE_CANARY, "event-api-canary", "other-api-canary", "account-canary", "us-east-1"):
        assert canary not in serialized


def test_both_client_creation_failures_are_independent_and_project_only_categories(
    valid_environment, monkeypatch, capsys
):
    calls = []
    _config_args, _config_instances = _fake_sdk(
        monkeypatch, calls, failed_services={"apigatewayv2", "lambda"}
    )
    result = entrypoint.handler({}, None)
    captured = capsys.readouterr()

    assert [call[1] for call in calls if call[0] == "client"] == ["apigatewayv2", "lambda"]
    assert not any(call[0] in {"update_api", "put_function_concurrency", "get_api", "get_function_concurrency"} for call in calls)
    assert result == {
        "api_write_call_returned": False,
        "function_write_call_returned": False,
        "api_closed": False,
        "function_reserved": False,
        "verified": False,
        "category": "shutdown_unverified",
        "warnings": (
            "api_write_failed",
            "function_write_failed",
            "api_readback_failed",
            "function_readback_failed",
        ),
    }
    assert _PRIVATE_CANARY not in repr(result) + captured.out + captured.err


def test_session_constructor_failure_is_static_and_silent(valid_environment, monkeypatch, capsys):
    calls = []
    _fake_sdk(monkeypatch, calls, session_error=True)
    result = entrypoint.handler({"account": _PRIVATE_CANARY}, None)
    captured = capsys.readouterr()
    assert result == entrypoint._UNAVAILABLE_RESULT
    assert calls == [("Session", {"region_name": "eu-west-1"})]
    assert _PRIVATE_CANARY not in repr(result) + captured.out + captured.err


@pytest.mark.parametrize(
    ("name", "value"),
    [
        (entrypoint.ENV_MAPIT_MCP_ENV, "prod"),
        (entrypoint.ENV_AWS_REGION, "us-east-1"),
        (entrypoint.ENV_LAMBDA_FUNCTION_NAME, "honda-mapit-mcp-dev-handler"),
        (entrypoint.ENV_API_ID, "A1b2c3d4e5"),
    ],
)
def test_rejected_environment_never_attempts_sdk_imports(valid_environment, monkeypatch, name, value):
    attempted = []

    def forbidden_import(module_name):
        attempted.append(module_name)
        raise AssertionError("SDK import should not occur for invalid shutdown environment")

    monkeypatch.setenv(name, value)
    monkeypatch.setattr(entrypoint.importlib, "import_module", forbidden_import)
    assert entrypoint.handler({"ApiId": "event-target"}, None) == entrypoint._UNAVAILABLE_RESULT
    assert attempted == []
