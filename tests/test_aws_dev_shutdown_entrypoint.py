from __future__ import annotations

from types import SimpleNamespace

import pytest

from mapit import aws_dev_shutdown_entrypoint as entrypoint

API_ID = "a1b2c3d4e5"


@pytest.fixture(autouse=True)
def valid_shutdown_environment(monkeypatch):
    monkeypatch.setenv(entrypoint.ENV_MAPIT_MCP_ENV, "dev")
    monkeypatch.setenv(entrypoint.ENV_AWS_REGION, "eu-west-1")
    monkeypatch.setenv(entrypoint.ENV_API_ID, API_ID)
    monkeypatch.setenv(entrypoint.ENV_LAMBDA_FUNCTION_NAME, entrypoint.SHUTDOWN_LAMBDA_NAME)


class FakeAPIClient:
    def __init__(self, calls):
        self.calls = calls

    def update_api(self, **kwargs):
        self.calls.append(("update_api", kwargs))

    def get_api(self, **kwargs):
        self.calls.append(("get_api", kwargs))
        return {"DisableExecuteApiEndpoint": True}


class FakeLambdaClient:
    def __init__(self, calls):
        self.calls = calls

    def put_function_concurrency(self, **kwargs):
        self.calls.append(("put_function_concurrency", kwargs))

    def get_function_concurrency(self, **kwargs):
        self.calls.append(("get_function_concurrency", kwargs))
        return {"ReservedConcurrentExecutions": 0}


def _install_fake_sdk(monkeypatch, *, client_fail=(), import_fail=()):
    calls = []
    config_calls = []

    class FakeConfig:
        def __init__(self, **kwargs):
            config_calls.append(kwargs)

    class FakeSession:
        def __init__(self, **kwargs):
            calls.append(("Session", kwargs))

        def client(self, service_name, **kwargs):
            calls.append(("client", service_name, kwargs))
            if service_name in client_fail:
                raise RuntimeError("private-provider-canary")
            return FakeAPIClient(calls) if service_name == "apigatewayv2" else FakeLambdaClient(calls)

    def fake_import(name):
        if name in import_fail:
            raise ImportError("private-import-canary")
        if name == "boto3":
            return SimpleNamespace(Session=FakeSession)
        if name == "botocore.config":
            return SimpleNamespace(Config=FakeConfig)
        raise AssertionError("unexpected SDK import")

    monkeypatch.setattr(entrypoint.importlib, "import_module", fake_import)
    return calls, config_calls


def test_valid_environment_constructs_two_regional_clients_and_runs_exact_core(monkeypatch):
    calls, config_calls = _install_fake_sdk(monkeypatch)
    response = entrypoint.handler({"ApiId": "event-target-must-be-ignored"}, object())

    assert response == {
        "api_write_call_returned": True,
        "function_write_call_returned": True,
        "api_closed": True,
        "function_reserved": True,
        "verified": True,
        "category": "shutdown_verified",
        "warnings": (),
    }
    assert config_calls == [{
        "retries": {"mode": "standard", "total_max_attempts": 1},
        "connect_timeout": 2,
        "read_timeout": 3,
    }]
    assert calls[:3] == [
        ("Session", {"region_name": "eu-west-1"}),
        ("client", "apigatewayv2", {"region_name": "eu-west-1", "config": calls[1][2]["config"]}),
        ("client", "lambda", {"region_name": "eu-west-1", "config": calls[2][2]["config"]}),
    ]
    assert calls[3:] == [
        ("update_api", {"ApiId": API_ID, "DisableExecuteApiEndpoint": True}),
        ("put_function_concurrency", {"FunctionName": "honda-mapit-mcp-dev-handler", "ReservedConcurrentExecutions": 0}),
        ("get_api", {"ApiId": API_ID}),
        ("get_function_concurrency", {"FunctionName": "honda-mapit-mcp-dev-handler"}),
    ]
    assert "event-target-must-be-ignored" not in repr(response)
    assert API_ID not in repr(response)


@pytest.mark.parametrize("name,value", [
    (entrypoint.ENV_MAPIT_MCP_ENV, "prod"),
    (entrypoint.ENV_AWS_REGION, "us-east-1"),
    (entrypoint.ENV_API_ID, "A1b2c3d4e5"),
    (entrypoint.ENV_API_ID, "not-an-api"),
    (entrypoint.ENV_LAMBDA_FUNCTION_NAME, "another-function"),
])
def test_invalid_environment_fails_before_lazy_sdk_import(monkeypatch, name, value):
    imports = []

    def forbidden_import(name):
        imports.append(name)
        raise AssertionError("SDK import must not happen")

    monkeypatch.setenv(name, value)
    monkeypatch.setattr(entrypoint.importlib, "import_module", forbidden_import)
    assert entrypoint.handler({"secret": "event-canary"}, None) == entrypoint._UNAVAILABLE_RESULT
    assert imports == []


@pytest.mark.parametrize("failed_service,expected", [
    ("apigatewayv2", ("api_write_failed", "api_readback_failed")),
    ("lambda", ("function_write_failed", "function_readback_failed")),
])
def test_one_client_creation_failure_does_not_skip_other_service_closure(monkeypatch, failed_service, expected):
    calls, _config_calls = _install_fake_sdk(monkeypatch, client_fail={failed_service})
    response = entrypoint.handler({}, None)

    assert response["verified"] is False
    assert response["category"] == "shutdown_unverified"
    assert response["warnings"] == expected
    assert sum(1 for call in calls if call[0] == "update_api") == (0 if failed_service == "apigatewayv2" else 1)
    assert sum(1 for call in calls if call[0] == "put_function_concurrency") == (0 if failed_service == "lambda" else 1)
    assert sum(1 for call in calls if call[0] == "get_api") == (0 if failed_service == "apigatewayv2" else 1)
    assert sum(1 for call in calls if call[0] == "get_function_concurrency") == (0 if failed_service == "lambda" else 1)
    assert "private-provider-canary" not in repr(response)


@pytest.mark.parametrize("failed_import", ["boto3", "botocore.config"])
def test_sdk_import_or_config_failure_returns_constant_unavailable(monkeypatch, failed_import):
    _calls, _config_calls = _install_fake_sdk(monkeypatch, import_fail={failed_import})
    response = entrypoint.handler({"payload": "private-event-canary"}, object())
    assert response == entrypoint._UNAVAILABLE_RESULT
    assert "private-event-canary" not in repr(response)


def test_output_is_closed_and_sdk_failures_never_reach_stdout_or_stderr(monkeypatch, capsys):
    _install_fake_sdk(monkeypatch, client_fail={"apigatewayv2"})
    response = entrypoint.handler({"secret": "private-event-canary"}, None)
    output = capsys.readouterr()
    assert "private-event-canary" not in repr(response)
    assert "private-provider-canary" not in repr(response)
    assert output.out == ""
    assert output.err == ""
