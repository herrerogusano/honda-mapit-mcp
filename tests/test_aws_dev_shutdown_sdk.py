"""Actual SDK service-model checks with Stubber; no HTTP or credentials lookup."""

import importlib
from types import SimpleNamespace

import pytest

boto3 = pytest.importorskip("boto3")
from botocore.config import Config
from botocore.stub import Stubber

from mapit import aws_dev_shutdown_entrypoint as entrypoint


@pytest.mark.parametrize("api_write_fails", [False, True])
def test_real_sdk_shutdown_shapes(monkeypatch, tmp_path, capsys, api_write_fails):
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_LAMBDA", "AWS_ENDPOINT_URL_APIGATEWAYV2"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "missing-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "missing-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("MAPIT_MCP_ENV", "dev")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", entrypoint.SHUTDOWN_LAMBDA_NAME)
    monkeypatch.setenv("MAPIT_API_ID", "a1b2c3d4e5")
    # Explicit dummy credentials only; Stubber intercepts before any HTTP call.
    session = boto3.Session(aws_access_key_id="synthetic-key", aws_secret_access_key="synthetic-secret", region_name="eu-west-1")
    config = Config(retries={"mode": "standard", "total_max_attempts": 1}, connect_timeout=2, read_timeout=3, proxies={})
    api = session.client("apigatewayv2", config=config)
    function = session.client("lambda", config=config)
    api_stub, function_stub = Stubber(api), Stubber(function)
    api_parameters = {"ApiId": "a1b2c3d4e5", "DisableExecuteApiEndpoint": True}
    if api_write_fails:
        api_stub.add_client_error("update_api", service_error_code="AccessDeniedException", service_message="synthetic-provider-canary", expected_params=api_parameters)
    else:
        api_stub.add_response("update_api", {"DisableExecuteApiEndpoint": True}, api_parameters)
    api_stub.add_response("get_api", {"DisableExecuteApiEndpoint": True}, {"ApiId": "a1b2c3d4e5"})
    function_name = "honda-mapit-mcp-dev-handler"
    function_stub.add_response("put_function_concurrency", {"ReservedConcurrentExecutions": 0}, {"FunctionName": function_name, "ReservedConcurrentExecutions": 0})
    function_stub.add_response("get_function_concurrency", {"ReservedConcurrentExecutions": 0}, {"FunctionName": function_name})

    class FixedSession:
        def client(self, service_name, *, region_name, config):
            assert region_name == "eu-west-1"
            assert config.retries == {"mode": "standard", "total_max_attempts": 1}
            assert config.connect_timeout == 2 and config.read_timeout == 3
            return {"apigatewayv2": api, "lambda": function}[service_name]

    def session_factory(*, region_name):
        assert region_name == "eu-west-1"
        return FixedSession()

    actual_import = importlib.import_module

    def fixed_import(name):
        if name == "boto3":
            return SimpleNamespace(Session=session_factory)
        return actual_import(name)

    monkeypatch.setattr(entrypoint.importlib, "import_module", fixed_import)
    with api_stub, function_stub:
        result = entrypoint.handler({"api_id": "ignored-event-canary"}, None)
        api_stub.assert_no_pending_responses()
        function_stub.assert_no_pending_responses()
    assert result["verified"] is True
    assert result["category"] == "shutdown_verified"
    assert result["api_write_call_returned"] is not api_write_fails
    assert result["warnings"] == (("api_write_failed",) if api_write_fails else ())
    assert "canary" not in repr(result)
    output = capsys.readouterr()
    assert output.out == output.err == ""
