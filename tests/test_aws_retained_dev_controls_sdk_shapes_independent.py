from __future__ import annotations

import sys
import types

import pytest

import scripts.run_aws_retained_dev_controls_bootstrap as runner
from scripts.aws_retained_dev_controls_bootstrap import _expected_physical


def test_runner_uses_botocore_service_model_names(monkeypatch):
    for key in runner._PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.upper(), raising=False)
    names = []

    class FakeConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeSession:
        def client(self, name, **kwargs):
            names.append(name)
            return object()

    boto3 = types.ModuleType("boto3")
    boto3.Session = lambda **kwargs: FakeSession()
    botocore = types.ModuleType("botocore")
    config_module = types.ModuleType("botocore.config")
    config_module.Config = FakeConfig
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config_module)

    runner._build_clients()
    assert "stepfunctions" in names
    assert "apigatewayv2" in names
    assert "lambda" in names
    assert "sfn" not in names


def test_runner_constructs_eight_direct_tls_clients_with_global_iam(monkeypatch):
    for key in runner._PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.upper(), raising=False)
    calls = []

    class FakeConfig:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class FakeSession:
        def client(self, name, **kwargs):
            calls.append((name, kwargs))
            return object()

    boto3 = types.ModuleType("boto3")
    boto3.Session = lambda **kwargs: FakeSession()
    botocore = types.ModuleType("botocore")
    config_module = types.ModuleType("botocore.config")
    config_module.Config = FakeConfig
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.config", config_module)

    clients = runner._build_clients()
    assert set(clients) == {"sts", "cloudformation", "iam", "sfn", "events", "cloudwatch", "apigatewayv2", "lambda"}
    assert len(calls) == 8
    by_name = {name: kwargs for name, kwargs in calls}
    assert by_name["stepfunctions"]["endpoint_url"] == "https://states.eu-west-1.amazonaws.com"
    assert by_name["stepfunctions"]["region_name"] == "eu-west-1"
    assert by_name["iam"]["endpoint_url"] == "https://iam.amazonaws.com"
    assert by_name["iam"]["region_name"] == "us-east-1"
    assert by_name["iam"]["verify"] is True
    assert by_name["apigatewayv2"]["endpoint_url"] == "https://apigateway.eu-west-1.amazonaws.com"
    assert by_name["lambda"]["endpoint_url"] == "https://lambda.eu-west-1.amazonaws.com"


def test_cloudformation_physical_ids_use_resource_names_for_named_resources():
    physical = _expected_physical("123456789012")
    assert physical["ShutdownWorkflowRole"] == "honda-mapit-mcp-dev-retained-shutdown-workflow"
    assert physical["RequestTripwireEventRole"] == "honda-mapit-mcp-dev-retained-request-tripwire"
    assert physical["RequestTripwireAlarmRule"] == "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"
    assert physical["ShutdownStateMachine"].endswith(":stateMachine:honda-mapit-mcp-dev-retained-shutdown")
