from __future__ import annotations

import sys
import types

import pytest

from test_aws_retained_dev_artifact_bootstrap import (
    CloudFormation,
    Journal,
    S3,
    Sts,
    Journal,
    _coordinator,
    _ok,
    _seed_preflight,
)
import scripts.run_aws_retained_dev_artifact_bootstrap as runner


def test_create_200_must_include_exact_stack_id_shape_before_acknowledging():
    class MalformedCreate(CloudFormation):
        def create_stack(self, **kwargs):
            self.calls.append(("create_stack", kwargs))
            return _ok(UnexpectedField="accepted-would-be-unsafe")

    journal = Journal()
    cfn = MalformedCreate()
    coordinator = _coordinator(journal, clients={"sts": Sts(), "cloudformation": cfn, "s3": S3()})
    _seed_preflight(coordinator, journal)
    result = coordinator.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert journal.state["intent"] is not None
    assert journal.state["acknowledged"] is False


def test_readback_receipt_reloads_without_replaying_create():
    journal = Journal()
    cfn = CloudFormation()
    clients = {"sts": Sts(), "cloudformation": cfn, "s3": S3()}
    first = _coordinator(journal, clients=clients)
    _seed_preflight(first, journal)
    assert first.run_step("create")["ok"] is True
    assert first.run_step("readback")["ok"] is True
    second = _coordinator(journal, clients=clients)
    assert second.run_step("readback")["category"] == "readback_verified"
    assert [name for name, _ in cfn.calls].count("create_stack") == 1


@pytest.mark.parametrize("value", [True, 200.0])
def test_http_status_must_be_an_integer_200(value):
    class BadSts(Sts):
        def get_caller_identity(self):
            return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:role/retained-artifact-operator",
                    "ResponseMetadata": {"HTTPStatusCode": value}}

    c = _coordinator(clients={"sts": BadSts(), "cloudformation": CloudFormation(), "s3": S3()})
    assert c.run_step("preflight")["category"] == "aws_response_invalid"


@pytest.mark.parametrize("clock", [lambda: float("nan"), lambda: True])
def test_initial_monotonic_nan_or_bool_fails_before_aws(clock):
    sts = Sts()
    c = _coordinator(clients={"sts": sts, "cloudformation": CloudFormation(), "s3": S3()}, mono=clock)
    assert c.run_step("preflight")["category"] == "window_invalid"
    assert sts.calls == 0


def test_runner_builds_only_direct_regional_clients(monkeypatch):
    for key in runner._PROXY_KEYS:
        monkeypatch.delenv(key, raising=False)
        monkeypatch.delenv(key.upper(), raising=False)
    configs = []
    calls = []

    class FakeConfig:
        def __init__(self, **kwargs):
            configs.append(kwargs)

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
    assert set(clients) == {"sts", "cloudformation", "s3"}
    assert configs == [{"region_name": "eu-west-1", "connect_timeout": 2, "read_timeout": 3,
                        "retries": {"total_max_attempts": 1, "mode": "standard"},
                        "proxies": {}, "signature_version": "v4"}]
    assert [(name, kwargs["endpoint_url"], kwargs["region_name"], kwargs["verify"])
            for name, kwargs in calls] == [
                ("sts", "https://sts.eu-west-1.amazonaws.com", "eu-west-1", True),
                ("cloudformation", "https://cloudformation.eu-west-1.amazonaws.com", "eu-west-1", True),
                ("s3", "https://s3.eu-west-1.amazonaws.com", "eu-west-1", True),
            ]
