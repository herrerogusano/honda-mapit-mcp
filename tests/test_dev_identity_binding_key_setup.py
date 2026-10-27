from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from mapit.aws_binding_keys import PARAMETER_PATH
from mapit.config import MapitConfig
from scripts.dev_identity_binding_key_setup import publish_keys

ACCOUNT = "123456789012"
CONFIG = MapitConfig(user_pool_id="eu-west-1_Synthetic", user_pool_client_id="synthetic")


class Journal:
    def __init__(self):
        self.state = None
    def locked(self):
        return nullcontext()
    def load(self):
        return self.state
    def save(self, value):
        self.state = dict(value)


class Missing(Exception):
    response = {"Error": {"Code": "ParameterNotFound"}, "ResponseMetadata": {"HTTPStatusCode": 400}}


def fixture():
    calls = []
    class SSM:
        meta = SimpleNamespace(service_model=SimpleNamespace(service_name="ssm"),
            region_name="eu-west-1", endpoint_url="https://ssm.eu-west-1.amazonaws.com",
            config=SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3))
        value = None
        unknown = False
        def get_parameter(self, **kwargs):
            calls.append(("get", kwargs))
            if self.value is None:
                raise Missing()
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": {
                "Name": PARAMETER_PATH, "Type": "SecureString", "DataType": "text", "Version": 1,
                "Selector": ":1", "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{PARAMETER_PATH}",
                "Value": self.value}}
        def put_parameter(self, **kwargs):
            calls.append(("put", {k: v for k, v in kwargs.items() if k != "Value"}))
            self.value = kwargs["Value"]
            if self.unknown:
                raise TimeoutError("sensitive SDK detail")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Version": 1, "Tier": "Standard"}
    class STS:
        meta = SimpleNamespace(service_model=SimpleNamespace(service_name="sts"),
            region_name="eu-west-1", endpoint_url="https://sts.eu-west-1.amazonaws.com",
            config=SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3))
        def get_caller_identity(self):
            calls.append(("sts", {}))
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/honda-mapit-mcp-dev-identity-enroller/probe"}
    return {"ssm": SSM(), "sts": STS()}, Journal(), calls


def run(clients, journal, **kwargs):
    return publish_keys(clients, journal, account_id=ACCOUNT, config=CONFIG,
        source_sha="a" * 40, run_id=123, bootstrap_sha256="b" * 64,
        start=1000, end=1100, clock=lambda: 1050, monotonic=lambda: 100, **kwargs)


def test_one_create_only_key_publication_redacted_journal_and_pinned_read():
    clients, journal, calls = fixture()
    assert run(clients, journal)["ok"] is True
    assert journal.state["phase"] == "accepted"
    assert clients["ssm"].value not in str(journal.state)
    assert [name for name, _ in calls] == ["sts", "get", "put", "sts", "get"]
    put = next(value for name, value in calls if name == "put")
    assert put == {"Name": PARAMETER_PATH, "Type": "SecureString", "KeyId": "alias/aws/ssm",
                   "Overwrite": False, "Tier": "Standard", "DataType": "text"}
    assert run(clients, journal)["category"] == "key_publication_consumed"
    assert len(calls) == 5


def test_unknown_put_consumes_intent_never_retried():
    clients, journal, calls = fixture()
    clients["ssm"].unknown = True
    assert run(clients, journal)["ok"] is False
    assert journal.state["phase"] == "put_intent"
    assert run(clients, journal)["category"] == "key_publication_consumed"
    assert [name for name, _ in calls].count("put") == 1


def test_existing_path_denied_without_intent_or_write():
    clients, journal, calls = fixture()
    clients["ssm"].value = "already-exists"
    assert run(clients, journal)["ok"] is False
    assert journal.state is None
    assert "put" not in [name for name, _ in calls]


def test_wrong_operator_role_denied_before_read():
    clients, journal, calls = fixture()
    clients["sts"].get_caller_identity = lambda: {"ResponseMetadata": {"HTTPStatusCode": 200},
        "Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/owner"}
    assert run(clients, journal)["ok"] is False
    assert journal.state is None and not calls
