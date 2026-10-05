import json
from dataclasses import asdict

import pytest

from mapit.aws_session_publication import publish_standard_session

ACCOUNT = "123456789012"
PATH = "/honda-mapit-mcp/prod/mapit-refresh-token"
TOKEN = "synthetic-publication-canary"


class Client:
    def __init__(self):
        self.calls = []
        self.put_response = {"ResponseMetadata": {"HTTPStatusCode": 200}, "Version": 1, "Tier": "Standard"}
        self.get_response = {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Parameter": {"Name": PATH, "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{PATH}",
                          "Type": "SecureString", "Value": TOKEN, "Version": 1, "DataType": "text"},
        }
        self.put_error = None
        self.get_error = None

    def put_parameter(self, **kwargs):
        self.calls.append(("put", kwargs))
        if self.put_error:
            raise self.put_error
        return self.put_response

    def get_parameter(self, **kwargs):
        self.calls.append(("get", kwargs))
        if self.get_error:
            raise self.get_error
        return self.get_response


def publish(client, token=TOKEN, **changes):
    kwargs = {"account_id": ACCOUNT, "deadline": 20.0, "monotonic": lambda: 10.0}
    kwargs.update(changes)
    return publish_standard_session(client, token, **kwargs)


def test_create_only_and_exact_readback_no_secret_output():
    client = Client()
    result = publish(client)
    assert result.success and result.write_acknowledged and result.parameter_version == 1
    assert TOKEN not in repr(result) + json.dumps(asdict(result))
    put, get = client.calls
    assert put[0] == "put" and put[1]["Name"] == PATH
    assert put[1]["Overwrite"] is False
    assert put[1]["Type"] == "SecureString" and put[1]["Tier"] == "Standard"
    assert put[1]["KeyId"] == "alias/aws/ssm" and put[1]["DataType"] == "text"
    assert get == ("get", {"Name": PATH + ":1", "WithDecryption": True})


@pytest.mark.parametrize("token", [None, "", "x" * 4097, "é" * 2049, "\ud800", b"token"])
def test_invalid_values_never_dispatch(token):
    client = Client()
    assert not publish(client, token).success
    assert client.calls == []


@pytest.mark.parametrize("changes", [
    {"account_id": "bad"}, {"account_id": "000000000000"},
    {"deadline": True}, {"deadline": float("inf")}, {"deadline": float("nan")},
    {"deadline": 0}, {"deadline": 10.0}, {"monotonic": lambda: float("nan")},
    {"monotonic": lambda: True}, {"monotonic": lambda: -1},
])
def test_invalid_policy_or_expired_clock_never_dispatch(changes):
    client = Client()
    assert not publish(client, **changes).success
    assert client.calls == []


@pytest.mark.parametrize("response", [None, {}, {"ResponseMetadata": {"HTTPStatusCode": 201}},
                                       {"ResponseMetadata": {"HTTPStatusCode": True}}])
def test_ambiguous_write_never_retries_or_readbacks(response):
    client = Client()
    client.put_response = response
    result = publish(client)
    assert result.category == "publication_outcome_unknown" and not result.write_acknowledged
    assert [kind for kind, _ in client.calls] == ["put"]


@pytest.mark.parametrize("field,value", [("Version", True), ("Version", 2), ("Tier", "Advanced")])
def test_acknowledged_but_invalid_shape_never_claims_no_write(field, value):
    client = Client()
    client.put_response[field] = value
    result = publish(client)
    assert not result.success and result.write_acknowledged
    assert len(client.calls) == 1


@pytest.mark.parametrize("field,value", [("Value", "wrong-secret"), ("ARN", "wrong"), ("Version", 2),
                                         ("SourceResult", None), ("Type", "String")])
def test_failed_readback_preserves_write_ack_and_no_cleanup(field, value):
    client = Client()
    client.get_response["Parameter"][field] = value
    result = publish(client)
    assert not result.success and result.write_acknowledged and result.parameter_version == 1
    assert len(client.calls) == 2


@pytest.mark.parametrize("where", ["put", "get"])
def test_raw_provider_error_never_in_result(where):
    client = Client()
    setattr(client, where + "_error", RuntimeError(TOKEN))
    result = publish(client)
    assert not result.success and TOKEN not in repr(result)
    assert len(client.calls) == (1 if where == "put" else 2)


def test_expiration_after_write_prevents_readback():
    client = Client()
    times = iter([10.0, 10.0, 20.0])
    result = publish(client, monotonic=lambda: next(times))
    assert result.category == "deadline_failed" and result.write_acknowledged
    assert len(client.calls) == 1


def test_clock_rollback_before_dispatch():
    client = Client()
    times = iter([10.0, 9.0])
    result = publish(client, monotonic=lambda: next(times))
    assert result.category == "deadline_failed" and client.calls == []
