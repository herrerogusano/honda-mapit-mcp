from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from scripts.dev_mapit_key_clients import create_mapit_key_clients


def credentials():
    return {"AccessKeyId": "ASIASYNTHETICEXAMPLE", "SecretAccessKey": "synthetic-secret",
        "SessionToken": "synthetic-session", "Expiration": datetime.fromtimestamp(1800000300, timezone.utc)}


def test_one_explicit_credential_triple_for_both_direct_clients(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    calls = []
    class Session:
        def __init__(self, **kwargs):
            self.values = kwargs
            assert set(kwargs) == {"aws_access_key_id", "aws_secret_access_key", "aws_session_token", "region_name"}
            calls.append("session")
        def client(self, service, **kwargs):
            assert {name: kwargs[name] for name in self.values} == self.values
            assert kwargs["endpoint_url"] == f"https://{service}.eu-west-1.amazonaws.com"
            assert kwargs["verify"] is True
            config = kwargs["config"]
            assert config.signature_version == "v4" and config.proxies == {}
            assert config.retries["total_max_attempts"] == 1
            assert config.connect_timeout == config.read_timeout == 2
            calls.append(service)
            return SimpleNamespace(service=service)
    monkeypatch.setattr(boto3.session, "Session", Session)
    clients = create_mapit_key_clients(credentials(), wall_clock=lambda: 1800000000)
    assert set(clients) == {"sts", "ssm"} and calls == ["session", "sts", "ssm"]


@pytest.mark.parametrize("change", ["missing", "long", "control", "expired", "too_long", "naive", "boolean_clock"])
def test_invalid_credential_authority_never_constructs_clients(monkeypatch, change):
    boto3 = pytest.importorskip("boto3")
    monkeypatch.setattr(boto3.session, "Session", lambda **_: pytest.fail("credential construction occurred"))
    values = credentials()
    if change == "missing":
        del values["SessionToken"]
    elif change == "long":
        values["SessionToken"] = "x" * 16385
    elif change == "control":
        values["SecretAccessKey"] = "sensitive\nerror"
    elif change in {"expired", "too_long"}:
        values["Expiration"] = datetime.fromtimestamp(1800000001 if change == "expired" else 1800003601, timezone.utc)
    elif change == "naive":
        values["Expiration"] = values["Expiration"].replace(tzinfo=None)
    with pytest.raises(ValueError, match="^mapit_key_clients_unverified$"):
        create_mapit_key_clients(values, wall_clock=lambda: True if change == "boolean_clock" else 1800000000)


def test_real_sdk_clients_use_equal_explicit_frozen_credentials_without_network():
    pytest.importorskip("boto3")
    clients = create_mapit_key_clients(credentials(), wall_clock=lambda: 1800000000)
    first, second = (clients[name]._request_signer._credentials.get_frozen_credentials() for name in ("sts", "ssm"))
    assert first == second
    for name, client in clients.items():
        assert client.meta.endpoint_url == f"https://{name}.eu-west-1.amazonaws.com"
        assert client._endpoint.http_session._verify is True
        client.close()
