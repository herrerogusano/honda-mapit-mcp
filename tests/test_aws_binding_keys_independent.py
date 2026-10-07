"""Independent shape and fail-closed checks for the DEV binding-key loader."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mapit.aws_binding_keys import (
    BindingKeysError,
    PARAMETER_PATH,
    decode_binding_keys,
    encode_binding_keys,
    generate_binding_keys,
    load_binding_keys,
)
from mapit.config import MapitConfig


ACCOUNT = "123456789012"
CONFIG = MapitConfig(user_pool_id="eu-west-1_Synthetic", user_pool_client_id="synthetic")


def _response(keys=None, *, account=ACCOUNT, config=CONFIG):
    keys = keys or generate_binding_keys()
    return {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Parameter": {
            "Name": PARAMETER_PATH,
            "ARN": f"arn:aws:ssm:eu-west-1:{account}:parameter{PARAMETER_PATH}",
            "Type": "SecureString",
            "Value": encode_binding_keys(keys, account_id=account, config=config),
            "Version": 1,
            "Selector": ":1",
            "DataType": "text",
        },
    }


def test_real_botocore_stubber_accepts_exact_versioned_get_shape():
    boto3 = pytest.importorskip("boto3")
    botocore_stub = pytest.importorskip("botocore.stub")
    botocore_config = pytest.importorskip("botocore.config")
    keys = generate_binding_keys()
    client = boto3.client(
        "ssm",
        region_name="eu-west-1",
        endpoint_url="https://ssm.eu-west-1.amazonaws.com",
        aws_access_key_id="synthetic-access",
        aws_secret_access_key="synthetic-secret",
        aws_session_token="synthetic-session",
        config=botocore_config.Config(
            retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3,
        ),
    )
    stubber = botocore_stub.Stubber(client)
    stubber.add_response(
        "get_parameter",
        _response(keys),
        {"Name": PARAMETER_PATH + ":1", "WithDecryption": True},
    )
    with stubber:
        actual = load_binding_keys(
            client,
            account_id=ACCOUNT,
            config=CONFIG,
            account_verifier=lambda seen, account: seen is client and account == ACCOUNT,
            deadline=114.0,
            monotonic=lambda: 100.0,
        )
    assert actual == keys
    assert "synthetic-secret" not in repr(actual)
    stubber.assert_no_pending_responses()


def test_wrong_or_throwing_account_verifier_prevents_ssm_request():
    calls = []

    class Client:
        meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name="ssm"),
            region_name="eu-west-1",
            endpoint_url="https://ssm.eu-west-1.amazonaws.com",
            config=SimpleNamespace(
                retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3,
            ),
        )

        def get_parameter(self, **kwargs):
            calls.append(kwargs)
            return _response()

    client = Client()
    for verifier in (
        lambda *_: False,
        lambda *_: (_ for _ in ()).throw(RuntimeError("private account proof")),
    ):
        with pytest.raises(BindingKeysError):
            load_binding_keys(client, account_id=ACCOUNT, config=CONFIG,
                              account_verifier=verifier, deadline=114, monotonic=lambda: 100)
    assert calls == []


def test_deadline_crossed_after_get_never_returns_key_material():
    calls = []
    ticks = iter((100.0, 100.0, 100.0, 114.0))

    class Client:
        meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name="ssm"),
            region_name="eu-west-1",
            endpoint_url="https://ssm.eu-west-1.amazonaws.com",
            config=SimpleNamespace(
                retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3,
            ),
        )

        def get_parameter(self, **kwargs):
            calls.append(kwargs)
            return _response()

    with pytest.raises(BindingKeysError) as caught:
        load_binding_keys(Client(), account_id=ACCOUNT, config=CONFIG,
                          account_verifier=lambda *_: True, deadline=114,
                          monotonic=lambda: next(ticks))
    assert str(caught.value) == "binding_keys_unverified"
    assert calls == [{"Name": PARAMETER_PATH + ":1", "WithDecryption": True}]


@pytest.mark.parametrize("mutation", [
    lambda response: response["Parameter"].update(ARN="arn:aws:ssm:eu-west-1:999999999999:parameter/x"),
    lambda response: response["Parameter"].update(Name=PARAMETER_PATH + ":1"),
    lambda response: response["Parameter"].update(Type="String"),
    lambda response: response["Parameter"].update(Version=True),
    lambda response: response["Parameter"].update(Selector=":2"),
    lambda response: response["Parameter"].update(DataType="aws:ec2:image"),
    lambda response: response["Parameter"].update(SourceResult=None),
    lambda response: response["ResponseMetadata"].update(HTTPStatusCode=200.0),
])
def test_malformed_ssm_readback_fails_closed(mutation):
    response = _response()

    class Client:
        meta = SimpleNamespace(
            service_model=SimpleNamespace(service_name="ssm"),
            region_name="eu-west-1",
            endpoint_url="https://ssm.eu-west-1.amazonaws.com",
            config=SimpleNamespace(
                retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3,
            ),
        )

        def get_parameter(self, **kwargs):
            assert kwargs == {"Name": PARAMETER_PATH + ":1", "WithDecryption": True}
            return response

    mutation(response)
    with pytest.raises(BindingKeysError) as caught:
        load_binding_keys(Client(), account_id=ACCOUNT, config=CONFIG,
                          account_verifier=lambda *_: True, deadline=114, monotonic=lambda: 100)
    assert str(caught.value) == "binding_keys_unverified"
    assert caught.value.__cause__ is None


def test_config_payload_rejects_nonfinite_and_noncanonical_key_material():
    valid = encode_binding_keys(generate_binding_keys(), account_id=ACCOUNT, config=CONFIG)
    with pytest.raises(BindingKeysError):
        decode_binding_keys(valid.replace('"schema":1', '"schema":NaN'), account_id=ACCOUNT, config=CONFIG)
    with pytest.raises(BindingKeysError):
        decode_binding_keys(valid, account_id=ACCOUNT, config=replace(CONFIG, email="not-allowed@example.test"))
