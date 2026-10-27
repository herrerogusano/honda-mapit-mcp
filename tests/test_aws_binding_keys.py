import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mapit.aws_binding_keys import (BindingKeysError, PARAMETER_PATH, decode_binding_keys,
    encode_binding_keys, generate_binding_keys, load_binding_keys)
from mapit.config import MapitConfig

ACCOUNT = "123456789012"
CONFIG = MapitConfig(user_pool_id="eu-west-1_Synthetic", user_pool_client_id="synthetic")


def test_canonical_key_roundtrip_and_redaction():
    keys = generate_binding_keys()
    value = encode_binding_keys(keys, account_id=ACCOUNT, config=CONFIG)
    assert decode_binding_keys(value, account_id=ACCOUNT, config=CONFIG) == keys
    assert keys.binding_mac_key != keys.identity_proof_hmac_key
    assert "redacted" in repr(keys)
    assert len(value.encode()) < 2048
    with pytest.raises(BindingKeysError):
        decode_binding_keys(value, account_id="999999999999", config=CONFIG)
    with pytest.raises(BindingKeysError):
        decode_binding_keys(value, account_id=ACCOUNT, config=replace(CONFIG, http_timeout=1))


@pytest.mark.parametrize("case", ["duplicate", "extra", "bool", "padding", "equal", "whitespace", "oversized"])
def test_invalid_payload_closed(case):
    value = encode_binding_keys(generate_binding_keys(), account_id=ACCOUNT, config=CONFIG)
    document = json.loads(value)
    if case == "duplicate":
        value = value[:-1] + ',"schema":1}'
    elif case == "extra":
        document["extra"] = 1
    elif case == "bool":
        document["schema"] = True
    elif case == "padding":
        document["binding_mac_key"] += "="
    elif case == "equal":
        document["identity_proof_hmac_key"] = document["binding_mac_key"]
    elif case == "whitespace":
        value = " " + value
    else:
        value = "a" * 2049
    if case in {"extra", "bool", "padding", "equal"}:
        value = json.dumps(document, sort_keys=True, separators=(",", ":"))
    with pytest.raises(BindingKeysError, match="binding_keys_unverified"):
        decode_binding_keys(value, account_id=ACCOUNT, config=CONFIG)


def client_and_response():
    material = generate_binding_keys()
    response = {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": {
        "Name": PARAMETER_PATH, "Type": "SecureString", "Version": 1, "Selector": ":1",
        "DataType": "text", "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{PARAMETER_PATH}",
        "Value": encode_binding_keys(material, account_id=ACCOUNT, config=CONFIG)}}
    calls = []
    def read(**kwargs):
        calls.append(kwargs)
        return response
    client = SimpleNamespace(get_parameter=read, meta=SimpleNamespace(
        service_model=SimpleNamespace(service_name="ssm"), region_name="eu-west-1",
        endpoint_url="https://ssm.eu-west-1.amazonaws.com", config=SimpleNamespace(
            retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3)))
    return client, response, material, calls


def test_pinned_fresh_read():
    client, _, material, calls = client_and_response()
    assert load_binding_keys(client, account_id=ACCOUNT, config=CONFIG,
        account_verifier=lambda c, a: c is client and a == ACCOUNT,
        deadline=114, monotonic=lambda: 100) == material
    assert calls == [{"Name": PARAMETER_PATH + ":1", "WithDecryption": True}]


@pytest.mark.parametrize("case", ["account", "version", "selector", "arn", "source", "http", "expired", "retry"])
def test_pinned_read_fail_closed(case):
    client, response, _, calls = client_and_response()
    verifier = lambda c, a: True
    if case == "account":
        verifier = lambda c, a: False
    if case == "version":
        response["Parameter"]["Version"] = 2
    if case == "selector":
        response["Parameter"].pop("Selector")
    if case == "arn":
        response["Parameter"]["ARN"] = "wrong"
    if case == "source":
        response["Parameter"]["SourceResult"] = "unexpected"
    if case == "http":
        response["ResponseMetadata"]["HTTPStatusCode"] = True
    if case == "retry":
        client.meta.config.retries["total_max_attempts"] = 2
    with pytest.raises(BindingKeysError):
        load_binding_keys(client, account_id=ACCOUNT, config=CONFIG, account_verifier=verifier,
            deadline=100 if case == "expired" else 114, monotonic=lambda: 100)
    assert len(calls) <= 1
    if case in {"account", "expired", "retry"}:
        assert not calls
