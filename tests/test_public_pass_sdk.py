"""Pass endpoint against the real botocore DynamoDB and SSM models, offline.

botocore's Stubber validates every request against the installed service
model and raises real modelled ClientError objects; nothing leaves the process.
Cloudflare is an in-memory transport. Skipped where the SDK is not installed.
"""

from __future__ import annotations

import base64
import json

import pytest

botocore_session = pytest.importorskip("botocore.session")
stub_module = pytest.importorskip("botocore.stub")

from mapit import public_pass as pp  # noqa: E402
from mapit import public_web as web  # noqa: E402

NOW = 1_794_000_000
KEY = bytes(range(32))
SECRET = "0x4AAAAAAAtestsecretvalue000000000"
TABLE = "honda-mapit-mcp-dev-web-state"
EMAIL = "rider@example.com"
RESULT = "XXXX.result-token.0123456789"
IP = "203.0.113.7"
SETTINGS = pp.Settings(env="dev", table=TABLE, hostnames=frozenset({"localhost"}))
OK = {"success": True, "challenge_ts": "2026-11-06T21:19:50.000Z", "hostname": "localhost",
      "error-codes": [], "action": "web-pass", "cdata": ""}


def _clients():
    session = botocore_session.get_session()
    made = {}
    for name in ("dynamodb", "ssm"):
        client = session.create_client(name, region_name="eu-west-1", aws_access_key_id="testing",
                                       aws_secret_access_key="testing")
        made[name] = (client, stub_module.Stubber(client))
    return made


def _event():
    return {"version": "2.0", "rawPath": "/pase", "headers": {"content-type": "application/json"},
            "requestContext": {"http": {"method": "POST", "path": "/pase", "sourceIp": IP}},
            "body": json.dumps({"email": EMAIL, "turnstile": RESULT}), "isBase64Encoded": False}


def _parameter(name, value):
    return {"Parameter": {"Name": name, "Type": "SecureString", "Value": value, "Version": 1,
                          "DataType": "text"}}


def _expect_reads(ddb, ssm):
    ddb.add_response("get_item", {}, expected_params={
        "TableName": TABLE, "Key": {"pk": {"S": "config"}}, "ConsistentRead": True})
    key_name = web.fingerprint_key_parameter_name("dev")
    ssm.add_response("get_parameter", _parameter(key_name, base64.b64encode(KEY).decode()),
                     expected_params={"Name": key_name, "WithDecryption": True})
    secret_name = pp.turnstile_secret_parameter_name("dev")
    ssm.add_response("get_parameter", _parameter(secret_name, SECRET),
                     expected_params={"Name": secret_name, "WithDecryption": True})


def _result_put():
    pk = web.used_result_key(web.result_fingerprint(KEY, RESULT))
    return {"TableName": TABLE, "Item": {**pk, "expires_at": {"N": str(NOW + 600)}},
            "ConditionExpression": "attribute_not_exists(#pk)",
            "ExpressionAttributeNames": {"#pk": "pk"}}


def _ip_update():
    window = NOW // 600
    return {"TableName": TABLE, "Key": web.ip_passes_key(web.ip_fingerprint(KEY, IP), window),
            "UpdateExpression": "SET #exp = :exp ADD passes :one",
            "ConditionExpression": "attribute_not_exists(passes) OR passes < :limit",
            "ExpressionAttributeNames": {"#exp": "expires_at"},
            "ExpressionAttributeValues": {":exp": {"N": str((window + 2) * 600)},
                                          ":one": {"N": "1"}, ":limit": {"N": "5"}}}


def _service(made):
    return pp.PassService(SETTINGS, dynamodb=made["dynamodb"][0], ssm=made["ssm"][0],
                          transport=lambda *a: (200, json.dumps(OK).encode()), clock=lambda: NOW)


def test_issue_with_real_models():
    made = _clients()
    ddb, ssm = made["dynamodb"][1], made["ssm"][1]
    _expect_reads(ddb, ssm)
    ddb.add_response("put_item", {}, expected_params=_result_put())
    ddb.add_response("update_item", {}, expected_params=_ip_update())
    ddb.add_response("put_item", {}, expected_params={"TableName": TABLE, "Item": {
        **web.pass_key(web.email_fingerprint(KEY, EMAIL)), "attempts_left": {"N": "3"},
        "issued_at": {"N": str(NOW)}, "expires_at": {"N": str(NOW + 300)}}})
    with ddb, ssm:
        assert _service(made).issue(_event()) == "issued"
    ddb.assert_no_pending_responses()
    ssm.assert_no_pending_responses()


def test_reused_result_with_real_conditional_error():
    made = _clients()
    ddb, ssm = made["dynamodb"][1], made["ssm"][1]
    _expect_reads(ddb, ssm)
    ddb.add_client_error("put_item", "ConditionalCheckFailedException", http_status_code=400,
                         expected_params=_result_put())
    with ddb, ssm, pytest.raises(pp.PassError) as caught:
        _service(made).issue(_event())
    assert (caught.value.code, caught.value.answer, caught.value.provider_code) == (
        "result_reused", "rejected", "ConditionalCheckFailedException")
    ddb.assert_no_pending_responses()


def test_ip_limit_with_real_conditional_error():
    made = _clients()
    ddb, ssm = made["dynamodb"][1], made["ssm"][1]
    _expect_reads(ddb, ssm)
    ddb.add_response("put_item", {}, expected_params=_result_put())
    ddb.add_client_error("update_item", "ConditionalCheckFailedException", http_status_code=400,
                         expected_params=_ip_update())
    with ddb, ssm, pytest.raises(pp.PassError) as caught:
        _service(made).issue(_event())
    assert (caught.value.code, caught.value.answer) == ("ip_limit_reached", "rate_limited")
    ddb.assert_no_pending_responses()


def test_missing_fingerprint_key_is_not_created_with_real_model():
    # No put_parameter is stubbed: the Stubber would raise if one were sent.
    made = _clients()
    ddb, ssm = made["dynamodb"][1], made["ssm"][1]
    ddb.add_response("get_item", {}, expected_params={
        "TableName": TABLE, "Key": {"pk": {"S": "config"}}, "ConsistentRead": True})
    key_name = web.fingerprint_key_parameter_name("dev")
    ssm.add_client_error("get_parameter", "ParameterNotFound", http_status_code=400,
                         expected_params={"Name": key_name, "WithDecryption": True})
    with ddb, ssm, pytest.raises(pp.PassError) as caught:
        _service(made).issue(_event())
    assert caught.value.code == "fingerprint_key_missing"
    ssm.assert_no_pending_responses()


def test_missing_secret_with_real_model():
    made = _clients()
    ddb, ssm = made["dynamodb"][1], made["ssm"][1]
    ddb.add_response("get_item", {}, expected_params={
        "TableName": TABLE, "Key": {"pk": {"S": "config"}}, "ConsistentRead": True})
    key_name = web.fingerprint_key_parameter_name("dev")
    ssm.add_response("get_parameter", _parameter(key_name, base64.b64encode(KEY).decode()))
    ssm.add_client_error("get_parameter", "ParameterNotFound", http_status_code=400)
    with ddb, ssm, pytest.raises(pp.PassError) as caught:
        _service(made).issue(_event())
    assert (caught.value.code, caught.value.provider_code) == ("turnstile_secret_missing",
                                                               "ParameterNotFound")
