"""FingerprintKeyStore against the real botocore SSM model, offline.

botocore's Stubber validates every request against the pinned service model
and raises real ClientError objects; nothing leaves the process. Skipped where
the SDK is not installed (it runs in the pinned SDK CI job).
"""

from __future__ import annotations

import base64

import pytest

botocore_session = pytest.importorskip("botocore.session")
stub_module = pytest.importorskip("botocore.stub")

from mapit import public_web as web  # noqa: E402

NAME = "/honda-mapit-mcp/dev/web/fingerprint-key"
KEY = bytes(range(32))
OTHER = bytes(range(50, 82))


def _client():
    session = botocore_session.get_session()
    client = session.create_client(
        "ssm", region_name="eu-west-1", aws_access_key_id="testing", aws_secret_access_key="testing",
    )
    return client, stub_module.Stubber(client)


def _get_response(value: str) -> dict:
    return {"Parameter": {"Name": NAME, "Type": "SecureString", "Value": value, "Version": 1,
                          "DataType": "text"}}


GET = {"Name": NAME, "WithDecryption": True}
PUT = {"Name": NAME, "Value": base64.b64encode(KEY).decode(), "Type": "SecureString",
       "Overwrite": False, "Tier": "Standard"}


def test_create_when_missing_with_real_model():
    client, stubber = _client()
    stubber.add_client_error("get_parameter", "ParameterNotFound", http_status_code=400, expected_params=GET)
    stubber.add_response("put_parameter", {"Version": 1, "Tier": "Standard"}, expected_params=PUT)
    with stubber:
        assert web.FingerprintKeyStore(client, "dev", token_bytes=lambda n: KEY).key() == KEY
    stubber.assert_no_pending_responses()


def test_concurrent_creation_rereads_with_real_model():
    client, stubber = _client()
    stubber.add_client_error("get_parameter", "ParameterNotFound", http_status_code=400, expected_params=GET)
    stubber.add_client_error("put_parameter", "ParameterAlreadyExists", http_status_code=400, expected_params=PUT)
    stubber.add_response("get_parameter", _get_response(base64.b64encode(OTHER).decode()), expected_params=GET)
    with stubber:
        assert web.FingerprintKeyStore(client, "dev", token_bytes=lambda n: KEY).key() == OTHER
    stubber.assert_no_pending_responses()


def test_access_denied_with_real_model():
    client, stubber = _client()
    stubber.add_client_error("get_parameter", "AccessDeniedException", http_status_code=400, expected_params=GET)
    with stubber, pytest.raises(web.PublicWebError) as caught:
        web.FingerprintKeyStore(client, "dev", token_bytes=lambda n: KEY).key()
    # botocore raises the modelled ClientError subclass, named after the code.
    assert (caught.value.code, caught.value.provider_code, caught.value.cause_type) == (
        "fingerprint_key_read_failed", "AccessDeniedException", "AccessDeniedException")


TABLE = "honda-mapit-mcp-dev-web-state"


def _dynamodb():
    client = botocore_session.get_session().create_client(
        "dynamodb", region_name="eu-west-1", aws_access_key_id="testing", aws_secret_access_key="testing",
    )
    return client, stub_module.Stubber(client)


def test_config_read_with_real_dynamodb_model():
    client, stubber = _dynamodb()
    expected = {"TableName": TABLE, "Key": {"pk": {"S": "config"}}, "ConsistentRead": True}
    stubber.add_response("get_item", {"Item": {"pk": {"S": "config"}, "cap": {"N": "0"}}}, expected)
    stubber.add_response("get_item", {}, expected)
    stubber.add_client_error("get_item", "ProvisionedThroughputExceededException", http_status_code=400,
                             expected_params=expected)
    with stubber:
        assert web.load_web_config(client, TABLE).cap == 0
        assert web.load_web_config(client, TABLE) == web.DEFAULT_WEB_CONFIG
        assert web.load_web_config(client, TABLE) == web.READ_FAILED_WEB_CONFIG
    stubber.assert_no_pending_responses()


def test_seat_claim_is_valid_for_update_item_and_transactions():
    client, stubber = _dynamodb()
    update = web.claim_seat_update(TABLE)
    stubber.add_response("update_item", {}, update)
    stubber.add_client_error("update_item", "ConditionalCheckFailedException", http_status_code=400,
                             expected_params=update)
    stubber.add_response("transact_write_items", {}, {"TransactItems": [{"Update": update}]})
    with stubber:
        client.update_item(**update)
        with pytest.raises(client.exceptions.ConditionalCheckFailedException):
            client.update_item(**update)
        client.transact_write_items(TransactItems=[{"Update": update}])
    stubber.assert_no_pending_responses()


def test_put_request_matches_the_real_input_shape():
    # The Stubber raises if a parameter is not in the PutParameter input model.
    model = botocore_session.get_session().get_service_model("ssm")
    members = model.operation_model("PutParameter").input_shape.members
    assert set(PUT) <= set(members)
    assert members["Overwrite"].type_name == "boolean"
    assert "ParameterAlreadyExists" in {e.name for e in model.operation_model("PutParameter").error_shapes}
    assert "ParameterNotFound" in {e.name for e in model.operation_model("GetParameter").error_shapes}
