"""Public identity requests against the real botocore DynamoDB/SSM models, offline.

botocore validates every request against the installed service model before
the Stubber answers, and builds real modelled errors (TransactionCanceled with
CancellationReasons, ConditionalCheckFailed); nothing leaves the process.
Skipped where the SDK is not installed (it runs in the pinned SDK CI job).
"""

from __future__ import annotations

import base64
import json

import pytest

botocore_session = pytest.importorskip("botocore.session")
stub_module = pytest.importorskip("botocore.stub")

from mapit import multiuser_identity as identity  # noqa: E402
from mapit import public_identity as public  # noqa: E402
from mapit import public_web as web  # noqa: E402

from test_public_identity import (  # noqa: E402
    FP, KEY, KEY_PARAMETER, MAPIT_CONFIG, NOW, PASSWORD, REFRESH, SESSION_PARAMETER, TABLE, TENANT,
    Context, _migration, _pre_auth, _token,
)

ANY = stub_module.ANY


def _client(service: str):
    client = botocore_session.get_session().create_client(
        service, region_name="eu-west-1", aws_access_key_id="testing", aws_secret_access_key="testing")
    return client, stub_module.Stubber(client)


@pytest.fixture
def stubs(monkeypatch: pytest.MonkeyPatch):
    dynamodb, dynamo_stub = _client("dynamodb")
    ssm, ssm_stub = _client("ssm")
    identity.reset_clients()
    monkeypatch.setattr(identity, "_dynamodb_client_factory", lambda: dynamodb)
    monkeypatch.setattr(identity, "_ssm_client_factory", lambda: ssm)
    monkeypatch.setattr(identity, "_wall_clock", lambda: float(NOW))
    monkeypatch.setattr(public, "_token_hex", lambda n: TENANT)
    monkeypatch.delenv("MULTIUSER_TABLE", raising=False)
    for key, value in {"MAPIT_MCP_ENV": "dev", "AWS_REGION": "eu-west-1", "MAPIT_WEB_MODE": "public",
                       "MAPIT_CONFIG_JSON": json.dumps(MAPIT_CONFIG)}.items():
        monkeypatch.setenv(key, value)
    ssm_stub.add_response("get_parameter", {"Parameter": {
        "Name": KEY_PARAMETER, "Type": "SecureString", "Value": base64.b64encode(KEY).decode(),
        "Version": 1}}, expected_params={"Name": KEY_PARAMETER, "WithDecryption": True})
    with dynamo_stub, ssm_stub:
        yield dynamo_stub, ssm_stub, monkeypatch
    dynamo_stub.assert_no_pending_responses()
    ssm_stub.assert_no_pending_responses()
    identity.reset_clients()


def _read(stub, *items: dict) -> None:
    stub.add_response("batch_get_item", {"Responses": {TABLE: list(items)}, "UnprocessedKeys": {}},
                      expected_params={"RequestItems": {TABLE: {"Keys": ANY, "ConsistentRead": True}}})


PASS_ROW = {"pk": {"S": f"pass#{FP}"}, "attempts_left": {"N": "3"}, "expires_at": {"N": str(NOW + 200)}}


def _mapit(monkeypatch, mode: str = "ok") -> None:
    def login(config, email, password, deadline):
        assert password == PASSWORD
        if mode == "reject":
            raise identity.MapitCredentialsRejected()
        return REFRESH
    monkeypatch.setattr(identity, "_mapit_login", login)


def test_admission_requests_match_the_models(stubs):
    dynamo, ssm, monkeypatch = stubs
    _mapit(monkeypatch)
    _read(dynamo, PASS_ROW)
    dynamo.add_response("transact_write_items", {})
    ssm.add_response("put_parameter", {"Version": 1, "Tier": "Standard"}, expected_params={
        "Name": SESSION_PARAMETER, "Value": REFRESH, "Type": "SecureString", "Overwrite": False,
        "Tier": "Standard"})
    result = identity.handler(_migration(), Context())
    assert result["response"]["userAttributes"]["custom:tenant_id"] == TENANT


def test_rejection_requests_match_the_models(stubs):
    dynamo, _, monkeypatch = stubs
    _mapit(monkeypatch, "reject")
    _read(dynamo, PASS_ROW)
    dynamo.add_response("transact_write_items", {})
    dynamo.add_response("update_item", {}, expected_params={
        "TableName": TABLE, "Key": web.pass_key(FP),
        "UpdateExpression": "SET attempts_left = attempts_left - :one",
        "ConditionExpression": "attempts_left > :zero AND expires_at > :now",
        "ExpressionAttributeValues": {":one": {"N": "1"}, ":zero": {"N": "0"}, ":now": {"N": str(NOW)}}})
    with pytest.raises(identity.IdentityError, match="^" + public.MSG_BAD_CREDENTIALS + "$"):
        identity.handler(_migration(), Context())


def test_modelled_seat_cancellation_says_full(stubs):
    dynamo, _, monkeypatch = stubs
    _mapit(monkeypatch)
    _read(dynamo, PASS_ROW)
    dynamo.add_client_error("transact_write_items", "TransactionCanceledException", http_status_code=400,
                            modeled_fields={"CancellationReasons": [
                                {"Code": "None"}, {"Code": "None"},
                                {"Code": "ConditionalCheckFailed", "Message": "x"}, {"Code": "None"}]})
    with pytest.raises(identity.IdentityError, match="^" + public.MSG_FULL + "$"):
        identity.handler(_migration(), Context())


def test_modelled_conditional_failure_on_pre_auth_spend(stubs):
    dynamo, _, _ = stubs
    _read(dynamo, PASS_ROW)
    dynamo.add_client_error("update_item", "ConditionalCheckFailedException", http_status_code=400)
    with pytest.raises(identity.IdentityError, match="^" + public.MSG_START_FROM_WEB + "$"):
        identity.handler(_pre_auth(False), Context())


def test_modelled_daily_limit_from_cancellation_item(stubs):
    dynamo, _, _ = stubs
    old = {"pk": {"S": f"person#{FP}"}, "expires_at": {"N": str(NOW + 100)},
           "login_day": {"S": "2027-01-15"}, "login_day_count": {"N": "10"}}
    for _ in range(2):
        dynamo.add_client_error("transact_write_items", "TransactionCanceledException", http_status_code=400,
                                modeled_fields={"CancellationReasons": [
                                    {"Code": "ConditionalCheckFailed", "Item": old}, {"Code": "None"},
                                    {"Code": "None"}]})
    with pytest.raises(identity.IdentityError, match="^" + public.MSG_DAILY_LIMIT + "$"):
        identity.handler(_token(), Context())
