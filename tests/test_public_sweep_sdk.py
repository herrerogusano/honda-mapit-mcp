"""Public web sweep against the real botocore SSM and Cognito models, offline.

botocore's Stubber validates every request against the installed service model
and returns parsed responses (real datetime objects) and modelled ClientError
objects; nothing leaves the process. Skipped where the SDK is not installed.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

botocore_session = pytest.importorskip("botocore.session")
stub_module = pytest.importorskip("botocore.stub")

from mapit import public_sweep as sweep  # noqa: E402
from mapit import public_web as web  # noqa: E402

NOW = 1_800_000_000.0
POOL = "eu-west-1_AbCdEfGhI"
T1, T2 = "a" * 32, "b" * 32
OLD = datetime.fromtimestamp(NOW - web.SWEEP_AGE_SECONDS, tz=timezone.utc)
YOUNG = datetime.fromtimestamp(NOW - 60, tz=timezone.utc)
DESCRIBE = {"ParameterFilters": [{"Key": "Path", "Option": "Recursive",
                                  "Values": ["/honda-mapit-mcp/dev/web/sessions"]}],
            "MaxResults": 50}


def _client(service: str):
    session = botocore_session.get_session()
    client = session.create_client(service, region_name="eu-west-1",
                                   aws_access_key_id="testing", aws_secret_access_key="testing")
    return client, stub_module.Stubber(client)


def _pool_client(name: str = "honda-mapit-mcp-dev-web-users"):
    """Cognito client whose first stubbed call is the DescribeUserPool check."""
    cognito, stub = _client("cognito-idp")
    stub.add_response("describe_user_pool", {"UserPool": {
        "Id": POOL, "Name": name, "Status": "Enabled", "CreationDate": OLD, "LastModifiedDate": OLD,
        "Arn": "arn:aws:cognito-idp:eu-west-1:123456789012:userpool/" + POOL,
    }}, {"UserPoolId": POOL})
    return cognito, stub


def test_invitation_pool_with_real_model_deletes_nothing():
    # No SSM or ListUsers response is queued: Stubber fails on any such call.
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _pool_client("honda-mapit-mcp-dev-users")
    with ssm_stub, cognito_stub:
        result = _run(ssm, cognito)
    cognito_stub.assert_no_pending_responses()
    assert result.codes == ["sweep_pool_mismatch"]


def test_describe_user_pool_error_with_real_model_deletes_nothing():
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _client("cognito-idp")
    cognito_stub.add_client_error("describe_user_pool", "ResourceNotFoundException", http_status_code=400,
                                  expected_params={"UserPoolId": POOL})
    with ssm_stub, cognito_stub:
        result = _run(ssm, cognito)
    assert result.codes == ["sweep_pool_check_failed"]


def test_seat_recount_with_real_dynamodb_model():
    now = int(NOW) // 86400 * 86400 + 3 * 3600 + 60
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _pool_client()
    dynamodb, dynamodb_stub = _client("dynamodb")
    table, key = "honda-mapit-mcp-dev-web-state", {"pk": {"S": "config"}}
    ssm_stub.add_response("describe_parameters", {"Parameters": []}, DESCRIBE)
    cognito_stub.add_response("list_users", {"Users": []})
    dynamodb_stub.add_response("get_item", {"Item": {**key, "occupied": {"N": "7"}}},
                               {"TableName": table, "Key": key, "ConsistentRead": True})
    dynamodb_stub.add_response("scan", {"Count": 3, "ScannedCount": 8})
    dynamodb_stub.add_client_error("update_item", "ConditionalCheckFailedException", http_status_code=400)
    with ssm_stub, cognito_stub, dynamodb_stub:
        result = sweep.Sweeper(env="dev", user_pool_id=POOL, ssm=ssm, cognito=cognito, now=lambda: now,
                               remaining_ms=lambda: 60_000, dynamodb=dynamodb).run()
    dynamodb_stub.assert_no_pending_responses()
    assert result.status == sweep.STATUS_OK and result.recount_conflict and result.persons_counted == 3


def _meta(name: str, when: datetime) -> dict:
    return {"Name": name, "Type": "SecureString", "LastModifiedDate": when, "Version": 1,
            "Tier": "Standard", "DataType": "text"}


def _run(ssm, cognito):
    return sweep.Sweeper(env="dev", user_pool_id=POOL, ssm=ssm, cognito=cognito,
                         now=lambda: NOW, remaining_ms=lambda: 60_000).run()


def test_full_sweep_with_real_models():
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _pool_client()
    s1, s2 = web.web_session_parameter_name("dev", T1), web.web_session_parameter_name("dev", T2)
    ssm_stub.add_response("describe_parameters",
                          {"Parameters": [_meta(s1, OLD)], "NextToken": "n1"}, DESCRIBE)
    ssm_stub.add_response("describe_parameters",
                          {"Parameters": [_meta(s2, YOUNG)]}, {**DESCRIBE, "NextToken": "n1"})
    ssm_stub.add_response("delete_parameter", {}, {"Name": s1})
    list_request = {"UserPoolId": POOL, "AttributesToGet": [], "Limit": 60}
    cognito_stub.add_response("list_users", {"Users": [
        {"Username": "u1", "UserCreateDate": OLD, "UserLastModifiedDate": YOUNG,
         "Enabled": True, "UserStatus": "CONFIRMED"},
    ], "PaginationToken": "p1"}, list_request)
    cognito_stub.add_response("list_users", {"Users": [
        {"Username": "u2", "UserCreateDate": YOUNG, "Enabled": True, "UserStatus": "CONFIRMED"},
    ]}, {**list_request, "PaginationToken": "p1"})
    cognito_stub.add_response("admin_delete_user", {}, {"UserPoolId": POOL, "Username": "u1"})
    with ssm_stub, cognito_stub:
        result = _run(ssm, cognito)
    ssm_stub.assert_no_pending_responses()
    cognito_stub.assert_no_pending_responses()
    assert result.status == sweep.STATUS_OK
    assert (result.sessions_deleted, result.users_deleted) == (1, 1)
    assert result.oldest_age == web.SWEEP_AGE_SECONDS


def test_real_not_found_errors_are_idempotent():
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _pool_client()
    s1 = web.web_session_parameter_name("dev", T1)
    ssm_stub.add_response("describe_parameters", {"Parameters": [_meta(s1, OLD)]}, DESCRIBE)
    ssm_stub.add_client_error("delete_parameter", "ParameterNotFound", http_status_code=400,
                              expected_params={"Name": s1})
    cognito_stub.add_response("list_users", {"Users": [{"Username": "u1", "UserCreateDate": OLD}]})
    cognito_stub.add_client_error("admin_delete_user", "UserNotFoundException", http_status_code=400,
                                  expected_params={"UserPoolId": POOL, "Username": "u1"})
    with ssm_stub, cognito_stub:
        result = _run(ssm, cognito)
    assert result.status == sweep.STATUS_OK
    assert (result.sessions_gone, result.users_gone) == (1, 1)


def test_real_access_denied_is_coded():
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _pool_client()
    ssm_stub.add_client_error("describe_parameters", "AccessDeniedException", http_status_code=400)
    cognito_stub.add_client_error("list_users", "NotAuthorizedException", http_status_code=400)
    with ssm_stub, cognito_stub:
        result = _run(ssm, cognito)
    assert result.codes == ["sweep_sessions_list_failed", "sweep_users_list_failed"]


def test_foreign_names_in_a_real_response_are_never_deleted():
    # Stubber raises on any unexpected call, so no delete_parameter is queued.
    ssm, ssm_stub = _client("ssm")
    cognito, cognito_stub = _pool_client()
    ssm_stub.add_response("describe_parameters", {"Parameters": [
        _meta(web.fingerprint_key_parameter_name("dev"), OLD),
        _meta("/honda-mapit-mcp/dev/web/sessions/" + T1 + "/other", OLD),
        _meta(web.web_session_parameter_name("prod", T1), OLD),
    ]}, DESCRIBE)
    cognito_stub.add_response("list_users", {"Users": []})
    with ssm_stub, cognito_stub:
        result = _run(ssm, cognito)
    ssm_stub.assert_no_pending_responses()
    assert result.codes == ["sweep_sessions_unexpected"] and result.sessions_deleted == 0
