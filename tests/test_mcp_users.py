from __future__ import annotations

import hashlib
from urllib.parse import parse_qs, urlsplit

import pytest
pytest.importorskip("botocore")  # mandatory in the pinned SDK CI job

from botocore.exceptions import ClientError

from mapit.multiuser_common import MAX_USERS, MultiuserError
from scripts import mcp_users

TENANT = "a" * 32


def _error(code):
    return ClientError({"Error": {"Code": code, "Message": "x"}}, "Op")


class FakeCfn:
    def describe_stacks(self, StackName):
        assert StackName == "honda-mapit-mcp-dev-multiuser"
        return {"Stacks": [{"Outputs": [
            {"OutputKey": "TableName", "OutputValue": "honda-mapit-mcp-dev-invitations"},
            {"OutputKey": "UserPoolId", "OutputValue": "eu-west-1_Pool12345"},
            {"OutputKey": "ApiBaseUrl", "OutputValue": "https://a1b2c3d4e5.execute-api.eu-west-1.amazonaws.com"},
        ]}]}


class FakeDynamo:
    def __init__(self):
        self.items: dict[str, dict] = {}
        self.calls: list[tuple[str, dict]] = []

    def scan(self, **kwargs):
        self.calls.append(("scan", kwargs))
        assert kwargs["ConsistentRead"] is True
        if kwargs.get("Select") == "COUNT":
            return {"Count": len(self.items)}
        return {"Items": [dict(item) for item in self.items.values()]}

    def put_item(self, **kwargs):
        self.calls.append(("put_item", kwargs))
        assert kwargs["ConditionExpression"] == "attribute_not_exists(email)"
        email = kwargs["Item"]["email"]["S"]
        if email in self.items:
            raise _error("ConditionalCheckFailedException")
        self.items[email] = kwargs["Item"]

    def get_item(self, **kwargs):
        self.calls.append(("get_item", kwargs))
        assert kwargs["ConsistentRead"] is True
        item = self.items.get(kwargs["Key"]["email"]["S"])
        return {"Item": item} if item else {}

    def delete_item(self, **kwargs):
        self.calls.append(("delete_item", kwargs))
        self.items.pop(kwargs["Key"]["email"]["S"], None)

    def update_item(self, **kwargs):
        self.calls.append(("update_item", kwargs))
        item = self.items[kwargs["Key"]["email"]["S"]]
        item["status"] = kwargs["ExpressionAttributeValues"][":accepted"]


class FakeCognito:
    def __init__(self, missing=False):
        self.missing = missing
        self.deleted = []

    def admin_delete_user(self, UserPoolId, Username):
        assert UserPoolId == "eu-west-1_Pool12345"
        if self.missing:
            raise _error("UserNotFoundException")
        self.deleted.append(Username)


class FakeSsm:
    def __init__(self, missing=False):
        self.missing = missing
        self.deleted = []

    def delete_parameter(self, Name):
        if self.missing:
            raise _error("ParameterNotFound")
        self.deleted.append(Name)


def _admin(dynamo=None, cognito=None, ssm=None, out=None, token="T" * 43):
    clients = mcp_users.Clients(FakeCfn(), dynamo or FakeDynamo(), cognito or FakeCognito(), ssm or FakeSsm())
    return mcp_users.UserAdmin("dev", clients, out=(out if out is not None else (lambda _l: None)),
                               clock=lambda: 1_900_000_000, token_factory=lambda: token,
                               tenant_factory=lambda: TENANT)


def test_invite_creates_hashed_item_and_prints_link():
    lines = []
    dynamo = FakeDynamo()
    link = _admin(dynamo, out=lines.append).invite("  Friend+X@Example.COM ", 14)
    item = dynamo.items["friend+x@example.com"]
    assert item["status"] == {"S": "invited"}
    assert item["tenant_id"] == {"S": TENANT}
    assert item["invite_token_sha256"] == {"S": hashlib.sha256(b"T" * 43).hexdigest()}
    assert item["invite_expires_at"] == {"N": str(1_900_000_000 + 14 * 86400)}
    assert "T" * 43 not in str(item)
    parts = urlsplit(link)
    assert parts.path == "/invitacion"
    assert parse_qs(parts.query) == {"email": ["friend+x@example.com"], "token": ["T" * 43]}
    assert "%2B" in link  # urlencoded
    assert link in lines


def test_invite_refuses_duplicates_limit_and_bad_input():
    dynamo = FakeDynamo()
    admin = _admin(dynamo)
    admin.invite("a@example.com")
    with pytest.raises(mcp_users.UsersError, match="already"):
        admin.invite("A@example.com")
    for index in range(MAX_USERS - 1):
        admin.invite(f"u{index}@example.com")
    with pytest.raises(mcp_users.UsersError, match="limit"):
        admin.invite("late@example.com")
    with pytest.raises(MultiuserError):
        _admin().invite("not-an-email")
    with pytest.raises(mcp_users.UsersError):
        _admin().invite("b@example.com", days=0)
    with pytest.raises(mcp_users.UsersError, match="token"):
        _admin(token="short").invite("c@example.com")


def test_real_token_factory_matches_runtime_pattern():
    token = __import__("secrets").token_urlsafe(32)
    assert mcp_users.TOKEN_RE.fullmatch(token)


def test_list_hides_tokens():
    lines = []
    dynamo = FakeDynamo()
    admin = _admin(dynamo, out=lines.append)
    admin.invite("a@example.com")
    lines.clear()
    rows = admin.list()
    assert rows == [{"email": "a@example.com", "status": "invited", "created": "2030-03-17T17:46:40Z",
                     "last_login": "-"}]
    scan = [kwargs for name, kwargs in dynamo.calls if name == "scan" and "ProjectionExpression" in kwargs][0]
    assert "invite_token" not in scan["ProjectionExpression"]
    assert "T" * 43 not in "\n".join(lines)


def test_revoke_deletes_user_parameter_and_item():
    dynamo, cognito, ssm = FakeDynamo(), FakeCognito(), FakeSsm()
    admin = _admin(dynamo, cognito, ssm)
    admin.invite("a@example.com")
    admin.revoke("A@example.com")
    assert cognito.deleted == ["a@example.com"]
    assert ssm.deleted == [f"/honda-mapit-mcp/dev/users/{TENANT}/mapit-refresh-token"]
    assert dynamo.items == {}


def test_revoke_ignores_missing_user_and_parameter():
    dynamo = FakeDynamo()
    admin = _admin(dynamo, FakeCognito(missing=True), FakeSsm(missing=True))
    admin.invite("a@example.com")
    admin.revoke("a@example.com")
    assert dynamo.items == {}
    _admin(FakeDynamo(), FakeCognito(missing=True)).revoke("ghost@example.com")


def test_revoke_propagates_unexpected_errors():
    class Broken(FakeCognito):
        def admin_delete_user(self, **_kwargs):
            raise _error("AccessDeniedException")

    dynamo = FakeDynamo()
    admin = _admin(dynamo, Broken())
    admin.invite("a@example.com")
    with pytest.raises(ClientError):
        admin.revoke("a@example.com")
    assert "a@example.com" in dynamo.items


def test_relink_resets_to_accepted():
    dynamo, cognito, ssm = FakeDynamo(), FakeCognito(), FakeSsm()
    admin = _admin(dynamo, cognito, ssm)
    admin.invite("a@example.com")
    dynamo.items["a@example.com"]["status"] = {"S": "active"}
    admin.relink("a@example.com")
    assert dynamo.items["a@example.com"]["status"] == {"S": "accepted"}
    assert cognito.deleted == ["a@example.com"] and len(ssm.deleted) == 1
    update = [kwargs for name, kwargs in dynamo.calls if name == "update_item"][0]
    assert "REMOVE locked_until" in update["UpdateExpression"]
    assert "IN (:accepted, :active)" in update["ConditionExpression"]
    with pytest.raises(mcp_users.UsersError):
        admin.relink("nobody@example.com")


def test_relink_refuses_unconsented_invitation():
    dynamo, cognito, ssm = FakeDynamo(), FakeCognito(), FakeSsm()
    admin = _admin(dynamo, cognito, ssm)
    admin.invite("a@example.com")
    with pytest.raises(mcp_users.UsersError, match="not accepted"):
        admin.relink("a@example.com")
    assert dynamo.items["a@example.com"]["status"] == {"S": "invited"}
    assert cognito.deleted == [] and ssm.deleted == []


def test_cli_main_dispatch(capsys):
    dynamo = FakeDynamo()
    clients = mcp_users.Clients(FakeCfn(), dynamo, FakeCognito(), FakeSsm())
    lines = []
    assert mcp_users.main(["--env", "dev", "invite", "a@example.com", "--days", "3"],
                          clients=clients, out=lines.append) == 0
    assert any("/invitacion?" in line for line in lines)
    assert mcp_users.main(["--env", "dev", "list"], clients=clients, out=lines.append) == 0
    assert mcp_users.main(["--env", "dev", "relink", "zz@example.com"], clients=clients, out=lines.append) == 1
    assert "error:" in capsys.readouterr().err
    assert mcp_users.main(["--env", "dev", "revoke", "a@example.com"], clients=clients, out=lines.append) == 0
    assert dynamo.items == {}


# --- web-* commands, against the real botocore models (Stubber, offline) ------------------

from datetime import datetime, timezone  # noqa: E402

from botocore.session import get_session  # noqa: E402
from botocore.stub import ANY, Stubber  # noqa: E402

from mapit import public_web as web  # noqa: E402
from scripts import mcp_users_web  # noqa: E402

WEB_NOW = 1_800_000_000  # 2027-01-15T08:00:00Z
WEB_TABLE = "honda-mapit-mcp-dev-web-state"
WEB_POOL = "eu-west-1_WebPool123"
OTHER_POOL = "eu-west-1_Invites12"
SESSION_PATH = "/honda-mapit-mcp/dev/web/sessions"
USER_NAME = "c0ffee00-0000-4000-8000-000000000001"
SESSION_NAME = f"{SESSION_PATH}/{'d' * 32}/mapit-refresh-token"


def _stubbed(service):
    client = get_session().create_client(service, region_name="eu-west-1",
                                         aws_access_key_id="testing", aws_secret_access_key="testing")
    return client, Stubber(client)


class _WebClients:
    def __init__(self):
        self.dynamodb, self.dynamo_stub = _stubbed("dynamodb")
        self.cognito, self.cognito_stub = _stubbed("cognito-idp")
        self.ssm, self.ssm_stub = _stubbed("ssm")
        self.lines: list[str] = []

    def __enter__(self):
        for stub in (self.dynamo_stub, self.cognito_stub, self.ssm_stub):
            stub.activate()
        return self

    def __exit__(self, *exc):
        for stub in (self.dynamo_stub, self.cognito_stub, self.ssm_stub):
            stub.deactivate()

    def verify(self):
        for stub in (self.dynamo_stub, self.cognito_stub, self.ssm_stub):
            stub.assert_no_pending_responses()

    def run(self, *argv):
        clients = mcp_users.Clients(None, self.dynamodb, self.cognito, self.ssm)
        return mcp_users.main(["--env", "dev", *argv], clients=clients, out=self.lines.append,
                              clock=lambda: WEB_NOW)

    def get(self, key, item=None):
        response = {"Item": item} if item is not None else {}
        self.dynamo_stub.add_response("get_item", response,
                                      {"TableName": WEB_TABLE, "Key": key, "ConsistentRead": True})

    def breakers(self, current=None, *older):
        window = web.breaker_window(WEB_NOW)
        rows = [current, *older, None, None][:3]
        for back, item in enumerate(rows):
            self.get(web.breaker_key(window - back), item)

    def pools(self):
        self.cognito_stub.add_response("list_user_pools", {"UserPools": [
            {"Id": OTHER_POOL, "Name": "honda-mapit-mcp-dev-users"},
            {"Id": WEB_POOL, "Name": "honda-mapit-mcp-dev-web-users"}]}, {"MaxResults": 60})

    def users(self, *ages):
        self.cognito_stub.add_response("list_users", {"Users": [
            {"Username": f"{USER_NAME[:-1]}{index}", "UserCreateDate": _date(age)}
            for index, age in enumerate(ages)]},
            {"UserPoolId": WEB_POOL, "AttributesToGet": [], "Limit": 60})

    def sessions(self, *ages):
        self.ssm_stub.add_response("describe_parameters", {"Parameters": [
            {"Name": SESSION_NAME, "LastModifiedDate": _date(age)} for age in ages]},
            {"ParameterFilters": [{"Key": "Path", "Option": "Recursive", "Values": [SESSION_PATH]}],
             "MaxResults": 50})

    @property
    def text(self):
        return "\n".join(self.lines)


def _date(age):
    return datetime.fromtimestamp(WEB_NOW - age, tz=timezone.utc)


def _config(**attributes):
    item = dict(web.config_key())
    for name, value in attributes.items():
        item[name] = {"BOOL": value} if type(value) is bool else {"N": str(value)}
    return item


def _assert_no_identifiers(text):
    for secret in (WEB_POOL, OTHER_POOL, USER_NAME[:-1], SESSION_NAME, "d" * 32):
        assert secret not in text


def test_web_status_reports_counts_ages_and_state_without_identifiers():
    with _WebClients() as c:
        c.get(web.config_key(), _config(cap=100, occupied=3, open=True))
        c.breakers({**web.breaker_key(web.breaker_window(WEB_NOW)), "rejections": {"N": "4"},
                    "expires_at": {"N": str(WEB_NOW + 900)}})
        c.pools()
        c.users(120, 2_400)
        c.sessions(2_400)
        assert c.run("web-status") == 0
        c.verify()
    assert "config (row): open=true pause_until=none cap=100 occupied=3 pass_required=true" in c.text
    assert "breaker: closed; MAPIT rejections in this 10-min window: 4/20" in c.text
    assert "/estado would answer: abierto" in c.text
    assert "users in web pool: 2, oldest 40 min 0 s (under one hour)" in c.text
    assert "session parameters: 1, oldest 40 min 0 s (under one hour)" in c.text
    _assert_no_identifiers(c.text)


def test_web_status_flags_malformed_config_open_breaker_and_old_items():
    with _WebClients() as c:
        c.get(web.config_key(), {**_config(cap=5), "surprise": {"S": "x"}})
        c.breakers(None, {**web.breaker_key(web.breaker_window(WEB_NOW) - 1), "rejections": {"N": "20"},
                          "open_until": {"N": str(WEB_NOW + 60)}, "expires_at": {"N": str(WEB_NOW + 900)}})
        c.pools()
        c.users(3_600)
        c.sessions()
        assert c.run("web-status") == mcp_users.WEB_STATUS_ATTENTION
        c.verify()
    assert "config: MALFORMED (service closed); attributes present: cap, pk, surprise" in c.text
    assert "breaker: OPEN" in c.text
    assert "/estado would answer: pausa" in c.text
    assert "users in web pool: 1, oldest 60 min 0 s (ONE HOUR OR OLDER)" in c.text
    assert "session parameters: 0" in c.text


def test_web_status_ignores_expired_breaker_rows_and_reads_states():
    expired = {**web.breaker_key(web.breaker_window(WEB_NOW)), "rejections": {"N": "25"},
               "open_until": {"N": str(WEB_NOW + 60)}, "expires_at": {"N": str(WEB_NOW)}}
    with _WebClients() as c:
        c.get(web.config_key(), _config(cap=2, occupied=2))
        c.breakers(expired)
        c.pools()
        c.users()
        c.sessions()
        assert c.run("web-status") == 0
    assert "breaker: closed" in c.text and "/estado would answer: lleno" in c.text
    now = WEB_NOW
    assert mcp_users_web.public_state(web.parse_web_config(None), now, False) == "abierto"
    assert mcp_users_web.public_state(web.parse_web_config(None), now, True) == "pausa"
    assert mcp_users_web.public_state(web.parse_web_config(_config(open=False)), now, True) == "cerrado"
    assert mcp_users_web.public_state(web.parse_web_config(_config(pause_until=now + 1)), now, False) == "pausa"
    assert mcp_users_web.public_state(web.READ_FAILED_WEB_CONFIG, now, False) == "pausa"


def test_web_status_fails_without_exactly_one_web_pool(capsys):
    with _WebClients() as c:
        c.get(web.config_key())
        c.breakers()
        c.cognito_stub.add_response("list_user_pools", {"UserPools": [
            {"Id": OTHER_POOL, "Name": "honda-mapit-mcp-dev-users"}]}, {"MaxResults": 60})
        assert c.run("web-status") == 1
        c.verify()
    assert "config (no row, defaults)" in c.text
    assert "web user pool not found" in capsys.readouterr().err


def test_web_status_fails_closed_when_the_config_read_fails(capsys):
    with _WebClients() as c:
        c.dynamo_stub.add_client_error("get_item", "ResourceNotFoundException")
        assert c.run("web-status") == 1
    assert "config read failed (ResourceNotFoundException)" in capsys.readouterr().err


def test_web_status_reports_aws_failures_by_code_only(capsys):
    with _WebClients() as c:
        c.get(web.config_key())
        c.breakers()
        c.pools()
        c.cognito_stub.add_client_error("list_users", "AccessDeniedException", service_message=WEB_POOL)
        assert c.run("web-status") == 1
        c.verify()
    err = capsys.readouterr().err
    assert "error: AWS call failed (AccessDeniedException)" in err and WEB_POOL not in err


def test_web_stats_reads_day_and_month_rows_across_a_year_change():
    with _WebClients() as c:
        c.get(web.day_key(WEB_NOW), {**web.day_key(WEB_NOW), "logins": {"N": "7"}, "new_people": {"N": "2"},
                                     "mapit_rejections": {"N": "3"}})
        c.get(web.day_key(WEB_NOW - 86400))
        c.get({"pk": {"S": "month#2027-01"}}, {"pk": {"S": "month#2027-01"}, "logins": {"N": "40"}})
        c.get({"pk": {"S": "month#2026-12"}}, {"pk": {"S": "month#2026-12"}, "logins": {"S": "bad"}})
        assert c.run("web-stats", "--days", "2", "--months", "2") == 0
        c.verify()
    rows = [line.split() for line in c.lines]
    assert ["2027-01-15", "7", "2", "3", "0"] in rows
    assert ["2027-01-14", "0", "0", "0", "0"] in rows
    assert ["2027-01", "40"] in rows and ["2026-12", "?"] in rows


def test_web_stats_bounds_its_reads(capsys):
    with _WebClients() as c:
        assert c.run("web-stats", "--days", "0") == 1
        assert c.run("web-stats", "--days", str(mcp_users_web.MAX_DAYS + 1)) == 1
        assert c.run("web-stats", "--months", "0") == 1
    assert "--days must be between" in capsys.readouterr().err


def test_web_config_dry_run_shows_both_values_and_writes_nothing():
    with _WebClients() as c:
        c.get(web.config_key(), _config(cap=100, occupied=7))
        assert c.run("web-config", "--cap", "200") == 0
        c.verify()  # no update_item stubbed: a write would have raised
    assert "current: open=true pause_until=none cap=100 occupied=7 pass_required=true" in c.text
    assert "new:     open=true pause_until=none cap=200 occupied=7 pass_required=true" in c.text
    assert "not written; run again with --yes to write" in c.text


def test_web_config_writes_only_the_requested_attributes_conditionally():
    pause = "2027-01-15T09:30:00Z"
    with _WebClients() as c:
        c.get(web.config_key(), _config(cap=100, occupied=7, open=True))
        c.dynamo_stub.add_response("update_item", {}, {
            "TableName": WEB_TABLE, "Key": web.config_key(),
            "UpdateExpression": "SET #a0 = :v0, #a1 = :v1, #a2 = :v2",
            "ConditionExpression": ("attribute_exists(#pk) AND #a0 = :o0 AND #a1 = :o1 "
                                    "AND attribute_not_exists(#a2)"),
            "ExpressionAttributeNames": {"#pk": "pk", "#a0": "cap", "#a1": "open", "#a2": "pause_until"},
            "ExpressionAttributeValues": {":v0": {"N": "0"}, ":o0": {"N": "100"},
                                          ":v1": {"BOOL": False}, ":o1": {"BOOL": True},
                                          ":v2": {"N": str(WEB_NOW + 5400)}},
        })
        assert c.run("web-config", "--cap", "0", "--open", "false", "--pause-until", pause, "--yes") == 0
        c.verify()
    assert f"new:     open=false pause_until={pause} cap=none occupied=7 pass_required=true" in c.text
    assert c.lines[-1] == "written"


def test_web_config_creates_an_absent_row_without_occupied():
    with _WebClients() as c:
        c.get(web.config_key())
        c.dynamo_stub.add_response("update_item", {}, {
            "TableName": WEB_TABLE, "Key": web.config_key(), "UpdateExpression": "SET #a0 = :v0",
            "ConditionExpression": "attribute_not_exists(#pk) AND attribute_not_exists(#a0)",
            "ExpressionAttributeNames": {"#pk": "pk", "#a0": "pass_required"},
            "ExpressionAttributeValues": {":v0": {"BOOL": False}},
        })
        assert c.run("web-config", "--pass-required", "false", "--yes") == 0
        c.verify()
    assert "warning: without the pass" in c.text


def test_web_config_can_repair_a_bad_value_but_not_an_unknown_attribute(capsys):
    with _WebClients() as c:
        c.get(web.config_key(), {**_config(occupied=1), "cap": {"S": "lots"}})
        c.dynamo_stub.add_response("update_item", {}, {
            "TableName": WEB_TABLE, "Key": web.config_key(), "UpdateExpression": "SET #a0 = :v0",
            "ConditionExpression": "attribute_exists(#pk) AND #a0 = :o0",
            "ExpressionAttributeNames": {"#pk": "pk", "#a0": "cap"},
            "ExpressionAttributeValues": {":v0": {"N": "50"}, ":o0": {"S": "lots"}},
        })
        assert c.run("web-config", "--cap", "50", "--yes") == 0
        c.get(web.config_key(), {**_config(cap=5), "surprise": {"S": "x"}})
        assert c.run("web-config", "--cap", "50", "--yes") == 1
        c.verify()
    assert "current: MALFORMED (service closed)" in c.text
    assert "the row would stay malformed" in capsys.readouterr().err


def test_web_config_reports_a_concurrent_change(capsys):
    with _WebClients() as c:
        c.get(web.config_key(), _config(cap=100))
        c.dynamo_stub.add_client_error("update_item", "ConditionalCheckFailedException",
                                       expected_params={"TableName": WEB_TABLE, "Key": web.config_key(),
                                                        "UpdateExpression": ANY, "ConditionExpression": ANY,
                                                        "ExpressionAttributeNames": ANY,
                                                        "ExpressionAttributeValues": ANY})
        assert c.run("web-config", "--cap", "10", "--yes") == 1
        c.verify()
    assert "changed while running; nothing written" in capsys.readouterr().err


def test_web_config_rejects_bad_options_before_any_call(capsys):
    with _WebClients() as c:
        assert c.run("web-config") == 1
        assert c.run("web-config", "--cap", "-1") == 1
        assert c.run("web-config", "--cap", str(mcp_users_web.MAX_CAP + 1)) == 1
        for bad in ("2027-01-15T07:59:59Z", "2027-01-15T09:00:00", "2027-01-15T09:00:00+01:00", "soon"):
            assert c.run("web-config", "--pause-until", bad) == 1
        c.verify()
    err = capsys.readouterr().err
    assert "give at least one of" in err and "--cap must be between" in err
    assert "not in the future" in err and "ISO-8601 UTC" in err
    assert mcp_users_web.parse_pause("none", WEB_NOW) == 0
    assert mcp_users_web.parse_pause("2027-01-15T08:00:01+00:00", WEB_NOW) == WEB_NOW + 1
