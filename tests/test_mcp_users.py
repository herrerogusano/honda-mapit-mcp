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
