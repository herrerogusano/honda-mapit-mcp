"""Offline tests for the multiuser identity Lambda (no network, no AWS)."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import logging
import re
import urllib.error
from typing import Any
from urllib.parse import quote

import pytest

from mapit import multiuser_identity as identity
from mapit.multiuser_common import (
    CONSENT_VERSION,
    LOCK_SECONDS,
    MAX_FAILED_LOGINS,
    TENANT_CLAIM,
    session_parameter_name,
    table_name,
)

NOW = 1_800_000_000
EMAIL = "friend@example.com"
TENANT = "0123456789abcdef0123456789abcdef"
PASSWORD = "S3cret-Pässword!"
REFRESH = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.refresh-token-value"
TOKEN = "Tk_invite-token-0123456789abcdefXYZ"
RESOURCE_URL = "https://abcde12345.execute-api.eu-west-1.amazonaws.com/mcp"
CLAUDE_ID = "claudeclient123"
CODEX_ID = "codexclient456"
MAPIT_CONFIG = {
    "region": "eu-west-1",
    "user_pool_id": "eu-west-1_AbCdEfGhI",
    "user_pool_client_id": "mapitclient1",
    "identity_pool_id": "eu-west-1:12345678-1234-1234-1234-123456789abc",
    "core_api_url": "https://core.prod.mapit.me",
    "geo_api_url": "https://geo.prod.mapit.me",
    "discovery_enabled": False,
    "http_timeout": 2,
}


# --- fakes ---------------------------------------------------------------------

class ConditionalCheckFailed(Exception):
    def __init__(self) -> None:
        super().__init__("conditional check failed")
        self.response = {"Error": {"Code": "ConditionalCheckFailedException"}}


def _value(attr: dict[str, str]) -> Any:
    if "N" in attr:
        return int(attr["N"])
    return attr["S"]


class FakeDynamo:
    """Tiny DynamoDB low-level client with just the expressions the Lambda uses."""

    def __init__(self) -> None:
        self.items: dict[str, dict[str, dict[str, str]]] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.fail_updates = False

    def get_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("get_item", copy.deepcopy(kwargs)))
        item = self.items.get(kwargs["Key"]["email"]["S"])
        return {"Item": copy.deepcopy(item)} if item is not None else {}

    def _clause(self, clause: str, item: dict | None, names: dict, values: dict) -> bool:
        clause = clause.strip()
        if clause.startswith("(") and clause.endswith(")"):
            return any(self._clause(part, item, names, values) for part in clause[1:-1].split(" OR "))
        match = re.fullmatch(r"attribute_exists\((\w+)\)", clause)
        if match:
            return item is not None and match.group(1) in item
        match = re.fullmatch(r"attribute_not_exists\((\w+)\)", clause)
        if match:
            return item is None or match.group(1) not in item
        if item is None:
            return False
        match = re.fullmatch(r"([#\w]+) IN \(([^)]*)\)", clause)
        if match:
            name = names.get(match.group(1), match.group(1))
            options = [_value(values[v.strip()]) for v in match.group(2).split(",")]
            return name in item and _value(item[name]) in options
        match = re.fullmatch(r"([#\w]+) (=|>|<=) (:\w+)", clause)
        if match:
            name = names.get(match.group(1), match.group(1))
            if name not in item:
                return False
            left, right = _value(item[name]), _value(values[match.group(3)])
            op = match.group(2)
            return left == right if op == "=" else left > right if op == ">" else left <= right
        raise AssertionError(f"unsupported clause {clause}")

    def update_item(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("update_item", copy.deepcopy(kwargs)))
        if self.fail_updates:
            raise RuntimeError("dynamodb unavailable")
        email = kwargs["Key"]["email"]["S"]
        names = kwargs.get("ExpressionAttributeNames", {})
        values = kwargs["ExpressionAttributeValues"]
        item = self.items.get(email)
        condition = kwargs.get("ConditionExpression")
        if condition and not all(self._clause(c, item, names, values) for c in condition.split(" AND ")):
            raise ConditionalCheckFailed()
        item = item if item is not None else {"email": {"S": email}}
        updated: dict[str, dict[str, str]] = {}
        parts = re.split(r"\b(SET|REMOVE|ADD)\b", kwargs["UpdateExpression"])
        for keyword, body in zip(parts[1::2], parts[2::2]):
            for piece in [p.strip() for p in body.split(",") if p.strip()]:
                if keyword == "SET":
                    left, right = [x.strip() for x in piece.split("=")]
                    name = names.get(left, left)
                    item[name] = copy.deepcopy(values[right])
                    updated[name] = item[name]
                elif keyword == "REMOVE":
                    item.pop(names.get(piece, piece), None)
                else:
                    left, right = piece.split()
                    current = int(item.get(left, {"N": "0"})["N"])
                    item[left] = {"N": str(current + int(values[right]["N"]))}
                    updated[left] = item[left]
        self.items[email] = item
        if kwargs.get("ReturnValues") == "UPDATED_NEW":
            return {"Attributes": copy.deepcopy(updated)}
        return {}


PUBLIC_PARAMETER = "/honda-mapit-mcp/dev/multiuser/public-config"
PUBLIC_CONFIG = {
    "resource_url": RESOURCE_URL, "claude_client_id": CLAUDE_ID,
    "codex_client_id": CODEX_ID, "codex_callback_port": 8789,
}


class FakeSSM:
    fail_put = False

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.parameters: dict[str, str] = {}
        self.get_calls: list[dict[str, Any]] = []
        self.public_value: Any = json.dumps(PUBLIC_CONFIG)
        self.fail_get = False

    def get_parameter(self, **kwargs: Any) -> dict[str, Any]:
        self.get_calls.append(dict(kwargs))
        if self.fail_get:
            raise RuntimeError("ssm unavailable")
        assert kwargs == {"Name": PUBLIC_PARAMETER, "WithDecryption": False}
        return {"Parameter": {"Name": PUBLIC_PARAMETER, "Type": "String", "Value": self.public_value}}

    def put_parameter(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(dict(kwargs))
        if self.fail_put:
            raise RuntimeError("ssm unavailable")
        self.parameters[kwargs["Name"]] = kwargs["Value"]
        return {"Version": len(self.calls), "Tier": "Standard"}


class FakeMapit:
    def __init__(self, mode: str = "ok") -> None:
        self.mode = mode
        self.calls: list[tuple[str, float]] = []

    def __call__(self, config: Any, email: str, password: str, deadline: float) -> str:
        assert config.discovery_enabled is False
        self.calls.append((email, deadline))
        if self.mode == "ok":
            assert password == PASSWORD
            return REFRESH
        if self.mode == "reject":
            raise identity.MapitCredentialsRejected()
        if self.mode == "timeout":
            raise identity.MapitLoginFailed()
        if self.mode == "leaky":
            raise RuntimeError(f"boom {password}")
        raise AssertionError("unknown mode")


class Context:
    def __init__(self, remaining_ms: int = 5000) -> None:
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self) -> int:
        return self.remaining_ms


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch):
    dynamo, ssm, mapit = FakeDynamo(), FakeSSM(), FakeMapit()
    identity.reset_clients()
    monkeypatch.setattr(identity, "_dynamodb_client_factory", lambda: dynamo)
    monkeypatch.setattr(identity, "_ssm_client_factory", lambda: ssm)
    monkeypatch.setattr(identity, "_mapit_login", mapit)
    monkeypatch.setattr(identity, "_wall_clock", lambda: float(NOW))
    for key, value in {
        "MAPIT_MCP_ENV": "dev",
        "AWS_REGION": "eu-west-1",
        "MULTIUSER_TABLE": table_name("dev"),
        "MAPIT_CONFIG_JSON": json.dumps(MAPIT_CONFIG),
        "MULTIUSER_RESOURCE_URL": RESOURCE_URL,
        "MULTIUSER_PUBLIC_CONFIG_PARAMETER": PUBLIC_PARAMETER,
        "MULTIUSER_CODEX_CALLBACK_PORT": "8789",
        "MULTIUSER_PRIVACY_CONTACT": "owner@example.com",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("MULTIUSER_CLAUDE_CLIENT_ID", raising=False)
    monkeypatch.delenv("MULTIUSER_CODEX_CLIENT_ID", raising=False)
    yield dynamo, ssm, mapit
    identity.reset_clients()


def _item(status: str = "accepted", **extra: Any) -> dict[str, dict[str, str]]:
    item = {
        "email": {"S": EMAIL},
        "tenant_id": {"S": TENANT},
        "status": {"S": status},
        "invite_token_sha256": {"S": hashlib.sha256(TOKEN.encode()).hexdigest()},
        "invite_expires_at": {"N": str(NOW + 3600)},
        "created_at": {"N": str(NOW - 100)},
        "updated_at": {"N": str(NOW - 100)},
    }
    for key, value in extra.items():
        item[key] = {"N": str(value)} if isinstance(value, int) else {"S": value}
    return item


def _migration_event(user: str = "  Friend@Example.com ", password: str = PASSWORD) -> dict[str, Any]:
    return {
        "version": "1",
        "triggerSource": "UserMigration_Authentication",
        "region": "eu-west-1",
        "userPoolId": "eu-west-1_Pool12345",
        "userName": user,
        "callerContext": {"awsSdkVersion": "x", "clientId": CLAUDE_ID},
        "request": {"password": password, "validationData": None, "clientMetadata": None},
        "response": {"userAttributes": None, "finalUserStatus": None, "messageAction": None},
    }


def _expect_error(event: dict[str, Any], message: str) -> pytest.ExceptionInfo:
    with pytest.raises(identity.IdentityError) as info:
        identity.handler(event, Context())
    assert str(info.value) == message
    assert info.value.__cause__ is None and info.value.__context__ is None
    return info


# --- UserMigration_Authentication -------------------------------------------------

def test_migration_success(fakes):
    dynamo, ssm, mapit = fakes
    dynamo.items[EMAIL] = _item("accepted", failed_logins=3, locked_until=NOW - 10)
    result = identity.handler(_migration_event(), Context())
    assert result["response"] == {
        "userAttributes": {"email": EMAIL, "email_verified": "true", "custom:tenant_id": TENANT},
        "finalUserStatus": "CONFIRMED",
        "messageAction": "SUPPRESS",
    }
    assert result["triggerSource"] == "UserMigration_Authentication"
    assert mapit.calls[0][0] == "Friend@Example.com"  # as typed, trimmed
    assert ssm.calls == [{
        "Name": session_parameter_name("dev", TENANT), "Value": REFRESH,
        "Type": "SecureString", "Overwrite": True, "Tier": "Standard",
    }]
    get = dynamo.calls[0]
    assert get[0] == "get_item" and get[1]["ConsistentRead"] is True
    assert get[1]["TableName"] == table_name("dev")
    stored = dynamo.items[EMAIL]
    assert stored["status"] == {"S": "active"}
    assert stored["failed_logins"] == {"N": "0"}
    assert "locked_until" not in stored
    assert stored["last_login_at"] == {"N": str(NOW)}
    assert stored["updated_at"] == {"N": str(NOW)}


def test_migration_budget_is_bounded(fakes):
    dynamo, _ssm, mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    start = identity._monotonic()
    identity.handler(_migration_event(), Context(5000))
    deadline = mapit.calls[0][1]
    assert deadline - start <= identity.MIGRATION_HARD_LIMIT_SECONDS - identity.POST_LOGIN_RESERVE_SECONDS + 0.05
    assert identity.SDK_CALL_RESERVE_SECONDS == 1.6
    assert identity.POST_LOGIN_RESERVE_SECONDS == pytest.approx(1.7)
    assert deadline - start >= 2.8  # ~3 s for MAPIT in the normal case
    mapit.calls.clear()
    start = identity._monotonic()
    identity.handler(_migration_event(), Context(4000))
    assert mapit.calls[0][1] - start <= 4.0 - identity.CONTEXT_SAFETY_SECONDS - identity.POST_LOGIN_RESERVE_SECONDS + 0.05


def test_sdk_timeouts_and_client_construction(monkeypatch):
    pytest.importorskip("botocore")
    config = identity.sdk_config()
    assert config.connect_timeout == 0.5
    assert config.read_timeout == 1
    assert config.retries == {"mode": "standard", "total_max_attempts": 1}
    assert config.proxies == {}
    # Worst case per SDK call fits in the reserve checked before each call.
    assert identity.SDK_CONNECT_TIMEOUT + identity.SDK_READ_TIMEOUT < identity.SDK_CALL_RESERVE_SECONDS
    assert identity._boto3 is not None  # imported at module import (init phase)
    captured: dict[str, Any] = {}

    class FakeBoto3:
        @staticmethod
        def client(service: str, **kwargs: Any) -> str:
            captured.update(kwargs, service=service)
            return "client"

    monkeypatch.setattr(identity, "_boto3", FakeBoto3)
    for key in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.setenv(key, "x")
    assert identity._make_ssm_client() == "client"
    assert captured["service"] == "ssm" and captured["region_name"] == "eu-west-1"
    assert captured["config"].connect_timeout == 0.5 and captured["config"].read_timeout == 1
    monkeypatch.delenv("AWS_SESSION_TOKEN")
    with pytest.raises(identity._ConfigInvalid):
        identity._make_dynamodb_client()


class SlowClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


@pytest.mark.parametrize("get_s,update_s,put_s", [
    (1.5, 1.5, 1.5), (0.05, 1.5, 1.5), (0.05, 0.05, 1.5), (0.05, 0.05, 0.05), (1.0, 0.2, 0.2),
])
def test_worst_case_stays_under_five_seconds(fakes, monkeypatch, get_s, update_s, put_s):
    """SDK calls take up to their 1.5 s worst case; MAPIT runs until its deadline."""
    dynamo, ssm, _mapit = fakes
    clock = SlowClock()
    monkeypatch.setattr(identity, "_monotonic", clock)
    dynamo.items[EMAIL] = _item("accepted")
    starts: list[tuple[str, float]] = []

    def slow(name, fn, seconds):
        def wrapper(**kwargs):
            starts.append((name, clock.now))
            clock.now += seconds
            return fn(**kwargs)
        return wrapper

    dynamo.get_item = slow("get", dynamo.get_item, get_s)
    dynamo.update_item = slow("update", dynamo.update_item, update_s)
    ssm.put_parameter = slow("put", ssm.put_parameter, put_s)

    def slow_mapit(config, email, password, deadline):
        if deadline - clock.now <= 0.05:  # same guard as the real login
            raise identity.MapitLoginFailed()
        clock.now = deadline  # login ends exactly at its deadline
        return REFRESH

    monkeypatch.setattr(identity, "_mapit_login", slow_mapit)
    started = clock.now
    try:
        identity.handler(_migration_event(), Context(5000))
        succeeded = True
    except identity.IdentityError as exc:
        assert str(exc) == identity.MSG_GENERIC
        succeeded = False
    assert clock.now - started < 5.0
    hard = started + identity.MIGRATION_HARD_LIMIT_SECONDS
    assert all(hard - at >= identity.SDK_CALL_RESERVE_SECONDS for _name, at in starts)
    names = [name for name, _at in starts]
    if "put" in names:
        assert names.index("update") < names.index("put")
    assert succeeded == (names == ["get", "update", "put"])
    if get_s >= 1.5:
        assert not succeeded and ssm.calls == []


def test_slow_mapit_leaves_no_time_for_put_then_retry_succeeds(fakes, monkeypatch):
    dynamo, ssm, _mapit = fakes
    clock = SlowClock()
    monkeypatch.setattr(identity, "_monotonic", clock)
    dynamo.items[EMAIL] = _item("accepted")
    original_update = dynamo.update_item

    def update_200ms(**kwargs):
        clock.now += 0.2
        return original_update(**kwargs)

    dynamo.update_item = update_200ms
    slow = {"on": True}

    def mapit_login(config, email, password, deadline):
        if slow["on"]:
            clock.now = deadline  # MAPIT uses its whole ~3 s budget
        return REFRESH

    monkeypatch.setattr(identity, "_mapit_login", mapit_login)
    started = clock.now
    _expect_error(_migration_event(), identity.MSG_GENERIC)
    assert clock.now - started < identity.MIGRATION_HARD_LIMIT_SECONDS
    assert dynamo.items[EMAIL]["status"] == {"S": "active"}  # update ran
    assert ssm.calls == []  # put skipped: < 1.6 s left
    slow["on"] = False
    clock.now += 10
    identity.handler(_migration_event(), Context())
    assert ssm.parameters == {session_parameter_name("dev", TENANT): REFRESH}


def test_mapit_receives_email_as_typed_and_table_uses_normalized(fakes):
    dynamo, _ssm, mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    result = identity.handler(_migration_event(user="  Friend@Example.com "), Context())
    assert mapit.calls[0][0] == "Friend@Example.com"
    assert dynamo.calls[0][1]["Key"] == {"email": {"S": EMAIL}}
    assert result["response"]["userAttributes"]["email"] == EMAIL


def test_item_update_precedes_session_put(fakes):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    order: list[str] = []
    original_update, original_put = dynamo.update_item, ssm.put_parameter
    dynamo.update_item = lambda **kw: (order.append("update"), original_update(**kw))[1]
    ssm.put_parameter = lambda **kw: (order.append("put"), original_put(**kw))[1]
    identity.handler(_migration_event(), Context())
    assert order == ["update", "put"]


@pytest.mark.parametrize("race", ["revoked", "relinked_other_tenant", "locked", "invited"])
def test_racing_change_stores_no_session(fakes, race):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    original_get = dynamo.get_item

    def racing_get(**kwargs):
        result = original_get(**kwargs)
        if race == "revoked":
            dynamo.items.pop(EMAIL)
        elif race == "relinked_other_tenant":
            dynamo.items[EMAIL]["tenant_id"] = {"S": "f" * 32}
        elif race == "locked":
            dynamo.items[EMAIL]["locked_until"] = {"N": str(NOW + 60)}
        else:
            dynamo.items[EMAIL]["status"] = {"S": "invited"}
        return result

    dynamo.get_item = racing_get
    _expect_error(_migration_event(), identity.MSG_GENERIC)
    assert ssm.calls == [] and ssm.parameters == {}


def test_session_put_failure_is_generic_and_retry_recovers(fakes):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    ssm.fail_put = True
    _expect_error(_migration_event(), identity.MSG_GENERIC)
    assert dynamo.items[EMAIL]["status"] == {"S": "active"}
    assert ssm.parameters == {}
    ssm.fail_put = False
    identity.handler(_migration_event(), Context())
    assert ssm.parameters == {session_parameter_name("dev", TENANT): REFRESH}


def test_not_invited_and_wrong_password_share_one_message(fakes):
    dynamo, _ssm, mapit = fakes
    with pytest.raises(identity.IdentityError) as missing:
        identity.handler(_migration_event(user="nobody@example.com"), Context())
    dynamo.items[EMAIL] = _item("accepted")
    mapit.mode = "reject"
    with pytest.raises(identity.IdentityError) as wrong:
        identity.handler(_migration_event(), Context())
    assert str(missing.value) == str(wrong.value) == (
        "Email o contraseña de MAPIT incorrectos, o esta cuenta no tiene invitación."
    )


def test_migration_retry_is_idempotent(fakes):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    first = identity.handler(_migration_event(), Context())
    second = identity.handler(_migration_event(), Context())
    assert first["response"] == second["response"]
    assert len(ssm.calls) == 2
    assert ssm.calls[0]["Name"] == ssm.calls[1]["Name"]
    assert all(call["Overwrite"] is True for call in ssm.calls)
    assert dynamo.items[EMAIL]["status"] == {"S": "active"}
    assert dynamo.items[EMAIL]["tenant_id"] == {"S": TENANT}


def test_migration_not_invited(fakes):
    _dynamo, ssm, mapit = fakes
    _expect_error(_migration_event(), identity.MSG_BAD_CREDENTIALS)
    assert mapit.calls == [] and ssm.calls == []


def test_migration_malformed_username_is_no_access(fakes):
    _expect_error(_migration_event(user="not-an-email"), identity.MSG_BAD_CREDENTIALS)


def test_migration_rejects_invited_without_consent(fakes):
    dynamo, ssm, mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    _expect_error(_migration_event(), identity.MSG_BAD_CREDENTIALS)
    assert mapit.calls == [] and ssm.calls == []


def test_migration_locked(fakes):
    dynamo, ssm, mapit = fakes
    dynamo.items[EMAIL] = _item("active", locked_until=NOW + 60)
    _expect_error(_migration_event(), identity.MSG_LOCKED)
    assert mapit.calls == [] and ssm.calls == []


def test_wrong_password_increments_and_locks(fakes):
    dynamo, ssm, mapit = fakes
    mapit.mode = "reject"
    dynamo.items[EMAIL] = _item("accepted")
    for attempt in range(1, MAX_FAILED_LOGINS):
        _expect_error(_migration_event(), identity.MSG_BAD_CREDENTIALS)
        assert dynamo.items[EMAIL]["failed_logins"] == {"N": str(attempt)}
        assert "locked_until" not in dynamo.items[EMAIL]
    _expect_error(_migration_event(), identity.MSG_LOCKED)
    assert dynamo.items[EMAIL]["locked_until"] == {"N": str(NOW + LOCK_SECONDS)}
    assert dynamo.items[EMAIL]["failed_logins"] == {"N": "0"}
    increments = [c for c in dynamo.calls if c[0] == "update_item" and "ADD" in c[1]["UpdateExpression"]]
    assert len(increments) == MAX_FAILED_LOGINS
    assert all("ADD failed_logins :one" in c[1]["UpdateExpression"] for c in increments)
    calls_before = len(mapit.calls)
    _expect_error(_migration_event(), identity.MSG_LOCKED)
    assert len(mapit.calls) == calls_before
    assert ssm.calls == []


def test_mapit_timeout_is_generic_and_not_counted(fakes):
    dynamo, ssm, mapit = fakes
    mapit.mode = "timeout"
    dynamo.items[EMAIL] = _item("accepted")
    _expect_error(_migration_event(), identity.MSG_GENERIC)
    assert "failed_logins" not in dynamo.items[EMAIL]
    assert ssm.calls == []


def test_store_failure_is_generic(fakes):
    dynamo, _ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    dynamo.fail_updates = True
    _expect_error(_migration_event(), identity.MSG_GENERIC)


def test_invalid_config_is_generic(fakes, monkeypatch):
    dynamo, _ssm, mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    bad = dict(MAPIT_CONFIG, discovery_enabled=True)
    monkeypatch.setenv("MAPIT_CONFIG_JSON", json.dumps(bad))
    _expect_error(_migration_event(), identity.MSG_GENERIC)
    monkeypatch.setenv("MAPIT_CONFIG_JSON", json.dumps(MAPIT_CONFIG))
    monkeypatch.setenv("MULTIUSER_TABLE", "other-table")
    _expect_error(_migration_event(), identity.MSG_GENERIC)
    assert mapit.calls == []


def test_password_never_leaks(fakes, caplog, capsys):
    dynamo, _ssm, mapit = fakes
    caplog.set_level(logging.DEBUG)
    dynamo.items[EMAIL] = _item("accepted")
    for mode, message in (
        ("leaky", identity.MSG_GENERIC),
        ("reject", identity.MSG_BAD_CREDENTIALS),
        ("timeout", identity.MSG_GENERIC),
    ):
        mapit.mode = mode
        info = _expect_error(_migration_event(), message)
        exc: BaseException | None = info.value
        while exc is not None:
            assert PASSWORD not in str(exc) and PASSWORD not in repr(exc)
            exc = exc.__cause__ or exc.__context__
        assert PASSWORD not in "".join(map(str, info.traceback))
    captured = capsys.readouterr()
    assert PASSWORD not in caplog.text
    assert PASSWORD not in captured.out and PASSWORD not in captured.err
    assert caplog.records == []


# --- default MAPIT login (fake opener, no network) --------------------------------

class FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._stream = io.BytesIO(body)
        self.closed = False

    def read1(self, size: int) -> bytes:
        return self._stream.read(size)

    def close(self) -> None:
        self.closed = True


class FakeOpener:
    def __init__(self, outcome: Any) -> None:
        self.outcome = outcome
        self.requests: list[tuple[Any, float]] = []

    def open(self, request: Any, timeout: float) -> Any:
        self.requests.append((request, timeout))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


def _http_error(status: int, payload: dict[str, Any]) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://cognito-idp.eu-west-1.amazonaws.com/", status, "err", None,
        io.BytesIO(json.dumps(payload).encode()),
    )


def _login_with(monkeypatch, outcome: Any) -> tuple[FakeOpener, Any]:
    opener = FakeOpener(outcome)
    monkeypatch.setattr(identity, "_opener_factory", lambda: opener)
    config = identity._mapit_config({"MAPIT_CONFIG_JSON": json.dumps(MAPIT_CONFIG)})
    deadline = identity._monotonic() + 3.0
    return opener, lambda: identity._default_mapit_login(config, EMAIL, PASSWORD, deadline)


def test_default_login_success_request_shape(monkeypatch):
    body = json.dumps({"AuthenticationResult": {"IdToken": "a.b.c", "RefreshToken": REFRESH}}).encode()
    opener, call = _login_with(monkeypatch, FakeResponse(200, body))
    assert call() == REFRESH
    request, timeout = opener.requests[0]
    assert request.full_url == "https://cognito-idp.eu-west-1.amazonaws.com/"
    assert request.get_method() == "POST"
    assert request.headers["X-amz-target"] == "AWSCognitoIdentityProviderService.InitiateAuth"
    payload = json.loads(request.data)
    assert payload["AuthFlow"] == "USER_PASSWORD_AUTH"
    assert payload["ClientId"] == "mapitclient1"
    assert payload["AuthParameters"] == {"USERNAME": EMAIL, "PASSWORD": PASSWORD}
    assert 0 < timeout <= 2.0


@pytest.mark.parametrize("kind", ["NotAuthorizedException", "com.amazon#UserNotFoundException"])
def test_default_login_rejection(monkeypatch, kind):
    _opener, call = _login_with(monkeypatch, _http_error(400, {"__type": kind, "message": "x"}))
    with pytest.raises(identity.MapitCredentialsRejected):
        call()


@pytest.mark.parametrize("outcome", [
    _http_error(400, {"__type": "TooManyRequestsException"}),
    _http_error(500, {"__type": "InternalErrorException"}),
    TimeoutError(),
    urllib.error.URLError("down"),
    FakeResponse(200, json.dumps({"ChallengeName": "NEW_PASSWORD_REQUIRED"}).encode()),
    FakeResponse(200, json.dumps({"AuthenticationResult": {"IdToken": "a.b.c"}}).encode()),
    FakeResponse(200, b"not json"),
    FakeResponse(200, b"{" + b" " * (70 * 1024) + b"}"),
    FakeResponse(302, b""),
])
def test_default_login_other_failures(monkeypatch, outcome):
    _opener, call = _login_with(monkeypatch, outcome)
    with pytest.raises(identity.MapitLoginFailed) as info:
        call()
    assert PASSWORD not in repr(info.value)


def test_default_login_expired_budget_makes_no_request(monkeypatch):
    opener = FakeOpener(FakeResponse(200, b"{}"))
    monkeypatch.setattr(identity, "_opener_factory", lambda: opener)
    config = identity._mapit_config({"MAPIT_CONFIG_JSON": json.dumps(MAPIT_CONFIG)})
    with pytest.raises(identity.MapitLoginFailed):
        identity._default_mapit_login(config, EMAIL, PASSWORD, identity._monotonic() - 1)
    assert opener.requests == []


# --- other triggers -------------------------------------------------------------------

def test_forgot_password(fakes):
    event = _migration_event()
    event["triggerSource"] = "UserMigration_ForgotPassword"
    _expect_error(event, identity.MSG_FORGOT_PASSWORD)


@pytest.mark.parametrize("source", [
    "TokenGeneration_HostedAuth", "TokenGeneration_Authentication",
    "TokenGeneration_RefreshTokens", "TokenGeneration_AuthenticateDevice",
    "TokenGeneration_NewPasswordChallenge",
])
def test_token_generation_adds_tenant_claim(fakes, source):
    event = {
        "version": "2", "triggerSource": source, "userName": "x",
        "request": {"userAttributes": {"sub": "s", "custom:tenant_id": TENANT}, "scopes": []},
        "response": {"claimsAndScopeOverrideDetails": None},
    }
    result = identity.handler(event, Context())
    assert result["response"] == {
        "claimsAndScopeOverrideDetails": {
            "accessTokenGeneration": {"claimsToAddOrOverride": {TENANT_CLAIM: TENANT}},
        },
    }


@pytest.mark.parametrize("attributes", [{}, {"custom:tenant_id": "ABC"}, {"custom:tenant_id": TENANT + "0"}])
def test_token_generation_missing_or_invalid(fakes, attributes):
    event = {"triggerSource": "TokenGeneration_HostedAuth", "request": {"userAttributes": attributes}, "response": {}}
    _expect_error(event, identity.MSG_GENERIC)


@pytest.mark.parametrize("source", ["PreSignUp_SignUp", "TokenGeneration_ClientCredentials", None])
def test_unknown_trigger(fakes, source):
    _expect_error({"triggerSource": source, "request": {}, "response": {}}, identity.MSG_GENERIC)


# --- HTTP pages ----------------------------------------------------------------------

def _http(method: str, path: str, *, query: str = "", body: str | None = None,
          b64: bool = False, content_type: str = "application/x-www-form-urlencoded") -> dict[str, Any]:
    event: dict[str, Any] = {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": query,
        "headers": {"content-type": content_type},
        "requestContext": {"http": {"method": method, "path": path}},
        "isBase64Encoded": b64,
    }
    if body is not None:
        event["body"] = base64.b64encode(body.encode()).decode() if b64 else body
    return event


def _assert_headers(response: dict[str, Any]) -> None:
    headers = response["headers"]
    assert headers["content-type"] == "text/html; charset=utf-8"
    assert headers["cache-control"] == "no-store"
    assert headers["content-security-policy"] == (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    )
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-frame-options"] == "DENY"
    assert response["isBase64Encoded"] is False
    assert "<script" not in response["body"].lower()


def _form(email: str = EMAIL, token: str = TOKEN, consent: bool = True) -> str:
    body = f"email={quote(email)}&token={quote(token)}"
    return body + ("&consent=on" if consent else "")


def test_get_form_renders_without_lookup(fakes):
    dynamo, _ssm, _mapit = fakes
    response = identity.handler(_http("GET", "/invitacion", query=f"email={quote(EMAIL)}&token={TOKEN}"), None)
    assert response["statusCode"] == 200
    _assert_headers(response)
    assert f'value="{EMAIL}"' in response["body"] and f'value="{TOKEN}"' in response["body"]
    assert 'name="consent"' in response["body"] and "/privacidad" in response["body"]
    assert dynamo.calls == []
    assert _ssm.get_calls == []


def test_get_form_escapes_xss(fakes):
    payload = '"><script>alert(1)</script>@example.com'
    response = identity.handler(_http("GET", "/invitacion", query=f"email={quote(payload)}&token={TOKEN}"), None)
    _assert_headers(response)
    assert response["statusCode"] == 400
    assert "<script>" not in response["body"] and "alert(1)" not in response["body"]
    # The renderer itself escapes every interpolated value (defence in depth).
    html = identity.pages.render_consent_form(payload, '"><b>x</b>')
    assert "<script>" not in html and "<b>x</b>" not in html
    assert "&quot;&gt;&lt;script&gt;" in html
    html = identity.pages.render_success('"><i>u</i>', "<c>", "<d>", 8789)
    assert "<i>u</i>" not in html and "<c>" not in html and "<d>" not in html
    assert "<x>" not in identity.pages.render_privacy("<x>@example.com")


def test_get_form_missing_params_is_generic(fakes):
    response = identity.handler(_http("GET", "/invitacion", query="email=x"), None)
    assert response["statusCode"] == 400
    _assert_headers(response)
    assert identity.pages.GENERIC_INVITATION_ERROR in response["body"]


def test_post_success_shows_instructions(fakes):
    dynamo, _ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
    assert response["statusCode"] == 200
    _assert_headers(response)
    body = response["body"]
    assert RESOURCE_URL in body and CLAUDE_ID in body and CODEX_ID in body and "8789" in body
    assert f"codex mcp add honda-mapit --url {RESOURCE_URL} --oauth-client-id {CODEX_ID}" in body
    assert "codex mcp login honda-mapit" in body
    assert "Inicia sesión con tu email y contraseña de MAPIT" in body
    stored = dynamo.items[EMAIL]
    assert stored["status"] == {"S": "accepted"}
    assert stored["consent_at"] == {"N": str(NOW)}
    assert stored["consent_version"] == {"S": CONSENT_VERSION}
    update = [c for c in dynamo.calls if c[0] == "update_item"][0][1]
    assert "invite_token_sha256 = :hash" in update["ConditionExpression"]


def test_post_accepted_again_and_base64(fakes):
    dynamo, _ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("accepted")
    response = identity.handler(_http("POST", "/invitacion", body=_form(email="FRIEND@example.com"), b64=True), None)
    assert response["statusCode"] == 200
    assert dynamo.items[EMAIL]["status"] == {"S": "accepted"}


@pytest.mark.parametrize("case", ["wrong_token", "expired", "no_consent", "unknown", "content_type", "duplicate"])
def test_post_errors_are_generic(fakes, case):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    if case == "expired":
        dynamo.items[EMAIL]["invite_expires_at"] = {"N": str(NOW - 1)}
    body = _form(
        email="nobody@example.com" if case == "unknown" else EMAIL,
        token="Wrong-token-0123456789abcdef" if case == "wrong_token" else TOKEN,
        consent=case != "no_consent",
    )
    if case == "duplicate":
        body += "&consent=on"
    content_type = "text/plain" if case == "content_type" else "application/x-www-form-urlencoded"
    response = identity.handler(_http("POST", "/invitacion", body=body, content_type=content_type), None)
    assert response["statusCode"] == 400
    _assert_headers(response)
    assert identity.pages.GENERIC_INVITATION_ERROR in response["body"]
    assert dynamo.items[EMAIL]["status"] == {"S": "invited"}
    assert "consent_at" not in dynamo.items[EMAIL]
    assert ssm.get_calls == []


def test_post_active_user_keeps_status_and_sees_instructions(fakes):
    dynamo, _ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("active", last_login_at=NOW - 50, consent_at=NOW - 500)
    response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
    assert response["statusCode"] == 200
    assert CLAUDE_ID in response["body"]
    stored = dynamo.items[EMAIL]
    assert stored["status"] == {"S": "active"}
    assert stored["consent_at"] == {"N": str(NOW)}
    assert stored["last_login_at"] == {"N": str(NOW - 50)}


def test_post_status_race_is_generic(fakes):
    dynamo, _ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    original = dynamo.get_item

    def racing_get(**kwargs):
        result = original(**kwargs)
        dynamo.items[EMAIL]["status"] = {"S": "active"}  # concurrent change
        return result

    dynamo.get_item = racing_get
    response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
    assert response["statusCode"] == 400
    assert "consent_at" not in dynamo.items[EMAIL]


def test_public_config_is_cached_per_container(fakes):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    for _ in range(2):
        response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
        assert response["statusCode"] == 200
    assert len(ssm.get_calls) == 1


@pytest.mark.parametrize("value", [
    json.dumps(dict(PUBLIC_CONFIG, resource_url="https://zzzzz99999.execute-api.eu-west-1.amazonaws.com/mcp")),
    json.dumps(dict(PUBLIC_CONFIG, codex_callback_port=9999)),
    json.dumps(dict(PUBLIC_CONFIG, codex_callback_port="8789")),
    json.dumps(dict(PUBLIC_CONFIG, extra="x")),
    json.dumps({k: v for k, v in PUBLIC_CONFIG.items() if k != "claude_client_id"}),
    json.dumps(dict(PUBLIC_CONFIG, claude_client_id="<bad>")),
    '{"resource_url": "a", "resource_url": "b"}',
    "not json",
    "",
    None,
])
def test_public_config_invalid_returns_503(fakes, value):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    ssm.public_value = value
    response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
    assert response["statusCode"] == 503
    _assert_headers(response)
    assert CLAUDE_ID not in response["body"]


def test_public_config_read_failure_returns_503(fakes):
    dynamo, ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    ssm.fail_get = True
    response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
    assert response["statusCode"] == 503
    ssm.fail_get = False
    response = identity.handler(_http("POST", "/invitacion", body=_form()), None)
    assert response["statusCode"] == 200


def test_wrong_public_config_parameter_name_returns_503(fakes, monkeypatch):
    monkeypatch.setenv("MULTIUSER_PUBLIC_CONFIG_PARAMETER", "/honda-mapit-mcp/prod/multiuser/public-config")
    response = identity.handler(_http("GET", "/invitacion", query=f"email={quote(EMAIL)}&token={TOKEN}"), None)
    assert response["statusCode"] == 503
    assert identity.public_config_parameter_name("dev") == PUBLIC_PARAMETER


def test_post_body_too_large(fakes):
    dynamo, _ssm, _mapit = fakes
    dynamo.items[EMAIL] = _item("invited")
    body = _form() + "&pad=" + "x" * 5000
    for b64 in (False, True):
        response = identity.handler(_http("POST", "/invitacion", body=body, b64=b64), None)
        assert response["statusCode"] == 400
    assert dynamo.calls == []


def test_privacy_page(fakes):
    response = identity.handler(_http("GET", "/privacidad"), None)
    assert response["statusCode"] == 200
    _assert_headers(response)
    body = response["body"]
    assert "owner@example.com" in body and "Este proyecto no está afiliado a Honda" in body
    assert "borrar_mis_datos" in body and "12 meses" in body and "eu-west-1" in body


@pytest.mark.parametrize("method,path", [("GET", "/"), ("POST", "/privacidad"), ("PUT", "/invitacion"), ("GET", "/mcp")])
def test_not_found(fakes, method, path):
    response = identity.handler(_http(method, path), None)
    assert response["statusCode"] == 404
    _assert_headers(response)


def test_misconfigured_api_returns_503(fakes, monkeypatch):
    monkeypatch.setenv("MULTIUSER_RESOURCE_URL", "http://evil.example/mcp")
    response = identity.handler(_http("GET", "/invitacion", query=f"email={quote(EMAIL)}&token={TOKEN}"), None)
    assert response["statusCode"] == 503
    _assert_headers(response)
    monkeypatch.setenv("MULTIUSER_PRIVACY_CONTACT", "nope")
    assert identity.handler(_http("GET", "/privacidad"), None)["statusCode"] == 503


def test_unrecognized_event_raises(fakes):
    with pytest.raises(identity.IdentityError):
        identity.handler({"foo": "bar"}, None)
