"""Offline tests for the public web mode of the identity Lambda (no network, no AWS)."""

from __future__ import annotations

import base64
import copy
import json
import logging
import re
from typing import Any

import pytest

from mapit import multiuser_identity as identity
from mapit import public_identity as public
from mapit import public_web as web

NOW = 1_800_000_000  # 2027-01-15 08:00 UTC
TODAY = "2027-01-15"
EMAIL = "rider@example.com"
TYPED = "  Rider@Example.com "
PASSWORD = "S3cret-Pässword!"
REFRESH = "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.refresh-token-value"
TENANT = "fedcba9876543210fedcba9876543210"
KEY = bytes(range(32))
FP = web.email_fingerprint(KEY, EMAIL)
TABLE = web.web_table_name("dev")
KEY_PARAMETER = web.fingerprint_key_parameter_name("dev")
SESSION_PARAMETER = web.web_session_parameter_name("dev", TENANT)
MAPIT_CONFIG = {
    "region": "eu-west-1", "user_pool_id": "eu-west-1_AbCdEfGhI", "user_pool_client_id": "mapitclient1",
    "identity_pool_id": "eu-west-1:12345678-1234-1234-1234-123456789abc",
    "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
    "discovery_enabled": False, "http_timeout": 2,
}


# --- fakes -------------------------------------------------------------------------

class ClientError(Exception):
    def __init__(self, code: str, **extra: Any) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code, "Message": "x"}, **extra}


class _Missing:
    """A missing attribute: every comparison is false, as in DynamoDB."""

    def _false(self, _other: object) -> bool:
        return False

    __eq__ = __ne__ = __lt__ = __le__ = __gt__ = __ge__ = _false  # type: ignore[assignment]


def _value(attr: dict[str, str]) -> Any:
    return int(attr["N"]) if "N" in attr else attr["S"] if "S" in attr else attr["BOOL"]


_TOKEN_RE = re.compile(r"attribute_(not_)?exists\((\w+)\)|:\w+|<>|<=|>=|=|<|>|\(|\)|\w+")


def _resolve(expression: str, names: dict) -> str:
    """Substitute ExpressionAttributeNames; every name must be defined and used."""
    used = set(re.findall(r"#\w+", expression))
    assert used == set(names), (used, names)
    return re.sub(r"#\w+", lambda m: names[m.group(0)], expression)


def _condition(expression: str, item: dict | None, values: dict) -> bool:
    out = []
    for match in _TOKEN_RE.finditer(expression):
        token = match.group(0)
        if token.startswith("attribute_"):
            out.append(f"({'not ' if match.group(1) else ''}({match.group(2)!r} in item))")
        elif token.startswith(":"):
            out.append(f"V({token!r})")
        elif token in {"AND", "OR"}:
            out.append(token.lower())
        elif token in {"<>", "="}:
            out.append({"<>": "!=", "=": "=="}[token])
        elif token in {"<", ">", "<=", ">=", "(", ")"}:
            out.append(token)
        else:
            out.append(f"A({token!r})")
    row = item or {}
    scope = {"item": row, "V": lambda k: _value(values[k]),
             "A": lambda n: _value(row[n]) if n in row else _Missing()}
    return bool(eval(" ".join(out), {"__builtins__": {}}, scope))  # noqa: S307 - test-only grammar


def _check_values(op: dict) -> None:
    """DynamoDB rejects unused or undefined expression attribute values."""
    used = set(re.findall(r":\w+", op.get("UpdateExpression", "") + " " + op.get("ConditionExpression", "")))
    assert used == set(op.get("ExpressionAttributeValues", {})), (used, op)


def _update(item: dict, expression: str, values: dict) -> dict:
    item = copy.deepcopy(item)
    parts = re.split(r"\b(SET|ADD)\b", expression)
    for keyword, body in zip(parts[1::2], parts[2::2]):
        for piece in [p.strip() for p in body.split(",") if p.strip()]:
            if keyword == "ADD":
                name, ref = piece.split()
                item[name] = {"N": str(_value(item.get(name, {"N": "0"})) + _value(values[ref]))}
                continue
            name, right = [x.strip() for x in piece.split("=")]
            match = re.fullmatch(r"(\w+) - (:\w+)", right)
            if match:
                item[name] = {"N": str(_value(item[match.group(1)]) - _value(values[match.group(2)]))}
            else:
                item[name] = copy.deepcopy(values[right])
    return item


class FakeTable:
    def __init__(self) -> None:
        self.items: dict[str, dict] = {}
        self.calls: list[tuple[str, Any]] = []
        self.before_transact: Any = None
        self.before_update: Any = None  # runs once, before the next update_item
        self.fail: set[str] = set()

    def put(self, pk: str, **attrs: Any) -> None:
        self.items[pk] = {"pk": {"S": pk}, **{k: ({"N": str(v)} if type(v) is int else {"BOOL": v}
                                                  if type(v) is bool else {"S": v}) for k, v in attrs.items()}}

    def n(self, pk: str, name: str) -> int | None:
        attr = self.items.get(pk, {}).get(name)
        return int(attr["N"]) if attr else None

    def writes(self) -> list[tuple[str, Any]]:
        return [c for c in self.calls if c[0] != "batch_get_item"]

    def _pk(self, op: dict) -> str:
        assert op["TableName"] == TABLE
        key = op["Key"] if "Key" in op else {"pk": op["Item"]["pk"]}
        assert set(key) == {"pk"}
        return key["pk"]["S"]

    def batch_get_item(self, **kwargs: Any) -> dict:
        self.calls.append(("batch_get_item", copy.deepcopy(kwargs)))
        if "batch_get_item" in self.fail:
            raise ClientError("ProvisionedThroughputExceededException")
        (table, request), = kwargs["RequestItems"].items()
        assert table == TABLE and request["ConsistentRead"] is True and set(request) == {"Keys", "ConsistentRead"}
        pks = [k["pk"]["S"] for k in request["Keys"]]
        assert len(set(pks)) == len(pks) <= 100
        return {"Responses": {table: [copy.deepcopy(self.items[p]) for p in pks if p in self.items]},
                "UnprocessedKeys": {}}

    @staticmethod
    def _named(op: dict) -> dict:
        names = op.get("ExpressionAttributeNames", {})
        text = " ".join(op.get(k, "") for k in ("UpdateExpression", "ConditionExpression"))
        _resolve(text, names)
        return {**op, **{k: _resolve(op[k], {n: v for n, v in names.items() if n in op[k]})
                         for k in ("UpdateExpression", "ConditionExpression") if k in op}}

    def _apply(self, kind: str, op: dict) -> None:
        op = self._named(op)
        pk = self._pk(op)
        if kind == "Put":
            self.items[pk] = copy.deepcopy(op["Item"])
        else:
            self.items[pk] = _update(self.items.get(pk, {"pk": {"S": pk}}), op["UpdateExpression"],
                                     op.get("ExpressionAttributeValues", {}))

    def _ok(self, op: dict) -> bool:
        op = self._named(op)
        _check_values(op)
        condition = op.get("ConditionExpression")
        return not condition or _condition(condition, self.items.get(self._pk(op)),
                                           op.get("ExpressionAttributeValues", {}))

    def update_item(self, **kwargs: Any) -> dict:
        self.calls.append(("update_item", copy.deepcopy(kwargs)))
        if "update_item" in self.fail:
            raise ClientError("InternalServerError")
        if self.before_update:
            hook, self.before_update = self.before_update, None
            hook(self)
        if not self._ok(kwargs):
            pk = self._pk(kwargs)
            extra = ({"Item": copy.deepcopy(self.items[pk])}
                     if kwargs.get("ReturnValuesOnConditionCheckFailure") == "ALL_OLD" and pk in self.items else {})
            raise ClientError("ConditionalCheckFailedException", **extra)
        self._apply("Update", kwargs)
        return {}

    def transact_write_items(self, **kwargs: Any) -> dict:
        assert set(kwargs) == {"TransactItems"}
        self.calls.append(("transact_write_items", copy.deepcopy(kwargs)))
        if self.before_transact:
            self.before_transact(self)
        if "transact_write_items" in self.fail:
            raise ClientError("InternalServerError")
        ops = [next(iter(entry.items())) for entry in kwargs["TransactItems"]]
        assert len({self._pk(op) for _, op in ops}) == len(ops)  # one op per item
        reasons, failed = [], False
        for _kind, op in ops:
            if self._ok(op):
                reasons.append({"Code": "None"})
            else:
                failed = True
                reason = {"Code": "ConditionalCheckFailed", "Message": "x"}
                if op.get("ReturnValuesOnConditionCheckFailure") == "ALL_OLD" and self._pk(op) in self.items:
                    reason["Item"] = copy.deepcopy(self.items[self._pk(op)])
                reasons.append(reason)
        if failed:
            raise ClientError("TransactionCanceledException", CancellationReasons=reasons)
        for kind, op in ops:
            self._apply(kind, op)
        return {}


class FakeSSM:
    def __init__(self) -> None:
        self.parameters = {KEY_PARAMETER: base64.b64encode(KEY).decode()}
        self.puts: list[dict] = []
        self.fail_put = False

    def get_parameter(self, **kwargs: Any) -> dict:
        assert kwargs == {"Name": KEY_PARAMETER, "WithDecryption": True}
        return {"Parameter": {"Name": KEY_PARAMETER, "Type": "SecureString", "Value": self.parameters[KEY_PARAMETER]}}

    def put_parameter(self, **kwargs: Any) -> dict:
        self.puts.append(dict(kwargs))
        if self.fail_put:
            raise ClientError("ThrottlingException")
        self.parameters[kwargs["Name"]] = kwargs["Value"]
        return {"Version": 1, "Tier": "Standard"}


class FakeMapit:
    def __init__(self) -> None:
        self.mode = "ok"
        self.calls: list[tuple[str, float]] = []

    def __call__(self, config: Any, email: str, password: str, deadline: float) -> str:
        self.calls.append((email, deadline))
        assert password == PASSWORD
        if self.mode == "reject":
            raise identity.MapitCredentialsRejected()
        if self.mode == "timeout":
            raise identity.MapitLoginFailed()
        return REFRESH


class Context:
    def get_remaining_time_in_millis(self) -> int:
        return 5000


@pytest.fixture
def fakes(monkeypatch: pytest.MonkeyPatch):
    table, ssm, mapit = FakeTable(), FakeSSM(), FakeMapit()
    identity.reset_clients()
    monkeypatch.setattr(identity, "_dynamodb_client_factory", lambda: table)
    monkeypatch.setattr(identity, "_ssm_client_factory", lambda: ssm)
    monkeypatch.setattr(identity, "_mapit_login", mapit)
    monkeypatch.setattr(identity, "_wall_clock", lambda: float(NOW))
    monkeypatch.setattr(public, "_token_hex", lambda n: TENANT)
    monkeypatch.delenv("MULTIUSER_TABLE", raising=False)
    for key, value in {"MAPIT_MCP_ENV": "dev", "AWS_REGION": "eu-west-1", "MAPIT_WEB_MODE": "public",
                       "MAPIT_CONFIG_JSON": json.dumps(MAPIT_CONFIG)}.items():
        monkeypatch.setenv(key, value)
    table.put(f"pass#{FP}", attempts_left=3, issued_at=NOW - 60, expires_at=NOW + 240)
    yield table, ssm, mapit
    identity.reset_clients()


def _migration(user: str = TYPED) -> dict:
    return {
        "version": "1", "triggerSource": "UserMigration_Authentication", "region": "eu-west-1",
        "userPoolId": "eu-west-1_Pool12345", "userName": user,
        "callerContext": {"awsSdkVersion": "x", "clientId": "webclient1"},
        "request": {"password": PASSWORD, "validationData": None, "clientMetadata": None},
        "response": {"userAttributes": None, "finalUserStatus": None, "messageAction": None},
    }


def _pre_auth(not_found: bool | None) -> dict:
    request: dict[str, Any] = {"userAttributes": {} if not_found else {"email": EMAIL, "sub": "s"},
                               "validationData": {}}
    if not_found is not None:
        request["userNotFound"] = not_found
    return {"version": "1", "triggerSource": "PreAuthentication_Authentication", "region": "eu-west-1",
            "userPoolId": "eu-west-1_Pool12345", "userName": TYPED,
            "callerContext": {"awsSdkVersion": "x", "clientId": "webclient1"},
            "request": request, "response": {}}


def _token(source: str = "TokenGeneration_HostedAuth") -> dict:
    return {"version": "2", "triggerSource": source, "region": "eu-west-1", "userPoolId": "eu-west-1_Pool12345",
            "userName": EMAIL, "callerContext": {"awsSdkVersion": "x", "clientId": "webclient1"},
            "request": {"userAttributes": {"email": EMAIL, "custom:tenant_id": TENANT, "sub": "s"},
                        "groupConfiguration": {}, "scopes": ["openid"]},
            "response": {"claimsAndScopeOverrideDetails": None}}


def _fails(event: dict, message: str) -> None:
    with pytest.raises(identity.IdentityError) as info:
        identity.handler(event, Context())
    assert str(info.value) == message
    assert info.value.__cause__ is None and info.value.__context__ is None


def _person(table: FakeTable, **attrs: Any) -> None:
    table.put(f"person#{FP}", first_login_at=NOW - 86400, last_login_at=NOW - 86400, login_count=1,
              consent_version="v0", consent_at=NOW - 86400, expires_at=NOW + 1000, **attrs)


# --- UserMigration_Authentication: admission -----------------------------------------

def test_new_person_is_admitted_with_usage_row_and_session(fakes):
    table, ssm, mapit = fakes
    result = identity.handler(_migration(), Context())
    assert result["response"] == {
        "userAttributes": {"email": EMAIL, "email_verified": "true", "custom:tenant_id": TENANT},
        "finalUserStatus": "CONFIRMED", "messageAction": "SUPPRESS"}
    assert mapit.calls[0][0] == "Rider@Example.com"
    assert ssm.puts == [{"Name": SESSION_PARAMETER, "Value": REFRESH, "Type": "SecureString",
                         "Overwrite": False, "Tier": "Standard"}]
    person = table.items[f"person#{FP}"]
    assert person["consent_version"] == {"S": public.PUBLIC_CONSENT_VERSION}
    assert table.n(f"person#{FP}", "consent_at") == NOW
    assert table.n(f"person#{FP}", "expires_at") == web.person_expires_at(NOW)
    assert table.items[f"usage#{TENANT}"] == {
        "pk": {"S": f"usage#{TENANT}"}, "person_fp": {"S": FP}, "login_at": {"N": str(NOW)},
        "calls": {"N": "0"}, "expires_at": {"N": str(web.session_usage_expires_at(NOW))}}
    assert table.n("config", "occupied") == 1
    assert table.n(f"day#{TODAY}", "new_people") == 1
    assert table.n(f"pass#{FP}", "attempts_left") == 2  # spent before MAPIT, whatever it answers
    assert table.n(f"pass#{FP}", "migration_spent_at") == NOW
    writes = [c[0] for c in table.writes()]
    assert writes == ["update_item", "transact_write_items"]  # pass spend, then admission
    reads = [c for c in table.calls if c[0] == "batch_get_item"]
    assert len(reads) == 1 and len(reads[0][1]["RequestItems"][TABLE]["Keys"]) == 7
    assert EMAIL not in json.dumps(table.items) and "Rider" not in json.dumps(table.items)


def test_returning_person_passes_with_full_cap(fakes):
    table, ssm, _ = fakes
    table.put("config", cap=2, occupied=2)
    _person(table)
    identity.handler(_migration(), Context())
    assert table.n("config", "occupied") == 2 and f"day#{TODAY}" not in table.items
    assert table.n(f"person#{FP}", "last_login_at") == NOW
    assert table.items[f"person#{FP}"]["consent_version"] == {"S": "v0"}
    assert ssm.puts[0]["Name"] == SESSION_PARAMETER


def test_new_person_with_full_cap_is_told_only_after_mapit(fakes):
    table, ssm, mapit = fakes
    table.put("config", cap=2, occupied=2)
    _fails(_migration(), public.MSG_FULL)
    assert len(mapit.calls) == 1 and ssm.puts == []
    assert f"person#{FP}" not in table.items and table.n("config", "occupied") == 2
    assert table.n(f"day#{TODAY}", "cap_rejections") == 1


@pytest.mark.parametrize("returning", [False, True])
def test_wrong_password_with_full_cap_says_the_same_for_any_email(fakes, returning):
    table, _, mapit = fakes
    table.put("config", cap=1, occupied=1)
    if returning:
        _person(table)
    mapit.mode = "reject"
    _fails(_migration(), public.MSG_BAD_CREDENTIALS)


def test_cap_zero_means_no_cap(fakes):
    table, ssm, _ = fakes
    table.put("config", cap=0, occupied=500)
    identity.handler(_migration(), Context())
    assert table.n("config", "occupied") == 501 and ssm.puts


def test_seat_taken_by_a_racing_login_says_full_and_takes_nothing(fakes):
    table, ssm, _ = fakes
    table.put("config", cap=100, occupied=99)
    table.before_transact = lambda t: t.put("config", cap=100, occupied=100)
    _fails(_migration(), public.MSG_FULL)
    # The session was stored first under a random tenant no token carries;
    # the sweep deletes it by age. No person, usage row or seat.
    assert [p["Name"] for p in ssm.puts] == [SESSION_PARAMETER]
    assert f"usage#{TENANT}" not in table.items and f"person#{FP}" not in table.items
    assert table.n("config", "occupied") == 100


class _Budget:
    """_has_sdk_time that says no once ``cut`` becomes true."""

    def __init__(self, cut: Any) -> None:
        self.cut = cut

    def __call__(self, deadline: float) -> bool:
        return not self.cut()


def test_no_time_for_the_session_stores_nothing(fakes, monkeypatch):
    table, ssm, mapit = fakes
    monkeypatch.setattr(identity, "_has_sdk_time", _Budget(lambda: bool(mapit.calls)))
    _fails(_migration(), public.MSG_GENERIC)
    assert ssm.puts == [] and f"person#{FP}" not in table.items and "config" not in table.items


def test_no_time_for_the_admission_takes_no_seat(fakes, monkeypatch):
    table, ssm, _ = fakes
    monkeypatch.setattr(identity, "_has_sdk_time", _Budget(lambda: bool(ssm.puts)))
    _fails(_migration(), public.MSG_GENERIC)
    assert [p["Name"] for p in ssm.puts] == [SESSION_PARAMETER]  # left to the sweep
    assert f"person#{FP}" not in table.items and f"usage#{TENANT}" not in table.items
    assert "config" not in table.items and f"day#{TODAY}" not in table.items


def test_expired_person_row_counts_as_new(fakes):
    table, _, _ = fakes
    _person(table)
    table.items[f"person#{FP}"]["expires_at"] = {"N": str(NOW)}
    identity.handler(_migration(), Context())
    assert table.n("config", "occupied") == 1
    assert table.items[f"person#{FP}"]["consent_version"] == {"S": public.PUBLIC_CONSENT_VERSION}


def test_daily_limit_is_checked_after_mapit_and_stores_nothing(fakes):
    table, ssm, mapit = fakes
    _person(table, login_day=TODAY, login_day_count=web.DAILY_LOGINS_PER_PERSON)
    _fails(_migration(), public.MSG_DAILY_LIMIT)
    assert len(mapit.calls) == 1 and ssm.puts == [] and f"usage#{TENANT}" not in table.items


def test_session_put_failure_is_generic(fakes):
    _, ssm, _ = fakes
    ssm.fail_put = True
    _fails(_migration(), public.MSG_GENERIC)


def test_mapit_budget_matches_invitation_mode(fakes):
    _, _, mapit = fakes
    start = identity._monotonic()
    identity.handler(_migration(), Context())
    budget = mapit.calls[0][1] - start
    assert 2.8 <= budget <= identity.MIGRATION_HARD_LIMIT_SECONDS - identity.POST_LOGIN_RESERVE_SECONDS + 0.05


# --- refusals before MAPIT ---------------------------------------------------------------

WINDOW = web.breaker_window(NOW)


@pytest.mark.parametrize("setup, message", [
    (lambda t: t.put("config", open=False), public.MSG_PAUSED),
    (lambda t: t.put("config", pause_until=NOW + 60), public.MSG_PAUSED),
    (lambda t: t.put("config", open="yes"), public.MSG_PAUSED),  # malformed row: closed
    (lambda t: t.put(f"breaker#{WINDOW - 1}", rejections=20, open_until=NOW + 60, expires_at=NOW + 900),
     public.MSG_PAUSED),
    (lambda t: t.put(f"breaker#{WINDOW}", rejections=20, expires_at=NOW + 900), public.MSG_PAUSED),
    (lambda t: t.put(f"attempts#{FP}", failed_logins=0, locked_until=NOW + 1, expires_at=NOW + 900),
     public.MSG_LOCKED),
    (lambda t: t.items.pop(f"pass#{FP}"), public.MSG_START_FROM_WEB),
    (lambda t: t.put(f"pass#{FP}", attempts_left=3, expires_at=NOW), public.MSG_START_FROM_WEB),
    (lambda t: t.put(f"pass#{FP}", attempts_left=0, expires_at=NOW + 60), public.MSG_START_FROM_WEB),
], ids=["closed", "paused", "malformed_config", "breaker_previous_window", "breaker_count", "locked",
        "no_pass", "pass_expired", "pass_used_up"])
def test_refusals_never_call_mapit_or_write(fakes, setup, message):
    table, ssm, mapit = fakes
    setup(table)
    _fails(_migration(), message)
    assert mapit.calls == [] and table.writes() == [] and ssm.puts == []


def test_pass_for_another_email_does_not_count(fakes):
    _, _, mapit = fakes
    _fails(_migration("other@example.com"), public.MSG_START_FROM_WEB)
    assert mapit.calls == []


def test_switch_off_pass_requirement(fakes):
    table, _, mapit = fakes
    table.items.pop(f"pass#{FP}")
    table.put("config", pass_required=False)
    identity.handler(_migration(), Context())
    assert len(mapit.calls) == 1


def test_expired_lock_and_breaker_do_not_refuse(fakes):
    table, _, _ = fakes
    table.put(f"attempts#{FP}", failed_logins=0, locked_until=NOW, expires_at=NOW + 900)
    table.put(f"breaker#{WINDOW - 2}", rejections=20, open_until=NOW, expires_at=NOW + 900)
    identity.handler(_migration(), Context())


# --- MAPIT rejections: counted once -------------------------------------------------------

def test_rejection_counts_attempt_breaker_day_and_pass_once(fakes):
    table, ssm, mapit = fakes
    mapit.mode = "reject"
    _fails(_migration(), public.MSG_BAD_CREDENTIALS)
    assert table.n(f"attempts#{FP}", "failed_logins") == 1
    assert table.n(f"attempts#{FP}", "expires_at") == web.attempts_expires_at(NOW)
    assert table.n(f"breaker#{WINDOW}", "rejections") == 1
    assert table.n(f"breaker#{WINDOW}", "expires_at") == web.breaker_expires_at(WINDOW)
    assert table.n(f"day#{TODAY}", "mapit_rejections") == 1
    assert table.n(f"pass#{FP}", "attempts_left") == 2
    transactions = [c for c in table.calls if c[0] == "transact_write_items"]
    assert len(transactions) == 1 and len(transactions[0][1]["TransactItems"]) == 3
    assert ssm.puts == [] and f"person#{FP}" not in table.items


def test_fifth_rejection_locks_for_fifteen_minutes(fakes):
    table, _, mapit = fakes
    mapit.mode = "reject"
    table.put(f"pass#{FP}", attempts_left=99, expires_at=NOW + 240)
    for _ in range(web.MAX_FAILED_LOGINS - 1):
        _fails(_migration(), public.MSG_BAD_CREDENTIALS)
    _fails(_migration(), public.MSG_LOCKED)
    assert table.n(f"attempts#{FP}", "locked_until") == NOW + web.LOCK_SECONDS
    assert table.n(f"attempts#{FP}", "failed_logins") == 0
    _fails(_migration(), public.MSG_LOCKED)
    assert len(mapit.calls) == web.MAX_FAILED_LOGINS


def test_twentieth_rejection_opens_the_breaker(fakes):
    table, _, mapit = fakes
    mapit.mode = "reject"
    table.put(f"breaker#{WINDOW}", rejections=web.BREAKER_REJECTIONS - 1, expires_at=NOW + 900)
    _fails(_migration(), public.MSG_BAD_CREDENTIALS)
    assert table.n(f"breaker#{WINDOW}", "open_until") == NOW + web.BREAKER_OPEN_SECONDS
    _fails(_migration(), public.MSG_PAUSED)
    assert len(mapit.calls) == 1


@pytest.mark.parametrize("outcome", ["reject", "ok"])
def test_racing_migrations_on_a_one_attempt_pass_reach_mapit_once(fakes, outcome):
    table, _, mapit = fakes
    mapit.mode = outcome
    table.put(f"pass#{FP}", attempts_left=1, expires_at=NOW + 240)
    results: list[str] = []

    def other_migration(_table: FakeTable) -> None:
        # B read the pass as valid too, before either spent it, and spends first.
        try:
            identity.handler(_migration(), Context())
            results.append("ok")
        except identity.IdentityError as exc:
            results.append(str(exc))

    table.before_update = other_migration  # runs just before A's spend
    _fails(_migration(), public.MSG_START_FROM_WEB)
    assert len(mapit.calls) == 1 and len(results) == 1
    assert table.n(f"pass#{FP}", "attempts_left") == 0


def test_mapit_transport_failure_is_generic_and_not_counted(fakes):
    table, _, mapit = fakes
    mapit.mode = "timeout"
    _fails(_migration(), public.MSG_GENERIC)
    assert [c[1]["Key"] for c in table.writes()] == [web.pass_key(FP)]  # only the pass spend
    assert f"attempts#{FP}" not in table.items and f"breaker#{WINDOW}" not in table.items


# --- PreAuthentication_Authentication ----------------------------------------------------

def test_pre_auth_existing_user_spends_one_attempt(fakes):
    table, _, mapit = fakes
    event = _pre_auth(False)
    assert identity.handler(copy.deepcopy(event), Context())["response"] == {}
    assert table.n(f"pass#{FP}", "attempts_left") == 2 and mapit.calls == []
    identity.handler(copy.deepcopy(event), Context())
    identity.handler(copy.deepcopy(event), Context())
    _fails(event, public.MSG_START_FROM_WEB)
    assert table.n(f"pass#{FP}", "attempts_left") == 0


def test_pre_auth_without_user_not_found_flag_is_an_existing_user(fakes):
    table, _, _ = fakes
    identity.handler(_pre_auth(None), Context())
    assert table.n(f"pass#{FP}", "attempts_left") == 2


@pytest.mark.parametrize("setup, message", [
    (lambda t: t.items.pop(f"pass#{FP}"), public.MSG_START_FROM_WEB),
    (lambda t: t.put("config", open=False), public.MSG_PAUSED),
    (lambda t: t.put(f"attempts#{FP}", failed_logins=0, locked_until=NOW + 1, expires_at=NOW + 900),
     public.MSG_LOCKED),
], ids=["no_pass", "closed", "locked"])
def test_pre_auth_refusals(fakes, setup, message):
    table, _, _ = fakes
    setup(table)
    _fails(_pre_auth(False), message)
    assert table.writes() == []


def test_pre_auth_absent_user_checks_but_never_spends(fakes):
    table, _, _ = fakes
    identity.handler(_pre_auth(True), Context())
    assert table.writes() == []
    table.items.pop(f"pass#{FP}")
    _fails(_pre_auth(True), public.MSG_START_FROM_WEB)


@pytest.mark.parametrize("attempts", [3, 1])
@pytest.mark.parametrize("order", ["pre_auth_first", "migration_first"])
@pytest.mark.parametrize("outcome", ["reject", "ok"])
def test_one_sign_in_spends_at_most_one_attempt_in_either_order(fakes, order, outcome, attempts):
    table, _, mapit = fakes
    mapit.mode = outcome
    table.put(f"pass#{FP}", attempts_left=attempts, issued_at=NOW - 60, expires_at=NOW + 240)
    steps = [lambda: identity.handler(_pre_auth(order == "pre_auth_first"), Context()),
             lambda: identity.handler(_migration(), Context())]
    errors: list[str] = []
    for step in steps if order == "pre_auth_first" else steps[::-1]:
        try:
            step()
        except identity.IdentityError as exc:
            errors.append(str(exc))
            break  # Cognito stops the sign-in at the first error
    # Spent once by the migration; a pre-authentication of the user it just
    # created spends nothing more, even when that was the last attempt.
    assert table.n(f"pass#{FP}", "attempts_left") == attempts - 1
    assert errors == ([public.MSG_BAD_CREDENTIALS] if outcome == "reject" else [])


def test_pre_auth_spends_again_once_the_migration_grace_is_over(fakes, monkeypatch):
    table, _, _ = fakes
    identity.handler(_migration(), Context())
    assert table.n(f"pass#{FP}", "attempts_left") == 2
    later = NOW + public.MIGRATION_SPEND_GRACE_SECONDS + 1
    monkeypatch.setattr(identity, "_wall_clock", lambda: float(later))
    identity.handler(_pre_auth(False), Context())
    assert table.n(f"pass#{FP}", "attempts_left") == 1


def test_grace_is_only_for_an_existing_user(fakes):
    table, _, _ = fakes
    table.put(f"pass#{FP}", attempts_left=0, expires_at=NOW + 240, migration_spent_at=NOW - 1)
    _fails(_pre_auth(True), public.MSG_START_FROM_WEB)  # absent user: the next migration could not spend
    identity.handler(_pre_auth(False), Context())        # existing user: same sign-in, no second spend
    assert table.n(f"pass#{FP}", "attempts_left") == 0


@pytest.mark.parametrize("spent_at, expires_at", [
    (NOW - public.MIGRATION_SPEND_GRACE_SECONDS - 1, NOW + 240),  # an older migration: no grace
    (NOW - 1, NOW),                                                  # recent, but the pass expired
], ids=["old_migration", "expired"])
def test_grace_does_not_revive_a_used_up_pass(fakes, spent_at, expires_at):
    table, _, _ = fakes
    table.put(f"pass#{FP}", attempts_left=1, expires_at=NOW + 240, migration_spent_at=spent_at)
    # Read as valid; another sign-in spends the last attempt before this spend.
    table.before_update = lambda t: t.put(f"pass#{FP}", attempts_left=0, expires_at=expires_at,
                                          migration_spent_at=spent_at)
    _fails(_pre_auth(False), public.MSG_START_FROM_WEB)


def test_pre_auth_without_pass_requirement_spends_nothing(fakes):
    table, _, _ = fakes
    table.put("config", pass_required=False)
    identity.handler(_pre_auth(False), Context())
    assert table.writes() == []


# --- token generation --------------------------------------------------------------------

def test_refresh_is_refused_without_any_read(fakes):
    table, _, _ = fakes
    _fails(_token("TokenGeneration_RefreshTokens"), public.MSG_SESSION_ENDED)
    assert table.calls == []


def test_token_issue_counts_sign_ins_and_caps_them_per_day(fakes):
    table, _, _ = fakes
    _person(table)
    result = identity.handler(_token(), Context())
    claims = result["response"]["claimsAndScopeOverrideDetails"]["accessTokenGeneration"]["claimsToAddOrOverride"]
    assert claims == {"mapit_tenant": TENANT}
    assert table.items[f"person#{FP}"]["login_day"] == {"S": TODAY}
    for _ in range(web.DAILY_LOGINS_PER_PERSON - 1):
        identity.handler(_token("TokenGeneration_Authentication"), Context())
    assert table.n(f"person#{FP}", "login_day_count") == web.DAILY_LOGINS_PER_PERSON
    _fails(_token(), public.MSG_DAILY_LIMIT)
    assert table.n(f"person#{FP}", "login_count") == 1 + web.DAILY_LOGINS_PER_PERSON
    assert table.n(f"day#{TODAY}", "logins") == web.DAILY_LOGINS_PER_PERSON
    assert table.n("month#2027-01", "logins") == web.DAILY_LOGINS_PER_PERSON
    assert set(table.items[f"day#{TODAY}"]) == {"pk", "logins"}


def test_a_new_day_restarts_the_daily_count(fakes):
    table, _, _ = fakes
    _person(table, login_day="2027-01-14", login_day_count=web.DAILY_LOGINS_PER_PERSON)
    identity.handler(_token(), Context())
    assert table.n(f"person#{FP}", "login_day_count") == 1


@pytest.mark.parametrize("expired", [False, True])
def test_token_for_a_person_without_row_is_refused(fakes, expired):
    table, _, _ = fakes
    if expired:
        _person(table)
        table.items[f"person#{FP}"]["expires_at"] = {"N": str(NOW)}
    _fails(_token(), public.MSG_GENERIC)
    assert f"day#{TODAY}" not in table.items


def test_forgot_password_and_unknown_trigger(fakes):
    _fails({"triggerSource": "UserMigration_ForgotPassword", "userName": EMAIL}, public.MSG_FORGOT_PASSWORD)
    _fails({"triggerSource": "PostConfirmation_ConfirmSignUp"}, public.MSG_GENERIC)


# --- configuration, logs ------------------------------------------------------------------

TRIGGERS = [_migration, lambda: _pre_auth(False), lambda: _pre_auth(True), _token,
            lambda: _token("TokenGeneration_RefreshTokens")]


@pytest.mark.parametrize("event", TRIGGERS[:4], ids=["migration", "pre_auth", "pre_auth_absent", "token"])
def test_invitation_table_variable_in_public_mode_fails_closed(fakes, monkeypatch, event):
    table, ssm, mapit = fakes
    monkeypatch.setenv("MULTIUSER_TABLE", "honda-mapit-mcp-dev-invitations")
    with pytest.raises(identity.IdentityError):
        identity.handler(event(), Context())
    assert table.calls == [] and mapit.calls == [] and ssm.puts == []


@pytest.mark.parametrize("event", TRIGGERS, ids=["migration", "pre_auth", "pre_auth_absent", "token", "refresh"])
def test_invalid_mode_value_fails_closed(fakes, monkeypatch, event):
    table, ssm, mapit = fakes
    monkeypatch.setenv("MAPIT_WEB_MODE", "Public")
    _fails(event(), identity.MSG_GENERIC)
    assert identity.handler(_http("GET", "/estado"), None)["statusCode"] == 503
    assert table.calls == [] and mapit.calls == [] and ssm.puts == []


def test_state_read_failure_is_generic(fakes):
    table, _, mapit = fakes
    table.fail.add("batch_get_item")
    _fails(_migration(), public.MSG_GENERIC)
    assert mapit.calls == []


def test_logs_carry_step_codes_only(fakes, caplog):
    table, _, mapit = fakes
    caplog.set_level(logging.WARNING, logger="mapit.public_identity")
    mapit.mode = "reject"
    _fails(_migration(), public.MSG_BAD_CREDENTIALS)
    table.fail.add("batch_get_item")
    _fails(_migration(), public.MSG_GENERIC)
    lines = [json.loads(r.getMessage()) for r in caplog.records]
    assert [line["step"] for line in lines] == ["mapit_rejected", "state_read_failed"]
    assert lines[1]["provider_code"] == "ProvisionedThroughputExceededException"
    text = caplog.text
    for secret in (EMAIL, "Rider", PASSWORD, REFRESH, FP, TENANT):
        assert secret not in text


DETAIL = "detail-with-rider@example.com"


def test_unexpected_and_status_logs_carry_no_exception_text(fakes, caplog, monkeypatch):
    table, _, _ = fakes
    caplog.set_level(logging.WARNING, logger="mapit.public_identity")

    def boom(_n: int) -> str:
        raise RuntimeError(DETAIL)
    monkeypatch.setattr(public, "_token_hex", boom)
    _fails(_migration(), public.MSG_GENERIC)

    class Odd(Exception):
        def __init__(self) -> None:
            super().__init__(DETAIL)
            self.response = {"Error": {"Code": "InternalServerError", "Message": DETAIL}}

    def failing(**_kwargs: Any) -> dict:
        raise Odd()
    monkeypatch.setattr(table, "batch_get_item", failing)
    assert identity.handler(_http("GET", "/estado"), None)["statusCode"] == 503
    lines = [json.loads(r.getMessage()) for r in caplog.records]
    assert [(line["trigger"], line["step"], line["error_type"]) for line in lines] == [
        ("UserMigration_Authentication", "unexpected", "RuntimeError"),
        ("http_status", "state_read_failed", "Odd")]
    assert lines[1]["provider_code"] == "InternalServerError"
    assert DETAIL not in caplog.text and "rider" not in caplog.text.lower()


# --- HTTP --------------------------------------------------------------------------------

def _http(method: str, path: str) -> dict:
    return {"version": "2.0", "rawPath": path, "rawQueryString": "", "headers": {},
            "requestContext": {"http": {"method": method, "path": path}}}


@pytest.mark.parametrize("setup, state", [
    (lambda t: None, "abierto"),
    (lambda t: t.put("config", cap=3, occupied=3), "lleno"),
    (lambda t: t.put("config", cap=0, occupied=3), "abierto"),
    (lambda t: t.put("config", open=False, cap=3, occupied=3), "cerrado"),
    (lambda t: t.put("config", open=False, pause_until=NOW + 1), "cerrado"),
    (lambda t: t.put("config", pause_until=NOW + 1), "pausa"),
    (lambda t: t.put(f"breaker#{WINDOW}", rejections=1, open_until=NOW + 1, expires_at=NOW + 900), "pausa"),
    (lambda t: t.put("config", open="yes"), "pausa"),
], ids=["no_row", "full", "no_cap", "closed", "closed_and_paused", "paused", "breaker", "malformed"])
def test_status_endpoint(fakes, setup, state):
    table, _, _ = fakes
    setup(table)
    response = identity.handler(_http("GET", "/estado"), None)
    assert response["statusCode"] == 200 and json.loads(response["body"]) == {"estado": state}
    assert response["headers"]["content-type"] == "application/json"
    assert response["headers"]["cache-control"] == "no-store"
    assert table.writes() == []


def test_status_read_failure_is_paused_503(fakes):
    table, _, _ = fakes
    table.fail.add("batch_get_item")
    response = identity.handler(_http("GET", "/estado"), None)
    assert response["statusCode"] == 503 and json.loads(response["body"]) == {"estado": "pausa"}


@pytest.mark.parametrize("method, path", [("GET", "/invitacion"), ("POST", "/invitacion"),
                                          ("GET", "/privacidad"), ("POST", "/estado")])
def test_invitation_pages_do_not_exist_in_public_mode(fakes, method, path):
    table, _, _ = fakes
    assert identity.handler(_http(method, path), None)["statusCode"] == 404
    assert table.calls == []


def test_mode_absent_keeps_invitation_routes(fakes, monkeypatch):
    table, _, _ = fakes
    monkeypatch.delenv("MAPIT_WEB_MODE")
    assert identity.handler(_http("GET", "/estado"), None)["statusCode"] == 404
    _fails(_pre_auth(False), identity.MSG_GENERIC)  # no such trigger in invitation mode
    assert table.calls == []
