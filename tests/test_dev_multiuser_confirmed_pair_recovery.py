from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import hashlib

from scripts.dev_multiuser_test_users import _base, _canonical, _token, _username
from scripts.dev_multiuser_confirmed_pair_recovery import (
    prepare_confirmed_pair_reset,
    reset_confirmed_pair_once,
)


ACCOUNT = "123456789012"
POOL = "eu-west-1_A1b2C3d4E"
RUN = "2026100601"
SOURCE = "c" * 40
OLD_SOURCE = "a" * 40
OLD_START, OLD_END = 1_900_000_000, 1_900_000_300
LATEST_START, LATEST_END = 1_900_001_000, 1_900_001_300
NEW_START, NEW_END = 1_900_002_000, 1_900_002_300
SUB_A = "12345678-1234-7abc-1234-123456789abc"
SUB_B = "22345678-1234-7abc-1234-123456789abc"
PASSWORD_A = "Aa1!" + "a" * 32
PASSWORD_B = "Bb2!" + "b" * 32


class Journal:
    def __init__(self, state=None):
        self.state = deepcopy(state)
        self.saves = 0

    def load(self):
        return deepcopy(self.state)

    def save(self, value):
        self.saves += 1
        self.state = deepcopy(value)

    def locked(self):
        return nullcontext()


class AwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 400}}


def _binding(start, end):
    value = {"account_id": ACCOUNT, "user_pool_id": POOL, "run_id": RUN,
             "authorized_from_epoch": start, "authorized_until_epoch": end}
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sub_hash(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _initial_journals():
    original = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                     binding_sha256=_binding(OLD_START, OLD_END), start=OLD_START, end=OLD_END)
    original["preflight"] = True
    original["slots"][0].update({
        "create_status": "intent",
        "create_intent": {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, "A", "create")},
    })
    latest = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                   binding_sha256=_binding(LATEST_START, LATEST_END),
                   start=LATEST_START, end=LATEST_END)
    latest["preflight"] = True
    for index, slot, subject, create_status in (
        (0, "A", SUB_A, "reconciled"), (1, "B", SUB_B, "created"),
    ):
        latest["slots"][index].update({
            "create_status": create_status,
            "create_intent": {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, slot, "create")},
            "password_status": "confirmed",
            "password_intent": {"operation": "set-password", "token": _token(ACCOUNT, POOL, RUN, slot, "set-password")},
            "user_sub_sha256": _sub_hash(subject),
        })
    return Journal(original), Journal(latest), Journal(), Journal(), Journal()


def _response(username, subject, created):
    return {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Username": username,
        "Enabled": True, "UserStatus": "CONFIRMED",
        "UserCreateDate": datetime.fromtimestamp(created, timezone.utc),
        "UserAttributes": [{"Name": "sub", "Value": subject}],
    }


class Cognito:
    def __init__(self, *, bad_b_date=False, fail_slot=None):
        self.calls = []
        self.fail_slot = fail_slot

    def admin_get_user(self, *, UserPoolId, Username):
        self.calls.append(("get", Username))
        if Username == _username(RUN, "A"):
            return _response(Username, SUB_A, OLD_START + 10)
        if Username == _username(RUN, "B"):
            created = LATEST_END + 5 if self.fail_slot == "bad-date" else LATEST_START + 10
            return _response(Username, SUB_B, created)
        raise AwsError("UserNotFoundException")

    def admin_set_user_password(self, *, UserPoolId, Username, Password, Permanent):
        slot = "A" if Username == _username(RUN, "A") else "B"
        self.calls.append(("set", slot, Password, Permanent))
        if self.fail_slot == slot:
            raise RuntimeError("synthetic ambiguous response")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def admin_create_user(self, **kwargs):
        raise AssertionError("pair recovery must never create a user")


def _prepare(journals, client, *, allow=True, start=NEW_START, end=NEW_END):
    original, latest, fresh, reset, provenance = journals
    return prepare_confirmed_pair_reset(
        clients={"cognito": client}, original_creation_journal=original,
        latest_pair_journal=latest, fresh_user_journal=fresh, reset_journal=reset,
        provenance_journal=provenance, account=ACCOUNT, user_pool_id=POOL,
        source_sha256=SOURCE, authorized_from_epoch=start, authorized_until_epoch=end,
        allow_two_confirmed_user_resets=allow, wall_clock=lambda: start + 1,
    )


def _execute(journals, client, *, on_user, start=NEW_START, end=NEW_END,
             source=SOURCE, passwords=None):
    _, _, fresh, reset, _ = journals
    values = iter(passwords or (PASSWORD_A, PASSWORD_B))
    return reset_confirmed_pair_once(
        clients={"cognito": client}, fresh_user_journal=fresh, reset_journal=reset,
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, source_sha256=source,
        authorized_from_epoch=start, authorized_until_epoch=end,
        allow_two_confirmed_user_resets=True, on_confirmed_user=on_user,
        password_factory=lambda slot: next(values), wall_clock=lambda: start + 1,
    )


def test_pair_prepare_is_read_only_and_executor_resets_logins_in_order_once():
    journals = _initial_journals()
    original, latest, fresh, reset, provenance = journals
    before = original.load(), latest.load()
    client = Cognito()
    result = _prepare(journals, client)
    assert result == {"success": True, "category": "reset_prepared", "calls": 2,
                      "cognito_writes": 0, "users": 2}
    assert [item[1] for item in client.calls] == [_username(RUN, "A"), _username(RUN, "B")]
    assert (original.load(), latest.load()) == before
    assert all(row["password_status"] == "confirmed" for row in fresh.load()["slots"])
    assert [row["phase"] for row in reset.load()["slots"]] == ["pending", "pending"]
    assert reset.load()["slots"][0]["reset_token"] != reset.load()["slots"][1]["reset_token"]
    assert provenance.load()["cognito_writes"] == 0
    assert PASSWORD_A not in repr(reset.load()) and PASSWORD_B not in repr(reset.load())
    assert SUB_A not in repr(provenance.load()) and SUB_B not in repr(provenance.load())

    client.calls.clear()
    callbacks = []
    executed = _execute(journals, client, on_user=lambda user, password: callbacks.append((user, password)))
    assert executed == {"success": True, "category": "users_confirmed", "calls": 6, "users": 2}
    assert [row[0:2] for row in client.calls if row[0] == "set"] == [
        ("set", "A"), ("set", "B")]
    assert [user for user, _ in callbacks] == [_username(RUN, "A"), _username(RUN, "B")]
    assert reset.load()["phase"] == "complete"
    assert [row["phase"] for row in reset.load()["slots"]] == ["confirmed", "confirmed"]
    calls_before = list(client.calls)
    replay = _execute(journals, client, on_user=lambda *_: None)
    assert replay["success"] is False and replay["category"] == "reset_journal_invalid"
    assert client.calls == calls_before


def test_pair_requires_explicit_authority_and_rejects_b_outside_latest_window():
    journals, client = _initial_journals(), Cognito()
    denied = _prepare(journals, client, allow=False)
    assert denied["category"] == "reset_authorization_required"
    assert not client.calls and all(j.load() is None for j in journals[2:])

    journals, client = _initial_journals(), Cognito(fail_slot="bad-date")
    result = _prepare(journals, client)
    assert result["category"] == "reset_readback_failed"
    assert all(j.load() is None for j in journals[2:])


def test_ambiguous_a_reset_stops_before_b_and_cannot_replay():
    journals, client = _initial_journals(), Cognito(fail_slot="A")
    assert _prepare(journals, client)["success"] is True
    client.calls.clear()
    callbacks = []
    result = _execute(journals, client, on_user=lambda user, _: callbacks.append(user))
    assert result["success"] is False and result["category"] == "reset_outcome_unknown"
    assert [row[1] for row in client.calls if row[0] == "set"] == ["A"]
    assert callbacks == []
    calls_before = list(client.calls)
    replay = _execute(journals, client, on_user=lambda *_: None)
    assert replay["category"] == "reset_journal_invalid"
    assert client.calls == calls_before


def test_ambiguous_b_reset_occurs_only_after_a_login_and_is_not_replayed():
    journals, client = _initial_journals(), Cognito(fail_slot="B")
    assert _prepare(journals, client)["success"] is True
    client.calls.clear()
    callbacks = []
    result = _execute(journals, client, on_user=lambda user, _: callbacks.append(user))
    assert result["success"] is False and result["category"] == "reset_outcome_unknown"
    assert [row[1] for row in client.calls if row[0] == "set"] == ["A", "B"]
    assert callbacks == [_username(RUN, "A")]
    calls_before = list(client.calls)
    replay = _execute(journals, client, on_user=lambda *_: None)
    assert replay["category"] == "reset_journal_invalid"
    assert client.calls == calls_before


def test_preparation_clock_rollback_stops_before_any_fresh_journal_write():
    journals, client = _initial_journals(), Cognito()
    original, latest, fresh, reset, provenance = journals
    samples = iter((NEW_START + 1, NEW_START + 2, NEW_START + 1))
    result = prepare_confirmed_pair_reset(
        clients={"cognito": client}, original_creation_journal=original,
        latest_pair_journal=latest, fresh_user_journal=fresh, reset_journal=reset,
        provenance_journal=provenance, account=ACCOUNT, user_pool_id=POOL,
        source_sha256=SOURCE, authorized_from_epoch=NEW_START,
        authorized_until_epoch=NEW_END, allow_two_confirmed_user_resets=True,
        wall_clock=lambda: next(samples),
    )
    assert result["success"] is False
    assert result["category"] == "reset_readback_failed"
    assert len(client.calls) == 1
    assert all(j.load() is None for j in journals[2:])


def test_a_login_failure_prevents_b_reset_and_malformed_binding_has_zero_calls():
    journals, client = _initial_journals(), Cognito()
    assert _prepare(journals, client)["success"] is True
    client.calls.clear()
    result = _execute(journals, client, on_user=lambda *_: (_ for _ in ()).throw(RuntimeError()))
    assert result["category"] == "login_failed"
    assert [row[1] for row in client.calls if row[0] == "set"] == ["A"]

    journals, client = _initial_journals(), Cognito()
    assert _prepare(journals, client)["success"] is True
    client.calls.clear()
    bad = _execute(journals, client, on_user=lambda *_: None, source="d" * 40)
    assert bad["success"] is False and bad["category"] == "reset_journal_invalid"
    assert client.calls == []
