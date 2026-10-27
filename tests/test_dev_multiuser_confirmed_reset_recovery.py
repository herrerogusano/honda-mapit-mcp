from __future__ import annotations

from contextlib import nullcontext
from copy import deepcopy
from datetime import datetime, timezone
import hashlib

from scripts.dev_multiuser_test_users import _base, _canonical, _token, _username
from scripts.dev_multiuser_confirmed_reset_recovery import (
    prepare_confirmed_a_reset,
    reset_a_then_provision_b,
)


ACCOUNT = "123456789012"
POOL = "eu-west-1_A1b2C3d4E"
RUN = "2026100601"
OLD_SOURCE = "a" * 40
NEW_SOURCE = "b" * 40
OLD_START, OLD_END = 1_900_000_000, 1_900_000_300
LATEST_START, LATEST_END = 1_900_001_000, 1_900_001_300
NEW_START, NEW_END = 1_900_002_000, 1_900_002_300
SUB_A = "12345678-1234-7abc-1234-123456789abc"
SUB_B = "22345678-1234-7abc-1234-123456789abc"
PASSWORD = "Aa1!" + "x" * 32


class MemoryJournal:
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
        self.response = {
            "Error": {"Code": code},
            "ResponseMetadata": {"HTTPStatusCode": 400},
        }


def _binding(start, end):
    value = {"account_id": ACCOUNT, "user_pool_id": POOL, "run_id": RUN,
             "authorized_from_epoch": start, "authorized_until_epoch": end}
    return hashlib.sha256(_canonical(value)).hexdigest()


def _subject_hash(subject):
    return hashlib.sha256(subject.encode("ascii")).hexdigest()


def _old_state():
    state = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                  binding_sha256=_binding(OLD_START, OLD_END),
                  start=OLD_START, end=OLD_END)
    state["preflight"] = True
    state["slots"][0]["create_status"] = "intent"
    state["slots"][0]["create_intent"] = {
        "operation": "create", "token": _token(ACCOUNT, POOL, RUN, "A", "create")}
    return state


def _latest_state():
    state = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                  binding_sha256=_binding(LATEST_START, LATEST_END),
                  start=LATEST_START, end=LATEST_END)
    state["preflight"] = True
    state["slots"][0].update({
        "create_status": "reconciled",
        "create_intent": {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, "A", "create")},
        "password_status": "confirmed",
        "password_intent": {"operation": "set-password", "token": _token(ACCOUNT, POOL, RUN, "A", "set-password")},
        "user_sub_sha256": _subject_hash(SUB_A),
    })
    return state


def _user(username, subject, *, status="CONFIRMED", enabled=True, created=OLD_START + 10):
    return {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Username": username,
        "Enabled": enabled, "UserStatus": status,
        "UserCreateDate": datetime.fromtimestamp(created, timezone.utc),
        "UserAttributes": [{"Name": "sub", "Value": subject}],
    }


class Cognito:
    def __init__(self, *, b_exists=False, reset_raises=False):
        self.calls = []
        self.b_exists = b_exists
        self.reset_raises = reset_raises

    def admin_get_user(self, *, UserPoolId, Username):
        self.calls.append(("get", Username))
        if Username == _username(RUN, "B"):
            if self.b_exists:
                return _user(Username, SUB_B)
            raise AwsError("UserNotFoundException")
        return _user(Username, SUB_A)

    def admin_set_user_password(self, *, UserPoolId, Username, Password, Permanent):
        self.calls.append(("reset", Username, Password, Permanent))
        if self.reset_raises:
            raise RuntimeError("synthetic ambiguous write")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def admin_create_user(self, *, UserPoolId, Username, MessageAction):
        self.calls.append(("create", Username, MessageAction))
        self.b_exists = True
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "User": {"Username": Username,
                     "Attributes": [{"Name": "sub", "Value": SUB_B}]},
        }


def _journals():
    original = MemoryJournal(_old_state())
    latest = MemoryJournal(_latest_state())
    fresh, reset, provenance = MemoryJournal(), MemoryJournal(), MemoryJournal()
    return original, latest, fresh, reset, provenance


def _prepare(client, journals, *, allow=True, latest_state=None, start=NEW_START, end=NEW_END):
    original, latest, fresh, reset, provenance = journals
    if latest_state is not None:
        latest.save(latest_state)
    return prepare_confirmed_a_reset(
        clients={"cognito": client}, original_creation_journal=original,
        latest_confirmed_journal=latest, fresh_user_journal=fresh,
        reset_journal=reset, provenance_journal=provenance,
        account=ACCOUNT, user_pool_id=POOL, new_source_sha256=NEW_SOURCE,
        new_authorized_from_epoch=start, new_authorized_until_epoch=end,
        allow_single_a_password_reset=allow, wall_clock=lambda: start + 1,
    )


def test_prepare_is_read_only_then_reset_is_one_shot_and_preserves_confirmed_a():
    journals = _journals()
    original, latest, fresh, reset, provenance = journals
    original_before, latest_before = original.load(), latest.load()
    client = Cognito()
    assert _prepare(client, journals) == {
        "success": True, "category": "reset_prepared", "calls": 2, "cognito_writes": 0}
    assert client.calls == [("get", _username(RUN, "A")), ("get", _username(RUN, "B"))]
    assert original.load() == original_before and latest.load() == latest_before
    state = fresh.load()
    assert state["slots"][0]["password_status"] == "confirmed"
    assert state["slots"][0]["create_status"] == "reconciled"
    assert state["slots"][1]["create_status"] == "pending"
    reset_state = reset.load()
    assert reset_state["phase"] == "prepared" and reset_state["reset_authorized"] is True
    assert reset_state["reset_token"] != _token(ACCOUNT, POOL, RUN, "A", "set-password")
    assert PASSWORD not in repr(reset_state) and SUB_A not in repr(reset_state)
    assert provenance.load()["cognito_writes"] == 0

    callbacks = []
    result = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=fresh, reset_journal=reset,
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256=NEW_SOURCE,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=True, on_confirmed_a=lambda u, p: callbacks.append(("A", u, p)),
        on_confirmed_b=lambda u, p: callbacks.append(("B", u, p)),
        password_factory=lambda: PASSWORD, wall_clock=lambda: NEW_START + 1,
    )
    assert result == {"success": True, "category": "users_confirmed", "calls": 7, "users": 2}
    assert [call[:2] for call in client.calls if call[0] == "reset"] == [("reset", _username(RUN, "A")), ("reset", _username(RUN, "B"))]
    assert [call[0] for call in callbacks] == ["A", "B"]
    assert reset.load()["phase"] == "complete"
    assert all(row["password_status"] == "confirmed" for row in fresh.load()["slots"])
    before_replay = list(client.calls)
    replay = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=fresh, reset_journal=reset,
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256=NEW_SOURCE,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=True, on_confirmed_a=lambda *_: None,
        password_factory=lambda: PASSWORD, wall_clock=lambda: NEW_START + 1,
    )
    assert replay["success"] is False and replay["category"] == "reset_journal_invalid"
    assert client.calls == before_replay


def test_preparation_requires_explicit_allowance_and_strict_latest_schema():
    journals = _journals()
    client = Cognito()
    result = _prepare(client, journals, allow=False)
    assert result["category"] == "reset_authorization_required"
    assert not client.calls and all(j.load() is None for j in journals[2:])

    bad = _latest_state()
    bad["schema"] = True
    result = _prepare(client, journals, latest_state=bad)
    assert result["success"] is False and not client.calls
    assert all(j.load() is None for j in journals[2:])


def test_preparation_rejects_a_outside_original_window_or_b_existing():
    journals = _journals()
    original, latest, *_ = journals
    client = Cognito()
    # The subject may match, but A's creation timestamp must belong to the
    # original creation authority, not merely the later recovery window.
    client.admin_get_user = lambda **kw: _user(kw["Username"], SUB_A, created=NEW_START + 1)
    assert _prepare(client, journals)["success"] is False
    assert all(j.load() is None for j in journals[2:])

    journals = _journals()
    client = Cognito(b_exists=True)
    assert _prepare(client, journals)["category"] == "reset_readback_failed"
    assert all(j.load() is None for j in journals[2:])


def test_ambiguous_reset_is_consumed_and_never_replayed():
    journals = _journals()
    client = Cognito(reset_raises=True)
    assert _prepare(client, journals)["success"] is True
    original, latest, fresh, reset, provenance = journals
    first = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=fresh, reset_journal=reset,
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256=NEW_SOURCE,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=True, on_confirmed_a=lambda *_: None,
        password_factory=lambda: PASSWORD, wall_clock=lambda: NEW_START + 1,
    )
    assert first["category"] == "password_outcome_unknown"
    assert reset.load()["phase"] == "blocked"
    calls_after = list(client.calls)
    second = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=fresh, reset_journal=reset,
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256=NEW_SOURCE,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=True, on_confirmed_a=lambda *_: None,
        password_factory=lambda: PASSWORD, wall_clock=lambda: NEW_START + 1,
    )
    assert second["category"] == "reset_journal_invalid"
    assert client.calls == calls_after
