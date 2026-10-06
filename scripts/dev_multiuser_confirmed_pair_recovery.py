"""One-shot, offline-preparable reset of an already-confirmed technical pair.

This path is separate from both historical user recovery and the A-only reset
recovery. Preparation performs exact readbacks and creates fresh journals; the
executor can reset A once, verify/login A, then reset B once and verify/login B.
It never creates users, constructs SDK clients, or resumes a consumed attempt.
"""
from __future__ import annotations

from collections.abc import Mapping
from contextlib import ExitStack
from datetime import datetime
import hashlib
import math
import re
import time
from typing import Any, Callable

from scripts.dev_multiuser_test_users import (
    MAX_CALLS, _UUID, _base, _canonical, _digest_subject, _generate_private_password,
    _ok, _token, _username, _valid_private_password, _validate_state,
)
from scripts.dev_multiuser_user_recovery import _validate_original

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_KIND = "retained-dev-multiuser-confirmed-pair-reset"
_CATEGORIES = frozenset({
    "reset_authorization_required", "reset_inputs_invalid", "reset_journal_invalid",
    "reset_journal_not_empty", "reset_readback_failed", "reset_prepared",
    "reset_outcome_unknown", "login_failed", "users_confirmed",
})


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _epoch(value: Any) -> float | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    try:
        result = value.timestamp()
    except Exception:
        return None
    return result if math.isfinite(result) else None


def _subject_sha(response: Any, *, username: str, start: int, end: int) -> str:
    if not isinstance(response, Mapping):
        raise ValueError
    metadata = response.get("ResponseMetadata")
    if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
        or metadata["HTTPStatusCode"] != 200 or response.get("Username") != username
        or response.get("Enabled") is not True or response.get("UserStatus") != "CONFIRMED"):
        raise ValueError
    created = _epoch(response.get("UserCreateDate"))
    if created is None or not start <= created < end:
        raise ValueError
    attributes = response.get("UserAttributes")
    if type(attributes) is not list:
        raise ValueError
    subs = [row.get("Value") for row in attributes
            if isinstance(row, Mapping) and row.get("Name") == "sub"]
    if len(subs) != 1 or type(subs[0]) is not str or _UUID.fullmatch(subs[0]) is None:
        raise ValueError
    if any(not isinstance(row, Mapping) or set(row) != {"Name", "Value"}
           or type(row.get("Name")) is not str or type(row.get("Value")) is not str
           for row in attributes):
        raise ValueError
    return _digest_subject(subs[0])


def _valid_journal(journal: Any) -> bool:
    return all(callable(getattr(journal, name, None)) for name in ("load", "save", "locked"))


def _latest_pair(value: Any, *, account: str, pool: str,
                 original: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or type(value.get("schema")) is not int:
        raise ValueError
    if isinstance(value.get("schema"), bool):
        raise ValueError
    start, end = value.get("authorized_from_epoch"), value.get("authorized_until_epoch")
    if (type(start) is not int or isinstance(start, bool) or type(end) is not int
        or isinstance(end, bool) or start < original["authorized_until_epoch"]
        or end <= start or end - start > 300):
        raise ValueError
    binding = _digest({"account_id": account, "user_pool_id": pool,
                       "run_id": original["run_id"],
                       "authorized_from_epoch": start, "authorized_until_epoch": end})
    state = _validate_state(value, account=account, pool=pool,
                            run_id=original["run_id"], binding_sha256=binding,
                            start=start, end=end)
    old_a, old_b = original["slots"]
    a, b = state["slots"]
    if (state["preflight"] is not True
        or a["create_status"] not in {"created", "reconciled", "confirmed"}
        or a["create_intent"] != old_a["create_intent"]
        or a["password_status"] != "confirmed"
        or a["password_intent"] != {"operation": "set-password", "token": _token(account, pool, original["run_id"], "A", "set-password")}
        or type(a["user_sub_sha256"]) is not str or _SHA256.fullmatch(a["user_sub_sha256"]) is None
        or b["create_status"] not in {"created", "reconciled", "confirmed"}
        or b["create_intent"] != {"operation": "create", "token": _token(account, pool, original["run_id"], "B", "create")}
        or b["password_status"] != "confirmed"
        or b["password_intent"] != {"operation": "set-password", "token": _token(account, pool, original["run_id"], "B", "set-password")}
        or type(b["user_sub_sha256"]) is not str or _SHA256.fullmatch(b["user_sub_sha256"]) is None
        or old_b["create_status"] != "pending"):
        raise ValueError
    return dict(state)


def _reset_state(value: Any, *, allow_complete: bool = False) -> dict[str, Any]:
    if type(allow_complete) is not bool:
        raise ValueError
    fields = {"schema", "kind", "revision", "phase", "account_id", "user_pool_id", "run_id",
              "source_sha256", "authorized_from_epoch", "authorized_until_epoch",
              "original_creation_sha256", "latest_pair_sha256", "original_start_epoch",
              "original_end_epoch", "latest_start_epoch", "latest_end_epoch",
              "binding_sha256", "slots"}
    recurring_fields = {"first_confirmed_pair_sha256", "previous_reset_sha256"}
    second_recurring_fields = recurring_fields | {"consumed_pair_sha256"}
    recurring = type(value) is dict and recurring_fields.issubset(value)
    if type(value) is not dict or set(value) not in (fields, fields | recurring_fields, fields | second_recurring_fields):
        raise ValueError
    if (type(value["schema"]) is not int or value["schema"] != 1
        or value["kind"] != _KIND or type(value["revision"]) is not int
        or isinstance(value["revision"], bool) or value["revision"] < 0
        or value["phase"] not in ({"prepared", "complete"} if allow_complete else {"prepared"})
        or type(value["account_id"]) is not str or _ACCOUNT.fullmatch(value["account_id"]) is None
        or value["account_id"] == "0" * 12 or type(value["user_pool_id"]) is not str
        or _POOL.fullmatch(value["user_pool_id"]) is None
        or type(value["run_id"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}\Z", value["run_id"])
        or type(value["source_sha256"]) is not str or _SHA1.fullmatch(value["source_sha256"]) is None
        or any(type(value[k]) is not int or isinstance(value[k], bool) or value[k] <= 0
               for k in ("authorized_from_epoch", "authorized_until_epoch"))
        or not 0 < value["authorized_until_epoch"] - value["authorized_from_epoch"] <= 300
        or any(type(value[k]) is not int or isinstance(value[k], bool) or value[k] <= 0
               for k in ("original_start_epoch", "original_end_epoch", "latest_start_epoch", "latest_end_epoch"))
        or value["original_end_epoch"] <= value["original_start_epoch"]
        or value["latest_end_epoch"] <= value["latest_start_epoch"]
        or value["original_end_epoch"] > value["latest_start_epoch"]
        or value["latest_end_epoch"] > value["authorized_from_epoch"]
        or any(type(value[k]) is not str or _SHA256.fullmatch(value[k]) is None
               for k in ("original_creation_sha256", "latest_pair_sha256", "binding_sha256"))
        or recurring and any(type(value[k]) is not str or _SHA256.fullmatch(value[k]) is None
                             for k in (second_recurring_fields if "consumed_pair_sha256" in value else recurring_fields))):
        raise ValueError
    slots = value["slots"]
    if type(slots) is not list or len(slots) != 2:
        raise ValueError
    expected = []
    for slot in ("A", "B"):
        expected.append({"slot": slot, "username": _username(value["run_id"], slot),
                         "subject_sha256": None, "reset_token": None, "phase": "pending"})
    base = {key: value[key] for key in (
        "account_id", "user_pool_id", "run_id", "source_sha256", "authorized_from_epoch",
        "authorized_until_epoch", "original_creation_sha256", "latest_pair_sha256")}
    base.update({key: value[key] for key in ("original_start_epoch", "original_end_epoch",
                                             "latest_start_epoch", "latest_end_epoch")})
    if recurring:
        base.update({key: value[key] for key in sorted(value.keys() & second_recurring_fields)})
    if value["binding_sha256"] != _digest(base):
        raise ValueError
    for index, row in enumerate(slots):
        if type(row) is not dict or set(row) != set(expected[index]):
            raise ValueError
        if (row.get("slot") != expected[index]["slot"] or row.get("username") != expected[index]["username"]
            or type(row.get("subject_sha256")) is not str or _SHA256.fullmatch(row["subject_sha256"]) is None
            or type(row.get("reset_token")) is not str or _SHA256.fullmatch(row["reset_token"]) is None
            or row.get("phase") != ("confirmed" if value["phase"] == "complete" else "pending")):
            raise ValueError
        token = _digest({"operation": "reset-confirmed-pair-user", "binding_sha256": value["binding_sha256"],
                         "slot": row["slot"], "subject_sha256": row["subject_sha256"]})
        if row["reset_token"] != token:
            raise ValueError
    return value


def prepare_confirmed_pair_reset(
    *, clients: Mapping[str, Any], original_creation_journal: Any,
    latest_pair_journal: Any, fresh_user_journal: Any, reset_journal: Any,
    provenance_journal: Any, account: str, user_pool_id: str, source_sha256: str,
    authorized_from_epoch: int, authorized_until_epoch: int,
    allow_two_confirmed_user_resets: bool = False,
    first_confirmed_pair_sha256: str | None = None,
    previous_reset_sha256: str | None = None,
    consumed_pair_sha256: str | None = None,
    wall_clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Read and bind both confirmed identities, then create only fresh journals."""
    calls = 0
    if allow_two_confirmed_user_resets is not True:
        return {"success": False, "category": "reset_authorization_required", "calls": 0}
    recurring = first_confirmed_pair_sha256 is not None or previous_reset_sha256 is not None
    if (not isinstance(clients, Mapping) or set(clients) != {"cognito"}
        or clients.get("cognito") is None or type(account) is not str
        or _ACCOUNT.fullmatch(account) is None or account == "0" * 12
        or type(user_pool_id) is not str or _POOL.fullmatch(user_pool_id) is None
        or type(source_sha256) is not str or _SHA1.fullmatch(source_sha256) is None
        or type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
        or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
        or not 0 < authorized_until_epoch - authorized_from_epoch <= 300
        or not callable(wall_clock)
        or recurring and (type(first_confirmed_pair_sha256) is not str or _SHA256.fullmatch(first_confirmed_pair_sha256) is None
                          or type(previous_reset_sha256) is not str or _SHA256.fullmatch(previous_reset_sha256) is None
                          or consumed_pair_sha256 is not None and (type(consumed_pair_sha256) is not str or _SHA256.fullmatch(consumed_pair_sha256) is None))
        or not recurring and consumed_pair_sha256 is not None):
        return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
    journals = (original_creation_journal, latest_pair_journal, fresh_user_journal,
                reset_journal, provenance_journal)
    if len({id(journal) for journal in journals}) != len(journals) or any(not _valid_journal(j) for j in journals):
        return {"success": False, "category": "reset_journal_invalid", "calls": 0}
    last = None

    def guard() -> float:
        nonlocal last
        now = wall_clock()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
            or now < authorized_from_epoch or now >= authorized_until_epoch
            or last is not None and now < last):
            raise ValueError
        last = float(now)
        return last

    try:
        guard()
        with ExitStack() as locks:
            for journal in journals:
                locks.enter_context(journal.locked())
            if any(j.load() is not None for j in journals[2:]):
                return {"success": False, "category": "reset_journal_not_empty", "calls": 0}
            original = _validate_original(original_creation_journal.load(), account=account, pool=user_pool_id)
            latest = _latest_pair(latest_pair_journal.load(), account=account, pool=user_pool_id,
                                  original=original)
            if (authorized_from_epoch < latest["authorized_until_epoch"]
                or type(original["run_id"]) is not str):
                return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
            run_id = original["run_id"]
            original_sha, latest_sha = _digest(original), _digest(latest)
            get_user = getattr(clients["cognito"], "admin_get_user", None)
            if not callable(get_user):
                return {"success": False, "category": "reset_readback_failed", "calls": 0}
            subjects = []
            for slot, window in (("A", (original["authorized_from_epoch"], original["authorized_until_epoch"])),
                                 ("B", (latest["authorized_from_epoch"], latest["authorized_until_epoch"]))):
                guard()
                calls += 1
                response = get_user(UserPoolId=user_pool_id, Username=_username(run_id, slot))
                guard()
                subject = _subject_sha(response, username=_username(run_id, slot), start=window[0], end=window[1])
                if subject != latest["slots"][0 if slot == "A" else 1]["user_sub_sha256"]:
                    return {"success": False, "category": "reset_readback_failed", "calls": calls}
                subjects.append(subject)
            guard()
            binding_base = {"account_id": account, "user_pool_id": user_pool_id, "run_id": run_id,
                            "source_sha256": source_sha256, "authorized_from_epoch": authorized_from_epoch,
                            "authorized_until_epoch": authorized_until_epoch,
                            "original_creation_sha256": original_sha, "latest_pair_sha256": latest_sha,
                            "original_start_epoch": original["authorized_from_epoch"],
                            "original_end_epoch": original["authorized_until_epoch"],
                            "latest_start_epoch": latest["authorized_from_epoch"],
                            "latest_end_epoch": latest["authorized_until_epoch"]}
            if recurring:
                binding_base["first_confirmed_pair_sha256"] = first_confirmed_pair_sha256
                binding_base["previous_reset_sha256"] = previous_reset_sha256
                if consumed_pair_sha256 is not None:
                    binding_base["consumed_pair_sha256"] = consumed_pair_sha256
            binding_sha = _digest(binding_base)
            reset_state = {
                "schema": 1, "kind": _KIND, "revision": 0, "phase": "prepared",
                **binding_base, "binding_sha256": binding_sha,
                "slots": [{"slot": slot, "username": _username(run_id, slot),
                           "subject_sha256": subject,
                           "reset_token": _digest({"operation": "reset-confirmed-pair-user",
                                                    "binding_sha256": binding_sha, "slot": slot,
                                                    "subject_sha256": subject}),
                           "phase": "pending"}
                          for slot, subject in zip(("A", "B"), subjects)],
            }
            fresh = _base(account=account, pool=user_pool_id, run_id=run_id,
                          binding_sha256=_digest({"account_id": account, "user_pool_id": user_pool_id,
                                                  "run_id": run_id, "authorized_from_epoch": authorized_from_epoch,
                                                  "authorized_until_epoch": authorized_until_epoch}),
                          start=authorized_from_epoch, end=authorized_until_epoch)
            fresh["preflight"] = True
            for index, slot in enumerate(("A", "B")):
                row = fresh["slots"][index]
                prior = latest["slots"][index]
                row.update({"create_status": "reconciled", "create_intent": prior["create_intent"],
                            "password_status": "confirmed", "password_intent": prior["password_intent"],
                            "user_sub_sha256": subjects[index]})
            provenance = {"schema": 1, "kind": _KIND, "phase": "readback_verified",
                          **binding_base, "binding_sha256": binding_sha,
                          "reset_slots": 2, "cognito_writes": 0}
            guard(); fresh_user_journal.save(fresh)
            guard(); provenance_journal.save(provenance)
            guard(); reset_journal.save(reset_state)
            guard()
        return {"success": True, "category": "reset_prepared", "calls": calls,
                "cognito_writes": 0, "users": 2}
    except Exception:
        return {"success": False, "category": "reset_readback_failed" if calls else "reset_journal_invalid",
                "calls": calls}


def validate_recurring_pair_history(*, original_creation_journal: Any,
                                    first_confirmed_pair_journal: Any,
                                    latest_pair_journal: Any,
                                    previous_reset_journal: Any,
                                    account: str, user_pool_id: str,
                                    earlier_reset_journal: Any = None) -> dict[str, Any]:
    """Validate immutable first-pair provenance and the latest completed reset.

    This is read-only. It proves B's creation window from the first confirmed
    pair journal, not from later password-reset windows.
    """
    original = _validate_original(original_creation_journal.load(), account=account, pool=user_pool_id)
    first = _latest_pair(first_confirmed_pair_journal.load(), account=account, pool=user_pool_id,
                         original=original)
    prior_reset = _reset_state(previous_reset_journal.load(), allow_complete=True)
    if prior_reset["phase"] != "complete" or prior_reset["revision"] != 6:
        raise ValueError
    first_sha, original_sha = _digest(first), _digest(original)
    has_chain = "first_confirmed_pair_sha256" in prior_reset
    if has_chain != (earlier_reset_journal is not None):
        raise ValueError
    if has_chain:
        if "consumed_pair_sha256" in prior_reset:
            raise ValueError
        earlier_reset = _reset_state(earlier_reset_journal.load(), allow_complete=True)
        if (earlier_reset["phase"] != "complete" or earlier_reset["revision"] != 6
            or earlier_reset["account_id"] != account
            or earlier_reset["user_pool_id"] != user_pool_id
            or earlier_reset["run_id"] != original["run_id"]
            or "first_confirmed_pair_sha256" in earlier_reset
            or "previous_reset_sha256" in earlier_reset
            or "consumed_pair_sha256" in earlier_reset
            or prior_reset["previous_reset_sha256"] != _digest(earlier_reset)
            or earlier_reset["authorized_until_epoch"] > prior_reset["authorized_from_epoch"]
            or earlier_reset["latest_pair_sha256"] != first_sha
            or earlier_reset["original_creation_sha256"] != original_sha
            or earlier_reset["original_start_epoch"] != original["authorized_from_epoch"]
            or earlier_reset["original_end_epoch"] != original["authorized_until_epoch"]
            or earlier_reset["latest_start_epoch"] != first["authorized_from_epoch"]
            or earlier_reset["latest_end_epoch"] != first["authorized_until_epoch"]):
            raise ValueError
        for index in range(2):
            if (earlier_reset["slots"][index]["slot"] != first["slots"][index]["slot"]
                or earlier_reset["slots"][index]["subject_sha256"] != first["slots"][index]["user_sub_sha256"]):
                raise ValueError
    elif earlier_reset_journal is not None:
        raise ValueError
    if (prior_reset["account_id"] != account or prior_reset["user_pool_id"] != user_pool_id
        or prior_reset["run_id"] != original["run_id"]
        or prior_reset["original_creation_sha256"] != original_sha
        or prior_reset["latest_pair_sha256"] != first_sha
        or prior_reset["original_start_epoch"] != original["authorized_from_epoch"]
        or prior_reset["original_end_epoch"] != original["authorized_until_epoch"]
        or prior_reset["latest_start_epoch"] != first["authorized_from_epoch"]
        or prior_reset["latest_end_epoch"] != first["authorized_until_epoch"]):
        raise ValueError
    if has_chain and prior_reset["first_confirmed_pair_sha256"] != first_sha:
        raise ValueError
    latest = latest_pair_journal.load()
    if not isinstance(latest, Mapping):
        raise ValueError
    start, end = latest.get("authorized_from_epoch"), latest.get("authorized_until_epoch")
    binding = _digest({"account_id": account, "user_pool_id": user_pool_id,
                       "run_id": original["run_id"], "authorized_from_epoch": start,
                       "authorized_until_epoch": end})
    current = _validate_state(latest, account=account, pool=user_pool_id,
                              run_id=original["run_id"], binding_sha256=binding,
                              start=start, end=end)
    if (current["preflight"] is not True or start != prior_reset["authorized_from_epoch"]
        or end != prior_reset["authorized_until_epoch"]
        or start < first["authorized_until_epoch"]
        or end > prior_reset["authorized_until_epoch"]):
        raise ValueError
    for index, slot in enumerate(("A", "B")):
        row, first_row, reset_row = current["slots"][index], first["slots"][index], prior_reset["slots"][index]
        if (row["create_status"] != "reconciled" or row["create_intent"] != first_row["create_intent"]
            or row["password_status"] != "confirmed" or row["password_intent"] != first_row["password_intent"]
            or row["user_sub_sha256"] != reset_row["subject_sha256"]
            or reset_row["subject_sha256"] != first_row["user_sub_sha256"]
            or reset_row["slot"] != slot or reset_row["phase"] != "confirmed"):
            raise ValueError
    return {"original": original, "first_pair": first, "latest_pair": current,
            "previous_reset": prior_reset, "original_sha256": original_sha,
            "first_pair_sha256": first_sha, "latest_pair_sha256": _digest(current),
            "previous_reset_sha256": _digest(prior_reset),
            "earlier_reset_sha256": _digest(earlier_reset) if has_chain else None}


def reset_confirmed_pair_once(
    *, clients: Mapping[str, Any], fresh_user_journal: Any, reset_journal: Any,
    account: str, user_pool_id: str, run_id: str, source_sha256: str,
    authorized_from_epoch: int, authorized_until_epoch: int,
    allow_two_confirmed_user_resets: bool = False,
    on_confirmed_user: Callable[[str, str], Any],
    password_factory: Callable[[str], str] | None = None,
    wall_clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Consume both reset intents in order; a non-prepared phase never replays."""
    if allow_two_confirmed_user_resets is not True:
        return {"success": False, "category": "reset_authorization_required", "calls": 0}
    if (not isinstance(clients, Mapping) or set(clients) != {"cognito"}
        or clients.get("cognito") is None or not callable(on_confirmed_user)
        or not callable(wall_clock) or type(account) is not str or _ACCOUNT.fullmatch(account) is None
        or type(user_pool_id) is not str or _POOL.fullmatch(user_pool_id) is None
        or type(run_id) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}\Z", run_id)
        or type(source_sha256) is not str or _SHA1.fullmatch(source_sha256) is None
        or type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
        or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
        or not 0 < authorized_until_epoch - authorized_from_epoch <= 300):
        return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
    if not _valid_journal(fresh_user_journal) or not _valid_journal(reset_journal):
        return {"success": False, "category": "reset_journal_invalid", "calls": 0}
    last, calls = None, 0
    previous_password = None

    def guard() -> float:
        nonlocal last
        now = wall_clock()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
            or now < authorized_from_epoch or now >= authorized_until_epoch
            or last is not None and now < last):
            raise ValueError
        last = float(now)
        return last

    try:
        with reset_journal.locked():
            state = _reset_state(reset_journal.load())
            expected_context = (state["account_id"] == account and state["user_pool_id"] == user_pool_id
                               and state["run_id"] == run_id and state["source_sha256"] == source_sha256
                               and state["authorized_from_epoch"] == authorized_from_epoch
                               and state["authorized_until_epoch"] == authorized_until_epoch)
            if not expected_context or state["phase"] != "prepared":
                return {"success": False, "category": "reset_journal_invalid", "calls": 0}
            with fresh_user_journal.locked():
                expected_user = _validate_state(
                    fresh_user_journal.load(), account=account, pool=user_pool_id, run_id=run_id,
                    binding_sha256=_digest({"account_id": account, "user_pool_id": user_pool_id,
                                            "run_id": run_id, "authorized_from_epoch": authorized_from_epoch,
                                            "authorized_until_epoch": authorized_until_epoch}),
                    start=authorized_from_epoch, end=authorized_until_epoch)
                if (expected_user["preflight"] is not True
                    or any(row["password_status"] != "confirmed" for row in expected_user["slots"])
                    or any(expected_user["slots"][i]["user_sub_sha256"] != state["slots"][i]["subject_sha256"]
                           for i in range(2))
                    or any(row["phase"] != "pending" for row in state["slots"])):
                    return {"success": False, "category": "reset_journal_invalid", "calls": 0}
            get_user = getattr(clients["cognito"], "admin_get_user", None)
            set_password = getattr(clients["cognito"], "admin_set_user_password", None)
            if not callable(get_user) or not callable(set_password):
                return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
            guard()
            for index, slot in enumerate(("A", "B")):
                # B is not touched unless A's reset, readback, and login all succeeded.
                if index == 1:
                    state["phase"] = "a_login_confirmed"
                    state["revision"] += 1
                    guard(); reset_journal.save(state); guard()
                password = password_factory(slot) if password_factory else _generate_private_password()
                if not _valid_private_password(password) or password == previous_password:
                    return {"success": False, "category": "reset_inputs_invalid", "calls": calls}
                previous_password = password
                user = state["slots"][index]
                # Confirm exact enabled/status/identity before consuming the slot's write.
                guard()
                calls += 1
                current = get_user(UserPoolId=user_pool_id, Username=user["username"])
                guard()
                start, end = ((state["original_start_epoch"], state["original_end_epoch"])
                              if slot == "A" else (state["latest_start_epoch"], state["latest_end_epoch"]))
                if _subject_sha(current, username=user["username"], start=start, end=end) != user["subject_sha256"]:
                    raise ValueError
                user["phase"] = "intent"
                state["phase"] = f"{slot.lower()}_intent"
                state["revision"] += 1
                guard(); reset_journal.save(state); guard()
                calls += 1
                try:
                    response = set_password(UserPoolId=user_pool_id, Username=user["username"],
                                             Password=password, Permanent=True)
                except Exception:
                    user["phase"] = "blocked"
                    state["phase"] = "blocked"
                    state["revision"] += 1
                    reset_journal.save(state)
                    return {"success": False, "category": "reset_outcome_unknown", "calls": calls}
                guard()
                if not _ok(response):
                    user["phase"] = "blocked"; state["phase"] = "blocked"
                    state["revision"] += 1; reset_journal.save(state)
                    return {"success": False, "category": "reset_outcome_unknown", "calls": calls}
                guard()
                calls += 1
                observed = get_user(UserPoolId=user_pool_id, Username=user["username"])
                guard()
                created_start, created_end = ((state["original_start_epoch"], state["original_end_epoch"])
                                              if slot == "A" else (state["latest_start_epoch"], state["latest_end_epoch"]))
                observed_sha = _subject_sha(observed, username=user["username"],
                                            start=created_start, end=created_end)
                if observed_sha != user["subject_sha256"]:
                    user["phase"] = "blocked"; state["phase"] = "blocked"
                    state["revision"] += 1; reset_journal.save(state)
                    return {"success": False, "category": "reset_outcome_unknown", "calls": calls}
                user["phase"] = "confirmed"
                state["phase"] = f"{slot.lower()}_password_confirmed"
                state["revision"] += 1
                guard(); reset_journal.save(state); guard()
                try:
                    on_confirmed_user(user["username"], password)
                    guard()
                except Exception:
                    user["phase"] = "login_failed"; state["phase"] = "blocked"
                    state["revision"] += 1; reset_journal.save(state)
                    return {"success": False, "category": "login_failed", "calls": calls}
            state["phase"] = "complete"
            state["revision"] += 1
            guard(); reset_journal.save(state); guard()
            return {"success": True, "category": "users_confirmed", "calls": calls, "users": 2}
    except Exception:
        return {"success": False, "category": "reset_journal_invalid", "calls": calls}


__all__ = ["prepare_confirmed_pair_reset", "reset_confirmed_pair_once"]
