"""Offline-testable, read-before-write recovery for a partial user setup.

The original journal is immutable input.  Recovery performs exactly two
``AdminGetUser`` reads (A and B), records a detached private provenance receipt,
and prepares a fresh user journal.  It never calls create/set-password and
never accepts ``ResourceNotFoundException`` as proof that B is absent.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import math
import re
from typing import Any

from scripts.dev_multiuser_test_users import (
    _UUID, _base, _canonical, _digest_subject, _intent, _ok, _token,
    _username, _validate_state, _error_code,
)

_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_RUN = re.compile(r"[1-9][0-9]{0,19}\Z")
_CATEGORIES = frozenset({
    "recovery_inputs_invalid", "recovery_journal_invalid", "recovery_readback_failed",
    "recovery_provenance_failed", "recovery_prepared",
})


class DevMultiuserRecoveryError(ValueError):
    def __init__(self, category: str):
        self.category = category if category in _CATEGORIES else "recovery_journal_invalid"
        super().__init__(self.category)


def _fail(category: str) -> None:
    raise DevMultiuserRecoveryError(category)


def _digest(value: Any) -> str:
    try:
        return hashlib.sha256(_canonical(value)).hexdigest()
    except Exception:
        _fail("recovery_journal_invalid")


def _aware_timestamp(value: Any) -> float | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    try:
        stamp = value.timestamp()
    except Exception:
        return None
    return stamp if math.isfinite(stamp) else None


def _subject_from_user(value: Any, *, username: str, start: int, end: int) -> str:
    if not _ok(value) or not isinstance(value, Mapping):
        _fail("recovery_readback_failed")
    if value.get("Username") != username or value.get("Enabled") is not True or value.get("UserStatus") != "FORCE_CHANGE_PASSWORD":
        _fail("recovery_readback_failed")
    stamp = _aware_timestamp(value.get("UserCreateDate"))
    if stamp is None or not start <= stamp < end:
        _fail("recovery_readback_failed")
    attrs = value.get("UserAttributes")
    if not isinstance(attrs, list):
        _fail("recovery_readback_failed")
    subjects: list[str] = []
    for row in attrs:
        if not isinstance(row, Mapping) or set(row) != {"Name", "Value"} or type(row["Name"]) is not str or type(row["Value"]) is not str:
            _fail("recovery_readback_failed")
        if row["Name"] == "sub":
            subjects.append(row["Value"])
    if len(subjects) != 1 or _UUID.fullmatch(subjects[0]) is None:
        _fail("recovery_readback_failed")
    return _digest_subject(subjects[0])


def _validate_original(state: Any, *, account: str, pool: str) -> dict[str, Any]:
    if not isinstance(state, Mapping):
        _fail("recovery_journal_invalid")
    run_id = state.get("run_id")
    start, end = state.get("authorized_from_epoch"), state.get("authorized_until_epoch")
    binding = state.get("binding_sha256")
    if (
        type(state.get("schema")) is not int or state.get("schema") != 1
        or type(state.get("account_id")) is not str or _ACCOUNT.fullmatch(state["account_id"]) is None
        or state["account_id"] != account
        or type(state.get("user_pool_id")) is not str or _POOL.fullmatch(state["user_pool_id"]) is None
        or state["user_pool_id"] != pool
        or type(run_id) is not str or _RUN.fullmatch(run_id) is None
        or type(start) is not int or isinstance(start, bool) or start <= 0
        or type(end) is not int or isinstance(end, bool) or end <= start or end - start > 300
        or type(binding) is not str or re.fullmatch(r"[0-9a-f]{64}", binding) is None
    ):
        _fail("recovery_journal_invalid")
    expected_binding = hashlib.sha256(_canonical({
        "account_id": account,
        "user_pool_id": pool,
        "run_id": run_id,
        "authorized_from_epoch": start,
        "authorized_until_epoch": end,
    })).hexdigest()
    if binding != expected_binding:
        _fail("recovery_journal_invalid")
    try:
        _validate_state(state, account=account, pool=pool, run_id=run_id,
                        binding_sha256=binding, start=start, end=end)
    except Exception:
        _fail("recovery_journal_invalid")
    if state.get("preflight") is not True or type(run_id) is not str:
        _fail("recovery_journal_invalid")
    rows = state["slots"]
    a, b = rows
    if (a.get("slot") != "A" or a.get("create_status") != "intent"
        or not _intent(a.get("create_intent"), operation="create", expected=_token(account, pool, run_id, "A", "create"))
        or a.get("password_status") != "not_started" or a.get("password_intent") is not None
        or a.get("user_sub_sha256") is not None
        or b.get("slot") != "B" or b.get("create_status") != "pending" or b.get("create_intent") is not None
        or b.get("password_status") != "not_started" or b.get("password_intent") is not None
        or b.get("user_sub_sha256") is not None):
        _fail("recovery_journal_invalid")
    return json.loads(_canonical(state).decode("ascii"))


def recover_partial_users(
    *,
    clients: Mapping[str, Any],
    original_journal: Any,
    new_journal: Any,
    provenance_journal: Any,
    account: str,
    user_pool_id: str,
    new_source_sha256: str,
    new_authorized_from_epoch: int,
    new_authorized_until_epoch: int,
) -> dict[str, Any]:
    """Prepare A-reconciled/B-pending state without replaying any write."""
    calls = 0
    try:
        if (not isinstance(clients, Mapping) or set(clients) != {"cognito"}
            or clients.get("cognito") is None or not _ACCOUNT.fullmatch(account)
            or not _POOL.fullmatch(user_pool_id) or not _SOURCE.fullmatch(new_source_sha256)
            or type(new_authorized_from_epoch) is not int or type(new_authorized_until_epoch) is not int
            or isinstance(new_authorized_from_epoch, bool) or isinstance(new_authorized_until_epoch, bool)
            or not 0 < new_authorized_until_epoch - new_authorized_from_epoch <= 300):
            return {"success": False, "category": "recovery_inputs_invalid", "calls": calls}
        load = getattr(original_journal, "load", None)
        new_load = getattr(new_journal, "load", None)
        provenance_load = getattr(provenance_journal, "load", None)
        if not all(callable(item) for item in (load, new_load, provenance_load)):
            return {"success": False, "category": "recovery_journal_invalid", "calls": calls}
        original = load()
        if new_load() is not None or provenance_load() is not None:
            return {"success": False, "category": "recovery_journal_invalid", "calls": 0}
        original = _validate_original(original, account=account, pool=user_pool_id)
        run_id = original["run_id"]
        start = original["authorized_from_epoch"]
        end = original["authorized_until_epoch"]
        username_a, username_b = _username(run_id, "A"), _username(run_id, "B")
        get_user = getattr(clients["cognito"], "admin_get_user", None)
        if not callable(get_user):
            return {"success": False, "category": "recovery_inputs_invalid", "calls": calls}
        calls += 1
        try:
            user_a = get_user(UserPoolId=user_pool_id, Username=username_a)
        except Exception:
            return {"success": False, "category": "recovery_readback_failed", "calls": calls}
        subject_digest = _subject_from_user(user_a, username=username_a, start=start, end=end)
        calls += 1
        try:
            get_user(UserPoolId=user_pool_id, Username=username_b)
        except Exception as exc:
            if _error_code(exc) != "UserNotFoundException":
                return {"success": False, "category": "recovery_readback_failed", "calls": calls}
        else:
            return {"success": False, "category": "recovery_readback_failed", "calls": calls}

        new_digest = _digest({"account": account, "pool": user_pool_id, "run_id": run_id,
                              "source": new_source_sha256, "start": new_authorized_from_epoch,
                              "end": new_authorized_until_epoch})
        provenance = {
            "schema": 1, "kind": "retained-dev-multiuser-user-recovery",
            "original_state_sha256": _digest(original), "recovered_subject_sha256": subject_digest,
            "account_id": account, "user_pool_id": user_pool_id, "run_id": run_id,
            "new_source_sha256": new_source_sha256, "new_authorization_sha256": new_digest,
            "new_authorized_from_epoch": new_authorized_from_epoch,
            "new_authorized_until_epoch": new_authorized_until_epoch,
            "phase": "readback_verified",
        }
        fresh = _base(account=account, pool=user_pool_id, run_id=run_id,
                      binding_sha256=_digest({"account_id": account, "user_pool_id": user_pool_id,
                                              "run_id": run_id, "authorized_from_epoch": new_authorized_from_epoch,
                                              "authorized_until_epoch": new_authorized_until_epoch}),
                      start=new_authorized_from_epoch, end=new_authorized_until_epoch)
        fresh["preflight"] = True
        fresh["slots"][0]["create_status"] = "reconciled"
        fresh["slots"][0]["create_intent"] = original["slots"][0]["create_intent"]
        fresh["slots"][0]["user_sub_sha256"] = subject_digest
        provenance_journal.save(provenance)
        new_journal.save(fresh)
        return {"success": True, "category": "recovery_prepared", "calls": calls, "users": 2}
    except DevMultiuserRecoveryError as exc:
        return {"success": False, "category": exc.category, "calls": calls}
    except Exception:
        return {"success": False, "category": "recovery_journal_invalid", "calls": calls}


__all__ = ["DevMultiuserRecoveryError", "recover_partial_users"]
