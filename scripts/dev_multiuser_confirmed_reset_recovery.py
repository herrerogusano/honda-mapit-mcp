"""Separate, one-shot reset recovery for confirmed technical user A.

The historical partial-create recovery and its consumed journals are never
modified. Preparation is read-only with respect to Cognito. A separate injected
operator consumes the reset-specific journal, persists one new intent, resets
A once, performs the A login callback, and then delegates B to the existing
two-user operator. No SDK client is constructed here.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
import hashlib
import json
import math
import re
import time
from typing import Any, Callable

from scripts.dev_multiuser_test_users import (
    MAX_CALLS, DevMultiuserTestUserOperator, _UUID, _base, _canonical,
    _digest_subject, _generate_private_password, _intent, _ok, _token,
    _username, _valid_private_password, _validate_state,
)
from scripts.dev_multiuser_user_recovery import _validate_original

_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,64}\Z")
_SOURCE = re.compile(r"[0-9a-f]{40}\Z")
_RESET_KIND = "retained-dev-multiuser-confirmed-a-reset"
_CATEGORIES = frozenset({
    "reset_authorization_required", "reset_inputs_invalid", "reset_journal_invalid",
    "reset_journal_not_empty", "reset_readback_failed", "reset_prepared",
    "reset_intent_saved", "password_outcome_unknown", "reset_password_confirmed",
    "login_failed", "a_login_confirmed", "b_user_conflict", "b_reconciliation_required",
    "users_confirmed", "provision_incomplete", "window_expired", "call_budget_exhausted",
})


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: Any) -> float | None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        return None
    try:
        stamp = value.timestamp()
    except Exception:
        return None
    return stamp if math.isfinite(stamp) else None


def _confirmed_subject(response: Any, *, username: str, original_start: int,
                       original_end: int) -> str:
    if not isinstance(response, Mapping):
        raise ValueError
    metadata = response.get("ResponseMetadata")
    if (not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
        or metadata.get("HTTPStatusCode") != 200 or response.get("Username") != username
        or response.get("Enabled") is not True or response.get("UserStatus") != "CONFIRMED"):
        raise ValueError
    created = _timestamp(response.get("UserCreateDate"))
    if created is None or not original_start <= created < original_end:
        raise ValueError
    attributes = response.get("UserAttributes")
    if type(attributes) is not list:
        raise ValueError
    subjects = []
    for row in attributes:
        if (not isinstance(row, Mapping) or set(row) != {"Name", "Value"}
            or type(row.get("Name")) is not str or type(row.get("Value")) is not str):
            raise ValueError
        if row["Name"] == "sub":
            subjects.append(row["Value"])
    if len(subjects) != 1 or _UUID.fullmatch(subjects[0]) is None:
        raise ValueError
    return _digest_subject(subjects[0])


def _error_code(exc: BaseException) -> str | None:
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return code if type(code) is str else None


def _require_journal(journal: Any) -> bool:
    return all(callable(getattr(journal, field, None)) for field in ("load", "save", "locked"))


def _latest_confirmed(value: Any, *, account: str, pool: str,
                      original: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError
    if type(value.get("schema")) is not int or isinstance(value.get("schema"), bool):
        raise ValueError
    start, end = value.get("authorized_from_epoch"), value.get("authorized_until_epoch")
    if (type(start) is not int or type(end) is not int or isinstance(start, bool)
        or isinstance(end, bool) or start < original["authorized_until_epoch"]
        or end <= start or end - start > 300):
        raise ValueError
    binding = _digest({"account_id": account, "user_pool_id": pool,
                       "run_id": original["run_id"],
                       "authorized_from_epoch": start,
                       "authorized_until_epoch": end})
    state = _validate_state(value, account=account, pool=pool,
                            run_id=original["run_id"], binding_sha256=binding,
                            start=start, end=end)
    original_a, original_b = original["slots"]
    a, b = state["slots"]
    if (state["preflight"] is not True
        or a["create_status"] != "reconciled"
        or a["create_intent"] != original_a["create_intent"]
        or a["password_status"] != "confirmed"
        or not _intent(a["password_intent"], operation="set-password",
                       expected=_token(account, pool, original["run_id"], "A", "set-password"))
        or type(a["user_sub_sha256"]) is not str
        or b["slot"] != "B" or b["create_status"] != "pending"
        or b["create_intent"] is not None or b["password_status"] != "not_started"
        or b["password_intent"] is not None or b["user_sub_sha256"] is not None
        or original_b["create_status"] != "pending"):
        raise ValueError
    return json.loads(_canonical(state).decode("ascii"))


def _reset_context(value: Any) -> dict[str, Any]:
    fields = {
        "schema", "kind", "revision", "phase", "account_id", "user_pool_id",
        "run_id", "source_sha256", "authorized_from_epoch", "authorized_until_epoch",
        "original_creation_sha256", "latest_confirmed_sha256", "original_start_epoch",
        "original_end_epoch", "confirmed_a_subject_sha256", "reset_token", "binding_sha256",
        "reset_authorized",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError
    if (type(value["schema"]) is not int or value["schema"] != 1
        or value["kind"] != _RESET_KIND or type(value["revision"]) is not int
        or isinstance(value["revision"], bool) or value["revision"] < 0
        or value["phase"] not in {"prepared", "intent", "password_confirmed", "a_login_confirmed", "b_provisioning", "complete", "blocked", "login_failed"}
        or type(value["account_id"]) is not str or _ACCOUNT.fullmatch(value["account_id"]) is None
        or value["account_id"] == "0" * 12 or type(value["user_pool_id"]) is not str
        or _POOL.fullmatch(value["user_pool_id"]) is None
        or value["reset_authorized"] is not True
        or type(value["run_id"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}\Z", value["run_id"])
        or type(value["source_sha256"]) is not str or _SOURCE.fullmatch(value["source_sha256"]) is None):
        raise ValueError
    for key in ("authorized_from_epoch", "authorized_until_epoch", "original_start_epoch", "original_end_epoch"):
        if type(value[key]) is not int or isinstance(value[key], bool) or value[key] <= 0:
            raise ValueError
    if (not value["authorized_from_epoch"] <= value["authorized_until_epoch"]
        or value["authorized_until_epoch"] - value["authorized_from_epoch"] > 300
        or value["original_start_epoch"] >= value["original_end_epoch"]
        or type(value["confirmed_a_subject_sha256"]) is not str
        or not re.fullmatch(r"[0-9a-f]{64}\Z", value["confirmed_a_subject_sha256"])):
        raise ValueError
    for key in ("original_creation_sha256", "latest_confirmed_sha256", "binding_sha256", "reset_token"):
        if type(value[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}\Z", value[key]):
            raise ValueError
    binding = {key: value[key] for key in (
        "account_id", "user_pool_id", "run_id", "source_sha256",
        "authorized_from_epoch", "authorized_until_epoch", "original_creation_sha256",
        "latest_confirmed_sha256", "original_start_epoch", "original_end_epoch",
        "confirmed_a_subject_sha256", "reset_authorized",
    )}
    if value["binding_sha256"] != _digest(binding) or value["reset_token"] != _digest({
        "operation": "reset-confirmed-a-password", "binding_sha256": value["binding_sha256"]
    }):
        raise ValueError
    return value


def prepare_confirmed_a_reset(
    *, clients: Mapping[str, Any], original_creation_journal: Any,
    latest_confirmed_journal: Any, fresh_user_journal: Any,
    reset_journal: Any, provenance_journal: Any, account: str, user_pool_id: str,
    new_source_sha256: str, new_authorized_from_epoch: int,
    new_authorized_until_epoch: int, allow_single_a_password_reset: bool = False,
    wall_clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Read back A/B and write fresh preparation only; no Cognito write occurs."""
    calls = 0
    if allow_single_a_password_reset is not True:
        return {"success": False, "category": "reset_authorization_required", "calls": 0}
    if (not isinstance(clients, Mapping) or set(clients) != {"cognito"}
        or clients.get("cognito") is None or type(account) is not str
        or _ACCOUNT.fullmatch(account) is None or account == "0" * 12
        or type(user_pool_id) is not str or _POOL.fullmatch(user_pool_id) is None
        or type(new_source_sha256) is not str or _SOURCE.fullmatch(new_source_sha256) is None
        or type(new_authorized_from_epoch) is not int or isinstance(new_authorized_from_epoch, bool)
        or type(new_authorized_until_epoch) is not int or isinstance(new_authorized_until_epoch, bool)
        or not 0 < new_authorized_until_epoch - new_authorized_from_epoch <= 300
        or not callable(wall_clock)):
        return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
    journals = (original_creation_journal, latest_confirmed_journal,
                fresh_user_journal, reset_journal, provenance_journal)
    if len({id(item) for item in journals}) != len(journals) or any(not _require_journal(item) for item in journals):
        return {"success": False, "category": "reset_journal_invalid", "calls": 0}
    last: float | None = None

    def guard() -> float:
        nonlocal last
        now = wall_clock()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
            or now < new_authorized_from_epoch or now >= new_authorized_until_epoch
            or last is not None and now < last):
            raise ValueError
        last = float(now)
        return last

    try:
        guard()
        with (original_creation_journal.locked(), latest_confirmed_journal.locked(),
              fresh_user_journal.locked(), reset_journal.locked(), provenance_journal.locked()):
            if (fresh_user_journal.load() is not None or reset_journal.load() is not None
                or provenance_journal.load() is not None):
                return {"success": False, "category": "reset_journal_not_empty", "calls": 0}
            original = _validate_original(original_creation_journal.load(), account=account, pool=user_pool_id)
            latest = _latest_confirmed(latest_confirmed_journal.load(), account=account,
                                       pool=user_pool_id, original=original)
            if new_authorized_from_epoch < latest["authorized_until_epoch"]:
                return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
            original_sha, latest_sha = _digest(original), _digest(latest)
            run_id = original["run_id"]
            username_a, username_b = _username(run_id, "A"), _username(run_id, "B")
            get_user = getattr(clients["cognito"], "admin_get_user", None)
            if not callable(get_user):
                return {"success": False, "category": "reset_readback_failed", "calls": 0}
            guard()
            calls += 1
            user_a = get_user(UserPoolId=user_pool_id, Username=username_a)
            guard()
            subject_sha = _confirmed_subject(
                user_a, username=username_a,
                original_start=original["authorized_from_epoch"],
                original_end=original["authorized_until_epoch"],
            )
            if subject_sha != latest["slots"][0]["user_sub_sha256"]:
                return {"success": False, "category": "reset_readback_failed", "calls": calls}
            guard()
            calls += 1
            try:
                get_user(UserPoolId=user_pool_id, Username=username_b)
            except Exception as exc:
                guard()
                response = getattr(exc, "response", None)
                error = response.get("Error") if isinstance(response, Mapping) else None
                metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
                if (not isinstance(error, Mapping) or error.get("Code") != "UserNotFoundException"
                    or not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
                    or metadata.get("HTTPStatusCode") != 400):
                    return {"success": False, "category": "reset_readback_failed", "calls": calls}
            else:
                return {"success": False, "category": "reset_readback_failed", "calls": calls}
            guard()

            context = {
                "account_id": account, "user_pool_id": user_pool_id, "run_id": run_id,
                "source_sha256": new_source_sha256,
                "authorized_from_epoch": new_authorized_from_epoch,
                "authorized_until_epoch": new_authorized_until_epoch,
                "original_creation_sha256": original_sha,
                "latest_confirmed_sha256": latest_sha,
                "original_start_epoch": original["authorized_from_epoch"],
                "original_end_epoch": original["authorized_until_epoch"],
                "confirmed_a_subject_sha256": subject_sha,
                "reset_authorized": True,
            }
            binding_sha = _digest(context)
            reset_state = {
                "schema": 1, "kind": _RESET_KIND, "revision": 0, "phase": "prepared",
                **context, "binding_sha256": binding_sha,
                "reset_authorized": True,
                "reset_token": _digest({"operation": "reset-confirmed-a-password", "binding_sha256": binding_sha}),
            }
            user_state = _base(
                account=account, pool=user_pool_id, run_id=run_id,
                binding_sha256=_digest({"account_id": account, "user_pool_id": user_pool_id,
                                        "run_id": run_id, "authorized_from_epoch": new_authorized_from_epoch,
                                        "authorized_until_epoch": new_authorized_until_epoch}),
                start=new_authorized_from_epoch, end=new_authorized_until_epoch,
            )
            user_state["preflight"] = True
            user_state["slots"][0].update({
                "create_status": "reconciled", "create_intent": original["slots"][0]["create_intent"],
                "password_status": "confirmed", "password_intent": latest["slots"][0]["password_intent"],
                "user_sub_sha256": subject_sha,
            })
            provenance = {
                "schema": 1, "kind": _RESET_KIND, "phase": "readback_verified",
                "binding_sha256": binding_sha, **context,
                "reset_authorized": True, "cognito_writes": 0,
            }
            guard()
            fresh_user_journal.save(user_state)
            guard()
            provenance_journal.save(provenance)
            guard()
            reset_journal.save(reset_state)
            guard()
        return {"success": True, "category": "reset_prepared", "calls": calls, "cognito_writes": 0}
    except Exception:
        return {"success": False, "category": "reset_readback_failed" if calls else "reset_journal_invalid", "calls": calls}


class _BoundedCognito:
    def __init__(self, client: Any, guard: Callable[[], float], *, initial_calls: int = 0):
        self._client, self._guard, self.calls = client, guard, initial_calls

    def __getattr__(self, name: str):
        if name not in {"admin_get_user", "admin_create_user", "admin_set_user_password"}:
            raise AttributeError(name)
        function = getattr(self._client, name, None)
        if not callable(function):
            raise AttributeError(name)

        def call(**kwargs):
            self._guard()
            if self.calls >= MAX_CALLS:
                raise RuntimeError("call_budget_exhausted")
            self.calls += 1
            try:
                result = function(**kwargs)
            except Exception:
                self._guard()
                raise
            self._guard()
            return result
        return call


def reset_a_then_provision_b(
    *, clients: Mapping[str, Any], fresh_user_journal: Any,
    reset_journal: Any, account: str, user_pool_id: str, run_id: str,
    new_source_sha256: str, authorized_from_epoch: int,
    authorized_until_epoch: int, allow_single_a_password_reset: bool = False,
    on_confirmed_a: Callable[[str, str], Any],
    on_confirmed_b: Callable[[str, str], Any] | None = None,
    password_factory: Callable[[], str] = _generate_private_password,
    wall_clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Consume one reset intent, login A, then let the standard operator provision B.

    This is a single process-local attempt. Every phase other than prepared is
    terminal for re-entry, including a crash after A login: the password and
    tokens are not persisted, so a later process cannot continue the pair proof.
    It can never replay the A reset call.
    """
    calls = 0
    if allow_single_a_password_reset is not True:
        return {"success": False, "category": "reset_authorization_required", "calls": 0}
    if (not isinstance(clients, Mapping) or set(clients) != {"cognito"}
        or clients.get("cognito") is None or not callable(on_confirmed_a)
        or on_confirmed_b is not None and not callable(on_confirmed_b)
        or not callable(password_factory) or not callable(wall_clock)
        or type(account) is not str or _ACCOUNT.fullmatch(account) is None or account == "0" * 12
        or type(user_pool_id) is not str or _POOL.fullmatch(user_pool_id) is None
        or type(run_id) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}\Z", run_id)
        or type(new_source_sha256) is not str or _SOURCE.fullmatch(new_source_sha256) is None
        or type(authorized_from_epoch) is not int or isinstance(authorized_from_epoch, bool)
        or type(authorized_until_epoch) is not int or isinstance(authorized_until_epoch, bool)
        or authorized_until_epoch - authorized_from_epoch <= 0
        or authorized_until_epoch - authorized_from_epoch > 300):
        return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
    last: float | None = None

    def guard() -> float:
        nonlocal last
        now = wall_clock()
        if (type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now)
            or now < authorized_from_epoch or now >= authorized_until_epoch
            or last is not None and now < last):
            raise ValueError
        last = float(now)
        return last

    if not _require_journal(reset_journal) or not _require_journal(fresh_user_journal):
        return {"success": False, "category": "reset_journal_invalid", "calls": 0}
    try:
        with reset_journal.locked():
            reset = _reset_context(reset_journal.load())
            if any(reset.get(key) != expected for key, expected in (
                ("account_id", account), ("user_pool_id", user_pool_id),
                ("run_id", run_id), ("source_sha256", new_source_sha256),
                ("authorized_from_epoch", authorized_from_epoch),
                ("authorized_until_epoch", authorized_until_epoch),
            )):
                raise ValueError
            if reset["phase"] == "prepared":
                with fresh_user_journal.locked():
                    user_state = fresh_user_journal.load()
                    expected_user = _validate_state(
                        user_state, account=account, pool=user_pool_id, run_id=run_id,
                        binding_sha256=_digest({"account_id": account, "user_pool_id": user_pool_id,
                                                "run_id": run_id, "authorized_from_epoch": authorized_from_epoch,
                                                "authorized_until_epoch": authorized_until_epoch}),
                        start=authorized_from_epoch, end=authorized_until_epoch,
                    )
                    a, b = expected_user["slots"]
                    if (expected_user["preflight"] is not True or a["create_status"] != "reconciled"
                        or a["password_status"] != "confirmed" or a["user_sub_sha256"] != reset["confirmed_a_subject_sha256"]
                        or b["create_status"] != "pending" or b["password_status"] != "not_started"):
                        raise ValueError
                password = password_factory()
                if not _valid_private_password(password):
                    return {"success": False, "category": "reset_inputs_invalid", "calls": 0}
                guard()
                cognito = clients["cognito"]
                username_a, username_b = _username(run_id, "A"), _username(run_id, "B")
                calls += 1
                user_a = cognito.admin_get_user(UserPoolId=user_pool_id, Username=username_a)
                guard()
                subject_sha = _confirmed_subject(
                    user_a, username=username_a, original_start=reset["original_start_epoch"],
                    original_end=reset["original_end_epoch"],
                )
                if subject_sha != reset["confirmed_a_subject_sha256"]:
                    raise ValueError
                calls += 1
                try:
                    cognito.admin_get_user(UserPoolId=user_pool_id, Username=username_b)
                except Exception as exc:
                    response = getattr(exc, "response", None)
                    error = response.get("Error") if isinstance(response, Mapping) else None
                    metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
                    if (not isinstance(error, Mapping) or error.get("Code") != "UserNotFoundException"
                        or not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
                        or metadata.get("HTTPStatusCode") != 400):
                        raise ValueError from None
                else:
                    return {"success": False, "category": "b_user_conflict", "calls": calls}
                guard()
                reset["phase"] = "intent"
                reset["revision"] += 1
                reset_journal.save(reset)
                guard()
                calls += 1
                try:
                    response = cognito.admin_set_user_password(
                        UserPoolId=user_pool_id, Username=username_a, Password=password, Permanent=True,
                    )
                except Exception:
                    reset["phase"] = "blocked"
                    reset["revision"] += 1
                    reset_journal.save(reset)
                    return {"success": False, "category": "password_outcome_unknown", "calls": calls}
                guard()
                if not _ok(response):
                    reset["phase"] = "blocked"
                    reset["revision"] += 1
                    reset_journal.save(reset)
                    return {"success": False, "category": "password_outcome_unknown", "calls": calls}
                reset["phase"] = "intent"  # The durable intent remains consumed until readback.
                reset["revision"] += 1
                reset_journal.save(reset)
                calls += 1
                user_a = cognito.admin_get_user(UserPoolId=user_pool_id, Username=username_a)
                guard()
                if _confirmed_subject(
                    user_a, username=username_a, original_start=reset["original_start_epoch"],
                    original_end=reset["original_end_epoch"],
                ) != subject_sha:
                    reset["phase"] = "blocked"
                    reset["revision"] += 1
                    reset_journal.save(reset)
                    return {"success": False, "category": "password_outcome_unknown", "calls": calls}
                reset["phase"] = "password_confirmed"
                reset["revision"] += 1
                reset_journal.save(reset)
                guard()
                try:
                    on_confirmed_a(username_a, password)
                    guard()
                except Exception:
                    reset["phase"] = "login_failed"
                    reset["revision"] += 1
                    reset_journal.save(reset)
                    return {"success": False, "category": "login_failed", "calls": calls}
                reset["phase"] = "a_login_confirmed"
                reset["revision"] += 1
                reset_journal.save(reset)
            else:
                return {"success": False, "category": "reset_journal_invalid", "calls": 0}

            # Only the existing provisioner can create B. It skips A because
            # the prepared standard journal keeps A's password confirmed.
            with fresh_user_journal.locked():
                user_state = _validate_state(
                    fresh_user_journal.load(), account=account, pool=user_pool_id, run_id=run_id,
                    binding_sha256=_digest({"account_id": account, "user_pool_id": user_pool_id,
                                            "run_id": run_id, "authorized_from_epoch": authorized_from_epoch,
                                            "authorized_until_epoch": authorized_until_epoch}),
                    start=authorized_from_epoch, end=authorized_until_epoch,
                )
                a, b = user_state["slots"]
                if (a["password_status"] != "confirmed" or b["create_status"] != "pending"
                    or b["create_intent"] is not None or b["password_status"] != "not_started"):
                    return {"success": False, "category": "b_reconciliation_required", "calls": calls}
            guard()
            # Recheck B's exact absence immediately before delegating its
            # create intent; preparation-time absence alone is not enough.
            calls += 1
            try:
                clients["cognito"].admin_get_user(
                    UserPoolId=user_pool_id, Username=_username(run_id, "B"),
                )
            except Exception as exc:
                guard()
                response = getattr(exc, "response", None)
                error = response.get("Error") if isinstance(response, Mapping) else None
                metadata = response.get("ResponseMetadata") if isinstance(response, Mapping) else None
                if (not isinstance(error, Mapping) or error.get("Code") != "UserNotFoundException"
                    or not isinstance(metadata, Mapping) or type(metadata.get("HTTPStatusCode")) is not int
                    or metadata.get("HTTPStatusCode") != 400):
                    return {"success": False, "category": "b_user_conflict", "calls": calls}
            else:
                return {"success": False, "category": "b_user_conflict", "calls": calls}
            guard()
            reset["phase"] = "b_provisioning"
            reset["revision"] += 1
            reset_journal.save(reset)
            bounded = _BoundedCognito(clients["cognito"], guard, initial_calls=calls)
            operator = DevMultiuserTestUserOperator(
                {"cognito": bounded}, fresh_user_journal, account_id=account,
                user_pool_id=user_pool_id, run_id=run_id,
                authorized_from_epoch=authorized_from_epoch,
                authorized_until_epoch=authorized_until_epoch, wall_clock=guard,
            )
            result = operator.provision(on_confirmed_user=on_confirmed_b,
                                        password_factory=password_factory)
            calls = bounded.calls
            if result.get("success") is True and result.get("category") == "users_confirmed":
                guard()
                reset["phase"] = "complete"
                reset["revision"] += 1
                reset_journal.save(reset)
                return {"success": True, "category": "users_confirmed", "calls": calls, "users": 2}
            if result.get("category") == "login_failed":
                reset["phase"] = "blocked"
                reset["revision"] += 1
                reset_journal.save(reset)
                return {"success": False, "category": "login_failed", "calls": calls}
            # This reset authorization is one-shot. A new recovery would need
            # a separately approved source, window, journal, and reset token.
            reset["phase"] = "a_login_confirmed"
            reset["revision"] += 1
            reset_journal.save(reset)
            return {"success": False, "category": "provision_incomplete", "calls": calls}
    except Exception:
        return {"success": False, "category": "reset_journal_invalid", "calls": calls}


__all__ = ["prepare_confirmed_a_reset", "reset_a_then_provision_b"]
