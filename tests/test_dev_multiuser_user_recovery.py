from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

import pytest

from scripts.dev_multiuser_journal import PlainFileJournal
from scripts.dev_multiuser_test_users import _base, _canonical, _token, _username
from scripts.dev_multiuser_user_recovery import recover_partial_users


def test_observed_cognito_shape_does_not_require_rfc_version_or_variant():
    from scripts.dev_multiuser_test_users import _digest_subject
    from scripts.run_dev_multiuser_hosted_acceptance import _UUID
    from mapit.aws_dev_runtime import cognito_dev_policy

    subject = "12345678-1234-7abc-1234-123456789abc"
    assert _digest_subject(subject) == hashlib.sha256(subject.encode("ascii")).hexdigest()
    assert _UUID.fullmatch(subject) is not None
    policy = cognito_dev_policy(user_pool_id="eu-west-1_A1b2C3d4E",
                               api_id="abcdefghij", client_id="clientexample",
                               owner_subject=subject)
    assert policy.owner_subject == subject

ACCOUNT = "123456789012"
POOL = "eu-west-1_A1b2C3d4E"
RUN = "2026100601"
OLD_SOURCE = "a" * 40
NEW_SOURCE = "b" * 40
OLD_START, OLD_END = 1_900_000_000, 1_900_000_300
NEW_START, NEW_END = 1_900_001_000, 1_900_001_300


class AwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": 400}}


class Cognito:
    def __init__(self, *, b_error="UserNotFoundException", a_date=True):
        self.calls = []
        self.b_error = b_error
        self.a_date = a_date

    def admin_get_user(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["Username"] == _username(RUN, "B"):
            raise AwsError(self.b_error)
        result = {
            "ResponseMetadata": {"HTTPStatusCode": 200}, "Username": kwargs["Username"],
            "Enabled": True, "UserStatus": "FORCE_CHANGE_PASSWORD",
            "UserAttributes": [{"Name": "sub", "Value": "00000000-0000-0000-0000-000000000001"}],
        }
        if self.a_date:
            result["UserCreateDate"] = datetime.fromtimestamp(OLD_START + 10, timezone.utc)
        return result


def _journal(path, *, original=True):
    path.mkdir()
    journal = PlainFileJournal(path)
    state = _base(account=ACCOUNT, pool=POOL, run_id=RUN,
                  binding_sha256=hashlib.sha256(_canonical({"account_id": ACCOUNT, "user_pool_id": POOL, "run_id": RUN, "authorized_from_epoch": OLD_START, "authorized_until_epoch": OLD_END})).hexdigest(),
                  start=OLD_START, end=OLD_END)
    state["preflight"] = True
    if original:
        state["slots"][0]["create_status"] = "intent"
        state["slots"][0]["create_intent"] = {"operation": "create", "token": _token(ACCOUNT, POOL, RUN, "A", "create")}
    journal.save(state)
    return journal, state


def _empty(path):
    path.mkdir()
    return PlainFileJournal(path)


def test_recovery_reads_a_and_b_once_prepares_fresh_state_and_never_writes_users(tmp_path):
    original, old = _journal(tmp_path / "original")
    fresh = _empty(tmp_path / "fresh")
    provenance = _empty(tmp_path / "provenance")
    client = Cognito()
    result = recover_partial_users(
        clients={"cognito": client}, original_journal=original, new_journal=fresh,
        provenance_journal=provenance, account=ACCOUNT, user_pool_id=POOL,
        new_source_sha256=NEW_SOURCE, new_authorized_from_epoch=NEW_START,
        new_authorized_until_epoch=NEW_END,
    )
    assert result == {"success": True, "category": "recovery_prepared", "calls": 2, "users": 2}
    assert [row["Username"] for row in client.calls] == [_username(RUN, "A"), _username(RUN, "B")]
    state = fresh.load()
    assert state["preflight"] is True
    assert state["run_id"] == RUN
    assert state["slots"][0]["create_status"] == "reconciled"
    assert state["slots"][0]["password_status"] == "not_started"
    assert state["slots"][1]["create_status"] == "pending"
    assert original.load() == old
    receipt = provenance.load()
    assert receipt["kind"] == "retained-dev-multiuser-user-recovery"
    assert "UserCreateDate" not in repr(receipt) and "00000000-0000" not in repr(receipt)


@pytest.mark.parametrize("b_error", ["ResourceNotFoundException", "AccessDeniedException"])
def test_recovery_requires_b_to_be_exact_user_not_found(tmp_path, b_error):
    original, _ = _journal(tmp_path / "original")
    result = recover_partial_users(
        clients={"cognito": Cognito(b_error=b_error)}, original_journal=original,
        new_journal=_empty(tmp_path / "fresh"), provenance_journal=_empty(tmp_path / "provenance"),
        account=ACCOUNT, user_pool_id=POOL, new_source_sha256=NEW_SOURCE,
        new_authorized_from_epoch=NEW_START, new_authorized_until_epoch=NEW_END,
    )
    assert result["category"] == "recovery_readback_failed"


def test_recovery_requires_original_shape_and_timestamp(tmp_path):
    original, _ = _journal(tmp_path / "original")
    original.save({**original.load(), "slots": [{**original.load()["slots"][0], "password_intent": {"operation": "set-password", "token": "x"}}, original.load()["slots"][1]]})
    result = recover_partial_users(
        clients={"cognito": Cognito()}, original_journal=original,
        new_journal=_empty(tmp_path / "fresh"), provenance_journal=_empty(tmp_path / "provenance"),
        account=ACCOUNT, user_pool_id=POOL, new_source_sha256=NEW_SOURCE,
        new_authorized_from_epoch=NEW_START, new_authorized_until_epoch=NEW_END,
    )
    assert result["category"] == "recovery_journal_invalid"

    original, _ = _journal(tmp_path / "original-date")
    result = recover_partial_users(
        clients={"cognito": Cognito(a_date=False)}, original_journal=original,
        new_journal=_empty(tmp_path / "fresh-date"), provenance_journal=_empty(tmp_path / "provenance-date"),
        account=ACCOUNT, user_pool_id=POOL, new_source_sha256=NEW_SOURCE,
        new_authorized_from_epoch=NEW_START, new_authorized_until_epoch=NEW_END,
    )
    assert result["category"] == "recovery_readback_failed"


@pytest.mark.parametrize(
    "label, mutate",
    [
        ("schema-bool", lambda state: state.update(schema=True)),
        ("binding-mutated", lambda state: state.update(binding_sha256=("0" if state["binding_sha256"][0] != "0" else "1") + state["binding_sha256"][1:])),
        ("start-float", lambda state: state.update(authorized_from_epoch=float(OLD_START))),
        ("end-float", lambda state: state.update(authorized_until_epoch=float(OLD_END))),
        ("start-bool", lambda state: state.update(authorized_from_epoch=True)),
        ("run-id-shape", lambda state: state.update(run_id="01")),
        ("window-too-long", lambda state: state.update(authorized_until_epoch=OLD_START + 301)),
        ("account-mismatch", lambda state: state.update(account_id="210987654321")),
        ("pool-mismatch", lambda state: state.update(user_pool_id="eu-west-1_Z9y8X7w6V")),
        ("slot-a-subject", lambda state: state["slots"][0].update(user_sub_sha256="a" * 64)),
        ("slot-b-subject", lambda state: state["slots"][1].update(user_sub_sha256="b" * 64)),
    ],
)
def test_recovery_original_binding_is_strict_and_pristine(tmp_path, label, mutate):
    original, state = _journal(tmp_path / f"original-{label}")
    mutated = json.loads(json.dumps(state))
    mutate(mutated)
    original.save(mutated)
    client = Cognito()
    result = recover_partial_users(
        clients={"cognito": client}, original_journal=original,
        new_journal=_empty(tmp_path / f"fresh-{label}"),
        provenance_journal=_empty(tmp_path / f"provenance-{label}"),
        account=ACCOUNT, user_pool_id=POOL, new_source_sha256=NEW_SOURCE,
        new_authorized_from_epoch=NEW_START, new_authorized_until_epoch=NEW_END,
    )
    assert result == {"success": False, "category": "recovery_journal_invalid", "calls": 0}
    assert client.calls == []
