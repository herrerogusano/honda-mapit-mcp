"""Adversarial one-shot reset recovery regressions; no AWS calls."""

from __future__ import annotations

from test_dev_multiuser_confirmed_reset_recovery import (
    ACCOUNT,
    NEW_END,
    NEW_START,
    PASSWORD,
    POOL,
    SUB_A,
    SUB_B,
    RUN,
    AwsError,
    Cognito,
    MemoryJournal,
    _journals,
    _prepare,
    _user,
)
from scripts.dev_multiuser_confirmed_reset_recovery import (
    prepare_confirmed_a_reset,
    reset_a_then_provision_b,
)
from scripts.dev_multiuser_test_users import _username


def test_prepare_expired_or_backward_clock_fails_before_any_read_or_write():
    for clock in (lambda: NEW_END, lambda: NEW_START - 1):
        journals = _journals()
        client = Cognito()
        original, latest, fresh, reset, provenance = journals
        result = prepare_confirmed_a_reset(
            clients={"cognito": client}, original_creation_journal=original,
            latest_confirmed_journal=latest, fresh_user_journal=fresh,
            reset_journal=reset, provenance_journal=provenance,
            account=ACCOUNT, user_pool_id=POOL, new_source_sha256="b" * 40,
            new_authorized_from_epoch=NEW_START, new_authorized_until_epoch=NEW_END,
            allow_single_a_password_reset=True, wall_clock=clock,
        )
        assert result["success"] is False and result["calls"] == 0
        assert client.calls == []
        assert all(j.load() is None for j in (fresh, reset, provenance))


def test_prepare_rejects_duplicate_subject_attribute_and_non_not_found_b():
    class DuplicateSubject(Cognito):
        def admin_get_user(self, *, UserPoolId, Username):
            value = super().admin_get_user(UserPoolId=UserPoolId, Username=Username)
            if Username == _username(RUN, "A"):
                value["UserAttributes"].append({"Name": "sub", "Value": SUB_A})
            return value

    journals = _journals()
    client = DuplicateSubject()
    assert _prepare(client, journals)["category"] == "reset_readback_failed"
    assert all(j.load() is None for j in journals[2:])

    class ForbiddenB(Cognito):
        def admin_get_user(self, *, UserPoolId, Username):
            if Username == _username(RUN, "B"):
                raise AwsError("AccessDeniedException")
            return super().admin_get_user(UserPoolId=UserPoolId, Username=Username)

    journals = _journals()
    client = ForbiddenB()
    assert _prepare(client, journals)["category"] == "reset_readback_failed"
    assert all(j.load() is None for j in journals[2:])


def test_reset_rejects_expired_or_backward_clock_before_password_write():
    for clock in (lambda: NEW_END, lambda: NEW_START - 1):
        journals = _journals()
        client = Cognito()
        assert _prepare(client, journals)["success"] is True
        calls_before = list(client.calls)
        result = reset_a_then_provision_b(
            clients={"cognito": client}, fresh_user_journal=journals[2], reset_journal=journals[3],
            account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256="b" * 40,
            authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
            allow_single_a_password_reset=True, on_confirmed_a=lambda *_: None,
            password_factory=lambda: PASSWORD, wall_clock=clock,
        )
        assert result["success"] is False
        assert client.calls == calls_before


def test_reset_subject_mismatch_never_calls_set_password():
    journals = _journals()
    client = Cognito()
    assert _prepare(client, journals)["success"] is True
    original_get = client.admin_get_user

    def wrong_a(*, UserPoolId, Username):
        if Username == _username(RUN, "A"):
            return _user(Username, SUB_B)
        return original_get(UserPoolId=UserPoolId, Username=Username)

    client.admin_get_user = wrong_a
    result = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=journals[2], reset_journal=journals[3],
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256="b" * 40,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=True, on_confirmed_a=lambda *_: None,
        password_factory=lambda: PASSWORD, wall_clock=lambda: NEW_START + 1,
    )
    assert result["success"] is False
    assert not any(call[0] == "reset" for call in client.calls)


def test_login_failure_is_terminal_and_never_creates_b():
    journals = _journals()
    client = Cognito()
    assert _prepare(client, journals)["success"] is True
    result = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=journals[2], reset_journal=journals[3],
        account=ACCOUNT, user_pool_id=POOL, run_id=RUN, new_source_sha256="b" * 40,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=True,
        on_confirmed_a=lambda *_: (_ for _ in ()).throw(RuntimeError("private callback")),
        on_confirmed_b=lambda *_: None, password_factory=lambda: PASSWORD,
        wall_clock=lambda: NEW_START + 1,
    )
    assert result["category"] == "login_failed"
    assert journals[3].load()["phase"] == "login_failed"
    assert not any(call[0] == "create" for call in client.calls)


def test_reset_requires_explicit_flag_and_rejects_binding_mismatch_without_calls():
    journals = _journals()
    client = Cognito()
    assert _prepare(client, journals)["success"] is True
    calls_before = list(client.calls)
    result = reset_a_then_provision_b(
        clients={"cognito": client}, fresh_user_journal=journals[2], reset_journal=journals[3],
        account="000000000000", user_pool_id=POOL, run_id=RUN, new_source_sha256="b" * 40,
        authorized_from_epoch=NEW_START, authorized_until_epoch=NEW_END,
        allow_single_a_password_reset=False, on_confirmed_a=lambda *_: None,
        password_factory=lambda: PASSWORD, wall_clock=lambda: NEW_START + 1,
    )
    assert result == {"success": False, "category": "reset_authorization_required", "calls": 0}
    assert client.calls == calls_before
