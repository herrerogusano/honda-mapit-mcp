from __future__ import annotations

from scripts.dev_mapit_binding_key_setup import publish_mapit_keys
from tests.test_dev_mapit_binding_key_setup import (
    ACCOUNT,
    CONFIG,
    SOURCE,
    _Journal,
    _call,
    _clients,
)


def test_fresh_window_expiry_after_durable_intent_never_dispatches_or_replays():
    clients, ssm = _clients()
    journal = _Journal()
    ticks = iter((100.0, 101.0, 102.0, 103.0, 104.0, 114.0))

    result = _call(clients, journal, monotonic=lambda: next(ticks))

    assert result["ok"] is False
    assert journal.state["phase"] == "put_intent"
    assert not any(call[0] == "put" for call in ssm.calls)
    call_count = len(ssm.calls)
    assert _call(clients, journal)["category"] == "key_publication_consumed"
    assert len(ssm.calls) == call_count


def test_nonexact_notfound_shape_never_creates_intent_or_put():
    for response in (
        {"Error": {"Code": "AccessDeniedException"}, "ResponseMetadata": {"HTTPStatusCode": 400}},
        {"Error": {"Code": "ParameterNotFound"}, "ResponseMetadata": {"HTTPStatusCode": 403}},
        {"Error": {"Code": "ParameterNotFound"}, "ResponseMetadata": {"HTTPStatusCode": True}},
    ):
        clients, ssm = _clients()
        journal = _Journal()

        class BadAbsence(Exception):
            def __init__(self, reply):
                self.response = reply

        ssm.get_parameter = lambda **_kw: (_ for _ in ()).throw(BadAbsence(response))
        result = _call(clients, journal)
        assert result == {"ok": False, "category": "key_publication_preflight_failed"}
        assert journal.state is None
        assert not any(call[0] == "put" for call in ssm.calls)


def test_wrong_sts_account_or_noncanonical_assumed_role_fails_before_ssm():
    for account, role in (("999999999999", None), (ACCOUNT, "honda-mapit-mcp-dev-identity-enroller")):
        clients, ssm = _clients()
        clients["sts"].account = account
        if role is not None:
            clients["sts"].role = role
        journal = _Journal()
        result = _call(clients, journal)
        assert result == {"ok": False, "category": "key_publication_unauthorized"}
        assert journal.state is None and ssm.calls == []


def test_public_entry_rejects_zero_account_and_invalid_source_before_calls():
    for account, source in (("000000000000", SOURCE), (ACCOUNT, "not-a-source-sha")):
        clients, ssm = _clients()
        journal = _Journal()
        result = publish_mapit_keys(
            clients, journal, account_id=account, config=CONFIG, source_sha=source,
            run_id=17, bootstrap_sha256="b" * 64, start=1_800_000_000, end=1_800_003_600,
            clock=lambda: 1_800_000_050, monotonic=lambda: 100.0,
        )
        assert result["ok"] is False
        assert journal.state is None and ssm.calls == [] and clients["sts"].calls == 0
