from __future__ import annotations

from test_aws_dev_identity_binding_bootstrap import _bootstrap_fixture
from test_dev_identity_binding_key_setup import ACCOUNT, CONFIG, fixture as _key_fixture
from scripts.dev_identity_binding_key_setup import publish_keys


def test_bootstrap_cutoff_after_saved_intent_never_dispatches_create_or_replays():
    coordinator, journal, _ = _bootstrap_fixture()
    assert coordinator.run_step("preflight")["ok"] is True

    clock = [100.0]
    coordinator.monotonic = lambda: clock[0]
    original_save = journal.save

    def slow_save(state):
        original_save(state)
        if state["intent"] is not None:
            clock[0] = 131.0

    journal.save = slow_save
    client = coordinator.clients["cloudformation"]
    original_dispatch = client._dispatch
    writes = []

    def dispatch(method, kwargs):
        if method == "create_stack":
            writes.append(kwargs)
            raise AssertionError("CreateStack must not run after the durable intent crosses cutoff")
        return original_dispatch(method, kwargs)

    client._dispatch = dispatch
    result = coordinator.run_step("create")
    assert result["ok"] is False
    assert result["category"] == "window_expired"
    assert journal.state["intent"] == {
        "token": coordinator._create_token(), "stack_name": "honda-mapit-mcp-dev-identity-bindings-bootstrap"
    }
    assert writes == []
    assert coordinator.run_step("create")["category"] == "create_intent_present"
    assert writes == []


def test_key_publication_cutoff_after_intent_is_consumed_without_put_or_secret_output():
    clients, journal, calls = _key_fixture()
    monotonic = [100.0]
    original_save = journal.save

    def slow_save(state):
        original_save(state)
        if state.get("phase") == "put_intent":
            monotonic[0] = 114.0

    journal.save = slow_save
    def run():
        return publish_keys(clients, journal, account_id=ACCOUNT, config=CONFIG,
            source_sha="a" * 40, run_id=123, bootstrap_sha256="b" * 64,
            start=1000, end=1100, clock=lambda: 1050, monotonic=lambda: monotonic[0])

    result = run()
    assert result == {"ok": False, "category": "key_publication_unverified"}
    assert journal.state["phase"] == "put_intent"
    assert [kind for kind, _ in calls].count("put") == 0
    assert clients["ssm"].value is None
    assert "sensitive SDK detail" not in str(result)
    retry = run()
    assert retry == {"ok": False, "category": "key_publication_consumed"}
    assert [kind for kind, _ in calls].count("put") == 0
