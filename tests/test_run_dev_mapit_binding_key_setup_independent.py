from __future__ import annotations

import copy
from contextlib import contextmanager
from pathlib import Path

import pytest

import scripts.run_dev_mapit_binding_key_setup as runner


def test_accepted_historical_bootstrap_load_does_not_require_old_window_open(monkeypatch, tmp_path):
    """The old create authority is provenance, not authority for the new publish step."""
    from tests.test_dev_mapit_bootstrap_coordinator import _coordinator

    coordinator, source_journal, _cfn, ddb, iam = _coordinator()
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["ok"] is True
    ddb.created = True
    iam.created = True
    assert coordinator.run_step("readback")["ok"] is True
    accepted_state = copy.deepcopy(source_journal.state)
    authority = coordinator.authority
    state_dir = tmp_path / "historical-state"
    state_dir.mkdir()
    state_path = state_dir / "rehearsal-state.json"
    state_path.write_text("{}", encoding="utf-8")

    class ReadOnlyJournal:
        def __init__(self, _directory):
            self.path = state_path

        def load(self):
            return copy.deepcopy(accepted_state)

        def save(self, _state):
            raise AssertionError("historical journal must never be written")

        @contextmanager
        def locked(self):
            raise AssertionError("read-only historical parsing must not acquire a write lock")
            yield

    monkeypatch.setattr(runner, "FileJournal", ReadOnlyJournal)
    monkeypatch.setattr(runner, "validate_private_location", lambda path, **_kwargs: Path(path))
    monkeypatch.setattr(
        runner,
        "load_runner_authority",
        lambda *_args, **_kwargs: (authority, {"source_sha": authority.source_sha}, {
            "github_owner_id": 123, "github_repository_id": 456,
        }),
    )

    # Constructor-only historical parsing must still work after expiry; no
    # old run_step is invoked and its journal has no write method by design.
    result = runner._load_accepted_bootstrap(
        tmp_path / "old-authority.json",
        state_dir,
        coordinator.clients,
        acl_checker=lambda _path: True,
        clock=lambda: authority.authorized_until_epoch + 1,
        monotonic=lambda: 500.0,
    )

    loaded_authority, _source, _github, loaded_state, plan, receipt_digest = result
    assert loaded_authority is authority
    assert loaded_state == accepted_state
    assert plan.template_sha256 == coordinator.plan.template_sha256
    assert len(receipt_digest) == 64


def test_read_client_allows_only_explicitly_scoped_ssm_put():
    calls = []
    start = 1_800_000_000

    class SSM:
        def put_parameter(self, **kwargs):
            calls.append(kwargs)
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def proxy(client, *, allow=()):
        return runner._ReadClient(client, [0, 0.0], 1.0, 10.0, lambda: 2.0,
                                  lambda: start + 10, start, start + 600,
                                  [float(start)], allow_methods=allow)

    denied = proxy(SSM())
    with pytest.raises(ValueError):
        denied.put_parameter(Name="/fixed", Type="SecureString", Value="secret")
    assert calls == []

    allowed = proxy(SSM(), allow=("put_parameter",))
    reply = allowed.put_parameter(Name="/fixed", Type="SecureString", Value="secret")
    assert reply["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert calls == [{"Name": "/fixed", "Type": "SecureString", "Value": "secret"}]

    # The capability is exact-method scoped; it must not turn the proxy into
    # a generic write client.
    with pytest.raises(ValueError):
        allowed.delete_parameter(Name="/fixed")
    assert len(calls) == 1
