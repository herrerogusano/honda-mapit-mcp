from __future__ import annotations

from types import SimpleNamespace
import copy

import pytest

from mapit.session import WindowsKeyringRefreshTokenStore, RefreshTokenStoreError
from tests.test_session import FakeKeyring, _native_backend
from scripts import run_dev_owner_mapit_enrollment as runner


@pytest.mark.parametrize("format", ["v1", "legacy", "absent", "orphan"])
def test_readonly_saved_session_never_migrates_deletes_or_saves(format):
    ring = FakeKeyring()
    backend = _native_backend()
    backend.get_password = ring.get_password
    store = WindowsKeyringRefreshTokenStore(keyring_module=ring, backend=backend)
    if format == "v1":
        store.save("private-refresh-canary")
        ring.values[(store.SERVICE, store.ACCOUNT)] = "retained-legacy-canary"
    elif format == "legacy":
        ring.values[(store.SERVICE, store.ACCOUNT)] = "private-refresh-canary"
    elif format == "orphan":
        ring.values[(store.SERVICE, store._chunk_account(0))] = "orphan-canary"
    before = copy.deepcopy(ring.values)
    ring.set_password = lambda *a: pytest.fail("read-only consent may not save")
    ring.delete_password = lambda *a: pytest.fail("read-only consent may not delete")
    if format == "orphan":
        with pytest.raises(RefreshTokenStoreError):
            store.load_readonly()
    else:
        assert store.load_readonly() == (None if format == "absent" else "private-refresh-canary")
    assert ring.values == before


@pytest.mark.parametrize("consent", [False, True, 1, "yes"])
def test_session_is_collected_only_after_exact_private_consent(consent):
    events = []
    def prompt():
        events.append("consent")
        return consent
    def factory():
        events.append("store")
        return SimpleNamespace(load_readonly=lambda: events.append("load") or "private-refresh-canary")
    if consent is True:
        submission = runner._collect_saved_session(consent_request=prompt,
            deadline=114, monotonic=lambda: 100, store_factory=factory)
        assert submission.consent is True
        assert "private-refresh-canary" not in repr(submission)
        assert events == ["consent", "store", "load"]
    else:
        with pytest.raises(runner.OwnerMapitEnrollmentError):
            runner._collect_saved_session(consent_request=prompt,
                deadline=114, monotonic=lambda: 100, store_factory=factory)
        assert events == ["consent"]


@pytest.mark.parametrize("token", [None, "", "private\ncanary", "x" * 4097])
def test_missing_or_malformed_saved_session_has_fixed_safe_diagnostic(token):
    with pytest.raises(runner.OwnerMapitSessionMissingError, match="^owner_mapit_session_missing$"):
        runner._collect_saved_session(consent_request=lambda: True, deadline=114,
            monotonic=lambda: 100, store_factory=lambda: SimpleNamespace(load_readonly=lambda: token))


def test_private_consent_expiration_prevents_even_constructing_keyring():
    now = [100]
    def consent():
        now[0] = 114
        return True
    with pytest.raises(runner.OwnerMapitEnrollmentError):
        runner._collect_saved_session(consent_request=consent, deadline=114, monotonic=lambda: now[0],
            store_factory=lambda: pytest.fail("keyring after consent expiry"))


def test_readonly_path_uses_captured_native_backend_after_global_swap():
    ring = FakeKeyring()
    backend = _native_backend()
    backend.get_password = ring.get_password
    store = WindowsKeyringRefreshTokenStore(keyring_module=ring, backend=backend)
    ring.values[(store.SERVICE, store.ACCOUNT)] = "native-session-canary"
    before = copy.deepcopy(ring.values)
    ring.get_password = lambda *a: pytest.fail("global backend routing must not run")
    ring.set_password = lambda *a: pytest.fail("no save")
    ring.delete_password = lambda *a: pytest.fail("no delete")
    assert store.load_readonly() == "native-session-canary"
    assert ring.values == before
