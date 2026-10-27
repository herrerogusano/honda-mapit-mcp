"""Independent capacity, contention and pre-intent negative regressions."""
import sqlite3
import threading
from contextlib import closing

import pytest

from mapit.durable_tenants import DurableTenantGuard, SQLiteTenantStore
from mapit.identity_binding import IdentityBindingError
from test_identity_binding import TOKEN_A, _AuthTransport, _Publisher, _make_setup


@pytest.mark.parametrize("token", ["", "x" * 4097, "é" * 2049, "bad\nvalue", "bad\x7fvalue", "bad\ud800value"])
def test_invalid_token_is_rejected_before_intent_or_auth(tmp_path, token):
    env = _make_setup(tmp_path)
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    registry = env["factory"](selected_auth=auth)
    publisher = _Publisher()
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        registry.enroll(env["grant_a"], env["snapshot_a"], token, publisher=publisher)
    assert auth.calls == publisher.calls == []
    assert env["connection"].execute("SELECT COUNT(*) FROM mapit_identity_bindings_v1").fetchone() == (0,)


def test_sixteen_terminal_tombstones_count_toward_capacity(tmp_path):
    env = _make_setup(tmp_path)
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    registry = env["factory"](selected_auth=auth)
    # Synthetic valid tombstones represent previously revoked invite slots.
    # Their private MAC is created only by this server-side fixture.
    for index in range(16):
        key = "tenant-" + format(index, "064x")
        path = registry._path(key)
        mac = registry._row_mac(key, "dev", None, path, 1, "revoked", 1, None)
        env["connection"].execute(
            "INSERT INTO mapit_identity_bindings_v1 VALUES (?, 'dev', NULL, ?, 1, 'revoked', 1, NULL, ?)",
            (key, path, mac),
        )
    env["connection"].commit()
    publisher = _Publisher()
    with pytest.raises(IdentityBindingError, match="identity_binding_capacity_exhausted"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert auth.calls == publisher.calls == []
    assert env["connection"].execute("SELECT COUNT(*) FROM mapit_identity_bindings_v1").fetchone() == (16,)


def test_two_connections_cannot_publish_the_same_enrollment_intent(tmp_path):
    env = _make_setup(tmp_path)
    env["factory"]()
    first_in_auth, release_first = threading.Event(), threading.Event()
    publisher = _Publisher()
    outcomes = []

    class PausedAuth(_AuthTransport):
        def __call__(self, url, headers, payload):
            if headers["X-Amz-Target"].endswith("InitiateAuth"):
                first_in_auth.set()
                if not release_first.wait(5):
                    raise AssertionError("synthetic test barrier expired")
            return super().__call__(url, headers, payload)

    def first():
        with closing(sqlite3.connect(tmp_path / "tenants.sqlite3")) as connection:
            guard = DurableTenantGuard(env["authority"], SQLiteTenantStore(connection))
            snapshot = guard.capture(env["grant_a"])
            registry = env["factory"](connection=connection, selected_guard=guard,
                                      selected_auth=PausedAuth(env["tokens"][TOKEN_A]))
            try:
                outcomes.append(registry.enroll(env["grant_a"], snapshot, TOKEN_A, publisher=publisher))
            except Exception as exc:
                outcomes.append(exc)

    thread = threading.Thread(target=first, daemon=True)
    thread.start()
    try:
        assert first_in_auth.wait(5)
        with closing(sqlite3.connect(tmp_path / "tenants.sqlite3")) as second_connection:
            guard = DurableTenantGuard(env["authority"], SQLiteTenantStore(second_connection))
            snapshot = guard.capture(env["grant_a"])
            auth = _AuthTransport(env["tokens"][TOKEN_A])
            registry = env["factory"](connection=second_connection, selected_guard=guard, selected_auth=auth)
            with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
                registry.enroll(env["grant_a"], snapshot, TOKEN_A, publisher=publisher)
            assert auth.calls == publisher.calls == []
    finally:
        release_first.set()
        thread.join(5)
    assert not thread.is_alive()
    assert len(outcomes) == 1 and not isinstance(outcomes[0], Exception)
    assert len(publisher.calls) == 1
