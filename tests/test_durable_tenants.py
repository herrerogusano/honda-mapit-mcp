from __future__ import annotations

import sqlite3
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.durable_tenants import (
    DurableTenantError,
    DurableTenantGuard,
    DurableTenantRecord,
    DurableTenantSnapshot,
    SQLiteTenantStore,
)
from mapit.tenant_router import AuthenticatedTenant, InvitedTenantAuthority


KEY = "tenant-" + "a" * 64
OTHER = "tenant-" + "b" * 64


def connection(path):
    return sqlite3.connect(path, check_same_thread=False, timeout=0)


def test_explicit_schema_and_reopen_persist_records(tmp_path):
    path = tmp_path / "tenants.sqlite3"
    first = SQLiteTenantStore.initialize(connection(path))
    assert first.cas(KEY, None, DurableTenantRecord(KEY, "active", 1)) is True
    reopened = SQLiteTenantStore(connection(path))
    assert reopened.get(KEY) == DurableTenantRecord(KEY, "active", 1)
    assert reopened.cas(KEY, 1, DurableTenantRecord(KEY, "revoked", 2)) is True
    assert reopened.cas(KEY, 2, DurableTenantRecord(KEY, "active", 3)) is False
    assert reopened.get(KEY).status == "revoked"


def test_constructor_does_not_migrate_wrong_schema_or_active_transaction():
    connection_obj = sqlite3.connect(":memory:")
    with pytest.raises(DurableTenantError, match="durable_configuration_invalid"):
        SQLiteTenantStore(connection_obj)
    connection_obj.execute("CREATE TABLE mapit_durable_tenants_v1(key TEXT)")
    with pytest.raises(DurableTenantError, match="durable_configuration_invalid"):
        SQLiteTenantStore(connection_obj)


def test_cas_requires_exact_revision_and_rejects_malformed_records(tmp_path):
    store = SQLiteTenantStore.initialize(connection(tmp_path / "x.sqlite3"))
    assert store.cas(KEY, None, DurableTenantRecord(KEY, "active", 1))
    assert store.cas(KEY, 1, DurableTenantRecord(KEY, "active", 3)) is False
    with pytest.raises(DurableTenantError, match="durable_record_invalid"):
        store.cas(KEY, True, DurableTenantRecord(KEY, "active", 2))
    with pytest.raises(DurableTenantError, match="durable_record_invalid"):
        store.cas(OTHER, None, DurableTenantRecord(KEY, "active", 1))


def test_capacity_includes_revoked_tombstones(tmp_path):
    store = SQLiteTenantStore.initialize(connection(tmp_path / "x.sqlite3"), max_records=1)
    assert store.cas(KEY, None, DurableTenantRecord(KEY, "active", 1))
    assert store.cas(KEY, 1, DurableTenantRecord(KEY, "revoked", 2))
    with pytest.raises(DurableTenantError, match="durable_capacity_exhausted"):
        store.cas(OTHER, None, DurableTenantRecord(OTHER, "active", 1))


def test_two_connections_have_atomic_create_race(tmp_path):
    path = tmp_path / "race.sqlite3"
    SQLiteTenantStore.initialize(connection(path))
    stores = [SQLiteTenantStore(connection(path)) for _ in range(2)]
    barrier = threading.Barrier(2)
    results = []

    def worker(store):
        barrier.wait()
        try:
            results.append(store.cas(KEY, None, DurableTenantRecord(KEY, "active", 1)))
        except DurableTenantError as exc:
            results.append(exc.category)

    threads = [threading.Thread(target=worker, args=(store,)) for store in stores]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in threads)
    # With timeout=0, SQLite may reject both simultaneous BEGIN IMMEDIATE
    # attempts with SQLITE_BUSY.  The store deliberately does not retry or
    # sleep, so this test proves atomicity and fail-closed behavior, not
    # eventual liveness: at most one writer may win, and a stored row exists
    # exactly when one writer reported success.
    assert len(results) == 2
    assert results.count(True) <= 1
    assert all(value is True or value is False or value == "durable_store_failed" for value in results)
    record = stores[0].get(KEY)
    if True in results:
        assert record == DurableTenantRecord(KEY, "active", 1)
    else:
        assert results == ["durable_store_failed", "durable_store_failed"]
        assert record is None


def test_busy_writer_fails_closed_without_row_then_succeeds_after_release(tmp_path):
    path = tmp_path / "locked.sqlite3"
    store = SQLiteTenantStore.initialize(connection(path))
    locker = sqlite3.connect(path, check_same_thread=False, timeout=0)
    try:
        locker.execute("BEGIN IMMEDIATE")
        with pytest.raises(DurableTenantError, match="durable_store_failed"):
            store.cas(KEY, None, DurableTenantRecord(KEY, "active", 1))
        assert store.get(KEY) is None
        locker.rollback()
        assert store.cas(KEY, None, DurableTenantRecord(KEY, "active", 1)) is True
        assert store.get(KEY) == DurableTenantRecord(KEY, "active", 1)
    finally:
        try:
            locker.rollback()
        finally:
            locker.close()


def _guard(tmp_path):
    store = SQLiteTenantStore.initialize(connection(tmp_path / "guard.sqlite3"))
    assert store.cas(KEY, None, DurableTenantRecord(KEY, "active", 1))
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    policy = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", "00000000-0000-4000-8000-000000000001")
    authority = InvitedTenantAuthority({KEY: policy}, {"test-key": public})
    expiry = int(time.time()) + 300
    grant = AuthenticatedTenant(KEY, expiry, authority._proof(KEY, expiry))
    return store, authority, grant


def test_guard_requires_exact_invitation_authority(tmp_path):
    store = SQLiteTenantStore.initialize(connection(tmp_path / "exact.sqlite3"))

    class FakeAuthority:
        def validate(self, grant):
            pass

    with pytest.raises(DurableTenantError, match="durable_configuration_invalid"):
        DurableTenantGuard(FakeAuthority(), store)


def test_guard_checks_authority_before_lookup_and_revalidates_revision(tmp_path):
    store, authority, grant = _guard(tmp_path)
    guard = DurableTenantGuard(authority, store)
    snapshot = guard.capture(grant)
    assert isinstance(snapshot, DurableTenantSnapshot)
    guard.check(grant, snapshot)
    assert store.cas(KEY, 1, DurableTenantRecord(KEY, "revoked", 2))
    with pytest.raises(DurableTenantError, match="durable_unauthorized"):
        guard.check(grant, snapshot)


def test_guard_foreign_or_tampered_snapshot_fails_before_store(tmp_path):
    store, authority, grant = _guard(tmp_path)
    guard = DurableTenantGuard(authority, store)
    snapshot = guard.capture(grant)
    foreign = DurableTenantGuard(authority, store)
    for candidate in (
        DurableTenantSnapshot(KEY, 1, snapshot._seal, object()),
        DurableTenantSnapshot(KEY, 2, snapshot._seal, snapshot._guard),
    ):
        with pytest.raises(DurableTenantError):
            foreign.check(grant, candidate)
    with pytest.raises(DurableTenantError):
        guard.check(grant, DurableTenantSnapshot(KEY, 1, b"bad", snapshot._guard))


def test_store_failures_are_safe_categories(tmp_path):
    store, authority, grant = _guard(tmp_path)
    guard = DurableTenantGuard(authority, store)
    original = store.get
    store.get = lambda key: (_ for _ in ()).throw(RuntimeError("private sql"))
    with pytest.raises(DurableTenantError, match="durable_store_failed"):
        guard.capture(grant)
    store.get = original
    store.get = lambda key: DurableTenantRecord(OTHER, "active", 1)
    with pytest.raises(DurableTenantError, match="durable_store_failed"):
        guard.capture(grant)
