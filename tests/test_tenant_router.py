import asyncio
import sqlite3
import time
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.durable_tenants import DurableTenantGuard, DurableTenantRecord, SQLiteTenantStore
from mapit.tenant_router import (
    AuthenticatedTenant, InvitedTenantAuthority, TenantIsolationError,
    TenantServicesRouter, tenant_key,
)

SUBJECT_A = "00000000-0000-4000-8000-000000000001"
SUBJECT_B = "00000000-0000-4000-8000-000000000002"
POLICY_A = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUBJECT_A)
POLICY_B = replace(POLICY_A, owner_subject=SUBJECT_B)
KEY_A = tenant_key(b"a" * 32, POLICY_A.issuer_url, SUBJECT_A)
KEY_B = tenant_key(b"a" * 32, POLICY_B.issuer_url, SUBJECT_B)


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def token(private, subject=SUBJECT_A, **overrides):
    now = int(time.time())
    claims = {"iss": POLICY_A.issuer_url, "aud": POLICY_A.audience, "sub": subject,
              "client_id": POLICY_A.client_id, "token_use": "access", "iat": now - 1,
              "exp": now + 300, "scope": POLICY_A.required_scope}
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "test-key"})


def authority(private):
    pem = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return InvitedTenantAuthority({KEY_A: POLICY_A, KEY_B: POLICY_B}, {"test-key": pem})


class Provider:
    def __init__(self, key, deadline):
        self.key, self.deadline, self.calls = key, deadline, 0
    def get(self):
        self.calls += 1
        return self
    def get_vehicle_status(self):
        return {"synthetic_tenant": self.key}


def test_opaque_key_is_domain_separated_and_canonical():
    assert KEY_A != KEY_B
    assert tenant_key(b"a" * 32, "https://one.invalid/a", "b:c") != tenant_key(b"a" * 32, "https://one.invalid/a:b", "c")
    with pytest.raises(TenantIsolationError):
        tenant_key(b"short", "issuer", "subject")


def test_two_signed_tenants_use_fresh_request_local_provider(signing_key):
    auth = authority(signing_key)
    a = asyncio.run(auth.authenticate(token(signing_key)))
    b = asyncio.run(auth.authenticate(token(signing_key, SUBJECT_B)))
    providers = []
    def factory(key, deadline):
        obj = Provider(key, deadline)
        providers.append(obj)
        return obj
    router = TenantServicesRouter(auth, factory)
    for grant in (a, b, a):
        with router.bind(grant):
            assert router.get().get_vehicle_status()["synthetic_tenant"] == grant.key
            assert router.get().get_vehicle_status()["synthetic_tenant"] == grant.key
    assert len(providers) == 3
    assert len({id(p) for p in providers}) == 3
    assert [p.key for p in providers] == [KEY_A, KEY_B, KEY_A]
    assert all(0 < p.deadline - time.monotonic() <= 14 for p in providers)
    with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
        router.get()


@pytest.mark.parametrize("overrides", [
    {"iss": "https://wrong.invalid"}, {"aud": "https://wrong.invalid/mcp"},
    {"client_id": "WrongClient"}, {"scope": "wrong"}, {"scope": POLICY_A.required_scope + " extra"},
    {"token_use": "id"}, {"exp": 1}, {"iat": 253402300798},
    {"sub": "00000000-0000-4000-8000-000000000003"},
])
def test_wrong_or_uninvited_token_cannot_select_session(signing_key, overrides):
    auth = authority(signing_key)
    reads = []
    router = TenantServicesRouter(auth, lambda key, deadline: reads.append(key))
    with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
        asyncio.run(auth.authenticate(token(signing_key, **overrides)))
    assert reads == []
    with pytest.raises(TenantIsolationError):
        router.get()


def test_forged_or_altered_grant_and_foreign_authority_are_denied(signing_key):
    auth = authority(signing_key)
    good = asyncio.run(auth.authenticate(token(signing_key)))
    foreign = authority(signing_key)
    for bad in (AuthenticatedTenant(KEY_A, int(time.time()) + 300, b"x" * 32),
                replace(good, key=KEY_B), replace(good, expires_at=good.expires_at + 300)):
        with pytest.raises(TenantIsolationError):
            auth.validate(bad)
    with pytest.raises(TenantIsolationError):
        foreign.validate(good)
    assert KEY_A not in repr(good)
    assert SUBJECT_A not in repr(auth)


def test_revocation_blocks_existing_grant_before_another_provider_call(signing_key):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    provider = Provider(KEY_A, 0)
    router = TenantServicesRouter(auth, lambda key, deadline: provider)
    with router.bind(grant):
        router.get()
        auth.revoke(KEY_A)
        with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
            router.get()
    assert provider.calls == 1


def test_factory_cannot_reuse_owner_provider_for_second_tenant(signing_key):
    auth = authority(signing_key)
    a = asyncio.run(auth.authenticate(token(signing_key)))
    b = asyncio.run(auth.authenticate(token(signing_key, SUBJECT_B)))
    shared = Provider(KEY_A, 0)
    router = TenantServicesRouter(auth, lambda key, deadline: shared)
    with router.bind(a):
        assert router.get().get_vehicle_status()["synthetic_tenant"] == KEY_A
    with router.bind(b):
        with pytest.raises(TenantIsolationError, match="tenant_provider_reused"):
            router.get()
    assert shared.calls == 1


def test_async_requests_and_children_cannot_outlive_context(signing_key):
    async def scenario():
        auth = authority(signing_key)
        a = await auth.authenticate(token(signing_key))
        b = await auth.authenticate(token(signing_key, SUBJECT_B))
        router = TenantServicesRouter(auth, Provider)
        async def request(grant):
            with router.bind(grant):
                await asyncio.sleep(0)
                return router.get().get_vehicle_status()["synthetic_tenant"]
        assert await asyncio.gather(request(a), request(b)) == [KEY_A, KEY_B]
        release = asyncio.Event()
        async def child():
            await release.wait()
            with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
                router.get()
        with router.bind(a):
            task = asyncio.create_task(child())
        release.set()
        await task
    asyncio.run(scenario())


def test_provider_exception_never_exposes_secret_text(signing_key):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    def bad(key, deadline):
        raise RuntimeError("synthetic-token-canary")
    router = TenantServicesRouter(auth, bad)
    with router.bind(grant):
        with pytest.raises(TenantIsolationError) as exc:
            router.get()
    assert str(exc.value) == "tenant_provider_failed"


def test_expiry_and_slow_factory_fail_before_provider_read(signing_key, monkeypatch):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    clock = [100.0]
    monkeypatch.setattr("mapit.tenant_router.time.monotonic", lambda: clock[0])
    made = []
    def slow(key, deadline):
        obj = Provider(key, deadline)
        made.append(obj)
        clock[0] = 115.0
        return obj
    router = TenantServicesRouter(auth, slow)
    with router.bind(grant):
        with pytest.raises(TenantIsolationError, match="tenant_context_expired"):
            router.get()
    assert made[0].calls == 0


def test_nested_contexts_and_duplicate_identities_are_rejected(signing_key):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    router = TenantServicesRouter(auth, Provider)
    with router.bind(grant):
        with pytest.raises(TenantIsolationError, match="tenant_context_already_bound"):
            with router.bind(grant):
                pass
    pem = signing_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(TenantIsolationError, match="tenant_configuration_invalid"):
        InvitedTenantAuthority({KEY_A: POLICY_A, KEY_B: POLICY_A}, {"test-key": pem})


def test_retained_service_cannot_escape_or_switch_tenants(signing_key):
    auth = authority(signing_key)
    a = asyncio.run(auth.authenticate(token(signing_key)))
    b = asyncio.run(auth.authenticate(token(signing_key, SUBJECT_B)))
    router = TenantServicesRouter(auth, Provider)
    with router.bind(a):
        services = router.get()
        method = services.get_vehicle_status
        assert method()["synthetic_tenant"] == KEY_A
        with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
            services.read_refresh_token()
    with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
        method()
    with router.bind(b):
        with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
            method()
        assert router.get().get_vehicle_status()["synthetic_tenant"] == KEY_B


@pytest.mark.parametrize("sample", [float("nan"), float("inf"), -1.0, True])
def test_invalid_monotonic_clocks_fail_closed_before_factory(signing_key, monkeypatch, sample):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    calls = []
    router = TenantServicesRouter(auth, lambda key, deadline: calls.append(key))
    monkeypatch.setattr("mapit.tenant_router.time.monotonic", lambda: sample)
    with pytest.raises(TenantIsolationError, match="tenant_clock_invalid"):
        with router.bind(grant):
            pass
    assert calls == []


def test_monotonic_rollback_invalidates_retained_method(signing_key, monkeypatch):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    clock = [100.0]
    monkeypatch.setattr("mapit.tenant_router.time.monotonic", lambda: clock[0])
    router = TenantServicesRouter(auth, Provider)
    with router.bind(grant):
        method = router.get().get_vehicle_status
        clock[0] = 99.0
        with pytest.raises(TenantIsolationError, match="tenant_clock_rollback"):
            method()


def test_revocation_invalidates_already_obtained_services(signing_key):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    router = TenantServicesRouter(auth, Provider)
    with router.bind(grant):
        method = router.get().get_vehicle_status
        auth.revoke(KEY_A)
        with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
            method()


def test_optional_durable_guard_captures_revision_and_blocks_rotation(signing_key, tmp_path):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    store = SQLiteTenantStore.initialize(sqlite3.connect(tmp_path / "router.sqlite3"))
    assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    guard = DurableTenantGuard(auth, store)
    router = TenantServicesRouter(auth, Provider, authorization_guard=guard)
    with router.bind(grant):
        method = router.get().get_vehicle_status
        assert method()["synthetic_tenant"] == KEY_A
        assert store.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
        with pytest.raises(TenantIsolationError, match="tenant_durable_unauthorized"):
            method()


def test_durable_capture_latency_is_debited_before_provider(signing_key, tmp_path, monkeypatch):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    store = SQLiteTenantStore.initialize(sqlite3.connect(tmp_path / "slow.sqlite3"))
    assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    clock = [100.0]
    monkeypatch.setattr("mapit.tenant_router.time.monotonic", lambda: clock[0])
    original_get = store.get

    def slow_get(key):
        value = original_get(key)
        clock[0] = 115.0
        return value

    store.get = slow_get
    guard = DurableTenantGuard(auth, store)
    made = []
    router = TenantServicesRouter(auth, lambda key, deadline: made.append(key), authorization_guard=guard)
    with pytest.raises(TenantIsolationError, match="tenant_context_expired"):
        with router.bind(grant):
            pass
    assert made == []
