"""Independent fail-closed clock-exception regressions for tenant routing."""

import asyncio
import time

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.tenant_router import TenantIsolationError, TenantServicesRouter
from test_tenant_router import KEY_A, POLICY_A, Provider, authority, token


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.mark.parametrize("clock_name", ["monotonic", "time"])
def test_clock_exceptions_are_sanitized_and_prevent_provider_creation(
    signing_key, monkeypatch, clock_name
):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    provider_calls = []
    router = TenantServicesRouter(
        auth,
        lambda key, deadline: provider_calls.append((key, deadline)) or Provider(key, deadline),
    )

    def fail_with_canary():
        raise RuntimeError("synthetic-clock-canary")

    monkeypatch.setattr(f"mapit.tenant_router.time.{clock_name}", fail_with_canary)
    with pytest.raises(TenantIsolationError, match="tenant_clock_invalid") as caught:
        with router.bind(grant):
            router.get()
    assert str(caught.value) == "tenant_clock_invalid"
    assert "synthetic-clock-canary" not in str(caught.value)
    assert provider_calls == []


def test_failed_clock_sample_does_not_leave_tenant_context_bound(signing_key, monkeypatch):
    auth = authority(signing_key)
    grant = asyncio.run(auth.authenticate(token(signing_key)))
    router = TenantServicesRouter(auth, Provider)

    with router.bind(grant):
        original = time.monotonic

        def fail_once():
            monkeypatch.setattr("mapit.tenant_router.time.monotonic", original)
            raise OSError("synthetic-clock-canary")

        monkeypatch.setattr("mapit.tenant_router.time.monotonic", fail_once)
        with pytest.raises(TenantIsolationError, match="tenant_clock_invalid"):
            router.get()

    with router.bind(grant):
        assert router.get().get_vehicle_status()["synthetic_tenant"] == KEY_A
