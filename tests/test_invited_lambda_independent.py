"""Independent deadline-provider checks; all identities and providers are synthetic."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import threading
import time

import jwt
import pytest
from types import SimpleNamespace
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit import invited_lambda as invited_lambda_module
from mapit import lambda_adapter as lambda_adapter_module
from mapit import tenant_router as tenant_router_module
from mapit.invited_lambda import create_invited_lambda_runtime
from mapit.services import Position, VehicleStatus
from mapit.tenant_router import InvitedTenantAuthority, TenantIsolationError, TenantServicesRouter, tenant_key


SUBJECT = "00000000-0000-4000-8000-000000000711"
POLICY = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUBJECT)
TENANT_B = "00000000-0000-4000-8000-000000000712"
POLICY_B = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", TENANT_B)
KEY_B = tenant_key(b"d" * 32, POLICY.issuer_url, TENANT_B)


def _authority_grant():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key = tenant_key(b"d" * 32, POLICY.issuer_url, SUBJECT)
    authority = InvitedTenantAuthority({key: POLICY}, {"deadline-test-key": public})
    now = int(time.time())
    token = jwt.encode(
        {"iss": POLICY.issuer_url, "aud": POLICY.audience, "sub": SUBJECT,
         "client_id": POLICY.client_id, "token_use": "access", "iat": now - 1,
         "exp": now + 300, "scope": POLICY.required_scope},
        private, algorithm="RS256", headers={"kid": "deadline-test-key"},
    )
    return authority, asyncio.run(authority.authenticate(token))


def _signed_runtime(monkeypatch, provider_factory, clock):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policies = {
        tenant_key(b"d" * 32, POLICY.issuer_url, SUBJECT): POLICY,
        KEY_B: POLICY_B,
    }
    runtime = create_invited_lambda_runtime(
        POLICY, policies, {"independent-deadline-key": public}, provider_factory=provider_factory
    )
    now = int(time.time())
    token = jwt.encode(
        {"iss": POLICY.issuer_url, "aud": POLICY.audience, "sub": SUBJECT,
         "client_id": POLICY.client_id, "token_use": "access", "iat": now - 1,
         "exp": now + 300, "scope": POLICY.required_scope},
        private, algorithm="RS256", headers={"kid": "independent-deadline-key"},
    )
    # Replace module-local clocks, not the process-wide `time` module used by
    # pytest, asyncio and unrelated threads.
    monkeypatch.setattr(invited_lambda_module, "_monotonic", clock)
    monkeypatch.setattr(
        lambda_adapter_module, "time", SimpleNamespace(monotonic=clock, time=time.time), raising=False
    )
    monkeypatch.setattr(
        tenant_router_module, "time", SimpleNamespace(monotonic=clock, time=time.time)
    )
    return runtime, token


def _tool_event(token):
    return {
        "version": "2.0", "routeKey": "$default", "rawPath": "/mcp",
        "rawQueryString": "", "headers": {
            "host": POLICY.api_host,
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
            "authorization": f"Bearer {token}",
        },
        "requestContext": {"stage": "$default", "http": {
            "method": "POST", "path": "/mcp", "protocol": "HTTP/1.1",
            "sourceIp": "127.0.0.1", "userAgent": "independent-test",
        }},
        "body": json.dumps({"jsonrpc": "2.0", "id": "deadline", "method": "tools/call",
                             "params": {"name": "get_vehicle_status", "arguments": {}}}),
        "isBase64Encoded": False,
    }


class LambdaContext:
    def __init__(self, remaining_ms, after_read=None):
        self.remaining_ms = remaining_ms
        self.after_read = after_read
        self.calls = 0

    def get_remaining_time_in_millis(self):
        self.calls += 1
        if self.after_read is not None:
            self.after_read()
        return self.remaining_ms


class SyntheticProvider:
    def __init__(self, service):
        self.service = service

    def get(self):
        return self.service


class SyntheticService:
    def __init__(self, label):
        self.label = label
        self.calls = 0

    def get_vehicle_status(self):
        self.calls += 1
        return VehicleStatus(status=self.label, position=Position())


class MutableClock:
    def __init__(self, value=100.0):
        self.value = value

    def __call__(self):
        return self.value


@pytest.mark.parametrize("callback", [
    lambda now: True,
    lambda now: float("nan"),
    lambda now: float("inf"),
    lambda now: -1.0,
])
def test_invalid_deadline_provider_fails_before_factory(monkeypatch, callback):
    authority, grant = _authority_grant()
    clock = MutableClock()
    monkeypatch.setattr(
        tenant_router_module, "time", SimpleNamespace(monotonic=clock, time=time.time)
    )
    created = []
    router = TenantServicesRouter(authority, lambda *_: created.append(True), deadline_provider=lambda: callback(clock.value))
    with pytest.raises(TenantIsolationError, match="tenant_clock_invalid"):
        with router.bind(grant):
            pass
    assert created == []


def test_deadline_provider_exception_fails_before_factory(monkeypatch):
    authority, grant = _authority_grant()
    clock = MutableClock()
    monkeypatch.setattr(
        tenant_router_module, "time", SimpleNamespace(monotonic=clock, time=time.time)
    )
    created = []

    def broken():
        raise RuntimeError("deadline-provider-canary")

    router = TenantServicesRouter(authority, lambda *_: created.append(True), deadline_provider=broken)
    with pytest.raises(TenantIsolationError, match="tenant_clock_invalid") as error:
        with router.bind(grant):
            pass
    assert created == [] and "canary" not in str(error.value)
    assert error.value.__cause__ is None


def test_past_or_elapsed_deadline_expires_before_provider_factory(monkeypatch):
    authority, grant = _authority_grant()
    clock = MutableClock()
    monkeypatch.setattr(
        tenant_router_module, "time", SimpleNamespace(monotonic=clock, time=time.time)
    )
    created = []
    router = TenantServicesRouter(
        authority, lambda *_: created.append(True), deadline_provider=lambda: clock.value - 0.01
    )
    with pytest.raises(TenantIsolationError, match="tenant_context_expired"):
        with router.bind(grant):
            pass
    assert created == []

    def deadline_that_elapses_during_callback():
        deadline = clock.value + 1
        clock.value += 2
        return deadline

    router = TenantServicesRouter(
        authority, lambda *_: created.append(True), deadline_provider=deadline_that_elapses_during_callback
    )
    with router.bind(grant):
        with pytest.raises(TenantIsolationError, match="tenant_context_expired"):
            router.get()
    assert created == []


def test_deadline_provider_can_only_clamp_the_default_fourteen_second_ceiling(monkeypatch):
    authority, grant = _authority_grant()
    clock = MutableClock()
    monkeypatch.setattr("mapit.tenant_router.time.monotonic", clock)
    captured = []
    router = TenantServicesRouter(
        authority, lambda _key, deadline: (captured.append(deadline) or object()),
        deadline_provider=lambda: clock.value + 1_000,
    )
    with router.bind(grant):
        with pytest.raises(TenantIsolationError, match="tenant_provider_failed"):
            router.get()
    assert captured == [114.0]

    captured.clear()
    router = TenantServicesRouter(
        authority, lambda _key, deadline: (captured.append(deadline) or object()),
        deadline_provider=lambda: clock.value + 2.5,
    )
    with router.bind(grant):
        with pytest.raises(TenantIsolationError, match="tenant_provider_failed"):
            router.get()
    assert captured == [102.5]


def test_slow_original_context_getter_cannot_restart_the_fourteen_second_cap(monkeypatch):
    clock = MutableClock(100.0)
    captured = []
    service = SyntheticService("tenant-a")
    provider = SyntheticProvider(service)

    def factory(key, deadline):
        captured.append((key, deadline))
        return provider

    runtime, token = _signed_runtime(monkeypatch, factory, clock)
    context = LambdaContext(30_000, after_read=lambda: setattr(clock, "value", 110.0))
    response = runtime.handler(_tool_event(token), context)

    assert response["statusCode"] == 200
    assert context.calls == 1
    assert len(captured) == 1 and captured[0][0] == tenant_key(b"d" * 32, POLICY.issuer_url, SUBJECT)
    # The absolute ceiling starts at 100, before the ten-second context read.
    assert captured[0][1] <= 114.0
    assert service.calls == 1


def test_clock_rollback_during_context_sampling_denies_before_event_or_factory(monkeypatch):
    samples = iter((100.0, 102.0, 101.5))
    captured = []

    def clock():
        return next(samples, 101.5)

    runtime, _token = _signed_runtime(
        monkeypatch,
        lambda key, deadline: captured.append((key, deadline)) or SyntheticProvider(SyntheticService("x")),
        clock,
    )

    class PoisonEvent(dict):
        def get(self, *args, **kwargs):
            raise AssertionError("event must not be inspected after clock rollback")

    response = runtime.handler(PoisonEvent(), LambdaContext(30_000))
    assert response["statusCode"] == 504
    assert captured == []


def test_warm_invocations_do_not_reuse_a_provider_object(monkeypatch):
    clock = MutableClock(100.0)
    service = SyntheticService("shared-canary")
    shared_provider = SyntheticProvider(service)
    factory_calls = []

    def factory(key, deadline):
        factory_calls.append(key)
        return shared_provider

    runtime, token_a = _signed_runtime(monkeypatch, factory, clock)
    # Repeated warm invocation exercises the router retained by the runtime.
    first = runtime.handler(_tool_event(token_a), LambdaContext(30_000))
    second = runtime.handler(_tool_event(token_a), LambdaContext(30_000))
    assert first["statusCode"] == 200
    assert service.calls == 1
    assert len(factory_calls) == 2
    body = json.loads(second["body"])
    assert body.get("error") or body.get("result", {}).get("isError") is True


def test_concurrent_tenant_binds_claim_a_shared_provider_at_most_once():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    key_a = tenant_key(b"e" * 32, POLICY.issuer_url, SUBJECT)
    authority = InvitedTenantAuthority(
        {key_a: POLICY, KEY_B: POLICY_B}, {"concurrent-key": public}
    )
    now = int(time.time())

    def grant_for(policy):
        encoded = jwt.encode(
            {"iss": policy.issuer_url, "aud": policy.audience, "sub": policy.owner_subject,
             "client_id": policy.client_id, "token_use": "access", "iat": now - 1,
             "exp": now + 300, "scope": policy.required_scope},
            private, algorithm="RS256", headers={"kid": "concurrent-key"},
        )
        return asyncio.run(authority.authenticate(encoded))

    grants = (grant_for(POLICY), grant_for(POLICY_B))
    service = SyntheticService("shared-provider")
    shared_provider = SyntheticProvider(service)
    factories_ready = threading.Barrier(2)

    def factory(_key, _deadline):
        factories_ready.wait(timeout=2)
        return shared_provider

    router = TenantServicesRouter(authority, factory)

    def use(grant):
        try:
            with router.bind(grant):
                router.get().get_vehicle_status()
            return "ok"
        except TenantIsolationError as exc:
            return exc.category

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(use, grants))
    assert outcomes.count("ok") == 1
    assert outcomes.count("tenant_provider_reused") == 1
    assert service.calls == 1
