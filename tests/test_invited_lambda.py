from __future__ import annotations

import asyncio
import json
import time
from contextlib import AsyncExitStack
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.invited_lambda import create_invited_lambda_runtime
from mapit.services import DistanceResult, Position, VehicleStatus
from mapit.tenant_router import InvitedTenantAuthority, TenantIsolationError, TenantServicesRouter, tenant_key

SUBJECT_A = "00000000-0000-4000-8000-000000000001"
SUBJECT_B = "00000000-0000-4000-8000-000000000002"
POLICY_A = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUBJECT_A)
POLICY_B = replace(POLICY_A, owner_subject=SUBJECT_B)
KEY_A = tenant_key(b"l" * 32, POLICY_A.issuer_url, SUBJECT_A)
KEY_B = tenant_key(b"l" * 32, POLICY_B.issuer_url, SUBJECT_B)


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, {"lambda-invited-key": public}


def token(private, policy=POLICY_A, **overrides):
    now = int(time.time())
    claims = {
        "iss": policy.issuer_url,
        "aud": policy.audience,
        "sub": policy.owner_subject,
        "client_id": policy.client_id,
        "token_use": "access",
        "iat": now - 1,
        "exp": now + 300,
        "scope": policy.required_scope,
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "lambda-invited-key"})


class FakeContext:
    def __init__(self, remaining_ms=30_000):
        self.remaining_ms = remaining_ms
        self.calls = 0

    def get_remaining_time_in_millis(self):
        self.calls += 1
        return self.remaining_ms


class SlowContext(FakeContext):
    def get_remaining_time_in_millis(self):
        self.calls += 1
        time.sleep(0.25)
        return self.remaining_ms


class FakeServices:
    def __init__(self, label, *, delay=0):
        self.label, self.delay = label, delay

    def get_vehicle_status(self):
        if self.delay:
            time.sleep(self.delay)
        return VehicleStatus(status=self.label, position=Position())

    def get_distance(self, from_time, to_time):
        return DistanceResult(
            from_time=from_time, to_time=to_time,
            distance=11 if self.label == "A" else 22,
            distance_km=11 if self.label == "A" else 22, route_count=1,
        )


class FakeProvider:
    def __init__(self, services):
        self.services = services

    def get(self):
        return self.services


def runtime(signing_material, *, policy=POLICY_A, policies=None, factory=None, geographic_queries=False):
    private, keys = signing_material
    policies = policies or {KEY_A: POLICY_A, KEY_B: POLICY_B}
    created, deadlines = [], []

    def selected_factory(key, deadline):
        created.append(key)
        deadlines.append(deadline)
        delay = 0
        return FakeProvider(FakeServices("A" if key == KEY_A else "B", delay=delay))

    selected_factory = factory or selected_factory
    result = create_invited_lambda_runtime(
        policy, policies, keys,
        provider_factory=selected_factory,
        geographic_queries=geographic_queries,
    )
    return private, keys, result, created, deadlines


def _event(policy, bearer=None, *, method="POST", path="/mcp", payload=None, fake_claims=None):
    headers = {"host": policy.api_host, "accept": "application/json, text/event-stream"}
    if method == "POST":
        headers["content-type"] = "application/json"
    if bearer is not None:
        headers["authorization"] = f"Bearer {bearer}"
    body = "" if payload is None else json.dumps(payload, separators=(",", ":"))
    context = {
        "stage": "$default",
        "http": {"method": method, "path": path, "protocol": "HTTP/1.1", "sourceIp": "127.0.0.1", "userAgent": "tests"},
    }
    if fake_claims is not None:
        context["authorizer"] = {"jwt": {"claims": fake_claims}}
    return {
        "version": "2.0", "routeKey": "$default", "rawPath": path,
        "rawQueryString": "", "headers": headers,
        "requestContext": context, "body": body, "isBase64Encoded": False,
    }


class LambdaHTTPTransport(httpx2.AsyncBaseTransport):
    def __init__(self, handler, *, remaining_ms=30_000, fake_claims=None):
        self.handler, self.remaining_ms, self.fake_claims = handler, remaining_ms, fake_claims
        self.invocations = 0

    async def handle_async_request(self, request):
        self.invocations += 1
        raw = await request.aread()
        event = _event(
            POLICY_A,
            request.headers.get("authorization", "").removeprefix("Bearer ") or None,
            method=request.method,
            path=request.url.path,
            payload=json.loads(raw) if raw else None,
            fake_claims=self.fake_claims,
        )
        event["headers"].update(dict(request.headers.items()))
        result = await asyncio.to_thread(self.handler, event, FakeContext(self.remaining_ms))
        return httpx2.Response(
            result["statusCode"], headers=result["headers"],
            content=result["body"].encode("utf-8"), request=request,
        )


async def _call_lambda_handler(handler, bearer, tool, arguments):
    transport = LambdaHTTPTransport(handler)
    async with httpx2.AsyncClient(
        transport=transport,
        base_url=POLICY_A.resource_url.removesuffix("/mcp"),
        headers={"Authorization": f"Bearer {bearer}"},
    ) as client:
        async with streamable_http_client(POLICY_A.resource_url, http_client=client) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                return await session.call_tool(tool, arguments)


@pytest.mark.parametrize("subject,expected", [(SUBJECT_A, "A"), (SUBJECT_B, "B")])
def test_payload_v2_real_mcp_protocol_warm_requests_route_to_bound_tenant(signing_material, subject, expected):
    private, _keys, built, created, _deadlines = runtime(signing_material)
    bearer = token(private, POLICY_A if subject == SUBJECT_A else POLICY_B)
    transport = LambdaHTTPTransport(built.handler)

    async def scenario():
        async with AsyncExitStack() as stack:
            client = await stack.enter_async_context(httpx2.AsyncClient(
                transport=transport, base_url=POLICY_A.resource_url.removesuffix("/mcp"),
                headers={"Authorization": f"Bearer {bearer}"},
            ))
            streams = await stack.enter_async_context(
                streamable_http_client(POLICY_A.resource_url, http_client=client)
            )
            session = await stack.enter_async_context(ClientSession(*streams))
            await session.initialize()
            listed = await session.list_tools()
            assert len(listed.tools) == 10
            assert created == []
            first = await session.call_tool("get_vehicle_status", {})
            second = await session.call_tool("get_vehicle_status", {})
            distance = await session.call_tool(
                "get_distance", {"from_time": "2026-01-01", "to_time": "2026-02-01"}
            )
            assert [first.structured_content["status"], second.structured_content["status"]] == [expected, expected]
            assert distance.structured_content["distance"] == (11 if expected == "A" else 22)

    asyncio.run(scenario())
    tenant = KEY_A if subject == SUBJECT_A else KEY_B
    assert created == [tenant, tenant, tenant]
    assert transport.invocations >= 6


def test_concurrent_payload_v2_requests_do_not_cross_tenant_context(signing_material):
    private, _keys, built, created, _deadlines = runtime(signing_material)
    transport_a, transport_b = LambdaHTTPTransport(built.handler), LambdaHTTPTransport(built.handler)

    async def call(bearer, transport):
        async with httpx2.AsyncClient(
            transport=transport, base_url=POLICY_A.resource_url.removesuffix("/mcp"),
            headers={"Authorization": f"Bearer {bearer}"},
        ) as client:
            async with streamable_http_client(POLICY_A.resource_url, http_client=client) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    result = await session.call_tool("get_vehicle_status", {})
                    return result.structured_content["status"]

    async def scenario():
        return await asyncio.gather(
            call(token(private, POLICY_A), transport_a),
            call(token(private, POLICY_B), transport_b),
        )

    assert asyncio.run(scenario()) == ["A", "B"]
    assert set(created) == {KEY_A, KEY_B}


def test_warm_invocations_reject_a_provider_instance_reused_by_factory(signing_material):
    private, keys = signing_material
    shared = FakeProvider(FakeServices("A"))
    built = create_invited_lambda_runtime(
        POLICY_A, {KEY_A: POLICY_A}, keys,
        provider_factory=lambda _key, _deadline: shared,
    )

    async def scenario():
        first = await _call_lambda_handler(
            built.handler, token(private, POLICY_A), "get_vehicle_status", {}
        )
        second = await _call_lambda_handler(
            built.handler, token(private, POLICY_A), "get_vehicle_status", {}
        )
        return first, second

    first, second = asyncio.run(scenario())
    assert not first.is_error
    assert second.is_error
    assert "tenant_provider_reused" in str(second)


def test_fake_authorizer_claims_do_not_select_tenant_and_bad_bearer_never_dispatches(signing_material):
    private, _keys, built, created, _deadlines = runtime(signing_material)
    valid_a = token(private, POLICY_A)
    transport = LambdaHTTPTransport(
        built.handler, fake_claims={"sub": SUBJECT_B, "client_id": POLICY_A.client_id}
    )

    async def valid_call():
        async with httpx2.AsyncClient(
            transport=transport, base_url=POLICY_A.resource_url.removesuffix("/mcp"),
            headers={"Authorization": f"Bearer {valid_a}"},
        ) as client:
            async with streamable_http_client(POLICY_A.resource_url, http_client=client) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    result = await session.call_tool("get_vehicle_status", {})
                    assert result.structured_content["status"] == "A"
    asyncio.run(valid_call())

    invalid = built.handler(
        _event(POLICY_A, "malformed-bearer-canary", fake_claims={"sub": SUBJECT_A}), FakeContext()
    )
    assert invalid["statusCode"] == 401
    assert "malformed-bearer-canary" not in str(invalid)
    assert created == [KEY_A]


def test_revoked_invite_denied_before_provider_factory(signing_material):
    private, _keys, built, created, _deadlines = runtime(signing_material)
    built.authority.revoke(KEY_A)
    response = built.handler(
        _event(POLICY_A, token(private, POLICY_A), payload={
            "jsonrpc": "2.0", "id": "revoked", "method": "tools/call",
            "params": {"name": "get_vehicle_status", "arguments": {}},
        }),
        FakeContext(),
    )
    assert response["statusCode"] == 401
    assert created == []


def test_context_getter_latency_is_subtracted_before_any_event_access(signing_material):
    _private, _keys, built, created, _deadlines = runtime(signing_material)

    class UnreadableEvent(dict):
        def get(self, *args, **kwargs):
            raise AssertionError("event accessed before deadline preflight")

    response = built.handler(UnreadableEvent(), SlowContext(remaining_ms=1200))
    assert response["statusCode"] == 504
    assert created == []


@pytest.mark.parametrize("clock_values", [(100.0, 102.0, 101.0), (100.0, 100.0, float("nan"))])
def test_deadline_clock_rollback_or_nonfinite_after_getter_fails_before_event(
    signing_material, monkeypatch, clock_values
):
    import mapit.invited_lambda as invited_lambda

    _private, _keys, built, created, _deadlines = runtime(signing_material)
    samples = iter(clock_values)
    monkeypatch.setattr(invited_lambda, "_monotonic", lambda: next(samples))

    class UnreadableEvent(dict):
        def get(self, *args, **kwargs):
            raise AssertionError("event accessed after invalid deadline clock")

    response = built.handler(UnreadableEvent(), FakeContext(remaining_ms=30_000))
    assert response["statusCode"] == 504
    assert created == []


def test_provider_factory_receives_clamped_invocation_deadline(signing_material):
    private, keys = signing_material
    captured = []
    authority_policies = {KEY_A: POLICY_A, KEY_B: POLICY_B}

    def factory(key, deadline):
        captured.append((key, deadline))
        return FakeProvider(FakeServices("A" if key == KEY_A else "B"))

    built = create_invited_lambda_runtime(POLICY_A, authority_policies, keys, provider_factory=factory)
    start = time.monotonic()
    result = built.handler(
        _event(POLICY_A, token(private, POLICY_A), payload={
            "jsonrpc": "2.0", "id": "bound", "method": "tools/call",
            "params": {"name": "get_vehicle_status", "arguments": {}},
        }),
        FakeContext(remaining_ms=3500),
    )
    assert result["statusCode"] == 200
    assert len(captured) == 1 and captured[0][0] == KEY_A
    assert start < captured[0][1] <= start + 2.55


def test_policy_binding_and_geo_flag_validation_are_fail_closed(signing_material):
    _private, keys = signing_material
    differing = replace(POLICY_B, api_id="z9y8x7w6v5")
    with pytest.raises(ValueError):
        create_invited_lambda_runtime(
            POLICY_A, {KEY_A: POLICY_A, KEY_B: differing}, keys,
            provider_factory=lambda key, deadline: FakeProvider(FakeServices("x")),
        )
    with pytest.raises(ValueError):
        create_invited_lambda_runtime(
            POLICY_A, {KEY_A: POLICY_A}, keys,
            provider_factory=lambda key, deadline: FakeProvider(FakeServices("x")),
            geographic_queries=1,
        )


def test_policy_expiry_and_outer_deadline_are_never_extended(signing_material):
    private, keys = signing_material
    deadlines = []

    def factory(key, deadline):
        deadlines.append(deadline)
        return FakeProvider(FakeServices("A" if key == KEY_A else "B"))

    built = create_invited_lambda_runtime(
        POLICY_A, {KEY_A: POLICY_A}, keys, provider_factory=factory,
    )
    started = time.monotonic()
    response = built.handler(
        _event(POLICY_A, token(private, POLICY_A), payload={
            "jsonrpc": "2.0", "id": "clamp", "method": "tools/call",
            "params": {"name": "get_vehicle_status", "arguments": {}},
        }),
        FakeContext(remaining_ms=2500),
    )
    assert response["statusCode"] == 200
    assert len(deadlines) == 1
    assert deadlines[0] <= started + 1.55


def test_shared_router_atomically_rejects_same_provider_from_concurrent_factories(signing_material):
    private, keys = signing_material
    authority = InvitedTenantAuthority({KEY_A: POLICY_A, KEY_B: POLICY_B}, keys)
    grants = [
        asyncio.run(authority.authenticate(token(private, POLICY_A))),
        asyncio.run(authority.authenticate(token(private, POLICY_B))),
    ]
    barrier = Barrier(2)
    shared_provider = FakeProvider(FakeServices("shared"))

    def factory(_key, _deadline):
        barrier.wait(timeout=3)
        return shared_provider

    router = TenantServicesRouter(authority, factory)

    def bind_and_get(grant):
        try:
            with router.bind(grant):
                router.get()
            return "accepted"
        except TenantIsolationError as exc:
            return exc.category

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(bind_and_get, grants))
    assert outcomes.count("accepted") == 1
    assert outcomes.count("tenant_provider_reused") == 1
