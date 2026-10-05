from __future__ import annotations

import asyncio
import time
from contextlib import AsyncExitStack
from dataclasses import replace

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.middleware.auth_context import AuthenticatedUser, auth_context_var
from mcp.server.auth.provider import AccessToken

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.invited_mcp import InvitedTokenVerifier, create_invited_mcp_app
from mapit.services import DistanceResult, Position, VehicleStatus
from mapit.tenant_router import (
    InvitedTenantAuthority,
    TenantIsolationError,
    TenantServicesRouter,
    tenant_key,
)

SUBJECT_A = "00000000-0000-4000-8000-000000000001"
SUBJECT_B = "00000000-0000-4000-8000-000000000002"
POLICY_A = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUBJECT_A)
POLICY_B = replace(POLICY_A, owner_subject=SUBJECT_B)
KEY_A = tenant_key(b"i" * 32, POLICY_A.issuer_url, SUBJECT_A)
KEY_B = tenant_key(b"i" * 32, POLICY_B.issuer_url, SUBJECT_B)


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, {"invited-test-key": public}


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
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "invited-test-key"})


class FakeServices:
    def __init__(self, label, *, fail=False, delay=0):
        self.label, self.fail, self.delay = label, fail, delay

    def get_vehicle_status(self):
        if self.delay:
            time.sleep(self.delay)
        if self.fail:
            raise RuntimeError("provider canary must not escape")
        return VehicleStatus(status=self.label, position=Position())

    def get_distance(self, from_time, to_time):
        return DistanceResult(
            from_time=from_time, to_time=to_time,
            distance=11.0 if self.label == "A" else 22.0,
            distance_km=11.0 if self.label == "A" else 22.0,
            route_count=1,
        )


class FakeProvider:
    def __init__(self, services):
        self.services = services

    def get(self):
        return self.services


def composition(signing_material, *, factory=None, policies=None):
    private, keys = signing_material
    selected = policies or {KEY_A: POLICY_A, KEY_B: POLICY_B}
    authority = InvitedTenantAuthority(selected, keys)
    created = []

    def default_factory(key, deadline):
        assert 0 < deadline - time.monotonic() <= 14
        service = FakeServices("A" if key == KEY_A else "B")
        created.append(key)
        return FakeProvider(service)

    router = TenantServicesRouter(authority, factory or default_factory)
    app = create_invited_mcp_app(authority, router, POLICY_A)
    return private, authority, router, app, created


def _origin(policy=POLICY_A):
    return policy.resource_url.removesuffix("/mcp")


async def _call(app, policy, bearer, tool, arguments):
    async with app.router.lifespan_context(app):
        async with httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=_origin(policy),
            headers={"Authorization": f"Bearer {bearer}"},
        ) as client:
            async with streamable_http_client(policy.resource_url, http_client=client) as streams:
                async with ClientSession(*streams) as session:
                    await session.initialize()
                    return await session.call_tool(tool, arguments)


def test_sdk_protocol_lists_tools_without_provider_and_routes_two_tenants(signing_material):
    private, _authority, _router, app, created = composition(signing_material)
    token_a, token_b = token(private, POLICY_A), token(private, POLICY_B)
    seen = []

    async def make_session(bearer, stack):
        client = await stack.enter_async_context(httpx2.AsyncClient(
            transport=httpx2.ASGITransport(app=app),
            base_url=_origin(),
            headers={"Authorization": f"Bearer {bearer}"},
        ))
        streams = await stack.enter_async_context(
            streamable_http_client(POLICY_A.resource_url, http_client=client)
        )
        session = await stack.enter_async_context(ClientSession(*streams))
        await session.initialize()
        tools = await session.list_tools()
        assert len(tools.tools) == 10
        assert created == []
        return client, streams, session

    async def scenario():
        async with app.router.lifespan_context(app):
            async with AsyncExitStack() as stack:
                resources = [
                    await make_session(token_a, stack),
                    await make_session(token_b, stack),
                ]
                # Overlap worker-thread calls through actual SDK dispatch.
                results = await asyncio.gather(*[
                    resource[2].call_tool("get_vehicle_status", {}) for resource in resources
                ])
                seen.extend(result.structured_content["status"] for result in results)
                distances = await asyncio.gather(
                    resources[0][2].call_tool("get_distance", {"from_time": "2026-01-01", "to_time": "2026-02-01"}),
                    resources[1][2].call_tool("get_distance", {"from_time": "2026-01-01", "to_time": "2026-02-01"}),
                )
                seen.extend(item.structured_content["distance"] for item in distances)
    asyncio.run(scenario())
    assert seen == ["A", "B", 11.0, 22.0]
    assert sorted(created) == sorted([KEY_A, KEY_A, KEY_B, KEY_B])


def test_authentication_denials_never_reach_tenant_factory(signing_material):
    private, _authority, _router, app, created = composition(signing_material)
    foreign = CognitoProdPolicy("eu-west-1_ZyXwVuTsR", "z9y8x7w6v5", "OtherClient", SUBJECT_A)
    cases = [
        (None, 401),
        ("malformed-bearer-canary", 401),
        (token(private, POLICY_A, scope="other"), 401),
        (token(private, foreign), 401),
        (token(private, POLICY_A, sub="00000000-0000-4000-8000-000000000099"), 401),
    ]

    async def scenario():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app), base_url=_origin()
            ) as client:
                for bearer, expected in cases:
                    headers = {} if bearer is None else {"Authorization": f"Bearer {bearer}"}
                    response = await client.post("/mcp", headers=headers, json={
                        "jsonrpc": "2.0", "id": "deny", "method": "tools/call",
                        "params": {"name": "get_vehicle_status", "arguments": {}},
                    })
                    assert response.status_code == expected
                    assert b"malformed-bearer-canary" not in response.content
    asyncio.run(scenario())
    assert created == []


def test_context_token_redacts_raw_bearer_grant_and_rejects_base_token(signing_material):
    private, _authority, _router, _app, _created = composition(signing_material)
    verifier = InvitedTokenVerifier(_authority, POLICY_A)
    raw = token(private, POLICY_A)
    access = asyncio.run(verifier.verify_token(raw))
    assert access is not None
    assert raw not in repr(access)
    assert KEY_A not in repr(access)
    dumped = str(access.model_dump())
    assert raw not in dumped and KEY_A not in dumped and "tenant_grant" not in dumped
    with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
        verifier.grant_for(AccessToken(
            token=raw, client_id=POLICY_A.client_id, scopes=[POLICY_A.required_scope],
            expires_at=access.expires_at, resource=POLICY_A.audience,
            subject=KEY_A, claims={"iss": POLICY_A.issuer_url},
        ))
    grant_b = asyncio.run(_authority.authenticate(token(private, POLICY_B)))
    substituted = access.model_copy(update={"tenant_grant": grant_b})
    with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
        verifier.grant_for(substituted)


def test_factory_requires_same_router_authority_and_matching_common_policy(signing_material):
    _private, keys = signing_material
    authority = InvitedTenantAuthority({KEY_A: POLICY_A}, keys)
    foreign_authority = InvitedTenantAuthority({KEY_A: POLICY_A}, keys)
    router = TenantServicesRouter(authority, lambda key, deadline: FakeProvider(FakeServices("A")))
    wrong = replace(POLICY_A, client_id="OtherClient")
    with pytest.raises(ValueError):
        create_invited_mcp_app(foreign_authority, router, POLICY_A)
    with pytest.raises(ValueError):
        create_invited_mcp_app(authority, router, wrong)


def test_revocation_during_provider_creation_blocks_business_method(signing_material):
    private, keys = signing_material
    authority = InvitedTenantAuthority({KEY_A: POLICY_A}, keys)
    created = []

    def revoke_during_factory(key, deadline):
        created.append(key)
        authority.revoke(key)
        return FakeProvider(FakeServices("must-not-return"))

    router = TenantServicesRouter(authority, revoke_during_factory)
    app = create_invited_mcp_app(authority, router, POLICY_A)
    async def scenario():
        response = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
        assert response.is_error
        assert "must-not-return" not in str(response)
    asyncio.run(scenario())
    assert created == [KEY_A]


def test_provider_exceptions_are_closed_and_context_is_unbound(signing_material):
    private, keys = signing_material
    authority = InvitedTenantAuthority({KEY_A: POLICY_A}, keys)
    router = TenantServicesRouter(
        authority, lambda key, deadline: FakeProvider(FakeServices("unused", fail=True))
    )
    app = create_invited_mcp_app(authority, router, POLICY_A)
    async def scenario():
        result = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
        assert result.is_error
        assert "provider canary" not in str(result)
    asyncio.run(scenario())
    with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
        router.get()


def test_direct_sdk_context_substitution_is_rejected(signing_material):
    private, _authority, _router, _app, _created = composition(signing_material)
    verifier = InvitedTokenVerifier(_authority, POLICY_A)
    access = asyncio.run(verifier.verify_token(token(private, POLICY_A)))
    assert access is not None
    ordinary = AccessToken(
        token="different", client_id=POLICY_A.client_id,
        scopes=[POLICY_A.required_scope], expires_at=access.expires_at,
        resource=POLICY_A.audience, subject=KEY_A, claims={"iss": POLICY_A.issuer_url},
    )
    context_token = auth_context_var.set(AuthenticatedUser(ordinary))
    try:
        with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
            verifier.grant_for(get_access_token_for_test())
    finally:
        auth_context_var.reset(context_token)


def get_access_token_for_test():
    from mcp.server.auth.middleware.auth_context import get_access_token
    return get_access_token()
