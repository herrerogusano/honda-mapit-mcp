from __future__ import annotations

import asyncio

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.mcpserver.exceptions import ToolError

from mapit.invited_mcp import InvitedTokenVerifier, _TenantProviderProxy
from mapit.services import Position, VehicleStatus
from mapit.tenant_router import InvitedTenantAuthority, TenantIsolationError, TenantServicesRouter
from test_invited_mcp import (
    KEY_A,
    KEY_B,
    POLICY_A,
    POLICY_B,
    FakeProvider,
    FakeServices,
    _call,
    composition,
    token,
)


@pytest.fixture
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, {"invited-test-key": public}


def test_context_access_token_grant_and_claim_changes_fail_the_dispatch_seal(signing_material):
    private, authority, _router, _app, _created = composition(signing_material)
    verifier = InvitedTokenVerifier(authority, POLICY_A)
    authentic = asyncio.run(verifier.verify_token(token(private, POLICY_A)))
    assert authentic is not None
    grant_b = asyncio.run(authority.authenticate(token(private, POLICY_B)))

    for altered in (
        authentic.model_copy(update={"tenant_grant": grant_b}),
        authentic.model_copy(update={"subject": KEY_B}),
        authentic.model_copy(update={"scopes": ["other"]}),
        authentic.model_copy(update={"resource": "https://other.invalid/mcp"}),
        authentic.model_copy(update={"claims": {"iss": "https://other.invalid"}}),
        authentic.model_copy(update={"token": token(private, POLICY_B)}),
        authentic.model_copy(update={"dispatch_proof": b"x" * 32}),
    ):
        with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
            verifier.grant_for(altered)


def test_grant_sealed_by_a_different_authority_cannot_be_reused(signing_material):
    private, authority, _router, _app, _created = composition(signing_material)
    keys = signing_material[1]
    foreign_authority = InvitedTenantAuthority({KEY_A: POLICY_A, KEY_B: POLICY_B}, keys)
    foreign_verifier = InvitedTokenVerifier(foreign_authority, POLICY_A)
    local_verifier = InvitedTokenVerifier(authority, POLICY_A)
    foreign_access = asyncio.run(foreign_verifier.verify_token(token(private, POLICY_A)))
    assert foreign_access is not None
    with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
        local_verifier.grant_for(foreign_access)


def test_proxy_outside_sdk_auth_context_cannot_reach_router_or_factory(signing_material):
    _private, authority, router, _app, created = composition(signing_material)
    verifier = InvitedTokenVerifier(authority, POLICY_A)
    proxy = _TenantProviderProxy(authority, router, verifier)
    with pytest.raises(ToolError):
        proxy.get()
    assert created == []


def test_revocation_after_provider_result_suppresses_result_and_unbinds_context(signing_material):
    async def scenario():
        private, keys = signing_material
        authority = InvitedTenantAuthority({KEY_A: POLICY_A}, keys)
        calls = []

        class RevokingServices(FakeServices):
            def get_vehicle_status(self):
                calls.append("service_reached")
                result = VehicleStatus(status="private-output-canary", position=Position())
                authority.revoke(KEY_A)
                return result

        router = TenantServicesRouter(
            authority,
            lambda key, deadline: (calls.append("provider_created") or FakeProvider(RevokingServices("unused"))),
        )
        from mapit.invited_mcp import create_invited_mcp_app
        app = create_invited_mcp_app(authority, router, POLICY_A)
        result = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
        assert result.is_error
        assert "private-output-canary" not in str(result)
        assert calls == ["provider_created", "service_reached"]
        with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
            router.get()

    asyncio.run(scenario())


def test_provider_factory_exception_is_fixed_and_never_surfaces_payload(signing_material):
    async def scenario():
        private, keys = signing_material
        authority = InvitedTenantAuthority({KEY_A: POLICY_A}, keys)
        router = TenantServicesRouter(authority, lambda *_: (_ for _ in ()).throw(
            RuntimeError("synthetic-provider-exception-canary")
        ))
        from mapit.invited_mcp import create_invited_mcp_app
        app = create_invited_mcp_app(authority, router, POLICY_A)
        result = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
        assert result.is_error
        assert "synthetic-provider-exception-canary" not in str(result)
        with pytest.raises(TenantIsolationError, match="tenant_context_missing"):
            router.get()

    asyncio.run(scenario())
