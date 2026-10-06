"""Real MCP/ASGI dispatch with synthetic tokens and local authorization state."""
from __future__ import annotations

import asyncio
import socket
import sqlite3

import pytest
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mapit.durable_tenants import DurableTenantGuard, DurableTenantRecord, SQLiteTenantStore
from mapit.invited_mcp import create_invited_mcp_app
from mapit.tenant_router import InvitedTenantAuthority, TenantServicesRouter
from test_invited_mcp import (
    KEY_A, KEY_B, POLICY_A, POLICY_B, FakeProvider, FakeServices,
    signing_material, token,
)


@pytest.fixture(autouse=True)
def deny_external_network(monkeypatch):
    original_connect = socket.socket.connect
    def denied(sock, address):
        # Windows asyncio implements its internal socketpair over loopback.
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
            return original_connect(sock, address)
        raise AssertionError("external networking is forbidden")
    monkeypatch.setattr(socket.socket, "connect", denied)


def connection(path):
    return sqlite3.connect(path, timeout=0, isolation_level=None, check_same_thread=False)


async def _call(app, policy, bearer, tool, arguments):
    async with httpx2.AsyncClient(
        transport=httpx2.ASGITransport(app=app),
        base_url=policy.resource_url.removesuffix("/mcp"),
        headers={"Authorization": f"Bearer {bearer}"},
    ) as client:
        async with streamable_http_client(policy.resource_url, http_client=client) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                return await session.call_tool(tool, arguments)


async def run_app(app, scenario):
    async with app.router.lifespan_context(app):
        await scenario()


def composition(store, keys, created, service_factory=None):
    authority = InvitedTenantAuthority({KEY_A: POLICY_A, KEY_B: POLICY_B}, keys)
    guard = DurableTenantGuard(authority, store)

    def factory(key, deadline):
        created.append(key)
        service = (service_factory(key) if service_factory else
                   FakeServices("synthetic-A" if key == KEY_A else "synthetic-B"))
        return FakeProvider(service)

    router = TenantServicesRouter(authority, factory, authorization_guard=guard)
    return create_invited_mcp_app(authority, router, POLICY_A)


def test_real_asgi_dispatch_separates_tenants_with_durable_guard(tmp_path, signing_material):
    private, keys = signing_material
    database = connection(tmp_path / "synthetic-authorizations.sqlite3")
    try:
        store = SQLiteTenantStore.initialize(database)
        assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
        assert store.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))
        created = []
        app = composition(store, keys, created)

        async def scenario():
            first = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
            second = await _call(app, POLICY_B, token(private, POLICY_B), "get_vehicle_status", {})
            assert not first.is_error and not second.is_error
            assert first.structured_content["status"] == "synthetic-A"
            assert second.structured_content["status"] == "synthetic-B"

        asyncio.run(run_app(app, scenario))
        assert created == [KEY_A, KEY_B]
    finally:
        database.close()


def test_revocation_during_business_suppresses_output_and_survives_reopen(tmp_path, signing_material):
    private, keys = signing_material
    path = tmp_path / "synthetic-authorizations.sqlite3"
    database = connection(path)
    created = []
    try:
        store = SQLiteTenantStore.initialize(database)
        assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
        assert store.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))

        class RevokingServices(FakeServices):
            def get_vehicle_status(self):
                result = super().get_vehicle_status()
                assert store.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
                return result

        app = composition(store, keys, created, lambda key: RevokingServices("private-canary"))

        async def scenario():
            result = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
            assert result.is_error
            assert "private-canary" not in str(result)
            repeated = await _call(app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
            assert repeated.is_error

        asyncio.run(run_app(app, scenario))
        assert created == [KEY_A]
    finally:
        database.close()

    reopened = connection(path)
    try:
        restarted_store = SQLiteTenantStore(reopened)
        restarted_created = []
        restarted_app = composition(restarted_store, keys, restarted_created)

        async def restarted_scenario():
            denied = await _call(restarted_app, POLICY_A, token(private, POLICY_A), "get_vehicle_status", {})
            allowed = await _call(restarted_app, POLICY_B, token(private, POLICY_B), "get_vehicle_status", {})
            assert denied.is_error
            assert not allowed.is_error
            assert allowed.structured_content["status"] == "synthetic-B"

        asyncio.run(run_app(restarted_app, restarted_scenario))
        assert restarted_created == [KEY_B]
    finally:
        reopened.close()
