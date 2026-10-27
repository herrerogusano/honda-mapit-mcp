from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest

from mapit.durable_tenants import DurableTenantRecord, SQLiteTenantStore
from mapit.invited_lambda import create_invited_lambda_runtime
from test_invited_lambda import (
    FakeContext, FakeProvider, FakeServices, KEY_A, KEY_B, POLICY_A, POLICY_B,
    LambdaHTTPTransport, _call_lambda_handler, signing_material, token,
)


def _runtime(signing_material, store, created, *, factory=None):
    private, keys = signing_material

    def default_factory(key, deadline):
        created.append(key)
        return FakeProvider(FakeServices("A" if key == KEY_A else "B"))

    return private, create_invited_lambda_runtime(
        POLICY_A, {KEY_A: POLICY_A, KEY_B: POLICY_B}, keys,
        provider_factory=factory or default_factory,
        authorization_store=store,
    )


def _store(tmp_path):
    connection = sqlite3.connect(tmp_path / "lambda-authorizations.sqlite3", timeout=0,
                                 isolation_level=None, check_same_thread=False)
    store = SQLiteTenantStore.initialize(connection)
    assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    assert store.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))
    return connection, store


@pytest.mark.parametrize("subject,expected", [("A", "A"), ("B", "B")])
def test_payload_v2_durable_guard_routes_synthetic_tenants(signing_material, tmp_path, subject, expected):
    connection, store = _store(tmp_path)
    created = []
    try:
        private, built = _runtime(signing_material, store, created)
        selected = POLICY_A if subject == "A" else POLICY_B
        result = asyncio.run(_call_lambda_handler(built.handler, token(private, selected), "get_vehicle_status", {}))
        assert not result.is_error
        assert result.structured_content["status"] == expected
        assert created == [KEY_A if subject == "A" else KEY_B]
    finally:
        connection.close()


def test_revoke_persists_between_warm_calls_and_reopen(signing_material, tmp_path):
    connection, store = _store(tmp_path)
    created = []
    try:
        private, built = _runtime(signing_material, store, created)
        first = asyncio.run(_call_lambda_handler(built.handler, token(private, POLICY_A), "get_vehicle_status", {}))
        assert not first.is_error
        assert store.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
        second = asyncio.run(_call_lambda_handler(built.handler, token(private, POLICY_A), "get_vehicle_status", {}))
        assert second.is_error
        assert created == [KEY_A]
    finally:
        connection.close()
    reopened = sqlite3.connect(tmp_path / "lambda-authorizations.sqlite3", timeout=0,
                               isolation_level=None, check_same_thread=False)
    try:
        restarted = SQLiteTenantStore(reopened)
        created_again = []
        private, built = _runtime(signing_material, restarted, created_again)
        denied = asyncio.run(_call_lambda_handler(built.handler, token(private, POLICY_A), "get_vehicle_status", {}))
        allowed = asyncio.run(_call_lambda_handler(built.handler, token(private, POLICY_B), "get_vehicle_status", {}))
        assert denied.is_error and not allowed.is_error
        assert created_again == [KEY_B]
    finally:
        reopened.close()


def test_revocation_after_business_discards_result(signing_material, tmp_path):
    connection, store = _store(tmp_path)
    created = []

    class RevokingServices(FakeServices):
        def get_vehicle_status(self):
            result = super().get_vehicle_status()
            assert store.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
            return result

    try:
        private, built = _runtime(
            signing_material, store, created,
            factory=lambda key, deadline: (created.append(key), FakeProvider(RevokingServices("private-canary")))[1],
        )
        result = asyncio.run(_call_lambda_handler(built.handler, token(private, POLICY_A), "get_vehicle_status", {}))
        assert result.is_error
        assert "private-canary" not in str(result)
        assert created == [KEY_A]
    finally:
        connection.close()


def test_invalid_grant_does_zero_provider_work(signing_material, tmp_path):
    connection, store = _store(tmp_path)
    created = []
    try:
        private, built = _runtime(signing_material, store, created)
        with pytest.raises(Exception):
            asyncio.run(_call_lambda_handler(built.handler, token(private, POLICY_A, sub="bad"), "get_vehicle_status", {}))
        assert created == []
    finally:
        connection.close()


def test_slow_authorization_lookup_expires_before_provider(signing_material, tmp_path):
    connection, store = _store(tmp_path)
    created = []

    class SlowStore:
        def get(self, key):
            time.sleep(0.15)
            return store.get(key)

        def cas(self, key, expected_revision, replacement):
            return store.cas(key, expected_revision, replacement)

    try:
        private, built = _runtime(signing_material, SlowStore(), created)

        async def call():
            transport = LambdaHTTPTransport(built.handler, remaining_ms=1_100)
            import httpx2
            from mcp import ClientSession
            from mcp.client.streamable_http import streamable_http_client
            async with httpx2.AsyncClient(transport=transport, base_url=POLICY_A.resource_url.removesuffix("/mcp"), headers={"Authorization": f"Bearer {token(private, POLICY_A)}"}) as client:
                async with streamable_http_client(POLICY_A.resource_url, http_client=client) as streams:
                    async with ClientSession(*streams) as session:
                        await session.initialize()
                        return await session.call_tool("get_vehicle_status", {})

        with pytest.raises(Exception):
            asyncio.run(call())
        assert created == []
    finally:
        connection.close()
