from __future__ import annotations

import asyncio
import json
import sqlite3
import time
from dataclasses import replace

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.durable_tenants import DurableTenantRecord, SQLiteTenantStore
from mapit.invited_lambda import create_invited_dev_lambda_runtime
from mapit.services import Position, VehicleStatus
from mapit.tenant_router import InvitedTenantAuthority, TenantIsolationError, tenant_key


SUBJECT_A = "00000000-0000-4000-8000-000000000101"
SUBJECT_B = "00000000-0000-4000-8000-000000000102"
DEV_A = replace(
    CognitoDevPolicy("eu-west-1_AbCdEfGhI", "abcdefghij", "DevClient", SUBJECT_A),
    request_deadline_seconds=14.0,
)
DEV_B = replace(DEV_A, owner_subject=SUBJECT_B)
KEY_A = tenant_key(b"d" * 32, DEV_A.issuer_url, SUBJECT_A)
KEY_B = tenant_key(b"d" * 32, DEV_B.issuer_url, SUBJECT_B)


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, {"dev-key": public}


def _token(private, policy):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": policy.issuer_url,
            "aud": policy.audience,
            "sub": policy.owner_subject,
            "client_id": policy.client_id,
            "token_use": "access",
            "iat": now - 1,
            "exp": now + 300,
            "scope": policy.required_scope,
        },
        private,
        algorithm="RS256",
        headers={"kid": "dev-key"},
    )


class _Context:
    def get_remaining_time_in_millis(self):
        return 30_000


class _Services:
    def __init__(self, label, on_status=None):
        self.label = label
        self.on_status = on_status

    def get_vehicle_status(self):
        if self.on_status is not None:
            self.on_status()
        return VehicleStatus(status=self.label, position=Position())


class _Provider:
    def __init__(self, services):
        self.services = services

    def get(self):
        return self.services


def _event(policy, bearer, payload):
    return {
        "version": "2.0", "routeKey": "$default", "rawPath": "/mcp",
        "rawQueryString": "", "headers": {
            "host": policy.api_host,
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
            "authorization": f"Bearer {bearer}",
        },
        "requestContext": {
            "stage": "$default",
            "http": {"method": "POST", "path": "/mcp", "protocol": "HTTP/1.1",
                     "sourceIp": "127.0.0.1", "userAgent": "tests"},
        },
        "body": json.dumps(payload, separators=(",", ":")),
        "isBase64Encoded": False,
    }


class _Transport(httpx2.AsyncBaseTransport):
    def __init__(self, handler, policy, bearer):
        self.handler, self.policy, self.bearer = handler, policy, bearer

    async def handle_async_request(self, request):
        raw = await request.aread()
        result = await asyncio.to_thread(
            self.handler,
            _event(self.policy, self.bearer, json.loads(raw)),
            _Context(),
        )
        return httpx2.Response(
            result["statusCode"], headers=result["headers"],
            content=result["body"].encode("utf-8"), request=request,
        )


async def _call(runtime, policy, bearer):
    async with httpx2.AsyncClient(
        transport=_Transport(runtime.handler, policy, bearer),
        base_url=policy.resource_url.removesuffix("/mcp"),
        headers={"Authorization": f"Bearer {bearer}"},
    ) as client:
        async with streamable_http_client(policy.resource_url, http_client=client) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                return await session.call_tool("get_vehicle_status", {})


def _store():
    connection = sqlite3.connect(":memory:", check_same_thread=False, timeout=0,
                                 isolation_level=None)
    store = SQLiteTenantStore.initialize(connection)
    assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    assert store.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))
    return connection, store


def _runtime(signing_material, store, *, on_status=None):
    private, keys = signing_material
    created = []

    def factory(key, _deadline):
        created.append(key)
        return _Provider(_Services("A" if key == KEY_A else "B", on_status=on_status))

    runtime = create_invited_dev_lambda_runtime(
        DEV_A, {KEY_A: DEV_A, KEY_B: DEV_B}, keys,
        provider_factory=factory, authorization_store=store,
    )
    return private, runtime, created


def test_dev_payload_v2_routes_two_tenants_and_enforces_durable_revoke(signing_material):
    connection, store = _store()
    try:
        private, runtime, created = _runtime(signing_material, store)
        result_a = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_A)))
        result_b = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_B)))
        assert not result_a.is_error and not result_b.is_error
        assert {created[0], created[1]} == {KEY_A, KEY_B}
        current = store.get(KEY_A)
        assert current is not None and store.cas(KEY_A, current.revision,
                                                  DurableTenantRecord(KEY_A, "revoked", current.revision + 1))
        denied = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_A)))
        assert denied.is_error
        assert len(created) == 2
    finally:
        connection.close()


def test_dev_revocation_after_business_discards_result(signing_material):
    connection, store = _store()

    def revoke_after_lookup():
        current = store.get(KEY_A)
        assert current is not None
        assert store.cas(KEY_A, current.revision,
                         DurableTenantRecord(KEY_A, "revoked", current.revision + 1))

    try:
        private, runtime, created = _runtime(signing_material, store, on_status=revoke_after_lookup)
        result = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_A)))
        assert result.is_error
        assert created == [KEY_A]
    finally:
        connection.close()


def test_dev_factory_rejects_missing_store_mixed_policy_and_wrong_environment(signing_material):
    private, keys = signing_material
    del private
    with pytest.raises(ValueError):
        create_invited_dev_lambda_runtime(
            DEV_A, {KEY_A: DEV_A}, keys, provider_factory=lambda *_: _Provider(_Services("A")),
            authorization_store=None,  # type: ignore[arg-type]
        )
    prod = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "abcdefghij", "DevClient", SUBJECT_A)
    connection, store = _store()
    try:
        with pytest.raises(ValueError):
            create_invited_dev_lambda_runtime(
                DEV_A, {KEY_A: prod}, keys, provider_factory=lambda *_: _Provider(_Services("A")),
                authorization_store=store,
            )
        with pytest.raises(TenantIsolationError):
            InvitedTenantAuthority({KEY_A: DEV_A}, keys)
        authority = InvitedTenantAuthority({KEY_A: DEV_A}, keys, environment="dev")
        assert authority.matches_token_policy(DEV_A)
        assert not authority.matches_token_policy(prod)
    finally:
        connection.close()
