"""Complete payload-v2 DEV composition using real DynamoDB wire shapes offline."""
import asyncio
import socket

import pytest

from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.durable_tenants import DurableTenantRecord
from test_aws_durable_tenants import MemoryClient, TABLE
from test_invited_dev_lambda import (
    DEV_A, DEV_B, KEY_A, KEY_B, _call, _runtime, _token, signing_material,
)


@pytest.fixture(autouse=True)
def no_external_network(monkeypatch):
    original = socket.socket.connect
    def deny(sock, address):
        if isinstance(address, tuple) and address[0] in {"127.0.0.1", "::1"}:
            return original(sock, address)
        raise AssertionError("external network denied")
    monkeypatch.setattr(socket.socket, "connect", deny)


def test_separate_dev_instances_observe_shared_authorization_and_revoke(signing_material):
    client = MemoryClient()
    operator = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(KEY_A, KEY_B), writer=client)
    assert operator.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    assert operator.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))
    first_store = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(KEY_A, KEY_B))
    second_store = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(KEY_A, KEY_B))
    private, first, first_providers = _runtime(signing_material, first_store)
    _, second, second_providers = _runtime(signing_material, second_store)

    async def scenario():
        a = await _call(first, DEV_A, _token(private, DEV_A))
        b = await _call(second, DEV_B, _token(private, DEV_B))
        assert not a.is_error and not b.is_error
        assert a.structured_content["status"] == "A"
        assert b.structured_content["status"] == "B"
        assert operator.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
        denied = await _call(second, DEV_A, _token(private, DEV_A))
        assert denied.is_error
        again = await _call(first, DEV_B, _token(private, DEV_B))
        assert not again.is_error and again.structured_content["status"] == "B"

    asyncio.run(scenario())
    assert first_providers == [KEY_A, KEY_B]
    assert second_providers == [KEY_B]
    assert all(request["ConsistentRead"] is True for method, request in client.calls if method == "get")


def test_dev_result_is_discarded_after_shared_store_revocation(signing_material):
    client = MemoryClient()
    operator = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(KEY_A, KEY_B), writer=client)
    assert operator.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    reader = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(KEY_A, KEY_B))
    def revoke():
        assert operator.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
    private, runtime, created = _runtime(signing_material, reader, on_status=revoke)
    result = asyncio.run(_call(runtime, DEV_A, _token(private, DEV_A)))
    assert result.is_error
    assert "structured_content={'status'" not in str(result)
    assert created == [KEY_A]


def test_expected_mapit_proof_cannot_be_ignored_without_verifier():
    from mapit.auth import CognitoAuthenticator
    from mapit.config import MapitConfig
    from mapit.mapit_identity import MapitIdentityError
    calls = []
    auth = CognitoAuthenticator(MapitConfig(), transport=lambda *args: calls.append(args))
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        auth.authenticate_with_refresh_token("synthetic-refresh", expected_identity_proof=object())
    assert calls == []
