from __future__ import annotations

import asyncio
import sqlite3

import pytest

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.durable_tenants import DurableTenantRecord, SQLiteTenantStore
from mapit.invited_lambda import create_invited_dev_lambda_runtime
from mapit.tenant_router import TenantIsolationError, TenantServicesRouter, InvitedTenantAuthority
from test_invited_lambda import (
    FakeProvider, FakeServices, KEY_A, KEY_B, POLICY_A, POLICY_B,
    _call_lambda_handler, signing_material, token,
)


def _dev_policies():
    return {
        KEY_A: CognitoDevPolicy(POLICY_A.user_pool_id, "a1b2c3d4e5", POLICY_A.client_id,
                                POLICY_A.owner_subject, request_deadline_seconds=14.0),
        KEY_B: CognitoDevPolicy(POLICY_B.user_pool_id, "a1b2c3d4e5", POLICY_B.client_id,
                                POLICY_B.owner_subject, request_deadline_seconds=14.0),
    }


def _store(tmp_path):
    connection = sqlite3.connect(tmp_path / "contextual-dev.sqlite3", timeout=0,
                                 isolation_level=None, check_same_thread=False)
    store = SQLiteTenantStore.initialize(connection)
    assert store.cas(KEY_A, None, DurableTenantRecord(KEY_A, "active", 1))
    assert store.cas(KEY_B, None, DurableTenantRecord(KEY_B, "active", 1))
    return connection, store


@pytest.mark.parametrize(("key", "policy", "label"), [
    (KEY_A, POLICY_A, "A"), (KEY_B, POLICY_B, "B"),
])
def test_dev_contextual_factory_receives_exact_signed_request_context(
    signing_material, tmp_path, key, policy, label,
):
    private, public_keys = signing_material
    connection, store = _store(tmp_path)
    captured = []
    try:
        dev_policies = _dev_policies()
        calls = []

        def contextual_factory(**context):
            calls.append(context)
            context["request_check"]()
            assert context["tenant_key"] == context["grant"].key == key
            assert context["authority"].matches_environment("dev")
            assert context["durable_guard"].is_bound_to(context["authority"])
            assert context["snapshot"].key == key
            assert context["snapshot"].revision == 1
            assert type(context["deadline"]) is float
            captured.append(context["request_check"])
            return FakeProvider(FakeServices(label))

        runtime = create_invited_dev_lambda_runtime(
            dev_policies[key], dev_policies, public_keys,
            authorization_store=store,
            contextual_provider_factory=contextual_factory,
        )
        result = asyncio.run(_call_lambda_handler(
            runtime.handler, token(private, policy), "get_vehicle_status", {},
        ))
        assert not result.is_error
        assert result.structured_content["status"] == label
        assert len(calls) == 1
        with pytest.raises(TenantIsolationError):
            captured[0]()
    finally:
        connection.close()


def test_contextual_factory_is_exclusive_dev_only_and_guarded(signing_material, tmp_path):
    _private, public_keys = signing_material
    dev_policies = _dev_policies()
    authority = InvitedTenantAuthority(dev_policies, public_keys, environment="dev")
    connection, store = _store(tmp_path)
    from mapit.durable_tenants import DurableTenantGuard
    guard = DurableTenantGuard(authority, store)
    contextual = lambda **_kwargs: FakeProvider(FakeServices("A"))

    try:
        with pytest.raises(TenantIsolationError):
            TenantServicesRouter(authority, lambda _key, _deadline: None,
                                 contextual_provider_factory=contextual,
                                 authorization_guard=guard)
        with pytest.raises(TenantIsolationError):
            TenantServicesRouter(authority, contextual_provider_factory=contextual)

        prod_policies = {KEY_A: POLICY_A}
        prod_authority = InvitedTenantAuthority(prod_policies, public_keys, environment="prod")
        prod_guard = DurableTenantGuard(prod_authority, store)
        with pytest.raises(TenantIsolationError):
            TenantServicesRouter(prod_authority, contextual_provider_factory=contextual,
                                 authorization_guard=prod_guard)
    finally:
        connection.close()


def test_revoked_durable_grant_never_reaches_contextual_factory(signing_material, tmp_path):
    private, public_keys = signing_material
    connection, store = _store(tmp_path)
    calls = []
    try:
        policies = _dev_policies()
        runtime = create_invited_dev_lambda_runtime(
            policies[KEY_A], policies, public_keys,
            authorization_store=store,
            contextual_provider_factory=lambda **kwargs: calls.append(kwargs),
        )
        assert store.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
        result = asyncio.run(_call_lambda_handler(
            runtime.handler, token(private, POLICY_A), "get_vehicle_status", {},
        ))
        assert result.is_error
        assert calls == []
    finally:
        connection.close()


def test_revocation_during_contextual_factory_stops_provider_dispatch(signing_material, tmp_path):
    private, public_keys = signing_material
    connection, store = _store(tmp_path)
    provider_calls = []
    try:
        policies = _dev_policies()

        class TrackedProvider(FakeProvider):
            def get(self):
                provider_calls.append("get")
                return super().get()

        def contextual_factory(**context):
            assert context["tenant_key"] == KEY_A
            assert store.cas(KEY_A, 1, DurableTenantRecord(KEY_A, "revoked", 2))
            return TrackedProvider(FakeServices("must-not-dispatch"))

        runtime = create_invited_dev_lambda_runtime(
            policies[KEY_A], policies, public_keys,
            authorization_store=store,
            contextual_provider_factory=contextual_factory,
        )
        result = asyncio.run(_call_lambda_handler(
            runtime.handler, token(private, POLICY_A), "get_vehicle_status", {},
        ))
        assert result.is_error
        assert provider_calls == []
        assert "must-not-dispatch" not in str(result)
    finally:
        connection.close()
