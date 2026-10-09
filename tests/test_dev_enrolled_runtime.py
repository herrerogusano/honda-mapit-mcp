"""Payload-v2 MCP through the actual readonly enrolled provider, offline."""
import asyncio
from dataclasses import replace

import pytest

from mapit.aws_binding_keys import BindingKeyMaterial
from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.dev_enrolled_runtime import DevEnrolledProviderFactory, DevEnrolledReadResources
from mapit.durable_tenants import DurableTenantRecord
from mapit.invited_lambda import create_invited_dev_lambda_runtime
from test_aws_identity_binding import _DynamoDocument, _registry
from test_enrolled_provider import ACCOUNT_ID, _Mapit, _PublishingSecrets, _SSM, _SelectingAuth
from test_identity_binding import KEY_A, KEY_B, NOW, SUBJECT_A, SUBJECT_B, TOKEN_A, TOKEN_B, _AuthTransport, _make_setup
from test_invited_dev_lambda import _call, _token, signing_material


class _Store:
    def __init__(self):
        self.records = {key: DurableTenantRecord(key, "active", 1) for key in (KEY_A, KEY_B)}

    def get(self, key):
        return self.records.get(key)

    def cas(self, key, expected_revision, replacement):
        old = self.records.get(key)
        if (old.revision if old else None) != expected_revision:
            return False
        self.records[key] = replacement
        return True


def _setup(tmp_path, signing_material, *, revoke_during_call=False):
    env = _make_setup(tmp_path)
    db, publisher, store = _DynamoDocument(), _PublishingSecrets(), _Store()
    for label, refresh in (("a", TOKEN_A), ("b", TOKEN_B)):
        registry = _registry(env, db, auth=_AuthTransport(env["tokens"][refresh]))
        registry.enroll(env["grant_" + label], env["snapshot_" + label], refresh, publisher=publisher)
    ssm, loads, calls = _SSM(publisher.values), [], []

    def load(*, deadline):
        loads.append(deadline)
        return DevEnrolledReadResources(db, ssm, BindingKeyMaterial(b"b" * 32, b"v" * 32))

    def transports(*, deadline):
        auth = _SelectingAuth(env["tokens"])
        def business(*args):
            label = "A" if auth.id_token == env["tokens"][TOKEN_A] else "B"
            calls.append(label)
            if revoke_during_call and label == "A":
                store.records[KEY_A] = DurableTenantRecord(KEY_A, "revoked", 2)
            return _Mapit(label, 11 if label == "A" else 22)(*args)
        return auth, business

    factory = DevEnrolledProviderFactory(account_id=ACCOUNT_ID, config=env["config"],
        mapit_public_keys={"mapit-test-key": env["mapit_public"]},
        resources_loader=load, transports_factory=transports, clock=lambda: NOW)
    a = replace(CognitoDevPolicy("eu-west-1_InvitePool123", "a1b2c3d4e5", "InviteClient123", SUBJECT_A),
                request_deadline_seconds=14.0)
    b = replace(a, owner_subject=SUBJECT_B)
    private, public = signing_material
    runtime = create_invited_dev_lambda_runtime(a, {KEY_A: a, KEY_B: b}, public,
        contextual_provider_factory=factory, authorization_store=store)
    return env, db, publisher, store, ssm, loads, calls, runtime, private, a, b


def test_payload_v2_restores_enrolled_binding_and_keeps_users_isolated(tmp_path, signing_material):
    env, db, _, _, ssm, loads, calls, runtime, private, a, b = _setup(tmp_path, signing_material)
    writes = len(db.put_calls)
    async def scenario():
        for policy, label in ((a, "A"), (b, "B"), (a, "A")):
            result = await _call(runtime, policy, _token(private, policy))
            assert not result.is_error and result.structured_content["status"] == label
    asyncio.run(scenario())
    assert calls == ["A", "B", "A"] and len(loads) == 3
    assert len(db.put_calls) == writes  # Runtime never enrolls/writes.
    assert [call[0] for call in ssm.calls] == [
        f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token:1" for key in (KEY_A, KEY_B, KEY_A)]
    assert "<redacted>" in repr(DevEnrolledReadResources(db, ssm, BindingKeyMaterial(b"b" * 32, b"v" * 32)))
    env["connection"].close()


def test_crossed_session_rejected_before_business(tmp_path, signing_material):
    env, _, publisher, _, ssm, _, calls, runtime, private, a, _ = _setup(tmp_path, signing_material)
    path = f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token"
    ssm.values[path] = publisher.values[f"/honda-mapit-mcp/dev/tenants/{KEY_B}/mapit-refresh-token"]
    result = asyncio.run(_call(runtime, a, _token(private, a)))
    assert result.is_error and calls == []
    env["connection"].close()


def test_inflight_revocation_discards_result_and_b_stays_usable(tmp_path, signing_material):
    env, _, _, _, _, loads, calls, runtime, private, a, b = _setup(
        tmp_path, signing_material, revoke_during_call=True)
    async def scenario():
        first = await _call(runtime, a, _token(private, a))
        assert first.is_error and first.structured_content is None
        second = await _call(runtime, b, _token(private, b))
        assert not second.is_error and second.structured_content["status"] == "B"
        denied = await _call(runtime, a, _token(private, a))
        assert denied.is_error
    asyncio.run(scenario())
    assert calls == ["A", "B"] and len(loads) == 2
    env["connection"].close()


def test_invalid_factory_config_does_not_load_resources(tmp_path):
    env = _make_setup(tmp_path)
    loads = []
    with pytest.raises(ValueError, match="dev_enrolled_configuration_invalid"):
        DevEnrolledProviderFactory(account_id="000000000000", config=env["config"],
            mapit_public_keys={"mapit-test-key": env["mapit_public"]},
            resources_loader=lambda **kw: loads.append(kw), transports_factory=lambda **kw: None)
    assert loads == []
    env["connection"].close()
