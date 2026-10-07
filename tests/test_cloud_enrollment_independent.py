"""Independent composition holdouts across enrollment, DDB, SSM and providers."""
import asyncio
import sqlite3
import time

import jwt
import pytest

from mapit.aws_enrollment_clients import EnrollmentAwsClients
from mapit.cloud_enrollment import CloudEnrollmentFactory, EnrollmentCredentials
from mapit.durable_tenants import DurableTenantGuard, DurableTenantRecord, SQLiteTenantStore
from mapit.enrolled_provider import EnrolledCloudServicesProvider
from mapit.identity_binding import IdentityBindingError
from mapit.private_enrollment import PrivateEnrollmentChannel
from mapit.tenant_router import InvitedTenantAuthority
from test_aws_identity_binding import ACCOUNT_ID, _DynamoDocument
from test_aws_identity_binding_publisher import Client as SSMClient
from test_enrolled_provider import _Mapit, _SelectingAuth
from test_identity_binding import KEY_A, KEY_B, NOW, TOKEN_A, TOKEN_B, _make_setup, _rsa_pair
from test_private_enrollment import form, request


def _composition(tmp_path, monkeypatch, *, ambiguous=False, reject_dynamodb_account=False):
    setup = _make_setup(tmp_path)
    invite_private, invite_public = _rsa_pair()
    authority = InvitedTenantAuthority(
        setup["authority"]._policies, {"composition-key": invite_public}, environment="dev"
    )
    connection = sqlite3.connect(tmp_path / "composition-tenants.sqlite3")
    tenant_store = SQLiteTenantStore.initialize(connection)
    for key in (KEY_A, KEY_B):
        assert tenant_store.cas(key, None, DurableTenantRecord(key, "active", 1))
    guard = DurableTenantGuard(authority, tenant_store)

    invite_tokens = {}
    for key, subject in ((KEY_A, setup["authority"]._policies[KEY_A].owner_subject),
                         (KEY_B, setup["authority"]._policies[KEY_B].owner_subject)):
        policy = authority._policies[key]
        now = int(time.time())
        invite_tokens[key] = jwt.encode({
            "iss": policy.issuer_url, "aud": policy.audience, "sub": subject,
            "client_id": policy.client_id, "token_use": "access", "iat": now - 1,
            "exp": now + 3600, "scope": policy.required_scope,
        }, invite_private, algorithm="RS256", headers={"kid": "composition-key"})

    events = []
    db = _DynamoDocument(ambiguous_after_write=ambiguous)
    original_put = db.put_item

    def tracked_put(**kwargs):
        events.append("dynamodb_put")
        return original_put(**kwargs)

    db.put_item = tracked_put
    ssm = SSMClient()
    original_ssm_put = ssm.put_parameter

    def tracked_ssm_put(**kwargs):
        events.append("ssm_put")
        return original_ssm_put(**kwargs)

    ssm.put_parameter = tracked_ssm_put
    identity_auth = _SelectingAuth(setup["tokens"])
    registries = []

    def credentials_supplier():
        events.append("credentials")
        return EnrollmentCredentials("synthetic-access", "synthetic-secret", "synthetic-session")

    def aws_clients(**kwargs):
        events.append("client_pair")
        assert kwargs["include_dynamodb"] is True
        assert kwargs["deadline"] <= time.monotonic() + 14

        def verify_ssm(client, account):
            events.append("ssm_account_verified")
            return client is ssm and account == ACCOUNT_ID

        def verify_dynamodb(client, account):
            events.append("dynamodb_account_verified")
            return (not reject_dynamodb_account and client is db and account == ACCOUNT_ID)

        return EnrollmentAwsClients(ssm, verify_ssm, db, verify_dynamodb)

    monkeypatch.setattr("mapit.cloud_enrollment.create_enrollment_clients", aws_clients)
    composition = CloudEnrollmentFactory(
        authority=authority, durable_guard=guard, environment="dev", account_id=ACCOUNT_ID,
        config=setup["config"], verifier=setup["verifier"], binding_key=b"c" * 32,
        auth_transport=identity_auth, clock=lambda: NOW, credentials_supplier=credentials_supplier,
        monotonic=time.monotonic,
    )

    def enrollment_factory(**kwargs):
        pair = composition(**kwargs)
        registries.append((pair[0], kwargs["grant"], kwargs["snapshot"], pair[1]))
        return pair

    return {
        "setup": setup, "authority": authority, "guard": guard,
        "connection": connection, "invite_tokens": invite_tokens, "events": events,
        "db": db, "ssm": ssm, "identity_auth": identity_auth,
        "registries": registries, "enrollment_factory": enrollment_factory,
    }


def _channel(context):
    return PrivateEnrollmentChannel(
        authority=context["authority"], durable_guard=context["guard"],
        enrollment_factory=context["enrollment_factory"], port=8787,
        deadline=time.monotonic() + 500,
    )


def _submit(context, key, refresh_token):
    channel = _channel(context)
    body = form(channel, context["invite_tokens"][key], mapit=refresh_token)
    return request(channel, body=body, method="POST", target="/enroll")


def test_private_channel_to_shared_registry_to_ssm_keeps_two_tenants_isolated(tmp_path, monkeypatch):
    context = _composition(tmp_path, monkeypatch)
    assert context["events"] == [] and context["db"].get_calls == [] and context["ssm"].calls == []
    assert _submit(context, KEY_A, TOKEN_A).status == 200
    assert _submit(context, KEY_B, TOKEN_B).status == 200
    assert len(context["registries"]) == 2
    assert len(context["db"].put_calls) == 6
    assert [entry[0] for entry in context["ssm"].calls] == ["put", "get", "put", "get"]
    for event, write in (("dynamodb_account_verified", "dynamodb_put"), ("ssm_account_verified", "ssm_put")):
        assert context["events"].index(event) < context["events"].index(write)

    setup, authority, guard = context["setup"], context["authority"], context["guard"]
    mapit_a, mapit_b = _Mapit("tenant-a", 11), _Mapit("tenant-b", 22)
    providers = []
    for index, key in enumerate((KEY_A, KEY_B)):
        token_key = TOKEN_A if index == 0 else TOKEN_B
        invite_grant = asyncio.run(authority.authenticate(context["invite_tokens"][key]))
        snapshot = guard.capture(invite_grant)
        registry = context["registries"][index][0]
        provider = EnrolledCloudServicesProvider(
            registry, authority=authority, grant=invite_grant, durable_guard=guard,
            snapshot=snapshot, ssm_client=context["ssm"], account_id=ACCOUNT_ID,
            auth_transport=_SelectingAuth(setup["tokens"]),
            mapit_transport=mapit_a if index == 0 else mapit_b,
            deadline=time.monotonic() + 10, monotonic=time.monotonic,
        )
        providers.append(provider)

    service_a, service_b = (provider.get() for provider in providers)
    assert service_a.get_vehicle_status().status == "tenant-a"
    assert service_b.get_vehicle_status().status == "tenant-b"
    assert service_a.get_distance("2026-01-01", "2026-02-01").distance == 11
    assert service_b.get_distance("2026-01-01", "2026-02-01").distance == 22
    assert [call[1]["Name"] for call in context["ssm"].calls if call[0] == "get"] == [
        f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token:1",
        f"/honda-mapit-mcp/dev/tenants/{KEY_B}/mapit-refresh-token:1",
        f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token:1",
        f"/honda-mapit-mcp/dev/tenants/{KEY_B}/mapit-refresh-token:1",
    ]


def test_ambiguous_channel_write_cannot_be_retried_by_same_registry(tmp_path, monkeypatch):
    context = _composition(tmp_path, monkeypatch, ambiguous=True)
    response = _submit(context, KEY_A, TOKEN_A)
    assert response.status == 409
    registry, grant, snapshot, publisher = context["registries"][0]
    assert len(context["db"].put_calls) == 1
    assert context["identity_auth"].calls == [] and context["ssm"].calls == []
    with pytest.raises(IdentityBindingError, match="identity_binding_store_failed"):
        registry.enroll(grant, snapshot, TOKEN_A, publisher=publisher)
    assert len(context["db"].put_calls) == 1
    assert context["identity_auth"].calls == [] and context["ssm"].calls == []


def test_failed_same_credential_account_proof_precedes_all_writes(tmp_path, monkeypatch):
    context = _composition(tmp_path, monkeypatch, reject_dynamodb_account=True)
    response = _submit(context, KEY_A, TOKEN_A)
    assert response.status == 409
    assert context["db"].put_calls == [] and context["ssm"].calls == []
    assert "dynamodb_account_verified" in context["events"]
    assert "dynamodb_put" not in context["events"]
