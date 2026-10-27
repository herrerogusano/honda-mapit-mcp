from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import sqlite3

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_dev_runtime import CognitoDevPolicy
from mapit.config import MapitConfig
from mapit.durable_tenants import DurableTenantError, DurableTenantGuard, DurableTenantRecord, SQLiteTenantStore
from mapit.identity_binding import (
    IdentityBindingError,
    SQLiteIdentityBindingRegistry,
    SecretPublicationReceipt,
)
from mapit.mapit_identity import MapitIdentityError, MapitIdentityVerifier
from mapit.tenant_router import AuthenticatedTenant, InvitedTenantAuthority, tenant_key

SUBJECT_A = "00000000-0000-4000-8000-000000000001"
SUBJECT_B = "00000000-0000-4000-8000-000000000002"
TOKEN_A = "synthetic-refresh-A"
TOKEN_B = "synthetic-refresh-B"
NOW = datetime.now(timezone.utc)
KEY_A = tenant_key(b"t" * 32, "https://invited.example.invalid", SUBJECT_A)
KEY_B = tenant_key(b"t" * 32, "https://invited.example.invalid", SUBJECT_B)


def _config(**changes):
    fields = {
        "region": "eu-west-1",
        "user_pool_id": "eu-west-1_MapitPool123",
        "user_pool_client_id": "MapitClient123",
        "identity_pool_id": "eu-west-1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "core_api_url": "https://core.prod.mapit.me",
        "geo_api_url": "https://geo.prod.mapit.me",
        "discovery_enabled": False,
        "http_timeout": 2.0,
    }
    fields.update(changes)
    return MapitConfig(**fields)


def _rsa_pair():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public


def _identity_token(private, config, subject):
    return jwt.encode({
        "iss": f"https://cognito-idp.{config.region}.amazonaws.com/{config.user_pool_id}",
        "aud": config.user_pool_client_id,
        "sub": subject,
        "token_use": "id",
        "iat": int((NOW - timedelta(seconds=2)).timestamp()),
        "exp": int((NOW + timedelta(hours=1)).timestamp()),
    }, private, algorithm="RS256", headers={"kid": "mapit-test-key", "typ": "JWT"})


class _AuthTransport:
    def __init__(self, id_token):
        self.id_token = id_token
        self.calls = []

    def __bool__(self):
        return False

    def __call__(self, url, headers, payload):
        target = headers["X-Amz-Target"]
        self.calls.append((target, payload))
        if target.endswith("InitiateAuth"):
            return {"AuthenticationResult": {"IdToken": self.id_token, "AccessToken": "a", "ExpiresIn": 3600}}
        if target.endswith("GetId"):
            return {"IdentityId": "eu-west-1:bbbbbbbb-cccc-4ddd-8eee-ffffffffffff"}
        if target.endswith("GetCredentialsForIdentity"):
            return {"Credentials": {
                "AccessKeyId": "synthetic-key", "SecretKey": "synthetic-secret",
                "SessionToken": "synthetic-session", "Expiration": NOW + timedelta(hours=1),
            }}
        raise AssertionError("unexpected auth operation")


class _Publisher:
    def __init__(self, *, fail=False, bad_receipt=False, after_publish=None):
        self.calls = []
        self.fail = fail
        self.bad_receipt = bad_receipt
        self.after_publish = after_publish

    def publish(self, **kwargs):
        self.calls.append(kwargs)
        if self.after_publish:
            self.after_publish()
        if self.fail:
            raise RuntimeError("publisher-canary")
        path = kwargs["path"] + "/wrong" if self.bad_receipt else kwargs["path"]
        return SecretPublicationReceipt(path, kwargs["version"], not self.bad_receipt)


def _make_setup(tmp_path):
    config = _config()
    mapit_private, mapit_public = _rsa_pair()
    verifier = MapitIdentityVerifier(config, {"mapit-test-key": mapit_public}, b"v" * 32, clock=lambda: NOW)
    invitation_private, invitation_public = _rsa_pair()
    del invitation_private
    policies = {
        KEY_A: CognitoDevPolicy("eu-west-1_InvitePool123", "a1b2c3d4e5", "InviteClient123", SUBJECT_A),
        KEY_B: CognitoDevPolicy("eu-west-1_InvitePool123", "a1b2c3d4e5", "InviteClient123", SUBJECT_B),
    }
    authority = InvitedTenantAuthority(policies, {"invite-key": invitation_public}, environment="dev")
    connection = sqlite3.connect(tmp_path / "tenants.sqlite3")
    tenants = SQLiteTenantStore.initialize(connection)
    for key in (KEY_A, KEY_B):
        assert tenants.cas(key, None, DurableTenantRecord(key, "active", 1))
    guard = DurableTenantGuard(authority, tenants)
    expiry = int(NOW.timestamp()) + 3600
    grant_a = AuthenticatedTenant(KEY_A, expiry, authority._proof(KEY_A, expiry))
    grant_b = AuthenticatedTenant(KEY_B, expiry, authority._proof(KEY_B, expiry))
    snapshot_a = guard.capture(grant_a)
    snapshot_b = guard.capture(grant_b)
    tokens = {
        TOKEN_A: _identity_token(mapit_private, config, SUBJECT_A),
        TOKEN_B: _identity_token(mapit_private, config, SUBJECT_B),
    }

    def factory(connection=connection, *, selected_config=config, selected_verifier=verifier,
                selected_authority=authority, selected_guard=guard, selected_auth=None):
        return SQLiteIdentityBindingRegistry.initialize(
            connection,
            authority=selected_authority,
            durable_guard=selected_guard,
            environment="dev",
            config=selected_config,
            verifier=selected_verifier,
            binding_key=b"b" * 32,
            auth_transport=selected_auth if selected_auth is not None else _AuthTransport(tokens[TOKEN_A]),
            clock=lambda: NOW,
        )

    return {
        "config": config, "verifier": verifier, "mapit_public": mapit_public,
        "authority": authority, "guard": guard, "tenants": tenants,
        "grant_a": grant_a, "grant_b": grant_b, "snapshot_a": snapshot_a,
        "snapshot_b": snapshot_b, "tokens": tokens, "factory": factory,
        "connection": connection,
    }


@pytest.fixture
def setup_binding(tmp_path):
    return _make_setup(tmp_path)


def test_enrollment_is_prepared_create_only_and_reopens_with_same_verifier_context(setup_binding, tmp_path):
    env = setup_binding
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    registry = env["factory"](selected_auth=auth)
    publisher = _Publisher()
    binding = registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)

    assert binding.environment == "dev"
    assert binding.tenant_key == KEY_A
    assert binding.secret_version == 1 and binding.revision == 3
    assert publisher.calls == [{
        "path": f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token",
        "version": 1, "refresh_token": TOKEN_A, "create_only": True,
    }]
    assert len(auth.calls) == 3
    assert registry.validate_binding(env["grant_a"], env["snapshot_a"], binding) is None

    raw = env["connection"].execute(
        "SELECT proof_envelope FROM mapit_identity_bindings_v1 WHERE tenant_key=?", (KEY_A,),
    ).fetchone()[0]
    assert TOKEN_A.encode() not in raw
    assert SUBJECT_A.encode() not in raw
    assert "<redacted>" in repr(binding)

    env["connection"].close()
    reopened_connection = sqlite3.connect(tmp_path / "tenants.sqlite3")
    reopened_tenants = SQLiteTenantStore(reopened_connection)
    reopened_guard = DurableTenantGuard(env["authority"], reopened_tenants)
    reopened_snapshot = reopened_guard.capture(env["grant_a"])
    reopened_config = _config()
    reopened_verifier = MapitIdentityVerifier(
        reopened_config, {"mapit-test-key": env["mapit_public"]}, b"v" * 32, clock=lambda: NOW,
    )
    reopened = SQLiteIdentityBindingRegistry(
        reopened_connection, authority=env["authority"], durable_guard=reopened_guard,
        environment="dev", config=reopened_config, verifier=reopened_verifier,
        binding_key=b"b" * 32, auth_transport=_AuthTransport(env["tokens"][TOKEN_A]), clock=lambda: NOW,
    )
    restored = reopened.get_binding(env["grant_a"], reopened_snapshot)
    reopened_verifier.ensure_continuity(
        reopened_verifier.verify(env["tokens"][TOKEN_A]), restored.expected_identity_proof,
    )


def test_pending_publication_failure_is_nonactive_and_never_replayed(setup_binding):
    env = setup_binding
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    registry = env["factory"](selected_auth=auth)
    publisher = _Publisher(fail=True)
    with pytest.raises(IdentityBindingError) as exc:
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert exc.value.category == "identity_binding_publication_unknown"
    assert len(publisher.calls) == 1 and len(auth.calls) == 3
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(publisher.calls) == 1 and len(auth.calls) == 3
    with pytest.raises(IdentityBindingError, match="identity_binding_not_active"):
        registry.get_binding(env["grant_a"], env["snapshot_a"])


def test_identity_cannot_be_bound_to_two_tenants_or_reenrolled_for_same_tenant(setup_binding):
    env = setup_binding
    auth_a = _AuthTransport(env["tokens"][TOKEN_A])
    registry = env["factory"](selected_auth=auth_a)
    publisher_a = _Publisher()
    registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher_a)
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher_a)
    assert len(auth_a.calls) == 3 and len(publisher_a.calls) == 1

    auth_b = _AuthTransport(env["tokens"][TOKEN_A])
    registry_b = env["factory"](selected_auth=auth_b)
    publisher_b = _Publisher()
    with pytest.raises(IdentityBindingError, match="identity_binding_identity_in_use"):
        registry_b.enroll(env["grant_b"], env["snapshot_b"], TOKEN_A, publisher=publisher_b)
    assert len(auth_b.calls) == 3 and publisher_b.calls == []
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry_b.enroll(env["grant_b"], env["snapshot_b"], TOKEN_A, publisher=publisher_b)
    assert len(auth_b.calls) == 3 and publisher_b.calls == []


def test_revoke_is_terminal_and_durable_guard_is_rechecked_after_publication(setup_binding):
    env = setup_binding
    registry = env["factory"](selected_auth=_AuthTransport(env["tokens"][TOKEN_A]))
    binding = registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=_Publisher())
    registry.revoke(env["grant_a"], env["snapshot_a"])
    with pytest.raises(IdentityBindingError, match="identity_binding_revoked"):
        registry.get_binding(env["grant_a"], env["snapshot_a"])
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=_Publisher())
    with pytest.raises(IdentityBindingError, match="identity_binding_revoked"):
        registry.validate_binding(env["grant_a"], env["snapshot_a"], binding)

    # A successful remote receipt cannot activate after durable authorization revokes.
    other_env = setup_binding
    registry2 = other_env["factory"](selected_auth=_AuthTransport(other_env["tokens"][TOKEN_B]))
    def revoke_tenant():
        assert other_env["tenants"].cas(KEY_B, 1, DurableTenantRecord(KEY_B, "revoked", 2))
    publisher = _Publisher(after_publish=revoke_tenant)
    with pytest.raises(IdentityBindingError, match="identity_binding_unauthorized"):
        registry2.enroll(other_env["grant_b"], other_env["snapshot_b"], TOKEN_B, publisher=publisher)
    assert len(publisher.calls) == 1
    row = other_env["connection"].execute(
        "SELECT status FROM mapit_identity_bindings_v1 WHERE tenant_key=?", (KEY_B,),
    ).fetchone()
    assert row == ("pending",)


def test_bad_receipt_and_auth_failure_leave_tombstone_without_retry(setup_binding):
    env = setup_binding
    auth = _AuthTransport(env["tokens"][TOKEN_A])
    registry = env["factory"](selected_auth=auth)
    publisher = _Publisher(bad_receipt=True)
    with pytest.raises(IdentityBindingError, match="identity_binding_receipt_invalid"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(publisher.calls) == 1
    with pytest.raises(IdentityBindingError, match="identity_binding_exists"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=publisher)
    assert len(publisher.calls) == 1 and len(auth.calls) == 3

    env2 = setup_binding
    bad_auth = _AuthTransport("not-a-jwt")
    registry2 = env2["factory"](selected_auth=bad_auth)
    with pytest.raises(IdentityBindingError, match="identity_binding_identity_invalid"):
        registry2.enroll(env2["grant_b"], env2["snapshot_b"], TOKEN_A, publisher=_Publisher())
    assert len(bad_auth.calls) == 1


def test_verifier_envelope_is_context_key_and_client_bound(setup_binding):
    env = setup_binding
    proof = env["verifier"].verify(env["tokens"][TOKEN_A])
    path = f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token"
    envelope = env["verifier"].export_proof(
        proof, environment="dev", tenant_key=KEY_A, secret_path=path, secret_version=1,
    )
    restored_config = _config()
    restored_verifier = MapitIdentityVerifier(
        restored_config, {"mapit-test-key": env["mapit_public"]}, b"v" * 32, clock=lambda: NOW,
    )
    restored = restored_verifier.restore_proof(
        envelope, environment="dev", tenant_key=KEY_A, secret_path=path, secret_version=1,
    )
    restored_verifier.ensure_continuity(restored_verifier.verify(env["tokens"][TOKEN_A]), restored)

    with pytest.raises(MapitIdentityError, match="identity_configuration_invalid"):
        env["verifier"].restore_proof(envelope, environment="prod", tenant_key=KEY_A,
                                       secret_path=path, secret_version=1)
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        env["verifier"].restore_proof(envelope, environment="dev", tenant_key=KEY_B,
                                       secret_path=f"/honda-mapit-mcp/dev/tenants/{KEY_B}/mapit-refresh-token",
                                       secret_version=1)
    other_config = _config(user_pool_client_id="DifferentClient123")
    other_verifier = MapitIdentityVerifier(
        other_config, {"mapit-test-key": env["mapit_public"]}, b"v" * 32, clock=lambda: NOW,
    )
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        other_verifier.restore_proof(envelope, environment="dev", tenant_key=KEY_A,
                                     secret_path=path, secret_version=1)
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        MapitIdentityVerifier(
            restored_config, {"mapit-test-key": env["mapit_public"]}, b"x" * 32, clock=lambda: NOW,
        ).restore_proof(envelope, environment="dev", tenant_key=KEY_A,
                        secret_path=path, secret_version=1)
    altered = bytearray(envelope)
    altered[-2] ^= 1
    with pytest.raises(MapitIdentityError):
        env["verifier"].restore_proof(bytes(altered), environment="dev", tenant_key=KEY_A,
                                      secret_path=path, secret_version=1)


def test_constructor_and_receipt_validation_fail_before_secret_publication(setup_binding):
    env = setup_binding
    config = env["config"]
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        SQLiteIdentityBindingRegistry(
            env["connection"], authority=env["authority"], durable_guard=env["guard"],
            environment="prod", config=config, verifier=env["verifier"], binding_key=b"b" * 32,
            auth_transport=_AuthTransport(env["tokens"][TOKEN_A]), clock=lambda: NOW,
        )
    credential_config = _config(email="private@example.invalid")
    credential_verifier = MapitIdentityVerifier(
        credential_config, {"mapit-test-key": env["mapit_public"]}, b"v" * 32,
        clock=lambda: NOW,
    )
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        SQLiteIdentityBindingRegistry(
            env["connection"], authority=env["authority"], durable_guard=env["guard"],
            environment="dev", config=credential_config, verifier=credential_verifier,
            binding_key=b"b" * 32,
            auth_transport=_AuthTransport(env["tokens"][TOKEN_A]), clock=lambda: NOW,
        )
    registry = env["factory"](selected_auth=_AuthTransport(env["tokens"][TOKEN_A]))
    with pytest.raises(IdentityBindingError, match="identity_binding_receipt_invalid"):
        registry.enroll(env["grant_a"], env["snapshot_a"], TOKEN_A, publisher=_Publisher(bad_receipt=True))


def test_registry_rejects_partial_unique_identity_index(setup_binding):
    env = setup_binding
    env["factory"](selected_auth=_AuthTransport(env["tokens"][TOKEN_A]))
    connection = env["connection"]
    connection.execute("DROP TABLE mapit_identity_bindings_v1")
    connection.execute(
        "CREATE TABLE mapit_identity_bindings_v1("
        "tenant_key TEXT PRIMARY KEY NOT NULL, environment TEXT NOT NULL, identity_tag TEXT, "
        "secret_path TEXT NOT NULL UNIQUE, secret_version INTEGER NOT NULL, status TEXT NOT NULL, "
        "revision INTEGER NOT NULL, proof_envelope BLOB, record_mac BLOB NOT NULL)"
    )
    connection.execute(
        "CREATE UNIQUE INDEX partial_identity_tag ON mapit_identity_bindings_v1(environment, identity_tag) "
        "WHERE identity_tag IS NOT NULL"
    )
    connection.commit()
    with pytest.raises(IdentityBindingError, match="identity_binding_configuration_invalid"):
        env["factory"](selected_auth=_AuthTransport(env["tokens"][TOKEN_A]))
