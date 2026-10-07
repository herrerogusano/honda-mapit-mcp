from __future__ import annotations

from datetime import datetime, timedelta, timezone
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.cloud_provider import CloudProviderError, CloudServicesProvider
from mapit.config import MapitConfig
from mapit.mapit_identity import MapitIdentityVerifier


SUBJECT_A = "00000000-0000-4000-8000-000000000001"
SUBJECT_B = "00000000-0000-4000-8000-000000000002"
REFRESH = "synthetic-refresh-token"
IDENTITY = "eu-west-1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


def _config():
    return MapitConfig(
        region="eu-west-1", user_pool_id="eu-west-1_Abcdefghi",
        user_pool_client_id="SyntheticClient123", identity_pool_id="eu-west-1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me",
        discovery_enabled=False, http_timeout=2.0,
    )


def _token(private_key, config, subject):
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "iss": f"https://cognito-idp.{config.region}.amazonaws.com/{config.user_pool_id}",
        "aud": config.user_pool_client_id,
        "sub": subject,
        "token_use": "id",
        "iat": int((now - timedelta(seconds=2)).timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
    }, private_key, algorithm="RS256", headers={"kid": "fixture-key", "typ": "JWT"})


class Reader:
    def __init__(self):
        self.calls = 0

    def read_refresh_token(self, *, deadline):
        self.calls += 1
        return type("Secret", (), {"success": True, "refresh_token": REFRESH})()


class Clock:
    def __call__(self):
        return 10.0


class AuthTransport:
    def __init__(self, initial, subsequent=()):
        self.tokens = [initial, *subsequent]
        self.initiates = 0
        self.calls = []

    def __bool__(self):
        return False

    def __call__(self, url, headers, payload):
        target = headers["X-Amz-Target"]
        self.calls.append((target, payload))
        if target.endswith("InitiateAuth"):
            token = self.tokens[min(self.initiates, len(self.tokens) - 1)]
            self.initiates += 1
            return {"AuthenticationResult": {
                "IdToken": token, "AccessToken": "synthetic-access", "ExpiresIn": 3600,
            }}
        if target.endswith("GetId"):
            return {"IdentityId": IDENTITY}
        if target.endswith("GetCredentialsForIdentity"):
            return {"Credentials": {
                "AccessKeyId": "synthetic-access-key", "SecretKey": "synthetic-secret",
                "SessionToken": "synthetic-session", "Expiration": datetime.now(timezone.utc) + timedelta(hours=1),
            }}
        raise AssertionError("unexpected Cognito operation")


class MapitTransport:
    def __bool__(self):
        return False

    def __call__(self, method, url, headers):
        return b'{"vehicles":[]}'


@pytest.fixture(scope="module")
def identity_setup():
    config = _config()
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verifier = MapitIdentityVerifier(config, {"fixture-key": public}, b"h" * 32)
    token_a = _token(private, config, SUBJECT_A)
    token_b = _token(private, config, SUBJECT_B)
    return config, private, verifier, public, token_a, token_b


def _provider(config, reader, auth, *, verifier=None, proof=None):
    return CloudServicesProvider(
        config, reader, auth, MapitTransport(), deadline=time.monotonic() + 12,
        monotonic=time.monotonic, identity_verifier=verifier,
        expected_identity_proof=proof,
    )


def test_crossed_identity_fails_before_identity_pool_exchange(identity_setup):
    config, _private, verifier, _public, token_a, token_b = identity_setup
    expected = verifier.verify(token_a)
    reader = Reader()
    auth = AuthTransport(token_b)
    provider = _provider(config, reader, auth, verifier=verifier, proof=expected)

    with pytest.raises(CloudProviderError) as exc:
        provider.get()

    assert exc.value.category == "identity_continuity_mismatch"
    assert reader.calls == 1
    assert [target.rsplit(".", 1)[-1] for target, _ in auth.calls] == ["InitiateAuth"]


def test_matching_identity_and_refresh_continuity_succeed(identity_setup):
    config, _private, verifier, _public, token_a, _token_b = identity_setup
    expected = verifier.verify(token_a)
    reader = Reader()
    auth = AuthTransport(token_a, [token_a])
    provider = _provider(config, reader, auth, verifier=verifier, proof=expected)
    provider.get()
    session = provider._services.client.session
    session.refresh_if_needed(force=True)

    assert reader.calls == 1
    assert session.identity_proof is not None
    assert len([target for target, _ in auth.calls if target.endswith("GetId")]) == 2


def test_changed_refresh_identity_fails_before_second_identity_pool_exchange(identity_setup):
    config, _private, verifier, _public, token_a, token_b = identity_setup
    expected = verifier.verify(token_a)
    reader = Reader()
    auth = AuthTransport(token_a, [token_b])
    provider = _provider(config, reader, auth, verifier=verifier, proof=expected)
    provider.get()
    session = provider._services.client.session
    original_id_token = session.id_token
    original_proof = session.identity_proof

    with pytest.raises(CloudProviderError) as exc:
        session.refresh_if_needed(force=True)

    assert exc.value.category == "identity_continuity_mismatch"
    assert session.id_token == original_id_token
    assert session.identity_proof is original_proof
    assert reader.calls == 1
    assert [target.rsplit(".", 1)[-1] for target, _ in auth.calls].count("GetId") == 1


def test_mutated_session_proof_cannot_rebind_provider_continuity(identity_setup):
    config, _private, verifier, _public, token_a, token_b = identity_setup
    reader = Reader()
    auth = AuthTransport(token_a, [token_a])
    provider = _provider(
        config, reader, auth, verifier=verifier,
        proof=verifier.verify(token_a),
    )
    provider.get()
    session = provider._services.client.session
    session.identity_proof = verifier.verify(token_b)
    calls_before_refresh = len(auth.calls)

    with pytest.raises(CloudProviderError) as exc:
        session.refresh_if_needed(force=True)

    assert exc.value.category == "identity_continuity_mismatch"
    assert len(auth.calls) == calls_before_refresh
    assert reader.calls == 1


@pytest.mark.parametrize("verifier_arg,proof_arg", [
    (None, "proof"), ("verifier", None),
])
def test_partial_opt_in_rejected_before_secret_read(identity_setup, verifier_arg, proof_arg):
    config, _private, verifier, _public, token_a, _token_b = identity_setup
    reader = Reader()
    auth = AuthTransport(token_a)
    selected_verifier = verifier if verifier_arg == "verifier" else None
    selected_proof = verifier.verify(token_a) if proof_arg == "proof" else None

    with pytest.raises(CloudProviderError) as exc:
        _provider(config, reader, auth, verifier=selected_verifier, proof=selected_proof)

    assert exc.value.category == "identity_configuration_invalid"
    assert reader.calls == 0 and auth.calls == []


def test_foreign_config_or_proof_rejected_before_secret_read(identity_setup):
    config, _private, verifier, public, token_a, _token_b = identity_setup
    proof = verifier.verify(token_a)
    reader = Reader()
    auth = AuthTransport(token_a)
    cloned_config = MapitConfig(**config.__dict__)
    with pytest.raises(CloudProviderError) as exc:
        _provider(cloned_config, reader, auth, verifier=verifier, proof=proof)
    assert exc.value.category == "identity_configuration_invalid"
    assert reader.calls == 0 and auth.calls == []

    foreign = MapitIdentityVerifier(config, {"fixture-key": public}, b"z" * 32)
    foreign_proof = foreign.verify(token_a)
    with pytest.raises(CloudProviderError) as exc:
        _provider(config, reader, auth, verifier=verifier, proof=foreign_proof)
    assert exc.value.category == "identity_proof_invalid"
    assert reader.calls == 0 and auth.calls == []
