from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from mapit.auth import CognitoAuthenticator, MapitSession, TemporaryCredentials
from mapit.config import MapitConfig
from mapit.mapit_identity import MapitIdentityError, MapitIdentityVerifier

NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)
SUBJECT_A = "00000000-0000-4000-8000-000000000001"
SUBJECT_B = "00000000-0000-4000-8000-000000000002"


@pytest.fixture(scope="module")
def rsa_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return private, {"mapit-kid": public}


@pytest.fixture
def config():
    return MapitConfig(region="eu-west-1", user_pool_id="eu-west-1_TEST", user_pool_client_id="client-test", identity_pool_id="eu-west-1:identity-test")


def identity_token(private, config, *, subject=SUBJECT_A, kid="mapit-kid", **overrides):
    claims = {
        "iss": f"https://cognito-idp.{config.region}.amazonaws.com/{config.user_pool_id}",
        "aud": config.user_pool_client_id, "sub": subject, "token_use": "id",
        "iat": int((NOW - timedelta(minutes=1)).timestamp()),
        "exp": int((NOW + timedelta(hours=1)).timestamp()),
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def verifier(config, rsa_material):
    private, public = rsa_material
    return private, MapitIdentityVerifier(config, public, b"h" * 32, clock=lambda: NOW)


def _raw_signed(private, header: bytes, payload: bytes) -> str:
    encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
    signing_input = (encode(header) + "." + encode(payload)).encode("ascii")
    signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return signing_input.decode("ascii") + "." + encode(signature)


def test_id_token_verifies_and_proof_redacts_subject_and_material(config, rsa_material):
    private, checked = verifier(config, rsa_material)
    raw = identity_token(private, config)
    proof = checked.verify(raw)
    checked.validate_proof(proof)
    rendered = repr(proof)
    assert SUBJECT_A not in rendered and raw not in rendered
    assert proof.issuer == "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_TEST"
    assert len(proof.subject_digest) == 32


@pytest.mark.parametrize("changes", [
    {"iss": "https://cognito-idp.eu-west-1.amazonaws.com/other"},
    {"aud": "other-client"}, {"token_use": "access"},
    {"exp": int((NOW - timedelta(seconds=1)).timestamp())},
    {"iat": int((NOW + timedelta(minutes=1)).timestamp())},
    {"nbf": int((NOW + timedelta(minutes=1)).timestamp())},
])
def test_id_token_claim_mismatch_fails_closed(config, rsa_material, changes):
    private, checked = verifier(config, rsa_material)
    with pytest.raises(MapitIdentityError, match="identity_token_invalid"):
        checked.verify(identity_token(private, config, **changes))


def test_unknown_kid_missing_claim_and_oversized_claims_are_rejected(config, rsa_material):
    private, checked = verifier(config, rsa_material)
    with pytest.raises(MapitIdentityError):
        checked.verify(identity_token(private, config, kid="unknown"))
    with pytest.raises(MapitIdentityError):
        checked.verify(identity_token(private, config, exp=None))
    with pytest.raises(MapitIdentityError):
        checked.verify(identity_token(private, config, extra="x" * 7000))


@pytest.mark.parametrize("header,payload", [
    (b'{"alg":"RS256","kid":"mapit-kid","kid":"other","typ":"JWT"}', None),
    (None, b'{"iss":"x","iss":"y"}'),
])
def test_duplicate_signed_json_members_fail_before_claim_trust(config, rsa_material, header, payload):
    private, checked = verifier(config, rsa_material)
    valid = identity_token(private, config)
    valid_header, valid_payload, _signature = valid.split(".")
    header = header or base64.urlsafe_b64decode(valid_header + "=" * (-len(valid_header) % 4))
    payload = payload or base64.urlsafe_b64decode(valid_payload + "=" * (-len(valid_payload) % 4))
    with pytest.raises(MapitIdentityError, match="identity_token_invalid"):
        checked.verify(_raw_signed(private, header, payload))


@pytest.mark.parametrize("kwargs", [
    {"region": "eu-west-1/evil"},
    {"user_pool_id": "us-east-1_TEST"},
    {"user_pool_id": "eu-west-1_TEST/evil"},
    {"user_pool_client_id": "client/test"},
])
def test_identity_configuration_is_fixed_and_bounded(config, rsa_material, kwargs):
    selected = MapitConfig(**{**config.__dict__, **kwargs})
    with pytest.raises(MapitIdentityError, match="identity_configuration_invalid"):
        MapitIdentityVerifier(selected, rsa_material[1], b"h" * 32)


def test_proof_continuity_rejects_swapped_subject_and_foreign_verifier(config, rsa_material):
    private, checked = verifier(config, rsa_material)
    first = checked.verify(identity_token(private, config, subject=SUBJECT_A))
    second = checked.verify(identity_token(private, config, subject=SUBJECT_B))
    with pytest.raises(MapitIdentityError, match="identity_continuity_mismatch"):
        checked.ensure_continuity(first, second)
    foreign = MapitIdentityVerifier(config, rsa_material[1], b"x" * 32, clock=lambda: NOW)
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        foreign.validate_proof(first)


def _auth_transport(config, id_token, refreshed=None, calls=None):
    calls = calls if calls is not None else []
    initiate_count = [0]

    def transport(url, headers, payload):
        calls.append((headers["X-Amz-Target"], payload))
        target = headers["X-Amz-Target"]
        if target.endswith("InitiateAuth"):
            initiate_count[0] += 1
            selected = refreshed if refreshed is not None and initiate_count[0] > 1 else id_token
            return {"AuthenticationResult": {"IdToken": selected, "AccessToken": "access", "RefreshToken": "refresh", "ExpiresIn": 3600}}
        if target.endswith("GetId"):
            return {"IdentityId": "eu-west-1:identity-test"}
        return {"Credentials": {"AccessKeyId": "AKIA_TEST", "SecretKey": "secret-test", "SessionToken": "session-test", "Expiration": (NOW + timedelta(hours=1)).isoformat()}}

    return transport, calls


def test_auth_optin_verifies_before_identity_pool_calls(config, rsa_material):
    private, checked = verifier(config, rsa_material)
    valid = identity_token(private, config)
    calls = []
    transport, _ = _auth_transport(config, valid, calls=calls)
    auth = CognitoAuthenticator(config, transport=transport, clock=lambda: NOW, identity_verifier=checked)
    session = auth.authenticate_with_refresh_token("refresh")
    assert session.identity_proof is not None
    assert [target for target, _ in calls] == ["AWSCognitoIdentityProviderService.InitiateAuth", "AWSCognitoIdentityService.GetId", "AWSCognitoIdentityService.GetCredentialsForIdentity"]

    bad_calls = []
    bad, _ = _auth_transport(config, identity_token(private, config, aud="wrong"), calls=bad_calls)
    bad_auth = CognitoAuthenticator(config, transport=bad, clock=lambda: NOW, identity_verifier=checked)
    with pytest.raises(MapitIdentityError):
        bad_auth.authenticate_with_refresh_token("refresh")
    assert len(bad_calls) == 1


def test_refresh_requires_bound_proof_and_rejects_changed_identity_before_pool(config, rsa_material):
    private, checked = verifier(config, rsa_material)
    initial = identity_token(private, config, subject=SUBJECT_A)
    changed = identity_token(private, config, subject=SUBJECT_B)
    calls = []
    transport, _ = _auth_transport(config, initial, refreshed=changed, calls=calls)
    auth = CognitoAuthenticator(config, transport=transport, clock=lambda: NOW, identity_verifier=checked)
    current = auth.authenticate_with_refresh_token("refresh")
    calls.clear()
    with pytest.raises(MapitIdentityError, match="identity_continuity_mismatch"):
        auth.refresh_session(current)
    assert [target for target, _ in calls] == ["AWSCognitoIdentityProviderService.InitiateAuth"]

    calls.clear()
    unverified = MapitSession("id", "access", "refresh", NOW, TemporaryCredentials("a", "b", "c", NOW))
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        auth.refresh_session(unverified)
    assert calls == []


def test_foreign_expected_proof_is_rejected_before_initiate_auth(config, rsa_material):
    private, checked = verifier(config, rsa_material)
    foreign = MapitIdentityVerifier(config, rsa_material[1], b"z" * 32, clock=lambda: NOW)
    proof = foreign.verify(identity_token(private, config))
    calls = []
    transport, _ = _auth_transport(config, identity_token(private, config), calls=calls)
    auth = CognitoAuthenticator(config, transport=transport, clock=lambda: NOW, identity_verifier=checked)
    with pytest.raises(MapitIdentityError, match="identity_proof_invalid"):
        auth.authenticate_with_refresh_token("refresh", proof)
    assert calls == []
