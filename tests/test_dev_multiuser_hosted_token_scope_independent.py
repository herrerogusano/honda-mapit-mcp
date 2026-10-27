"""Independent policy checks for signed JWT scope enforcement."""

from __future__ import annotations

import base64
import json
import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import scripts.run_dev_multiuser_hosted_acceptance as hosted


POOL = "eu-west-1_A1b2C3d4E"
API = "abcdefghij"
CLIENT = "SyntheticClient123"
SUBJECT = "12345678-1234-7abc-1234-123456789abc"
REQUIRED = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp/use"


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwk(public_key, *, kid="scope-key"):
    numbers = public_key.public_numbers()
    return {
        "kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def _signed_token(private_key, policy, scope):
    now = int(time.time())
    claims = {
        "iss": policy.issuer_url, "aud": policy.audience,
        "sub": policy.owner_subject, "client_id": policy.client_id,
        "token_use": "access", "iat": now - 1, "exp": now + 300,
    }
    if scope is not None:
        claims["scope"] = scope
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": "scope-key", "typ": "JWT"})


def _real_jwks(private_key):
    return json.dumps({"keys": [_jwk(private_key.public_key())]}, separators=(",", ":")).encode("ascii")


def test_signed_token_scope_must_be_exact_required_scope(monkeypatch):
    policy = hosted.CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)

    class FakeVerifier:
        def __init__(self, _policy, _keys):
            pass

        async def verify_token(self, _token):
            return SimpleNamespace(
                subject=SUBJECT, client_id=CLIENT, resource=policy.audience,
                scopes=["other"],
            )

    monkeypatch.setattr(hosted, "parse_cognito_jwks", lambda _raw: object())
    monkeypatch.setattr(hosted, "FixedRS256TokenVerifier", FakeVerifier)
    with pytest.raises(hosted.HostedAcceptanceError) as caught:
        hosted._verify_token(
            "synthetic-signed-token", subject=SUBJECT, pool=POOL,
            api_id=API, client_id=CLIENT, jwks=b"{}",
        )
    assert caught.value.category == "token_verify_failed"


def test_signed_token_with_required_scope_is_accepted_even_when_oauth_body_scope_was_omitted(monkeypatch):
    policy = hosted.CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)

    class FakeVerifier:
        def __init__(self, _policy, _keys):
            pass

        async def verify_token(self, _token):
            return SimpleNamespace(
                subject=SUBJECT, client_id=CLIENT, resource=policy.audience,
                scopes=[policy.required_scope],
            )

    monkeypatch.setattr(hosted, "parse_cognito_jwks", lambda _raw: object())
    monkeypatch.setattr(hosted, "FixedRS256TokenVerifier", FakeVerifier)
    hosted._verify_token(
        "synthetic-signed-token", subject=SUBJECT, pool=POOL,
        api_id=API, client_id=CLIENT, jwks=b"{}",
    )


def test_invalid_signature_is_redacted_to_token_verify_failed(monkeypatch):
    class FakeVerifier:
        def __init__(self, _policy, _keys):
            pass

        async def verify_token(self, _token):
            raise ValueError("private JWT signature and token")

    monkeypatch.setattr(hosted, "parse_cognito_jwks", lambda _raw: object())
    monkeypatch.setattr(hosted, "FixedRS256TokenVerifier", FakeVerifier)
    with pytest.raises(hosted.HostedAcceptanceError) as caught:
        hosted._verify_token(
            "synthetic-token", subject=SUBJECT, pool=POOL,
            api_id=API, client_id=CLIENT, jwks=b"{}",
        )
    assert caught.value.category == "token_verify_failed"
    assert "private JWT" not in repr(caught.value)


@pytest.mark.parametrize("scope", [None, "other"])
def test_real_signed_jwt_missing_or_wrong_scope_is_rejected(scope):
    policy = hosted.CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _signed_token(private_key, policy, scope)
    with pytest.raises(hosted.HostedAcceptanceError) as caught:
        hosted._verify_token(
            token, subject=SUBJECT, pool=POOL, api_id=API, client_id=CLIENT,
            jwks=_real_jwks(private_key),
        )
    assert caught.value.category == "token_verify_failed"


def test_real_signed_jwt_with_required_scope_is_accepted():
    policy = hosted.CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    hosted._verify_token(
        _signed_token(private_key, policy, policy.required_scope),
        subject=SUBJECT, pool=POOL, api_id=API, client_id=CLIENT,
        jwks=_real_jwks(private_key),
    )


def test_real_foreign_signature_is_rejected_without_leaking_token():
    policy = hosted.CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)
    trusted_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _signed_token(foreign_key, policy, policy.required_scope)
    with pytest.raises(hosted.HostedAcceptanceError) as caught:
        hosted._verify_token(
            token, subject=SUBJECT, pool=POOL, api_id=API, client_id=CLIENT,
            jwks=_real_jwks(trusted_key),
        )
    assert caught.value.category == "token_verify_failed"
    assert token not in repr(caught.value)


@pytest.mark.parametrize("scopes", ([], ["other"], None))
def test_signed_token_missing_or_wrong_scope_is_fail_closed(monkeypatch, scopes):
    policy = hosted.CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)

    class FakeVerifier:
        def __init__(self, _policy, _keys):
            pass

        async def verify_token(self, _token):
            return SimpleNamespace(
                subject=SUBJECT, client_id=CLIENT, resource=policy.audience,
                scopes=scopes,
            )

    monkeypatch.setattr(hosted, "parse_cognito_jwks", lambda _raw: object())
    monkeypatch.setattr(hosted, "FixedRS256TokenVerifier", FakeVerifier)
    with pytest.raises(hosted.HostedAcceptanceError) as caught:
        hosted._verify_token(
            "synthetic-signed-token", subject=SUBJECT, pool=POOL,
            api_id=API, client_id=CLIENT, jwks=b"{}",
        )
    assert caught.value.category == "token_verify_failed"
