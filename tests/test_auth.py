import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from mapit.auth import CognitoAuthenticator, MapitSession, TemporaryCredentials, UnsupportedCognitoChallenge, jwt_expiration
from mapit.config import MapitConfig


def token(exp: int) -> str:
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"{header}.{payload}.signature"


def test_jwt_expiration_uses_exp_and_fallback():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert jwt_expiration(token(int(now.timestamp()) + 120), now=now) == now + timedelta(seconds=120)
    assert jwt_expiration("not-a-jwt", now=now, fallback_seconds=30) == now + timedelta(seconds=30)


def test_temporary_credentials_refresh_before_expiry():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    creds = TemporaryCredentials("AKIA_TEST", "secret-test", "session-test", now + timedelta(seconds=30))
    assert creds.is_expired(now=now, skew_seconds=60)


def test_session_and_credentials_repr_do_not_expose_secrets():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    creds = TemporaryCredentials("access-key-test", "secret-key-test", "session-token-test", now)
    current = MapitSession("id-token-test", "access-token-test", "refresh-token-test", now, creds)
    rendered = repr(current) + repr(creds)
    for secret in ("id-token-test", "access-token-test", "refresh-token-test", "access-key-test", "secret-key-test", "session-token-test"):
        assert secret not in rendered


def test_cognito_flow_and_refresh_are_injectable():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    calls = []
    initial = token(int((now + timedelta(hours=1)).timestamp()))
    renewed = token(int((now + timedelta(hours=2)).timestamp()))

    def transport(url, headers, payload):
        calls.append((url, headers, payload))
        target = headers["X-Amz-Target"]
        if target.endswith("InitiateAuth"):
            if payload["AuthFlow"] == "USER_PASSWORD_AUTH":
                return {"AuthenticationResult": {"IdToken": initial, "AccessToken": "access", "RefreshToken": "refresh", "ExpiresIn": 3600}}
            return {"AuthenticationResult": {"IdToken": renewed, "AccessToken": "access-new", "RefreshToken": "rotated-refresh", "ExpiresIn": 3600}}
        if target.endswith("GetId"):
            return {"IdentityId": "eu-west-1:identity-test"}
        return {"Credentials": {"AccessKeyId": "AKIA_TEST", "SecretKey": "secret-test", "SessionToken": "session-test", "Expiration": (now + timedelta(hours=1)).isoformat()}}

    config = MapitConfig(region="eu-west-1", user_pool_id="eu-west-1_TEST", user_pool_client_id="client-test", identity_pool_id="eu-west-1:identity-test", email="user@example.test", password="password-test")
    auth = CognitoAuthenticator(config, transport=transport, clock=lambda: now)
    session = auth.authenticate()
    assert session.id_token == initial
    session.refresh_if_needed(force=True)
    assert session.id_token == renewed
    assert session.refresh_token == "rotated-refresh"
    assert len(calls) == 6


def test_cognito_challenge_fails_closed_without_identity_exchange():
    calls = []

    def transport(url, headers, payload):
        calls.append((url, headers, payload))
        return {"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": "challenge-session"}

    config = MapitConfig(
        region="eu-west-1",
        user_pool_id="eu-west-1_TEST",
        user_pool_client_id="client-test",
        identity_pool_id="eu-west-1:identity-test",
        email="user@example.test",
        password="password-test",
    )
    auth = CognitoAuthenticator(config, transport=transport)
    with pytest.raises(UnsupportedCognitoChallenge) as exc_info:
        auth.authenticate()
    assert exc_info.value.challenge_name == "NEW_PASSWORD_REQUIRED"
    assert "challenge-session" not in repr(exc_info.value)
    assert len(calls) == 1


def test_authenticate_with_refresh_token_preserves_token_when_not_rotated():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    refreshed = token(int((now + timedelta(hours=1)).timestamp()))
    calls = []

    def transport(url, headers, payload):
        calls.append((url, headers, payload))
        target = headers["X-Amz-Target"]
        if target.endswith("InitiateAuth"):
            return {"AuthenticationResult": {"IdToken": refreshed, "AccessToken": "access-new", "ExpiresIn": 3600}}
        if target.endswith("GetId"):
            return {"IdentityId": "eu-west-1:identity-test"}
        return {"Credentials": {"AccessKeyId": "AKIA_TEST", "SecretKey": "secret-test", "SessionToken": "session-test", "Expiration": (now + timedelta(hours=1)).isoformat()}}

    config = MapitConfig(region="eu-west-1", user_pool_id="eu-west-1_TEST", user_pool_client_id="client-test", identity_pool_id="eu-west-1:identity-test")
    auth = CognitoAuthenticator(config, transport=transport, clock=lambda: now)
    session = auth.authenticate_with_refresh_token("refresh-old")
    assert session.refresh_token == "refresh-old"
    assert calls[0][2]["AuthFlow"] == "REFRESH_TOKEN_AUTH"


def test_expired_session_without_refresh_callback_fails_closed():
    now = datetime.now(timezone.utc)
    current = MapitSession(
        "id-token-test", "access-test", None, now - timedelta(seconds=1),
        TemporaryCredentials("access-key-test", "secret-key-test", "session-token-test", now - timedelta(seconds=1)),
    )
    with pytest.raises(RuntimeError, match="refresh"):
        current.refresh_if_needed(now=now)
