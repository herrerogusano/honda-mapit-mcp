"""Cognito User Pool and Identity Pool session handling."""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping

from .config import MapitConfig


JsonTransport = Callable[[str, Mapping[str, str], Mapping[str, Any]], Mapping[str, Any]]


def _utc(value: datetime | None = None) -> datetime:
    value = value or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)


def jwt_expiration(token: str, *, now: datetime | None = None, fallback_seconds: int | None = None) -> datetime:
    """Read a JWT ``exp`` claim without verifying it; verification is Cognito's job."""
    try:
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        exp = float(payload["exp"])
        return datetime.fromtimestamp(exp, timezone.utc)
    except (ValueError, IndexError, KeyError, TypeError, json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error):
        if fallback_seconds is None:
            raise ValueError("token has no usable expiration")
        return _utc(now) + timedelta(seconds=fallback_seconds)


class UnsupportedCognitoChallenge(RuntimeError):
    """Authentication needs an interactive/unsupported Cognito challenge."""

    def __init__(self, challenge_name: str) -> None:
        self.challenge_name = str(challenge_name)
        super().__init__(f"unsupported Cognito challenge: {self.challenge_name}")


class SessionRefreshError(RuntimeError):
    """A session needed refresh but no safe refresh callback was available."""


class CognitoHTTPError(RuntimeError):
    """A Cognito endpoint returned an HTTP error without exposing its body."""

    def __init__(self, status: int) -> None:
        self.status = int(status)
        super().__init__(f"Cognito request failed with HTTP {self.status}")


@dataclass
class TemporaryCredentials:
    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expiration: datetime

    def is_expired(self, *, now: datetime | None = None, skew_seconds: int = 60) -> bool:
        return _utc(now) + timedelta(seconds=skew_seconds) >= _utc(self.expiration)


@dataclass
class MapitSession:
    id_token: str = field(repr=False)
    access_token: str | None = field(repr=False)
    refresh_token: str | None = field(repr=False)
    token_expiration: datetime
    credentials: TemporaryCredentials = field(repr=False)
    _refresh_callback: Callable[["MapitSession"], None] | None = field(default=None, repr=False)

    def needs_refresh(self, *, now: datetime | None = None, skew_seconds: int = 60) -> bool:
        current = _utc(now) + timedelta(seconds=skew_seconds)
        return current >= _utc(self.token_expiration) or self.credentials.is_expired(now=now, skew_seconds=skew_seconds)

    def refresh_if_needed(self, *, force: bool = False, now: datetime | None = None, skew_seconds: int = 60) -> None:
        if not (force or self.needs_refresh(now=now, skew_seconds=skew_seconds)):
            return
        if self._refresh_callback is None:
            raise SessionRefreshError("session refresh is required but unavailable")
        self._refresh_callback(self)


class CognitoAuthenticator:
    """Synchronous Cognito flow with injectable transport for offline tests."""

    def __init__(
        self,
        config: MapitConfig,
        *,
        transport: JsonTransport | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.config = config
        self._transport = transport or self._default_transport
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def user_pool_endpoint(self) -> str:
        return f"https://cognito-idp.{self.config.region}.amazonaws.com/"

    @property
    def identity_endpoint(self) -> str:
        return f"https://cognito-identity.{self.config.region}.amazonaws.com/"

    def authenticate(self) -> MapitSession:
        """Perform USER_PASSWORD_AUTH using only MAPIT_EMAIL/MAPIT_PASSWORD."""
        email = self.config.email or os.environ.get("MAPIT_EMAIL")
        password = self.config.password or os.environ.get("MAPIT_PASSWORD")
        if not email or not password:
            raise ValueError("MAPIT_EMAIL and MAPIT_PASSWORD are required")
        self._require_pool_config()
        response = self._call_user_pool("InitiateAuth", {
            "AuthFlow": "USER_PASSWORD_AUTH",
            "ClientId": self.config.user_pool_client_id,
            "AuthParameters": {"USERNAME": email, "PASSWORD": password},
            "ClientMetadata": {},
        })
        self._raise_if_challenge(response)
        return self._session_from_auth(response.get("AuthenticationResult", {}), refresh_token_required=True)

    login = authenticate

    def authenticate_with_refresh_token(self, refresh_token: str) -> MapitSession:
        """Resume with REFRESH_TOKEN_AUTH, then exchange the new IdToken."""
        if not refresh_token:
            raise ValueError("refresh token is required")
        self._require_pool_config()
        response = self._call_user_pool("InitiateAuth", {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": self.config.user_pool_client_id,
            "AuthParameters": {"REFRESH_TOKEN": refresh_token},
            "ClientMetadata": {},
        })
        self._raise_if_challenge(response)
        return self._session_from_auth(response.get("AuthenticationResult", {}), refresh_token_required=False, prior_refresh_token=refresh_token)

    def refresh_session(self, session: MapitSession) -> None:
        if not session.refresh_token:
            raise ValueError("session has no refresh token")
        updated = self.authenticate_with_refresh_token(session.refresh_token)
        session.id_token = updated.id_token
        session.access_token = updated.access_token
        session.refresh_token = updated.refresh_token
        session.token_expiration = updated.token_expiration
        session.credentials = updated.credentials

    def _session_from_auth(self, result: Mapping[str, Any], *, refresh_token_required: bool, prior_refresh_token: str | None = None) -> MapitSession:
        id_token = result.get("IdToken")
        if not id_token:
            raise ValueError("Cognito response did not contain IdToken")
        token_expiration = jwt_expiration(id_token, now=self._clock(), fallback_seconds=int(result.get("ExpiresIn", 3600)))
        refresh_token = result.get("RefreshToken") or prior_refresh_token
        if refresh_token_required and not refresh_token:
            raise ValueError("Cognito response did not contain RefreshToken")
        identity_id = self._get_identity_id(id_token)
        credentials = self._get_credentials(identity_id, id_token)
        return MapitSession(id_token, result.get("AccessToken"), refresh_token, token_expiration, credentials, self.refresh_session)

    def _require_pool_config(self) -> None:
        missing = [name for name, value in (("MAPIT_USER_POOL_ID", self.config.user_pool_id), ("MAPIT_USER_POOL_CLIENT_ID", self.config.user_pool_client_id), ("MAPIT_IDENTITY_POOL_ID", self.config.identity_pool_id)) if not value]
        if missing:
            raise ValueError("missing Cognito configuration: " + ", ".join(missing))

    @staticmethod
    def _raise_if_challenge(response: Mapping[str, Any]) -> None:
        challenge = response.get("ChallengeName")
        if challenge:
            raise UnsupportedCognitoChallenge(str(challenge))

    def _call_user_pool(self, target: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._transport(self.user_pool_endpoint, {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}",
        }, payload)

    def _get_identity_id(self, id_token: str) -> str:
        response = self._transport(self.identity_endpoint, {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetId",
        }, {
            "IdentityPoolId": self.config.identity_pool_id,
            "Logins": {f"cognito-idp.{self.config.region}.amazonaws.com/{self.config.user_pool_id}": id_token},
        })
        identity_id = response.get("IdentityId")
        if not identity_id:
            raise ValueError("Cognito GetId response did not contain IdentityId")
        return str(identity_id)

    def _get_credentials(self, identity_id: str, id_token: str) -> TemporaryCredentials:
        response = self._transport(self.identity_endpoint, {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
        }, {
            "IdentityId": identity_id,
            "Logins": {f"cognito-idp.{self.config.region}.amazonaws.com/{self.config.user_pool_id}": id_token},
        })
        raw = response.get("Credentials", {})
        expiration = raw.get("Expiration")
        if isinstance(expiration, str):
            expiration = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
        elif isinstance(expiration, (int, float)):
            expiration = datetime.fromtimestamp(expiration, timezone.utc)
        if not all(raw.get(key) for key in ("AccessKeyId", "SecretKey", "SessionToken")) or not isinstance(expiration, datetime):
            raise ValueError("Cognito response did not contain complete temporary credentials")
        return TemporaryCredentials(raw["AccessKeyId"], raw["SecretKey"], raw["SessionToken"], _utc(expiration))

    def _default_transport(self, url: str, headers: Mapping[str, str], payload: Mapping[str, Any]) -> Mapping[str, Any]:
        request = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=dict(headers), method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.config.http_timeout) as response:  # noqa: S310 - endpoint is fixed by region.
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise CognitoHTTPError(exc.code) from None
