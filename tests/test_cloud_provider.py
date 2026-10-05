import base64
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import pytest

from mapit.cloud_provider import CloudProviderError, CloudServicesProvider
from mapit.config import MapitConfig
from mapit.services import MapitServices, ServiceError

ACCOUNT = "123456789012"
POOL = "eu-west-1_Abcdefghi"
CLIENT = "SyntheticClient123"
IDENTITY_POOL = "eu-west-1:12345678-1234-4234-8234-123456789abc"
REFRESH = "synthetic-refresh-token"
IDENTITY = "eu-west-1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
_PROVIDER_LOGIN = f"cognito-idp.eu-west-1.amazonaws.com/{POOL}"


def _config(**changes):
    values = {
        "region": "eu-west-1",
        "user_pool_id": POOL,
        "user_pool_client_id": CLIENT,
        "identity_pool_id": IDENTITY_POOL,
        "core_api_url": "https://core.prod.mapit.me",
        "geo_api_url": "https://geo.prod.mapit.me",
        "discovery_enabled": False,
        "http_timeout": 2.0,
    }
    values.update(changes)
    return MapitConfig(**values)


@dataclass
class SecretResult:
    success: bool
    refresh_token: str = field(repr=False)


class FakeReader:
    def __init__(self, token=REFRESH, *, error=None, on_read=None):
        self.token = token
        self.error = error
        self.on_read = on_read
        self.calls = []

    def read_refresh_token(self, *, deadline):
        self.calls.append(deadline)
        if self.on_read:
            self.on_read()
        if self.error:
            raise self.error
        return SecretResult(True, self.token)


class Clock:
    def __init__(self, value=10.0):
        self.value = value

    def __call__(self):
        return self.value


def _jwt(expiration):
    payload = base64.urlsafe_b64encode(json.dumps({"exp": expiration}).encode()).decode().rstrip("=")
    return f"synthetic.{payload}.signature"


class FakeAuthTransport:
    def __init__(self, *, rotate_on_call=None, expire_initial=False, error=None):
        self.calls = []
        self.rotate_on_call = rotate_on_call
        self.expire_initial = expire_initial
        self.error = error

    def __bool__(self):
        return False

    def __call__(self, url, headers, payload):
        self.calls.append((url, dict(headers), payload))
        if self.error:
            raise self.error
        target = headers["X-Amz-Target"]
        if target == "AWSCognitoIdentityProviderService.InitiateAuth":
            if self.rotate_on_call == len(self.calls):
                new_refresh = "rotated-refresh-token"
            elif self.rotate_on_call == -1 and len(self.calls) == 1:
                new_refresh = "rotated-refresh-token"
            else:
                new_refresh = None
            expiration = int(time.time()) + (5 if self.expire_initial and len(self.calls) == 1 else 3600)
            result = {"IdToken": _jwt(expiration), "AccessToken": "synthetic.access.token", "ExpiresIn": 3600}
            if new_refresh:
                result["RefreshToken"] = new_refresh
            return {"AuthenticationResult": result}
        if target == "AWSCognitoIdentityService.GetId":
            return {"IdentityId": IDENTITY}
        if target == "AWSCognitoIdentityService.GetCredentialsForIdentity":
            expiration = datetime.now(timezone.utc) + timedelta(hours=1)
            return {"Credentials": {
                "AccessKeyId": "synthetic-access-key",
                "SecretKey": "synthetic-secret-key",
                "SessionToken": "synthetic-session-token",
                "Expiration": expiration,
            }}
        raise AssertionError("unexpected Cognito target")


class FakeMapitTransport:
    def __init__(self, response=None):
        self.response = response or b'{"vehicles":[{"id":"synthetic-vehicle","device":{"state":{"status":"synthetic"}}}]}'
        self.calls = []

    def __bool__(self):
        return False

    def __call__(self, method, url, headers):
        self.calls.append((method, url, headers))
        return self.response


def _provider(*, config=None, reader=None, auth=None, mapit=None, clock=None, deadline=20):
    clock = clock or Clock()
    reader = FakeReader() if reader is None else reader
    auth = FakeAuthTransport() if auth is None else auth
    mapit = FakeMapitTransport() if mapit is None else mapit
    provider = CloudServicesProvider(
        config or _config(),
        reader,
        auth,
        mapit,
        deadline=deadline,
        monotonic=clock,
    )
    return provider, reader, auth, mapit, clock


def test_construction_is_lazy_and_get_caches_only_inside_provider_instance():
    provider, reader, auth, mapit, _clock = _provider()
    assert reader.calls == [] and auth.calls == [] and mapit.calls == []
    assert "refresh" not in repr(provider)
    services = provider.get()
    assert isinstance(services, MapitServices)
    assert provider.get() is services
    assert reader.calls == [20]
    assert len(auth.calls) == 3
    assert mapit.calls == []
    status = services.get_vehicle_status()
    assert status.status == "synthetic"
    assert len(mapit.calls) == 1
    assert mapit.calls[0][0] == "GET"


@pytest.mark.parametrize("config", [
    _config(region="us-east-1"),
    _config(core_api_url="https://core.staging.mapit.me"),
    _config(geo_api_url="https://geo.staging.mapit.me"),
    _config(discovery_enabled=True),
    _config(email="person@example.invalid"),
    _config(password="password-canary"),
    _config(http_timeout=2.01),
    _config(http_timeout=float("nan")),
    _config(user_pool_id="bad-pool"),
    _config(user_pool_client_id="bad client"),
    _config(identity_pool_id="bad-identity"),
])
def test_unpinned_config_is_rejected_without_read_or_auth(config):
    reader, auth = FakeReader(), FakeAuthTransport()
    with pytest.raises(CloudProviderError) as exc:
        CloudServicesProvider(config, reader, auth, FakeMapitTransport(), deadline=20, monotonic=Clock())
    assert exc.value.category == "configuration_invalid"
    assert reader.calls == [] and auth.calls == []


def test_reader_failure_is_generic_and_provider_cannot_retry_secret_read():
    reader = FakeReader(error=RuntimeError("secret-canary-reader-error"))
    provider, _, auth, _mapit, _clock = _provider(reader=reader)
    for _ in range(2):
        with pytest.raises(CloudProviderError) as exc:
            provider.get()
        assert exc.value.category in {"secret_read_failed", "provider_already_used"}
        assert "canary" not in str(exc.value)
    assert len(reader.calls) == 1
    assert auth.calls == []


def test_authentication_is_refresh_token_only_and_changed_initial_token_is_rejected():
    auth = FakeAuthTransport(rotate_on_call=-1)
    provider, reader, _auth, mapit, _clock = _provider(auth=auth)
    with pytest.raises(CloudProviderError) as exc:
        provider.get()
    assert exc.value.category == "refresh_token_changed"
    assert len(reader.calls) == 1
    assert [call[2].get("AuthFlow") for call in auth.calls if "AuthFlow" in call[2]] == ["REFRESH_TOKEN_AUTH"]
    assert not mapit.calls


def test_auth_transport_errors_do_not_surface_provider_text():
    auth = FakeAuthTransport(error=RuntimeError("refresh-token-private-canary"))
    provider, _reader, _auth, _mapit, _clock = _provider(auth=auth)
    with pytest.raises(CloudProviderError) as exc:
        provider.get()
    assert exc.value.category == "auth_failed"
    assert "private-canary" not in str(exc.value)


def test_refresh_callback_reuses_token_and_rejects_rotation_without_mapit_get():
    auth = FakeAuthTransport(expire_initial=True, rotate_on_call=4)
    mapit = FakeMapitTransport()
    provider, reader, _auth, _mapit, _clock = _provider(auth=auth, mapit=mapit)
    services = provider.get()
    with pytest.raises(CloudProviderError) as exc:
        services.client.get_core("/v1/account-summary")
    assert exc.value.category == "refresh_token_changed"
    assert len(reader.calls) == 1
    assert len(auth.calls) == 6
    assert mapit.calls == []


def test_deadline_after_secret_read_prevents_cognito_calls():
    clock = Clock()
    reader = FakeReader(on_read=lambda: setattr(clock, "value", 20.0))
    auth = FakeAuthTransport()
    provider, _reader, _auth, _mapit, _clock = _provider(reader=reader, auth=auth, clock=clock, deadline=19.0)
    with pytest.raises(CloudProviderError) as exc:
        provider.get()
    assert exc.value.category == "deadline_expired"
    assert len(reader.calls) == 1 and auth.calls == []


def test_clock_rollback_prevents_service_cache_reuse():
    clock = Clock()
    provider, _reader, _auth, _mapit, _clock = _provider(clock=clock)
    services = provider.get()
    clock.value = 9
    with pytest.raises(CloudProviderError) as exc:
        provider.get()
    assert exc.value.category == "clock_rollback"
    assert isinstance(services, MapitServices)
