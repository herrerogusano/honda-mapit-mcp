import json
import io
import traceback

import pytest

from mapit.auth import CognitoHTTPError
from mapit.client import MapitHTTPError, MapitResponseTooLarge
from mapit.cloud_transport import CloudDirectTransport, CloudTransportError
from mapit.config import MapitConfig

ACCOUNT = "123456789012"
POOL = "eu-west-1_Abcdefghi"
CLIENT = "SyntheticClient123"
IDENTITY_POOL = "eu-west-1:12345678-1234-4234-8234-123456789abc"
META = {"ResponseMetadata": {"HTTPStatusCode": 200}}


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


class Clock:
    def __init__(self, value=10.0):
        self.value = value

    def __call__(self):
        return self.value


class FakeResponse:
    def __init__(self, body=b"{}", status=200, chunks=None):
        self.status = status
        self.body = body
        self.chunks = chunks
        self.closed = False
        self.read_requests = []

    def read1(self, size):
        self.read_requests.append(size)
        if self.chunks is not None:
            return self.chunks.pop(0)
        result, self.body = self.body[:size], self.body[size:]
        return result

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        result = self.results.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def _transport(opener=None, *, clock=None, timeout=2.0, deadline=20.0):
    clock = clock or Clock()
    return CloudDirectTransport(_config(http_timeout=timeout), deadline=deadline, opener=opener, monotonic=clock)


def _pool_request(refresh="synthetic-refresh"):
    return (
        "https://cognito-idp.eu-west-1.amazonaws.com/",
        {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
        },
        {
            "AuthFlow": "REFRESH_TOKEN_AUTH",
            "ClientId": CLIENT,
            "AuthParameters": {"REFRESH_TOKEN": refresh},
            "ClientMetadata": {},
        },
    )


def _identity_request(target, payload):
    return (
        "https://cognito-identity.eu-west-1.amazonaws.com/",
        {
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityService.{target}",
        },
        payload,
    )


def test_cognito_refresh_post_is_exact_direct_and_bounded():
    raw = b'{"AuthenticationResult":{"IdToken":"synthetic"}}'
    response = FakeResponse(raw)
    opener = FakeOpener(response)
    transport = _transport(opener, clock=Clock(10), deadline=11)
    url, headers, payload = _pool_request()
    result = transport.cognito_json(url, headers, payload)
    assert result == {"AuthenticationResult": {"IdToken": "synthetic"}}
    request, timeout = opener.calls[0]
    assert request.get_method() == "POST"
    assert request.full_url == url
    assert timeout == 1.0
    assert request.data == json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode()
    assert response.closed is True
    assert transport.attempts == 1


@pytest.mark.parametrize(
    "url,headers,payload",
    [
        ("https://evil.example/", _pool_request()[1], _pool_request()[2]),
        (_pool_request()[0], _pool_request()[1], {**_pool_request()[2], "AuthFlow": "USER_PASSWORD_AUTH"}),
        (_pool_request()[0], _pool_request()[1], {**_pool_request()[2], "ClientMetadata": {"x": "y"}}),
        (_pool_request()[0], {**_pool_request()[1], "X-Amz-Target": "wrong"}, _pool_request()[2]),
        (_pool_request()[0], _pool_request()[1], {**_pool_request()[2], "Password": "canary"}),
        ("https://cognito-idp.eu-west-1.amazonaws.com/?q=1", _pool_request()[1], _pool_request()[2]),
    ],
)
def test_cognito_unapproved_endpoint_target_or_payload_fails_before_open(url, headers, payload):
    opener = FakeOpener(FakeResponse())
    transport = _transport(opener)
    with pytest.raises(CloudTransportError) as exc:
        transport.cognito_json(url, headers, payload)
    assert exc.value.category == "request_invalid"
    assert opener.calls == []
    assert transport.attempts == 0


def test_only_fixed_identity_pool_calls_are_accepted():
    opener = FakeOpener(FakeResponse(b'{"IdentityId":"eu-west-1:12345678-1234-4234-8234-123456789abc"}'))
    transport = _transport(opener)
    login_key = f"cognito-idp.eu-west-1.amazonaws.com/{POOL}"
    url, headers, payload = _identity_request("GetId", {"IdentityPoolId": IDENTITY_POOL, "Logins": {login_key: "synthetic.id.token"}})
    assert transport.cognito_json(url, headers, payload)["IdentityId"].startswith("eu-west-1:")

    bad_url, headers, payload = _identity_request("GetId", {"IdentityPoolId": "eu-west-1:wrong", "Logins": {login_key: "synthetic.id.token"}})
    with pytest.raises(CloudTransportError):
        transport.cognito_json(bad_url, headers, payload)
    assert len(opener.calls) == 1


def test_get_credentials_for_identity_requires_exact_target_pool_and_identity():
    opener = FakeOpener(FakeResponse(b'{"Credentials":{}}'))
    transport = _transport(opener)
    login_key = f"cognito-idp.eu-west-1.amazonaws.com/{POOL}"
    url, headers, payload = _identity_request(
        "GetCredentialsForIdentity",
        {"IdentityId": IDENTITY_POOL, "Logins": {login_key: "synthetic.id.token"}},
    )
    transport.cognito_json(url, headers, payload)
    assert len(opener.calls) == 1
    assert opener.calls[0][0].get_method() == "POST"


def test_cognito_http_failure_exposes_only_status_no_body_or_url():
    opener = FakeOpener(urllib_http_error(401, "https://secret.example/path?canary=yes", b"body-canary"))
    transport = _transport(opener)
    url, headers, payload = _pool_request()
    with pytest.raises(CognitoHTTPError) as exc:
        transport.cognito_json(url, headers, payload)
    assert exc.value.status == 401
    assert "secret.example" not in str(exc.value)
    assert "body-canary" not in str(exc.value)
    formatted = "".join(traceback.format_exception(exc.value))
    assert "secret.example" not in formatted and "body-canary" not in formatted
    assert transport.attempts == 1


def test_cognito_redirect_fails_without_following_second_request():
    opener = FakeOpener(urllib_http_error(302, "https://cognito-idp.eu-west-1.amazonaws.com/", b""))
    transport = _transport(opener)
    url, headers, payload = _pool_request()
    with pytest.raises(CloudTransportError) as exc:
        transport.cognito_json(url, headers, payload)
    assert exc.value.category == "redirect_rejected"
    assert len(opener.calls) == 1


def test_mapit_get_returns_raw_bytes_with_fixed_https_host_and_no_retry():
    response = FakeResponse(b'{"ok":true}')
    opener = FakeOpener(response)
    transport = _transport(opener)
    raw = transport.mapit_request("GET", "https://core.prod.mapit.me/v1/account-summary", {"Authorization": "synthetic"})
    assert raw == b'{"ok":true}'
    request, timeout = opener.calls[0]
    assert request.get_method() == "GET"
    assert timeout == 2.0
    assert response.closed is True
    assert transport.attempts == 1


@pytest.mark.parametrize("url", [
    "http://core.prod.mapit.me/v1/x",
    "https://evil.example/v1/x",
    "https://user@core.prod.mapit.me/v1/x",
    "https://core.prod.mapit.me:444/v1/x",
    "https://core.prod.mapit.me/v1/x#fragment",
])
def test_mapit_get_rejects_unapproved_urls(url):
    opener = FakeOpener(FakeResponse())
    with pytest.raises(CloudTransportError):
        _transport(opener).mapit_request("GET", url, {})
    assert opener.calls == []


def test_mapit_transport_rejects_non_get_and_bodies_are_never_sent():
    opener = FakeOpener(FakeResponse())
    transport = _transport(opener)
    with pytest.raises(CloudTransportError):
        transport.mapit_request("POST", "https://core.prod.mapit.me/v1/x", {})
    assert opener.calls == []


def test_mapit_401_is_compatible_with_single_existing_auth_recovery():
    opener = FakeOpener(urllib_http_error(401, "https://core.prod.mapit.me/private?q=canary", b"body-canary"))
    transport = _transport(opener)
    with pytest.raises(MapitHTTPError) as exc:
        transport.mapit_request("GET", "https://core.prod.mapit.me/v1/x", {})
    assert exc.value.status == 401
    assert exc.value.url == ""
    assert "canary" not in str(exc.value)
    assert transport.attempts == 1


def test_large_body_is_rejected_at_correct_mapit_and_auth_limits():
    opener = FakeOpener(FakeResponse(b"x" * (2 * 1024 * 1024 + 1)))
    transport = _transport(opener)
    with pytest.raises(MapitResponseTooLarge):
        transport.mapit_request("GET", "https://geo.prod.mapit.me/v1/x", {})
    assert len(opener.calls) == 1

    opener = FakeOpener(FakeResponse(b" " * (256 * 1024 + 1)))
    transport = _transport(opener)
    url, headers, payload = _pool_request()
    with pytest.raises(CloudTransportError) as exc:
        transport.cognito_json(url, headers, payload)
    assert exc.value.category == "response_too_large"
    assert len(opener.calls) == 1


def test_attempt_ceiling_is_shared_between_cognito_and_mapit():
    opener = FakeOpener(*[FakeResponse() for _ in range(25)])
    transport = _transport(opener)
    pool_url, pool_headers, pool_payload = _pool_request()
    for _ in range(3):
        transport.cognito_json(pool_url, pool_headers, pool_payload)
    for _ in range(21):
        assert transport.mapit_request("GET", "https://geo.prod.mapit.me/v1/x", {}) == b"{}"
    with pytest.raises(CloudTransportError) as exc:
        transport.mapit_request("GET", "https://geo.prod.mapit.me/v1/x", {})
    assert exc.value.category == "attempt_limit"
    assert len(opener.calls) == 24


def test_direct_opener_timeout_and_deadline_expiry_before_open():
    opener = FakeOpener(FakeResponse())
    clock = Clock(10)
    transport = _transport(opener, clock=clock, deadline=10.25)
    transport.mapit_request("GET", "https://core.prod.mapit.me/v1/x", {})
    assert opener.calls[0][1] == 0.25

    clock = Clock(10)
    opener = FakeOpener(FakeResponse())
    transport = _transport(opener, clock=clock, deadline=10.25)
    clock.value = 10.25
    with pytest.raises(CloudTransportError) as exc:
        transport.mapit_request("GET", "https://core.prod.mapit.me/v1/x", {})
    assert exc.value.category == "deadline_expired"
    assert opener.calls == []


def test_deadline_is_rechecked_after_request_construction_before_open(monkeypatch):
    import mapit.cloud_transport as cloud_transport

    clock = Clock(10)
    opener = FakeOpener(FakeResponse())
    transport = _transport(opener, clock=clock, deadline=10.5)
    original_request = cloud_transport.urllib.request.Request

    def slow_request(*args, **kwargs):
        request = original_request(*args, **kwargs)
        clock.value = 10.5
        return request

    monkeypatch.setattr(cloud_transport.urllib.request, "Request", slow_request)
    with pytest.raises(CloudTransportError) as exc:
        transport.mapit_request("GET", "https://core.prod.mapit.me/v1/x", {})
    assert exc.value.category == "deadline_expired"
    assert opener.calls == []


def test_clock_rollback_fails_before_open():
    clock = Clock(10)
    opener = FakeOpener(FakeResponse())
    transport = _transport(opener, clock=clock)
    clock.value = 9
    with pytest.raises(CloudTransportError) as exc:
        transport.mapit_request("GET", "https://core.prod.mapit.me/v1/x", {})
    assert exc.value.category == "clock_rollback"
    assert opener.calls == []


def test_reader_checks_deadline_between_chunks_and_before_return():
    clock = Clock(10)
    response = FakeResponse(chunks=[b"{}", b""])
    opener = FakeOpener(response)
    transport = _transport(opener, clock=clock, deadline=12)
    original = response.read1
    reads = 0

    def slow_read(size):
        nonlocal reads
        result = original(size)
        reads += 1
        clock.value += 1
        return result

    response.read1 = slow_read
    with pytest.raises(CloudTransportError) as exc:
        transport.mapit_request("GET", "https://core.prod.mapit.me/v1/x", {})
    assert exc.value.category == "deadline_expired"
    assert reads == 2


def test_invalid_config_is_rejected_before_any_open():
    opener = FakeOpener(FakeResponse())
    with pytest.raises(CloudTransportError):
        CloudDirectTransport(_config(discovery_enabled=True), deadline=20, opener=opener, monotonic=Clock(10))
    assert opener.calls == []


def urllib_http_error(status, url, body):
    import urllib.error
    return urllib.error.HTTPError(url, status, "canary", {}, io.BytesIO(body))
