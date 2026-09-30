from datetime import datetime, timedelta, timezone
import json
import urllib.error

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitClient, MapitHTTPError, MapitResponseError, MapitResponseTooLarge, MapitTransportError
from mapit.config import MapitConfig
from mapit.signing import canonical_query, canonical_request, sign_get


NOW = datetime.now(timezone.utc) + timedelta(hours=1)


def session(refresh=None):
    return MapitSession("id-token-test", "access-test", "refresh-test", NOW + timedelta(hours=1), TemporaryCredentials("AKIA_TEST", "secret-test", "session-test", NOW + timedelta(hours=1)), refresh)


def test_canonical_query_and_request_are_deterministic():
    assert canonical_query("b=two&a=hello%20world&a=") == "a=&a=hello%20world&b=two"
    # SigV4 sorts encoded names, and '+' is a literal plus in a URI query.
    assert canonical_query("z=2&%C3%A9=1&a+b=x%20y") == "%C3%A9=1&a%2Bb=x%20y&z=2"
    headers = {"Host": "core.prod.mapit.me", "X-Amz-Date": "20260102T030405Z"}
    request, signed = canonical_request("GET", "https://core.prod.mapit.me/v1/test?z=2&a=1", headers)
    assert "GET\n/v1/test\na=1&z=2\n" in request
    assert signed == "host;x-amz-date"
    with pytest.raises(ValueError):
        canonical_request("GET", "https://core.prod.mapit.me/v1/../secret", headers)
    with pytest.raises(ValueError):
        canonical_request("GET", "https://core.prod.mapit.me/v1/%2e%2e%2fsecret", headers)
    with pytest.raises(ValueError):
        canonical_request("GET", "https://core.prod.mapit.me/v1/%252e%252e%252fsecret", headers)


def test_sigv4_has_temporary_token_and_id_token():
    headers = sign_get("https://core.prod.mapit.me/v1/test?a=1", session().credentials, "id-token-test", region="eu-west-1", now=NOW)
    assert headers["X-Amz-Security-Token"] == "session-test"
    assert headers["X-Id-Token"] == "id-token-test"
    assert headers["X-Amz-Date"] == NOW.strftime("%Y%m%dT%H%M%SZ")
    assert headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIA_TEST/")


def test_client_allowlist_and_single_recovery():
    attempts = []
    refreshed = []
    current = session(lambda s: refreshed.append(True))

    def transport(method, url, headers):
        attempts.append((method, url, headers))
        if len(attempts) == 1:
            raise MapitHTTPError(401, url)
        return {"ok": True}

    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, current, transport=transport)
    assert client.get_core("/v1/account-summary") == {"ok": True}
    assert len(attempts) == 2 and refreshed == [True]
    with pytest.raises(ValueError):
        client.get("http://core.prod.mapit.me/v1/account-summary")
    with pytest.raises(ValueError):
        client.get("https://example.test/v1/account-summary")
    with pytest.raises(ValueError):
        client.get_core("/v1/../secret")
    captured = []
    client.transport = lambda method, url, headers: captured.append(url) or {"ok": True}
    assert client.get_core("/v1/search", params={"q": "hello world"}) == {"ok": True}
    assert captured[-1].endswith("q=hello%20world")


def test_client_does_not_retry_after_second_auth_failure():
    attempts = []
    refreshed = []
    current = session(lambda s: refreshed.append(True))

    def transport(method, url, headers):
        attempts.append((method, url, headers))
        raise MapitHTTPError(403, url)

    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, current, transport=transport)
    with pytest.raises(MapitHTTPError) as exc_info:
        client.get_core("/v1/account-summary")
    assert exc_info.value.status == 403
    assert len(attempts) == 2
    assert refreshed == [True]


@pytest.mark.parametrize("failure", [urllib.error.URLError("url-secret"), TimeoutError("body-secret"), OSError("body-secret")])
def test_client_sanitizes_transport_failures(failure):
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session(lambda current: None), transport=lambda method, url, headers: (_ for _ in ()).throw(failure))
    with pytest.raises(MapitTransportError) as caught:
        client.get_core("/v1/account-summary")
    assert str(caught.value) == "MAPIT transport failed"
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize(
    "failure",
    [
        UnicodeDecodeError("utf-8", b"\\xff", 0, 1, "body-secret"),
        json.JSONDecodeError("body-secret", "{", 0),
    ],
)
def test_client_sanitizes_invalid_response_failures(failure):
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session(), transport=lambda method, url, headers: (_ for _ in ()).throw(failure))
    with pytest.raises(MapitResponseError) as caught:
        client.get_core("/v1/account-summary")
    assert str(caught.value) == "MAPIT response is invalid JSON"
    assert "secret" not in str(caught.value)


def test_client_keeps_http_status_separate_from_transport_and_hides_body():
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    failure = urllib.error.HTTPError("https://core.prod.mapit.me/v1/account-summary?secret=id", 403, "body-secret", {}, None)
    client = MapitClient(config, session(lambda current: None), transport=lambda method, url, headers: (_ for _ in ()).throw(failure))
    with pytest.raises(MapitHTTPError) as caught:
        client.get_core("/v1/account-summary")
    assert caught.value.status == 403
    assert "body-secret" not in str(caught.value)


def test_client_response_byte_limit_applies_before_json_materialization():
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session(), transport=lambda method, url, headers: b'{"secret":"payload"}')
    with pytest.raises(MapitResponseTooLarge):
        client.get_geo("/v1/routes", max_response_bytes=4)

    client.transport = lambda method, url, headers: b'{"ok":true}'
    assert client.get_geo("/v1/routes", max_response_bytes=64) == {"ok": True}


def test_client_default_global_cap_and_tighter_limit_apply_to_injected_bytes(monkeypatch):
    import mapit.client as client_module

    monkeypatch.setattr(client_module, "MAX_MAPIT_RESPONSE_BYTES", 16)
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    payload = b'{"long":"123456789"}'
    client = MapitClient(config, session(), transport=lambda method, url, headers: payload)
    with pytest.raises(MapitResponseTooLarge):
        client.get_geo("/v1/routes")
    with pytest.raises(MapitResponseTooLarge):
        client.get_geo("/v1/routes", max_response_bytes=100)
    with pytest.raises(MapitResponseTooLarge):
        client.get_geo("/v1/routes", max_response_bytes=4)
    monkeypatch.setattr(client_module, "MAX_MAPIT_RESPONSE_BYTES", 32)
    assert client.get_geo("/v1/routes", max_response_bytes=64) == {"long": "123456789"}
    client.transport = lambda method, url, headers: {"trusted": True}
    assert client.get_geo("/v1/routes") == {"trusted": True}


def test_private_send_get_also_normalizes_missing_cap_to_global_default(monkeypatch):
    import mapit.client as client_module
    monkeypatch.setattr(client_module, "MAX_MAPIT_RESPONSE_BYTES", 4)
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session(), transport=lambda method, url, headers: b'{"ok":true}')
    with pytest.raises(MapitResponseTooLarge):
        client._send_get("https://geo.prod.mapit.me/v1/routes", {})


def test_client_response_limit_keeps_single_auth_recovery():
    attempts = []
    refreshed = []
    current = session(lambda current: refreshed.append(True))

    def transport(method, url, headers):
        attempts.append(url)
        if len(attempts) == 1:
            raise MapitHTTPError(401, url)
        return b'{"ok":true}'

    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, current, transport=transport)
    assert client.get_geo("/v1/routes", max_response_bytes=64) == {"ok": True}
    assert len(attempts) == 2
    assert refreshed == [True]


def test_urlopen_response_limit_reads_before_json_parse(monkeypatch):
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session())
    reads = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            reads.append(size)
            return b"x" * 8

    from mapit import http_transport
    monkeypatch.setattr(http_transport, "direct_opener", lambda: type("Opener", (), {"open": staticmethod(lambda request, timeout: Response())})())
    with pytest.raises(MapitResponseTooLarge):
        client.get_geo("/v1/routes", max_response_bytes=4)
    assert reads == [5]


def test_urlopen_response_limit_accepts_exact_boundary_and_fragmented_body(monkeypatch):
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session())
    body = b'{"ok":true}'

    class Response:
        def __init__(self):
            self.parts = [body[:3], body[3:]]

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            return self.parts.pop(0) if self.parts else b""

    from mapit import http_transport
    monkeypatch.setattr(http_transport, "direct_opener", lambda: type("Opener", (), {"open": staticmethod(lambda request, timeout: Response())})())
    assert client.get_geo("/v1/routes", max_response_bytes=len(body)) == {"ok": True}


def test_urlopen_response_limit_allows_empty_at_zero_and_rejects_invalid_limits(monkeypatch):
    config = MapitConfig(core_api_url="https://core.prod.mapit.me", geo_api_url="https://geo.prod.mapit.me")
    client = MapitClient(config, session())

    class EmptyResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size=-1):
            return b""

    from mapit import http_transport
    monkeypatch.setattr(http_transport, "direct_opener", lambda: type("Opener", (), {"open": staticmethod(lambda request, timeout: EmptyResponse())})())
    assert client.get_geo("/v1/routes", max_response_bytes=0) is None
    with pytest.raises(ValueError):
        client.get_geo("/v1/routes", max_response_bytes=-1)
    with pytest.raises(ValueError):
        client.get_geo("/v1/routes", max_response_bytes=True)
