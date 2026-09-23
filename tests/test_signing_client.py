from datetime import datetime, timedelta, timezone

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitClient, MapitHTTPError
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
