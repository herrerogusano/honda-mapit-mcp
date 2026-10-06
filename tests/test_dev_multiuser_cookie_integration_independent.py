"""Independent regressions for cookie-store integration boundaries."""

from __future__ import annotations

import pytest

from scripts.dev_multiuser_cookie_policy import CookiePolicyError
from scripts.dev_multiuser_managed_login import ManagedLoginError
from test_dev_multiuser_managed_login import DOMAIN, _client


URL = f"https://{DOMAIN}/login"


def test_managed_login_maps_outgoing_cookie_bound_to_allowlisted_error():
    client = _client(lambda *args: None)
    for index in range(32):
        client._cookie_store.update(URL, (f"c{index}=" + ("x" * 600),))

    with pytest.raises(ManagedLoginError) as caught:
        client._cookies_header(URL)
    assert caught.value.category == "cookie_invalid"
    assert caught.value.stage is None
    assert "cookie_header_invalid" not in repr(caught.value)


def test_managed_login_cookie_store_is_not_shared_between_clients():
    first = _client(lambda *args: None)
    second = _client(lambda *args: None)
    first._cookie_store.update(URL, ("session=first-only; Path=/",))

    assert first._cookie_store.values(URL) == {"session": "first-only"}
    assert second._cookie_store.values(URL) == {}


@pytest.mark.parametrize(
    "url",
    (
        f"http://{DOMAIN}/login",
        f"https://{DOMAIN}:444/login",
        f"https://user@{DOMAIN}/login",
        f"https://{DOMAIN}/login#fragment",
        f"https://{DOMAIN}:not-a-port/login",
    ),
)
def test_cookie_store_rejects_non_exact_https_urls_without_mutation(url):
    client = _client(lambda *args: None)
    client._cookie_store.update(URL, ("session=known; Path=/",))
    with pytest.raises(CookiePolicyError):
        client._cookie_store.update(url, ("session=attacker; Path=/",))
    assert client._cookie_store.values(URL) == {"session": "known"}


def test_cookie_store_rejects_leading_crlf_before_native_parsing():
    client = _client(lambda *args: None)
    with pytest.raises(CookiePolicyError):
        client._cookie_store.update(URL, ("\r\nforeign=secret; Path=/",))
