from __future__ import annotations

import pytest

from scripts.dev_multiuser_cookie_policy import BoundedCookieStore, CookiePolicyError


DOMAIN = "honda-mapit-mcp-dev-multiuser-123456789012.auth.eu-west-1.amazoncognito.com"
URL = f"https://{DOMAIN}/login"


def test_exact_clear_redirect_removes_known_cookie() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("cognito=opaque-session; Path=/", "csrf-state=opaque-state; Path=/"))
    jar.update(URL, ("cognito=; Max-Age=0; Path=/",))
    assert jar.values(URL) == {"csrf-state": "opaque-state"}


def test_empty_cookie_value_is_valid_and_does_not_mean_deletion() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("cognito=opaque-session; Path=/",))
    jar.update(URL, ("cognito=; Path=/",))
    assert jar.values(URL) == {"cognito": ""}


def test_expiry_attributes_are_delegated_to_cookiejar() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("cognito=opaque-session; Path=/",))
    jar.update(URL, ("cognito=; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/",))
    assert jar.values(URL) == {}


def test_nonempty_expired_cookie_is_a_native_deletion() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("cognito=opaque-session; Path=/",))
    jar.update(URL, ("cognito=deleted; Max-Age=0; Path=/",))
    assert jar.values(URL) == {}


def test_negative_max_age_and_multiple_set_cookie_values_are_bounded() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("cognito=opaque-session; Path=/",))
    jar.update(URL, ("cognito=; Max-Age=-1; Path=/", "new=opaque; Path=/"))
    assert jar.values(URL) == {"new": "opaque"}


def test_invalid_late_header_does_not_partially_mutate_jar() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("cognito=opaque-session; Path=/",))
    with pytest.raises(CookiePolicyError):
        jar.update(URL, ("cognito=updated; Path=/", "foreign=opaque\x7f; Path=/"))
    assert jar.values(URL) == {"cognito": "opaque-session"}


def test_invalid_unicode_surrogate_fails_closed() -> None:
    jar = BoundedCookieStore(DOMAIN)
    with pytest.raises(CookiePolicyError):
        jar.update(URL, ("cognito=\ud800",))


def test_control_characters_and_unbounded_iterables_fail_closed() -> None:
    jar = BoundedCookieStore(DOMAIN)
    with pytest.raises(CookiePolicyError):
        jar.update(URL, ("cognito=opaque\x7f",))

    def endless():
        while True:
            yield "new=opaque"

    with pytest.raises(CookiePolicyError):
        jar.update(URL, endless())


def test_domain_path_secure_and_header_bounds_are_enforced() -> None:
    jar = BoundedCookieStore(DOMAIN)
    jar.update(URL, ("secure=opaque; Secure; Path=/oauth2",))
    assert jar.header(f"https://{DOMAIN}/login") is None
    assert jar.values(f"https://{DOMAIN}/oauth2/token") == {"secure": "opaque"}
    jar.update(URL, ("other=opaque; Domain=evil.example; Path=/",))
    assert "other" not in jar.values(URL)
    jar.update(URL, ("dot=opaque; Domain=." + DOMAIN + "; Path=/",))
    assert jar.values(URL)["dot"] == "opaque"
    with pytest.raises(CookiePolicyError):
        jar.update(URL, ("oversized=" + ("x" * 4096),))


def test_cookie_value_can_use_the_bounded_header_budget() -> None:
    jar = BoundedCookieStore(DOMAIN)
    value = "x" * 2049
    jar.update(URL, ("large=" + value,))
    assert jar.values(URL)["large"] == value


def test_outgoing_cookie_header_has_a_total_bound() -> None:
    jar = BoundedCookieStore(DOMAIN)
    for index in range(32):
        jar.update(URL, (f"c{index}=" + ("x" * 600),))
    with pytest.raises(CookiePolicyError):
        jar.header(URL)
