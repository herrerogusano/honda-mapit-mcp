from __future__ import annotations

import pytest

from scripts.dev_multiuser_cookie_policy import CookiePolicyError, apply_set_cookie_updates


def test_exact_clear_redirect_removes_known_cookie() -> None:
    jar = {"cognito": "opaque-session", "csrf-state": "opaque-state"}
    apply_set_cookie_updates(jar, ("cognito=; Max-Age=0; Path=/",))
    assert jar == {"csrf-state": "opaque-state"}


@pytest.mark.parametrize(
    "header",
    (
        "cognito=; Path=/",
        "unknown=; Max-Age=0; Path=/",
        "cognito=; Max-Age=1; Path=/",
        "cognito=; Max-Age=bad; Path=/",
        "cognito=; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Path=/",
    ),
)
def test_empty_cookie_requires_known_name_and_nonpositive_max_age(header: str) -> None:
    jar = {"cognito": "opaque-session"}
    with pytest.raises(CookiePolicyError):
        apply_set_cookie_updates(jar, (header,))
    assert jar == {"cognito": "opaque-session"}


def test_negative_max_age_and_multiple_set_cookie_values_are_bounded() -> None:
    jar = {"cognito": "opaque-session"}
    apply_set_cookie_updates(jar, ("cognito=; Max-Age=-1", "new=opaque; Path=/"))
    assert jar == {"new": "opaque"}


def test_invalid_late_header_does_not_partially_mutate_jar() -> None:
    jar = {"cognito": "opaque-session"}
    with pytest.raises(CookiePolicyError):
        apply_set_cookie_updates(jar, ("cognito=; Max-Age=0", "unknown=; Path=/"))
    assert jar == {"cognito": "opaque-session"}


def test_invalid_unicode_surrogate_fails_closed() -> None:
    with pytest.raises(CookiePolicyError):
        apply_set_cookie_updates({"cognito": "opaque-session"}, ("cognito=\ud800",))


def test_control_characters_and_unbounded_iterables_fail_closed() -> None:
    with pytest.raises(CookiePolicyError):
        apply_set_cookie_updates({"cognito": "opaque-session"}, ("cognito=opaque\x7f",))

    def endless():
        while True:
            yield "new=opaque"

    with pytest.raises(CookiePolicyError):
        apply_set_cookie_updates({}, endless())
