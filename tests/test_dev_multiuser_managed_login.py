from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import pytest

from scripts.dev_multiuser_managed_login import (
    HttpResponse,
    ManagedLoginClient,
    ManagedLoginError,
    ManagedLoginTokens,
    parse_login_form,
    provision_and_login_pair,
)


ACCOUNT = "123456789012"
DOMAIN = f"honda-mapit-mcp-dev-multiuser-{ACCOUNT}.auth.eu-west-1.amazoncognito.com"
CLIENT = "SyntheticClient123"
CALLBACK = "http://localhost:39031/callback"
RESOURCE = "https://abcdefghij.execute-api.eu-west-1.amazonaws.com/mcp"
SCOPE = RESOURCE + "/use"
USERNAME = "honda-dev-tech-a-abcdef0123456789"
PASSWORD = "Aa1!" + "x" * 28


def _response(status, url, body=b"", set_cookies=(), **headers):
    return HttpResponse(status=status, url=url, headers=headers, body=body, set_cookies=tuple(set_cookies))


class FlowTransport:
    def __init__(self, *, external=False):
        self.calls = []
        self.external = external
        self.state = None

    def __call__(self, method, url, headers, body, timeout):
        self.calls.append((method, url, dict(headers), body, timeout))
        parsed = urlsplit(url)
        if method == "GET" and parsed.path == "/oauth2/authorize" and self.state is None:
            self.state = parse_qs(parsed.query)["state"][0]
            return _response(302, url, Location=("https://evil.example/login" if self.external else f"https://{DOMAIN}/login?state={self.state}"), **{"Set-Cookie": "session=opaque; Path=/"})
        if method == "GET" and parsed.path == "/login":
            html = f'''<html><form method="post" action="/login"><input type="hidden" name="csrf" value="csrf-value"><input type="hidden" name="cognitoAsfData" value=""><input type="text" name="username"><input type="password" name="password"><button type="submit">Sign in</button></form></html>'''.encode()
            return _response(200, url, html)
        if method == "POST" and parsed.path == "/login":
            assert headers.get("Cookie") == "session=opaque"
            assert b"username=honda-dev-tech-a-abcdef0123456789" in body
            assert b"password=" in body
            assert b"cognitoAsfData=" in body
            return _response(302, url, Location=f"https://{DOMAIN}/oauth2/authorize?state={self.state}&continue=1")
        if method == "GET" and parsed.path == "/oauth2/authorize":
            return _response(302, url, Location=f"{CALLBACK}?code=one-time-code&state={self.state}")
        if method == "POST" and parsed.path == "/oauth2/token":
            assert b"grant_type=authorization_code" in body
            assert b"code_verifier=" in body
            return _response(200, url, json.dumps({"access_token": "opaque-access", "refresh_token": "opaque-refresh", "token_type": "Bearer", "expires_in": 900, "scope": SCOPE}).encode())
        raise AssertionError((method, url))


def _client(transport):
    return ManagedLoginClient(account_id=ACCOUNT, domain=DOMAIN, client_id=CLIENT, callback_url=CALLBACK, resource=RESOURCE, required_scope=SCOPE, transport=transport)


def test_direct_flow_binds_resource_audience_and_does_not_retry_or_use_password_auth():
    transport = FlowTransport()
    tokens = _client(transport).login(username=USERNAME, password=PASSWORD)
    first_query = parse_qs(urlsplit(transport.calls[0][1]).query)
    assert first_query["resource"] == [RESOURCE]
    assert first_query["scope"] == [SCOPE]
    assert first_query["code_challenge_method"] == ["S256"]
    assert len(transport.calls) == 5
    assert all(b"USER_PASSWORD_AUTH" not in (call[3] or b"") for call in transport.calls)
    assert tokens.access_token == "opaque-access"
    assert "opaque-access" not in repr(tokens)


def test_documented_token_response_without_scope_is_accepted_without_inventing_scope():
    class NoScopeFlow(FlowTransport):
        def __call__(self, method, url, headers, body, timeout):
            response = super().__call__(method, url, headers, body, timeout)
            if method == "POST" and urlsplit(url).path == "/oauth2/token":
                return _response(200, url, json.dumps({
                    "access_token": "opaque-access", "refresh_token": "opaque-refresh",
                    "token_type": "Bearer", "expires_in": 900,
                }).encode())
            return response

    tokens = _client(NoScopeFlow()).login(username=USERNAME, password=PASSWORD)
    assert tokens.access_token == "opaque-access"
    assert tokens._scope is None


@pytest.mark.parametrize("scope", (None, 42, SCOPE.replace("/use", "/other")))
def test_explicit_or_insufficient_scope_remains_fail_closed(scope):
    class BadScopeFlow(FlowTransport):
        def __call__(self, method, url, headers, body, timeout):
            response = super().__call__(method, url, headers, body, timeout)
            if method == "POST" and urlsplit(url).path == "/oauth2/token":
                payload = {"access_token": "opaque-access", "refresh_token": "opaque-refresh",
                           "token_type": "Bearer", "expires_in": 900, "scope": scope}
                return _response(200, url, json.dumps(payload).encode())
            return response

    with pytest.raises(ManagedLoginError, match="token_invalid") as caught:
        _client(BadScopeFlow()).login(username=USERNAME, password=PASSWORD)
    assert caught.value.stage == "token_post"
    assert caught.value.reason in {"scope_invalid", "scope_missing_required"}


def test_external_redirect_is_rejected_before_login_form():
    transport = FlowTransport(external=True)
    with pytest.raises(ManagedLoginError, match="redirect_rejected"):
        _client(transport).login(username=USERNAME, password=PASSWORD)
    assert len(transport.calls) == 1


def test_login_form_requires_documented_shape_and_csrf_field():
    valid = b'<form method="post" action="/login"><input type="hidden" name="csrf" value="x"><input name="username" type="text"><input name="password" type="password"></form>'
    form = parse_login_form(valid, domain=DOMAIN)
    assert form.csrf_name == "csrf"
    assert "x" not in repr(form)
    with pytest.raises(ManagedLoginError, match="login_form_unstable"):
        parse_login_form(b'<form method="post" action="/login"><input name="username"><input name="password" type="password"></form>', domain=DOMAIN)


@pytest.mark.parametrize("field", [
    b'<input type="hidden" name="synthASF" value="">',
    b'<input type="hidden" name="state" value="opaque-state">',
    b'<input type="text" name="cognitoAsfData" value="x">',
    b'<input type="hidden" name="cognitoAsfData" value="' + b"x" * (16 * 1024 + 1) + b'">',
    b'<input type="hidden" name="csrf" value="">',
])
def test_login_form_rejects_unknown_asf_wrong_type_oversize_or_empty_csrf(field):
    body = b'<form method="post" action="/login">' + field + b'<input type="hidden" name="csrf" value="token"><input name="username"><input name="password" type="password"></form>'
    if b'name="csrf" value=""' in field:
        body = b'<form method="post" action="/login">' + field + b'<input name="username"><input name="password" type="password"></form>'
    with pytest.raises(ManagedLoginError, match="login_form_unstable"):
        parse_login_form(body, domain=DOMAIN)


def test_login_form_preserves_bounded_nonempty_asf_field():
    body = b'<form method="post" action="/login"><input type="hidden" name="csrf" value="token"><input type="hidden" name="cognitoAsfData" value="opaque-asf"><input name="username"><input name="password" type="password"></form>'
    form = parse_login_form(body, domain=DOMAIN)
    assert form.hidden["cognitoAsfData"] == "opaque-asf"


def test_login_form_ignores_auxiliary_forms_and_accepts_safe_boolean_attributes():
    body = b'''<form method="post" action="/telemetry"><input name="email"></form>
    <form method="post" action="/login"><input type="hidden" name="csrf" value="x">
    <input type="text" name="username" autofocus required><input type="password" name="password" required disabled>
    <button type="submit" disabled>Sign in</button></form>'''
    form = parse_login_form(body, domain=DOMAIN)
    assert form.action == f"https://{DOMAIN}/login"
    duplicate = body.replace(
        b'<form method="post" action="/telemetry"><input name="email"></form>',
        b'<form method="post" action="/login"><input type="hidden" name="csrf" value="y"><input name="username"><input name="password" type="password"></form>',
    )
    with pytest.raises(ManagedLoginError, match="login_form_unstable"):
        parse_login_form(duplicate, domain=DOMAIN)


def test_multiple_set_cookie_values_are_kept_in_memory_and_response_url_is_bound():
    client = _client(lambda *args: _response(200, args[1], set_cookies=("a=1", "b=2")))
    client._record_cookies(client.transport("GET", "https://" + DOMAIN + "/login", {}, None, 1))
    assert client._cookies == {"a": "1", "b": "2"}
    bad = lambda method, url, headers, body, timeout: _response(302, "https://other.example/login", Location="https://" + DOMAIN + "/login")
    with pytest.raises(ManagedLoginError, match="redirect_rejected"):
        _client(bad).login(username=USERNAME, password=PASSWORD)


def test_full_login_redirect_accepts_explicit_known_cookie_clear():
    class ClearingFlow(FlowTransport):
        def __call__(self, method, url, headers, body, timeout):
            response = super().__call__(method, url, headers, body, timeout)
            if method == "POST" and urlsplit(url).path == "/login":
                return _response(response.status, response.url, response.body,
                                 set_cookies=("session=; Max-Age=0; Path=/",), **response.headers)
            return response

    transport = ClearingFlow()
    tokens = _client(transport).login(username=USERNAME, password=PASSWORD)
    assert tokens.access_token == "opaque-access"
    assert len(transport.calls) == 5


def test_empty_cookie_value_is_valid_at_login_post_stage():
    class UnsafeClearingFlow(FlowTransport):
        def __call__(self, method, url, headers, body, timeout):
            response = super().__call__(method, url, headers, body, timeout)
            if method == "POST" and urlsplit(url).path == "/login":
                return _response(response.status, response.url, response.body,
                                 set_cookies=("session=; Path=/",), **response.headers)
            return response

    tokens = _client(UnsafeClearingFlow()).login(username=USERNAME, password=PASSWORD)
    assert tokens.access_token == "opaque-access"


def test_foreign_cookie_domain_is_ignored_and_never_sent():
    class ForeignCookieFlow(FlowTransport):
        def __call__(self, method, url, headers, body, timeout):
            response = super().__call__(method, url, headers, body, timeout)
            if method == "POST" and urlsplit(url).path == "/login":
                return _response(response.status, response.url, response.body,
                                 set_cookies=("session=opaque; Domain=evil.example; Path=/",), **response.headers)
            return response

    transport = ForeignCookieFlow()
    tokens = _client(transport).login(username=USERNAME, password=PASSWORD)
    assert tokens.access_token == "opaque-access"
    assert all("evil.example" not in repr(call) for call in transport.calls)


def test_control_character_cookie_is_allowlisted_cookie_invalid_without_raw_header():
    class InvalidCookieFlow(FlowTransport):
        def __call__(self, method, url, headers, body, timeout):
            response = super().__call__(method, url, headers, body, timeout)
            if method == "POST" and urlsplit(url).path == "/login":
                return _response(response.status, response.url, response.body,
                                 set_cookies=("session=opaque\x7f; Path=/",), **response.headers)
            return response

    transport = InvalidCookieFlow()
    with pytest.raises(ManagedLoginError, match="cookie_invalid") as caught:
        _client(transport).login(username=USERNAME, password=PASSWORD)
    assert caught.value.stage == "login_post"
    assert len(transport.calls) == 3


def test_wrong_callback_state_and_unbounded_body_fail_closed():
    transport = FlowTransport()
    client = _client(transport)
    # A valid initial response is not enough to permit a callback with a
    # foreign state; the fake flow is changed only at the redirect boundary.
    def bad_callback(method, url, headers, body, timeout):
        if method == "GET" and urlsplit(url).path == "/oauth2/authorize":
            query = parse_qs(urlsplit(url).query)
            if "continue" in query:
                return _response(302, url, Location=f"{CALLBACK}?code=x&state=foreign")
        return transport(method, url, headers, body, timeout)
    with pytest.raises(ManagedLoginError, match="callback_invalid") as caught:
        ManagedLoginClient(account_id=ACCOUNT, domain=DOMAIN, client_id=CLIENT, callback_url=CALLBACK, resource=RESOURCE, required_scope=SCOPE, transport=bad_callback).login(username=USERNAME, password=PASSWORD)
    assert caught.value.stage == "authorize_redirect"


def test_pair_bridge_keeps_password_and_tokens_in_memory_only():
    class FakeClient(ManagedLoginClient):
        def login(self, *, username, password):
            assert password.startswith("Aa1!")
            return ManagedLoginTokens("opaque-access", 900, SCOPE, "opaque-refresh")

    class FakeOperator:
        def provision(self, *, on_confirmed_user):
            on_confirmed_user("synthetic-a", PASSWORD)
            on_confirmed_user("synthetic-b", PASSWORD)
            return {"success": True, "category": "users_confirmed", "calls": 4, "users": 2}

    consumed = []
    result = provision_and_login_pair(FakeOperator(), lambda: FakeClient.__new__(FakeClient), on_tokens=lambda user, token: consumed.append(token.access_token))
    assert result == {"success": True, "category": "users_authenticated", "users": 2}
    assert consumed == ["opaque-access", "opaque-access"]
    assert "opaque-access" not in repr(result)


def test_pair_bridge_returns_allowlisted_login_category_and_stage_on_callback_failure():
    class FailedClient(ManagedLoginClient):
        def login(self, *, username, password):
            raise ManagedLoginError("callback_invalid", stage="authorize_redirect")

    class FakeOperator:
        def provision(self, *, on_confirmed_user):
            try:
                on_confirmed_user("synthetic-a", PASSWORD)
            except ManagedLoginError:
                pass
            return {"success": False, "category": "login_failed", "users": 0}

    result = provision_and_login_pair(FakeOperator(), lambda: FailedClient.__new__(FailedClient))
    assert result == {
        "success": False, "category": "login_failed",
        "login_category": "callback_invalid", "stage": "authorize_redirect", "users": 0,
    }
    assert "synthetic" not in repr(result)
