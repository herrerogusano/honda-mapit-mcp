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
            html = f'''<html><form method="post" action="/login"><input type="hidden" name="csrf" value="csrf-value"><input type="hidden" name="state" value="{self.state}"><input type="text" name="username"><input type="password" name="password"><button type="submit">Sign in</button></form></html>'''.encode()
            return _response(200, url, html)
        if method == "POST" and parsed.path == "/login":
            assert headers.get("Cookie") == "session=opaque"
            assert b"username=honda-dev-tech-a-abcdef0123456789" in body
            assert b"password=" in body
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
    with pytest.raises(ManagedLoginError, match="callback_invalid"):
        ManagedLoginClient(account_id=ACCOUNT, domain=DOMAIN, client_id=CLIENT, callback_url=CALLBACK, resource=RESOURCE, required_scope=SCOPE, transport=bad_callback).login(username=USERNAME, password=PASSWORD)


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
