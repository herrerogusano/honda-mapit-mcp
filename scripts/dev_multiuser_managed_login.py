"""Bounded direct Managed Login + PKCE client for retained-dev test users.

The public Cognito client is intentionally small and injectable.  It follows
only the exact owned Cognito domain and the exact localhost callback, performs
one request per redirect, disables ambient proxies, and never retries.  The
HTML login page is *not* a documented API: its form is parsed with a strict
allowlist and any shape drift fails closed.  Tokens, cookies, passwords and
authorization codes remain memory-only and are redacted by representations.

This module does not create users or open a browser.  It is suitable for a
private operator that already has the two generated passwords in the same
process as the one-shot login.  Cognito explicitly documents the authorize
endpoint as browser-facing and does not promise programmatic access to the
Managed Login pages; therefore a parser failure must use the reviewed browser
fallback, never a guessed form or USER_PASSWORD_AUTH.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from html.parser import HTMLParser
import json
import math
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from scripts.dev_multiuser_test_users import (
    DevMultiuserUserError,
    PkceChallenge,
    new_pkce_challenge,
)


MAX_HTML_BYTES = 512 * 1024
MAX_TOKEN_BYTES = 8192
MAX_REDIRECTS = 8
HTTP_TIMEOUT_SECONDS = 10
_DOMAIN = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}\.auth\.eu-west-1\.amazoncognito\.com\Z")
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_RESOURCE = re.compile(r"https://[a-z0-9]{10}\.execute-api\.eu-west-1\.amazonaws\.com/mcp\Z")
_CLIENT = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_CALLBACK = re.compile(r"http://localhost:[1-9][0-9]{2,5}/[A-Za-z0-9._~/-]+\Z")
_USERNAME = re.compile(r"[A-Za-z0-9._+@-]{1,128}\Z")
_COOKIE_NAME = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}\Z")
_CSRF_NAMES = frozenset({"csrf", "csrf_token", "_csrf", "_csrf_token"})


class ManagedLoginError(ValueError):
    """Safe category; never includes page text, URLs with query, or tokens."""

    _ALLOWED = frozenset({
        "configuration_invalid", "transport_failed", "response_invalid",
        "redirect_rejected", "login_form_unstable", "login_rejected",
        "callback_invalid", "token_invalid", "token_endpoint_rejected",
    })

    def __init__(self, category: str):
        self.category = category if category in self._ALLOWED else "response_invalid"
        super().__init__(self.category)


def _fail(category: str) -> None:
    raise ManagedLoginError(category)


def _bounded_text(value: Any, maximum: int = 4096) -> bool:
    return type(value) is str and bool(value) and len(value.encode("utf-8")) <= maximum and "\r" not in value and "\n" not in value


def _managed_domain(value: Any, account_id: Any) -> str:
    if type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None or type(value) is not str or _DOMAIN.fullmatch(value) is None or value != f"honda-mapit-mcp-dev-multiuser-{account_id}.auth.eu-west-1.amazoncognito.com":
        _fail("configuration_invalid")
    return value


def _owned_url(value: Any, *, domain: str, path: str | None = None, callback: str | None = None) -> urllib.parse.SplitResult:
    if type(value) is not str or len(value.encode("utf-8")) > 4096:
        _fail("redirect_rejected")
    parsed = urllib.parse.urlsplit(value)
    if callback is not None:
        expected = urllib.parse.urlsplit(callback)
        if parsed.username or parsed.password or parsed.fragment or (parsed.scheme, parsed.hostname, parsed.port, parsed.path) != (expected.scheme, expected.hostname, expected.port, expected.path):
            _fail("redirect_rejected")
        return parsed
    if parsed.scheme != "https" or parsed.hostname != domain or parsed.username or parsed.password or parsed.port not in (None, 443) or path is not None and parsed.path != path or parsed.fragment:
        _fail("redirect_rejected")
    return parsed


@dataclass(frozen=True, repr=False)
class HttpResponse:
    status: int
    url: str
    headers: Mapping[str, str]
    body: bytes
    set_cookies: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "HttpResponse(<redacted>)"


@dataclass(frozen=True, repr=False)
class ManagedLoginTokens:
    _access_token: str
    _expires_in: int
    _scope: str
    _refresh_token: str | None = None
    _id_token: str | None = None

    @property
    def access_token(self) -> str:
        return self._access_token

    @property
    def refresh_token(self) -> str | None:
        return self._refresh_token

    def __repr__(self) -> str:
        return "ManagedLoginTokens(<redacted>)"


@dataclass(frozen=True, repr=False)
class LoginForm:
    action: str
    hidden: Mapping[str, str]
    username_name: str
    password_name: str
    csrf_name: str

    def __repr__(self) -> str:
        return "LoginForm(<redacted>)"


class _LoginFormParser(HTMLParser):
    """Parse one narrowly accepted local-user form; no generic HTML execution."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None
        self.invalid = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map: dict[str, str] = {}
        for key, value in attrs:
            if key in attrs_map or value is None and key not in {"autofocus", "disabled", "required"}:
                self.invalid = True
                return
            attrs_map[key] = "" if value is None else value
        if tag == "form":
            if self._current is not None:
                self.invalid = True
                return
            self._current = {"attrs": attrs_map, "inputs": []}
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append(attrs_map)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            if self._current is None:
                self.invalid = True
            else:
                self.forms.append(self._current)
                self._current = None

    def result(self, *, domain: str) -> LoginForm:
        if self.invalid or self._current is not None or not self.forms:
            _fail("login_form_unstable")
        candidates: list[LoginForm] = []
        for form in self.forms:
            attrs = form["attrs"]
            inputs = form["inputs"]
            names = {item.get("name") for item in inputs if isinstance(item, Mapping)}
            has_credentials = bool({"username", "password"} & names)
            if attrs.get("method", "get").lower() != "post":
                if has_credentials:
                    _fail("login_form_unstable")
                continue
            action = attrs.get("action", "/login")
            if action.startswith("/"):
                action = f"https://{domain}{action}"
            try:
                parsed = _owned_url(action, domain=domain)
            except ManagedLoginError:
                if has_credentials:
                    raise
                continue
            if parsed.path != "/login":
                if has_credentials:
                    _fail("login_form_unstable")
                continue
            hidden: dict[str, str] = {}
            username_name = password_name = None
            csrf_name = None
            candidate_invalid = False
            for item in inputs:
                name, kind, value = item.get("name"), item.get("type", "text").lower(), item.get("value", "")
                if kind in {"submit", "button"} and name is None:
                    continue
                if type(name) is not str or not name or len(name) > 128 or name in hidden or name in {username_name, password_name}:
                    candidate_invalid = True
                    continue
                if kind == "hidden":
                    if not _bounded_text(value, 16 * 1024):
                        candidate_invalid = True
                    hidden[name] = value
                    if name in _CSRF_NAMES:
                        if csrf_name is not None:
                            candidate_invalid = True
                        csrf_name = name
                elif kind in {"text", "email"} and username_name is None and name == "username":
                    username_name = name
                elif kind == "password" and password_name is None and name == "password":
                    password_name = name
                elif kind in {"submit", "button"}:
                    continue
                else:
                    candidate_invalid = True
            if candidate_invalid or username_name != "username" or password_name != "password" or csrf_name is None or not hidden.get(csrf_name):
                if has_credentials:
                    _fail("login_form_unstable")
                continue
            candidates.append(LoginForm(action=urllib.parse.urlunsplit(parsed), hidden=dict(hidden), username_name=username_name, password_name=password_name, csrf_name=csrf_name))
        if len(candidates) != 1:
            _fail("login_form_unstable")
        return candidates[0]


def parse_login_form(body: bytes, *, domain: str) -> LoginForm:
    if type(body) is not bytes or not 0 < len(body) <= MAX_HTML_BYTES:
        _fail("login_form_unstable")
    try:
        parser = _LoginFormParser()
        parser.feed(body.decode("utf-8", errors="strict"))
        parser.close()
        return parser.result(domain=domain)
    except ManagedLoginError:
        raise
    except Exception:
        _fail("login_form_unstable")


def _header(response: HttpResponse, name: str) -> str | None:
    for key, value in response.headers.items():
        if key.casefold() == name.casefold():
            return value if type(value) is str else None
    return None


def direct_https_transport(method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float = 10) -> HttpResponse:
    """One direct TLS request; no proxy, redirect handler, retry, or SDK."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        _fail("configuration_invalid")
    if type(timeout) not in (int, float) or isinstance(timeout, bool) or not 0 < timeout <= HTTP_TIMEOUT_SECONDS:
        _fail("configuration_invalid")
    request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        response = opener.open(request, timeout=timeout)
        with response:
            raw = response.read(MAX_HTML_BYTES + 1)
            header_map = {key: value for key, value in response.headers.items()}
            set_cookies = tuple(response.headers.get_all("Set-Cookie") or ())
            status = int(response.status)
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(MAX_HTML_BYTES + 1)
            header_map = {key: value for key, value in exc.headers.items()}
            set_cookies = tuple(exc.headers.get_all("Set-Cookie") or ())
            status, final_url = int(exc.code), exc.geturl()
        finally:
            exc.close()
    except Exception:
        _fail("transport_failed")
    if len(raw) > MAX_HTML_BYTES:
        _fail("response_invalid")
    return HttpResponse(status=status, url=final_url, headers=header_map, body=raw, set_cookies=set_cookies)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ManagedLoginClient:
    """Direct authorize/login/token flow with an in-memory cookie jar."""

    def __init__(self, *, domain: str, account_id: str | None = None, client_id: str, callback_url: str,
                 resource: str, required_scope: str,
                 transport: Callable[[str, str, Mapping[str, str], bytes | None, float], HttpResponse] = direct_https_transport,
                 timeout: float = HTTP_TIMEOUT_SECONDS):
        domain = _managed_domain(domain, account_id)
        if type(client_id) is not str or _CLIENT.fullmatch(client_id) is None or type(callback_url) is not str or _CALLBACK.fullmatch(callback_url) is None:
            _fail("configuration_invalid")
        parsed = urllib.parse.urlsplit(resource) if type(resource) is str else None
        if parsed is None or _RESOURCE.fullmatch(resource) is None or parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.netloc or not parsed.path:
            _fail("configuration_invalid")
        if type(required_scope) is not str or required_scope != resource.rstrip("/") + "/use" or "\r" in required_scope or "\n" in required_scope or not callable(transport):
            _fail("configuration_invalid")
        if type(timeout) not in (int, float) or isinstance(timeout, bool) or not 0 < timeout <= HTTP_TIMEOUT_SECONDS:
            _fail("configuration_invalid")
        self.domain, self.client_id, self.callback_url = domain, client_id, callback_url
        self.resource, self.required_scope, self.transport, self.timeout = resource, required_scope, transport, float(timeout)
        self._cookies: dict[str, str] = {}
        self.calls = 0

    def _cookies_header(self) -> str | None:
        return "; ".join(f"{key}={value}" for key, value in self._cookies.items()) or None

    def _record_cookies(self, response: HttpResponse) -> None:
        values = [value.strip() for value in response.set_cookies]
        if not values:
            values = [value.strip() for key, value in response.headers.items() if key.casefold() == "set-cookie"]
        for raw in values:
            first = raw.split(";", 1)[0]
            if "=" not in first:
                _fail("response_invalid")
            name, value = first.split("=", 1)
            if _COOKIE_NAME.fullmatch(name) is None or not _bounded_text(value, 2048) or any(char in value for char in ";,"):
                _fail("response_invalid")
            self._cookies[name] = value

    def _request(self, method: str, url: str, *, body: bytes | None = None, content_type: str | None = None) -> HttpResponse:
        headers = {"Accept": "text/html,application/json", "Cache-Control": "no-store"}
        if content_type:
            headers["Content-Type"] = content_type
        cookie = self._cookies_header()
        if cookie:
            headers["Cookie"] = cookie
        self.calls += 1
        try:
            response = self.transport(method, url, headers, body, self.timeout)
        except ManagedLoginError:
            raise
        except Exception:
            _fail("transport_failed")
        if not isinstance(response, HttpResponse) or type(response.status) is not int or type(response.url) is not str or type(response.body) is not bytes or len(response.body) > MAX_HTML_BYTES:
            _fail("response_invalid")
        expected = urllib.parse.urlsplit(url)
        actual = urllib.parse.urlsplit(response.url)
        if (actual.scheme, actual.hostname, actual.port, actual.path, actual.query, actual.fragment) != (expected.scheme, expected.hostname, expected.port, expected.path, expected.query, expected.fragment):
            _fail("redirect_rejected")
        self._record_cookies(response)
        return response

    def _authorize_url(self, challenge: PkceChallenge) -> str:
        query = {
            "response_type": "code", "client_id": self.client_id,
            "redirect_uri": self.callback_url, "scope": self.required_scope,
            "resource": self.resource, "state": challenge.state,
            "code_challenge_method": "S256", "code_challenge": challenge.code_challenge,
        }
        return f"https://{self.domain}/oauth2/authorize?{urllib.parse.urlencode(query)}"

    def _location(self, response: HttpResponse) -> str:
        location = _header(response, "Location")
        if not _bounded_text(location, 4096):
            _fail("response_invalid")
        return location

    def _follow_intermediate(self, location: str, *, allow_callback: bool, state: str) -> tuple[str, str | None]:
        parsed = urllib.parse.urlsplit(location)
        if parsed.scheme == "http" and parsed.hostname == "localhost":
            if not allow_callback:
                _fail("redirect_rejected")
            _owned_url(location, domain=self.domain, callback=self.callback_url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            if parsed.fragment or set(query) != {"code", "state"} or query.get("state") != [state] or len(query.get("code", [])) != 1 or not query["code"][0]:
                _fail("callback_invalid")
            return location, query["code"][0]
        _owned_url(location, domain=self.domain)
        if parsed.path not in {"/login", "/oauth2/authorize"}:
            _fail("redirect_rejected")
        return location, None

    def _token_exchange(self, code: str, challenge: PkceChallenge) -> ManagedLoginTokens:
        endpoint = f"https://{self.domain}/oauth2/token"
        form = {"grant_type": "authorization_code", "client_id": self.client_id, "code": code, "code_verifier": challenge.code_verifier, "redirect_uri": self.callback_url}
        response = self._request("POST", endpoint, body=urllib.parse.urlencode(form).encode("ascii"), content_type="application/x-www-form-urlencoded")
        if response.status != 200:
            _fail("token_endpoint_rejected")
        try:
            value = json.loads(response.body.decode("utf-8"))
        except Exception:
            _fail("token_invalid")
        if not isinstance(value, Mapping) or type(value.get("access_token")) is not str or not 0 < len(value["access_token"].encode("utf-8")) <= MAX_TOKEN_BYTES or value.get("token_type") != "Bearer" or type(value.get("expires_in")) is not int or isinstance(value["expires_in"], bool) or not 1 <= value["expires_in"] <= 3600 or type(value.get("scope")) is not str or self.required_scope not in value["scope"].split():
            _fail("token_invalid")
        refresh = value.get("refresh_token")
        identity = value.get("id_token")
        if refresh is not None and (type(refresh) is not str or len(refresh.encode("utf-8")) > MAX_TOKEN_BYTES):
            _fail("token_invalid")
        if identity is not None and (type(identity) is not str or len(identity.encode("utf-8")) > MAX_TOKEN_BYTES):
            _fail("token_invalid")
        return ManagedLoginTokens(value["access_token"], value["expires_in"], value["scope"], refresh, identity)

    def dry_login_page(self) -> dict[str, Any]:
        """Fetch and strictly parse the login page without sending credentials.

        This is the mandatory pre-provision smoke check for the private DEV
        operator.  It performs the authorize redirect and one login-page GET,
        but never posts a username/password and never exchanges a code.
        """
        challenge = new_pkce_challenge()
        try:
            response = self._request("GET", self._authorize_url(challenge))
            if response.status not in {301, 302, 303, 307, 308}:
                _fail("response_invalid")
            location, code = self._follow_intermediate(self._location(response), allow_callback=False, state=challenge.state)
            if code is not None:
                _fail("response_invalid")
            if urllib.parse.urlsplit(location).path != "/login":
                response = self._request("GET", location)
                if response.status not in {301, 302, 303}:
                    _fail("response_invalid")
                location, code = self._follow_intermediate(self._location(response), allow_callback=False, state=challenge.state)
                if code is not None or urllib.parse.urlsplit(location).path != "/login":
                    _fail("response_invalid")
            page = self._request("GET", location)
            if page.status != 200:
                _fail("login_rejected")
            parse_login_form(page.body, domain=self.domain)
            return {"success": True, "category": "login_page_verified", "calls": self.calls}
        except ManagedLoginError as exc:
            return {"success": False, "category": exc.category, "calls": self.calls}
        except Exception:
            return {"success": False, "category": "transport_failed", "calls": self.calls}

    def login(self, *, username: str, password: str) -> ManagedLoginTokens:
        """Perform one direct flow; the caller must discard password/tokens after use."""
        if type(username) is not str or _USERNAME.fullmatch(username) is None or type(password) is not str or not password or len(password.encode("utf-8")) > 512:
            _fail("configuration_invalid")
        challenge = new_pkce_challenge()
        response = self._request("GET", self._authorize_url(challenge))
        if response.status not in {301, 302, 303, 307, 308}:
            _fail("response_invalid")
        location, code = self._follow_intermediate(self._location(response), allow_callback=False, state=challenge.state)
        form: LoginForm | None = None
        if code is None:
            if urllib.parse.urlsplit(location).path != "/login":
                response = self._request("GET", location)
                if response.status not in {301, 302, 303}:
                    _fail("response_invalid")
                location, code = self._follow_intermediate(self._location(response), allow_callback=False, state=challenge.state)
            if code is None:
                page = self._request("GET", location)
                if page.status != 200:
                    _fail("login_rejected")
                form = parse_login_form(page.body, domain=self.domain)
                values = dict(form.hidden)
                values[form.username_name] = username
                values[form.password_name] = password
                body = urllib.parse.urlencode(values).encode("utf-8")
                if len(body) > MAX_HTML_BYTES:
                    _fail("response_invalid")
                posted = self._request("POST", form.action, body=body, content_type="application/x-www-form-urlencoded")
                if posted.status not in {301, 302, 303}:
                    _fail("login_rejected")
                location, code = self._follow_intermediate(self._location(posted), allow_callback=True, state=challenge.state)
                for _ in range(MAX_REDIRECTS):
                    if code is not None:
                        break
                    next_response = self._request("GET", location)
                    if next_response.status not in {301, 302, 303}:
                        _fail("login_rejected")
                    location, code = self._follow_intermediate(self._location(next_response), allow_callback=True, state=challenge.state)
        if code is None:
            _fail("callback_invalid")
        return self._token_exchange(code, challenge)


def provision_and_login_pair(operator: Any, client_factory: Callable[[], ManagedLoginClient], *,
                             on_tokens: Callable[[str, ManagedLoginTokens], Any] | None = None) -> dict[str, Any]:
    """Bridge the user operator to PKCE without persisting credentials.

    ``operator.provision`` invokes the callback while each generated password
    is still in the same process.  A fresh client/cookie jar is used per user;
    the optional token sink is the only in-memory consumer and its return value
    is discarded.  No token, password or username is included in the result.
    """
    if not callable(getattr(operator, "provision", None)) or not callable(client_factory) or on_tokens is not None and not callable(on_tokens):
        _fail("configuration_invalid")
    authenticated = 0

    def _login(username: str, password: str) -> None:
        nonlocal authenticated
        client = client_factory()
        if not isinstance(client, ManagedLoginClient):
            _fail("configuration_invalid")
        tokens = client.login(username=username, password=password)
        if on_tokens is not None:
            on_tokens(username, tokens)
        authenticated += 1

    result = operator.provision(on_confirmed_user=_login)
    if not isinstance(result, Mapping):
        _fail("response_invalid")
    if result.get("success") is True and authenticated == 2:
        return {"success": True, "category": "users_authenticated", "users": 2}
    return {"success": False, "category": result.get("category", "response_invalid"), "users": authenticated}


__all__ = [
    "HttpResponse", "LoginForm", "ManagedLoginClient", "ManagedLoginError", "ManagedLoginTokens",
    "parse_login_form", "direct_https_transport", "provision_and_login_pair",
]
