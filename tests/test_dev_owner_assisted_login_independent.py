from __future__ import annotations

import base64
from dataclasses import replace
import json
import time
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_dev_runtime import CognitoDevPolicy
from scripts import dev_owner_login_context
from tests.test_dev_owner_login_context import SDK as _ContextSDK, parse as _parse_context, receipt as _context_receipt
from scripts.dev_owner_assisted_login import (
    AUTHORIZE_URL,
    CALLBACK_HOST,
    CALLBACK_ORIGIN,
    CALLBACK_URL,
    TOKEN_URL,
    AssistedLoginError,
    DevOwnerAssistedLogin,
)


POOL = "eu-west-1_abcdefghijk"
API = "abcdefghij"
CLIENT = "OwnerClient123"
SUBJECT = "12345678-1234-1234-1234-123456789abc"
KID = "owner-key"
POLICY = CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, {KID: public}


def _access_token(private, policy=POLICY, **overrides):
    now = int(time.time())
    claims = {
        "iss": policy.issuer_url,
        "aud": policy.audience,
        "sub": policy.owner_subject,
        "client_id": policy.client_id,
        "token_use": "access",
        "iat": now,
        "exp": now + 300,
        "scope": policy.required_scope,
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": KID, "typ": "JWT"})


class _Response:
    status = 200

    def __init__(self, body):
        self.body = body
        self.offset = 0
        self.closed = False
        self.headers = _Headers(str(len(body)))

    def read(self, size):
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self):
        self.closed = True


class _Headers:
    def __init__(self, length):
        self.length = length

    def get_all(self, name):
        if name.casefold() == "content-length":
            return [self.length]
        if name.casefold() == "content-type":
            return ["application/json"]
        return None


class _Opener:
    def __init__(self, body):
        self.body = body
        self.requests = []
        self.response = None

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        self.response = _Response(self.body)
        return self.response


def _body(token, **extra):
    return json.dumps({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 300,
        **extra,
    }, separators=(",", ":")).encode()


def _headers(*extra):
    return [("Host", CALLBACK_HOST), *extra]


def _new_login(signing_material, opener, consumer, *, clock=None, window=600):
    private, keys = signing_material
    return DevOwnerAssistedLogin(
        POLICY, keys, consumer, token_opener=opener,
        monotonic=clock or (lambda: 10.0), wall_clock=time.time,
        random_bytes=lambda count: b"x" * count, window_seconds=window,
    ), private


def _begin(login):
    root = login.handle("GET", "/", _headers(), "127.0.0.1")
    assert root.status == 200
    capability = root.body.split(b'name=cap value="', 1)[1].split(b'"', 1)[0].decode()
    response = login.handle("GET", "/start?cap=" + capability, _headers(), "127.0.0.1")
    assert response.status == 302
    return response.location


def _callback(login, location, query, *, headers=None, peer="127.0.0.1"):
    state = parse_qs(urlsplit(location).query, strict_parsing=True)["state"][0]
    separator = "&" if "?" in query else "?"
    target = "/callback" + separator + query.replace("{state}", state)
    return login.handle("GET", target, headers or _headers(), peer)


def test_success_is_exact_pkce_request_and_callback_consumes_once(signing_material):
    private, _keys = signing_material
    token = _access_token(private)
    opener = _Opener(_body(token, scope=POLICY.required_scope))
    consumed = []
    login, _ = _new_login(signing_material, opener, consumed.append)
    location = _begin(login)
    authorize = urlsplit(location)
    assert authorize.scheme == "https"
    assert authorize.netloc == urlsplit(AUTHORIZE_URL).netloc
    params = parse_qs(authorize.query, strict_parsing=True)
    assert set(params) == {
        "response_type", "client_id", "redirect_uri", "scope", "resource", "state",
        "code_challenge", "code_challenge_method",
    }
    assert params["response_type"] == ["code"]
    assert params["client_id"] == [POLICY.client_id]
    assert params["redirect_uri"] == [CALLBACK_URL]
    assert params["resource"] == [POLICY.resource_url]
    assert params["scope"] == [POLICY.required_scope]
    assert params["code_challenge_method"] == ["S256"]
    assert len(params["state"][0]) == 43
    assert len(params["code_challenge"][0]) == 43

    response = _callback(login, location, "code=authorization-code&state={state}")
    assert response.status == 200
    assert response.category == "verified"
    assert len(consumed) == 1
    assert consumed[0].token == token
    assert consumed[0].scopes == [POLICY.required_scope]
    assert len(opener.requests) == 1
    request, timeout = opener.requests[0]
    assert request.full_url == TOKEN_URL
    assert request.get_method() == "POST"
    fields = parse_qs(request.data.decode("ascii"), strict_parsing=True)
    assert fields == {
        "grant_type": ["authorization_code"], "client_id": [CLIENT],
        "code": ["authorization-code"], "redirect_uri": [CALLBACK_URL],
        "code_verifier": [fields["code_verifier"][0]],
    }
    verifier = fields["code_verifier"][0]
    assert 43 <= len(verifier) <= 128
    assert params["code_challenge"][0] == base64.urlsafe_b64encode(
        __import__("hashlib").sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    assert 0 < timeout <= 15
    assert opener.response.closed is True
    replay = _callback(login, location, "code=second-code&state={state}")
    assert replay.status == 410
    assert len(opener.requests) == len(consumed) == 1


@pytest.mark.parametrize("query", [
    "code=code&state={state}&extra=x",
    "code=code&state={state}&state={state}",
    "code=&state={state}",
    "code=code&state=wrong",
    "error=access_denied&state={state}",
    "code=code&state={state}&error_description=bad",
])
def test_bad_or_ambiguous_callback_is_terminal_before_exchange(signing_material, query):
    token = _access_token(signing_material[0])
    opener = _Opener(_body(token))
    consumed = []
    login, _ = _new_login(signing_material, opener, consumed.append)
    location = _begin(login)
    response = _callback(login, location, query)
    assert response.status == 400
    assert response.body == b"Login could not be verified. Close this tab."
    assert response.category in {"request_rejected", "login_failed"}
    assert not opener.requests and not consumed
    assert login.terminal is True


@pytest.mark.parametrize("headers,peer", [
    (_headers(("Host", CALLBACK_HOST)), "127.0.0.1"),
    (_headers(("Origin", "http://localhost:8787")), "127.0.0.1"),
    (_headers(("Origin", CALLBACK_ORIGIN)), "127.0.0.2"),
    (_headers(("Transfer-Encoding", "chunked")), "127.0.0.1"),
    (_headers(("Content-Length", "1")), "127.0.0.1"),
])
def test_callback_transport_origin_host_and_framing_are_fenced(signing_material, headers, peer):
    token = _access_token(signing_material[0])
    opener = _Opener(_body(token))
    consumed = []
    login, _ = _new_login(signing_material, opener, consumed.append)
    location = _begin(login)
    response = _callback(login, location, "code=authorization-code&state={state}", headers=headers, peer=peer)
    assert response.status == 400
    assert not opener.requests and not consumed


@pytest.mark.parametrize("claims", [
    {"iss": "https://wrong.example/issuer"},
    {"aud": "https://wrong.example/mcp"},
    {"client_id": "other-client"},
    {"sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
    {"token_use": "id"},
    {"scope": "openid"},
    {"exp": int(time.time()) - 1},
])
def test_only_exact_signed_owner_resource_scope_claims_reach_consumer(signing_material, claims):
    token = _access_token(signing_material[0], **claims)
    opener = _Opener(_body(token))
    consumed = []
    login, _ = _new_login(signing_material, opener, consumed.append)
    location = _begin(login)
    response = _callback(login, location, "code=authorization-code&state={state}")
    assert response.status == 400
    assert response.category == "token_invalid"
    assert not consumed
    assert len(opener.requests) == 1
    assert response.body == b"Login could not be verified. Close this tab."


def test_unsigned_or_foreign_signature_token_is_never_consumed(signing_material):
    foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _access_token(foreign)
    opener = _Opener(_body(token))
    consumed = []
    login, _ = _new_login(signing_material, opener, consumed.append)
    location = _begin(login)
    response = _callback(login, location, "code=authorization-code&state={state}")
    assert response.category == "token_invalid"
    assert not consumed


def test_token_body_scope_contradiction_duplicate_json_and_redirect_fail_closed(signing_material):
    token = _access_token(signing_material[0])
    consumed = []
    for body in (
        _body(token, scope="openid"),
        b'{"access_token":"x","access_token":"y","token_type":"Bearer","expires_in":300}',
    ):
        opener = _Opener(body)
        login, _ = _new_login(signing_material, opener, consumed.append)
        location = _begin(login)
        response = _callback(login, location, "code=authorization-code&state={state}")
        assert response.category == "exchange_failed"
        assert not consumed
    assert consumed == []


def test_consumer_failure_is_redacted_and_still_consumes_attempt(signing_material):
    token = _access_token(signing_material[0])
    opener = _Opener(_body(token))
    login, _ = _new_login(signing_material, opener, lambda _token: (_ for _ in ()).throw(RuntimeError(token)))
    location = _begin(login)
    response = _callback(login, location, "code=authorization-code&state={state}")
    rendered = repr(response) + response.body.decode("ascii") + response.category
    assert response.status == 400
    assert response.category == "consumer_failed"
    assert token not in rendered
    assert login.terminal is True
    assert len(opener.requests) == 1


def test_parser_context_cannot_be_replaced_with_another_owner_subject():
    accepted = _parse_context(_context_receipt())
    forged = replace(accepted, policy=CognitoDevPolicy(
        accepted.policy.user_pool_id, accepted.policy.api_id,
        accepted.policy.client_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        request_deadline_seconds=accepted.policy.request_deadline_seconds))
    sdk = _ContextSDK(accepted)
    # Contexts are capabilities minted by the receipt parser. A dataclass copy
    # must not be treated as having passed that provenance check.
    with pytest.raises(Exception, match="owner_login_context_unverified"):
        dev_owner_login_context.verify_current_context(forged, sdk)
    assert sdk.calls_seen == []
