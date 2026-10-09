from __future__ import annotations

import base64
import http.client
import hashlib
import json
import threading
import time
import urllib.parse
from email.message import Message
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_dev_runtime import CognitoDevPolicy
from scripts.dev_owner_assisted_login import (
    AUTHORIZE_URL,
    CALLBACK_HOST,
    CALLBACK_URL,
    OWNER_DOMAIN,
    TOKEN_URL,
    AssistedLoginError,
    DevOwnerAssistedLogin,
)


POOL = "eu-west-1_OwnerPool123"
API = "abcdefghij"
CLIENT = "OwnerPublicClient123"
SUBJECT = "12345678-1234-4234-8234-123456789abc"
POLICY = CognitoDevPolicy(POOL, API, CLIENT, SUBJECT)
SCOPE = POLICY.required_scope


class _Random:
    def __init__(self):
        self.next_value = 1

    def __call__(self, length: int) -> bytes:
        value = bytes([self.next_value]) * length
        self.next_value += 1
        return value


class _Response:
    status = 200

    def __init__(self, body: bytes):
        self._body = body
        self._offset = 0
        self.headers = Message()
        self.headers["Content-Length"] = str(len(body))
        self.headers["Content-Type"] = "application/json"
        self.closed = False

    def read(self, count: int) -> bytes:
        result = self._body[self._offset:self._offset + count]
        self._offset += len(result)
        return result

    def close(self) -> None:
        self.closed = True


class _Opener:
    def __init__(self, response: _Response | Exception):
        self.response = response
        self.calls: list[tuple[Any, float]] = []

    def open(self, request: Any, *, timeout: float) -> _Response:
        self.calls.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class _Clock:
    def __init__(self, start: float = 100.0):
        self.value = start

    def __call__(self) -> float:
        return self.value


@pytest.fixture(scope="module")
def signing_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, {"owner-kid": public_pem}


def _signed_token(private_key, *, scope: str = SCOPE, subject: str = SUBJECT,
                  client: str = CLIENT, audience: str | None = None,
                  expires_in: int = 240) -> str:
    now = int(time.time())
    return jwt.encode({
        "iss": POLICY.issuer_url,
        "aud": audience if audience is not None else POLICY.audience,
        "client_id": client,
        "sub": subject,
        "token_use": "access",
        "scope": scope,
        "iat": now,
        "exp": now + expires_in,
    }, private_key, algorithm="RS256", headers={"kid": "owner-kid"})


def _session(*, token_response: bytes | None = None, exception: Exception | None = None,
             clock: _Clock | None = None, random: _Random | None = None):
    private, keys = _KEYS
    access = _signed_token(private)
    body = token_response if token_response is not None else json.dumps({
        "access_token": access, "token_type": "Bearer", "expires_in": 300,
        "scope": SCOPE,
    }).encode()
    response = _Response(body)
    opener = _Opener(exception if exception is not None else response)
    received = []
    selected_clock = clock or _Clock()
    login = DevOwnerAssistedLogin(
        POLICY, keys, received.append, token_opener=opener,
        monotonic=selected_clock, wall_clock=time.time,
        random_bytes=random or _Random(),
    )
    root = login.handle("GET", "/", [("Host", CALLBACK_HOST)], "127.0.0.1")
    cap = root.body.decode().split('name=cap value="', 1)[1].split('"', 1)[0]
    start = login.handle("GET", "/start?" + urllib.parse.urlencode({"cap": cap}),
                         [("Host", CALLBACK_HOST)], "127.0.0.1")
    return login, opener, response, received, selected_clock, start


@pytest.fixture(autouse=True)
def _set_keys(signing_keys):
    global _KEYS
    _KEYS = signing_keys


def _start_params(response):
    assert response.status == 302
    parsed = urllib.parse.urlsplit(response.location)
    assert f"{parsed.scheme}://{parsed.netloc}" == AUTHORIZE_URL.split("/oauth2/authorize", 1)[0]
    return urllib.parse.parse_qs(parsed.query, strict_parsing=True)


def _callback(login, state, *, code="sample-code", headers=None, target_extra=""):
    target = "/callback?" + urllib.parse.urlencode({"code": code, "state": state}) + target_extra
    return login.handle("GET", target, headers or [("Host", CALLBACK_HOST)], "127.0.0.1")


def test_start_uses_fixed_owner_domain_exact_callback_and_pkce_then_consumes_code_once(signing_keys):
    private, _keys = signing_keys
    login, opener, response, received, _clock, start = _session()
    params = _start_params(start)
    assert set(params) == {"response_type", "client_id", "redirect_uri", "scope", "resource",
                           "state", "code_challenge", "code_challenge_method"}
    assert params["response_type"] == ["code"]
    assert params["client_id"] == [CLIENT]
    assert params["redirect_uri"] == [CALLBACK_URL]
    assert params["scope"] == [SCOPE]
    assert params["resource"] == [POLICY.resource_url]
    assert params["code_challenge_method"] == ["S256"]
    assert OWNER_DOMAIN in start.location
    assert b"code_verifier" not in start.location.encode()
    state = params["state"][0]

    completed = _callback(login, state)
    assert completed.status == 200
    assert completed.body == b"Login verified. You may close this tab."
    assert len(received) == 1 and received[0].token.startswith("eyJ")
    assert len(opener.calls) == 1
    request, timeout = opener.calls[0]
    assert request.full_url == TOKEN_URL and request.get_method() == "POST"
    post = urllib.parse.parse_qs(request.data.decode(), strict_parsing=True)
    assert post["grant_type"] == ["authorization_code"]
    assert post["client_id"] == [CLIENT]
    assert post["redirect_uri"] == [CALLBACK_URL]
    assert post["code"] == ["sample-code"]
    verifier = post["code_verifier"][0]
    expected_challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    assert params["code_challenge"] == [expected_challenge]
    assert 0 < timeout <= 15
    assert response.closed
    assert login.terminal and login.outcome == "verified"
    replay = _callback(login, state)
    assert replay.status == 410 and len(opener.calls) == 1
    assert "sample-code" not in repr(completed) + repr(login) + repr(start)


def test_exact_signed_scope_is_required_even_when_fixed_verifier_returns_token(signing_keys):
    private, _keys = signing_keys
    wrong = _signed_token(private, scope="openid other-scope")
    body = json.dumps({"access_token": wrong, "token_type": "Bearer", "expires_in": 300}).encode()
    login, opener, _response, received, _clock, start = _session(token_response=body)
    state = _start_params(start)["state"][0]
    result = _callback(login, state)
    assert result.status == 400 and login.outcome == "token_invalid"
    assert len(opener.calls) == 1 and received == []


def test_short_lived_signed_token_is_not_delivered(signing_keys):
    private, _ = signing_keys
    token = _signed_token(private, expires_in=10)
    body = json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 300}).encode()
    login, opener, _response, received, _clock, start = _session(token_response=body)
    result = _callback(login, _start_params(start)["state"][0])
    assert result.status == 400 and login.outcome == "token_invalid"
    assert len(opener.calls) == 1 and received == []


@pytest.mark.parametrize("body", [
    lambda token: json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 300,
                              "scope": "wrong"}).encode(),
    lambda token: (b'{"access_token":"' + token.encode() + b'","access_token":"duplicate",'
                   b'"token_type":"Bearer","expires_in":300}'),
    lambda token: json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": True}).encode(),
    lambda token: json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 14}).encode(),
    lambda token: json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 300,
                              "extra": "not-allowed"}).encode(),
])
def test_token_endpoint_response_is_strict_and_does_not_deliver_tokens(signing_keys, body):
    private, _ = signing_keys
    response_body = body(_signed_token(private))
    login, opener, _response, received, _clock, start = _session(token_response=response_body)
    state = _start_params(start)["state"][0]
    result = _callback(login, state)
    assert result.status == 400 and received == []
    assert login.terminal and len(opener.calls) == 1


@pytest.mark.parametrize("target,headers,peer", [
    ("http://127.0.0.1:8787/callback?code=x&state=y", [("Host", CALLBACK_HOST)], "127.0.0.1"),
    ("/callback#fragment", [("Host", CALLBACK_HOST)], "127.0.0.1"),
    ("/callback?code=x&code=y&state=z", [("Host", CALLBACK_HOST)], "127.0.0.1"),
    ("/callback?code=x&state=y&extra=z", [("Host", CALLBACK_HOST)], "127.0.0.1"),
    ("/callback?code=x&state=y", [("Host", CALLBACK_HOST), ("Host", CALLBACK_HOST)], "127.0.0.1"),
    ("/callback?code=x&state=y", [("Host", "localhost:8787")], "127.0.0.1"),
    ("/callback?code=x&state=y", [("Host", CALLBACK_HOST)], "::1"),
    ("/callback?code=x&state=y", [("Host", CALLBACK_HOST), ("Transfer-Encoding", "chunked")], "127.0.0.1"),
    ("/callback?code=x&state=y", [("Host", CALLBACK_HOST), ("Content-Length", "1")], "127.0.0.1"),
])
def test_callback_rejects_unsafe_request_shapes_before_exchange(signing_keys, target, headers, peer):
    login, opener, _response, received, _clock, start = _session()
    _state = _start_params(start)["state"][0]
    # Even syntactically valid supplied state cannot cause token exchange when
    # a request shape is malformed; callback attempts are terminal by design.
    result = login.handle("GET", target, headers, peer)
    assert result.status in {400, 410}
    assert opener.calls == [] and received == []


def test_state_mismatch_and_invalid_authorization_error_are_one_shot(signing_keys):
    login, opener, _response, received, _clock, start = _session()
    state = _start_params(start)["state"][0]
    wrong = _callback(login, "not-the-state")
    assert wrong.status == 400 and login.terminal
    assert opener.calls == [] and received == []
    assert _callback(login, state).status == 410


def test_start_capability_is_single_use_and_random_cap_not_reflected_in_errors(signing_keys):
    login, opener, _response, _received, _clock, start = _session()
    cap = "A" * 43
    denied = login.handle("GET", "/start?cap=" + cap, [("Host", CALLBACK_HOST)], "127.0.0.1")
    assert denied.status == 400
    assert cap not in denied.body.decode()
    assert opener.calls == []
    # The actual cap has already been consumed by the successful start.
    assert start.status == 302


def test_unknown_transport_failure_is_sanitized_and_never_replayed(signing_keys):
    canary = "secret-code-canary"
    login, opener, _response, received, _clock, start = _session(exception=RuntimeError(canary))
    state = _start_params(start)["state"][0]
    result = _callback(login, state, code=canary)
    combined = repr(result) + result.body.decode() + repr(login)
    assert result.status == 400 and login.outcome == "exchange_failed"
    assert canary not in combined
    assert len(opener.calls) == 1 and received == []
    assert _callback(login, state, code=canary).status == 410
    assert len(opener.calls) == 1


def test_consumer_failure_is_a_fixed_terminal_category(signing_keys):
    private, keys = signing_keys
    token = _signed_token(private)
    response = _Response(json.dumps({"access_token": token, "token_type": "Bearer",
                                     "expires_in": 300, "scope": SCOPE}).encode())
    opener = _Opener(response)
    login = DevOwnerAssistedLogin(POLICY, keys, lambda _token: (_ for _ in ()).throw(RuntimeError("consumer-canary")),
                                  token_opener=opener, monotonic=_Clock(), random_bytes=_Random())
    root = login.handle("GET", "/", [("Host", CALLBACK_HOST)], "127.0.0.1")
    cap = root.body.decode().split('name=cap value="', 1)[1].split('"', 1)[0]
    start = login.handle("GET", "/start?cap=" + cap, [("Host", CALLBACK_HOST)], "127.0.0.1")
    state = _start_params(start)["state"][0]
    result = _callback(login, state)
    assert result.category == "consumer_failed" and login.terminal
    assert "consumer-canary" not in result.body.decode() + repr(result)
    assert len(opener.calls) == 1


def test_exchange_deadline_is_checked_during_bounded_response_reads(signing_keys):
    private, keys = signing_keys
    clock = _Clock()
    token = _signed_token(private)
    body = json.dumps({"access_token": token, "token_type": "Bearer", "expires_in": 300,
                       "scope": SCOPE}).encode()

    class SlowResponse(_Response):
        def read(self, count: int) -> bytes:
            clock.value += 8.0
            return super().read(count)

    opener = _Opener(SlowResponse(body))
    received = []
    login = DevOwnerAssistedLogin(POLICY, keys, received.append, token_opener=opener,
                                  monotonic=clock, random_bytes=_Random())
    root = login.handle("GET", "/", [("Host", CALLBACK_HOST)], "127.0.0.1")
    cap = root.body.decode().split('name=cap value="', 1)[1].split('"', 1)[0]
    start = login.handle("GET", "/start?cap=" + cap, [("Host", CALLBACK_HOST)], "127.0.0.1")
    state = _start_params(start)["state"][0]
    result = _callback(login, state)
    assert result.status == 400 and login.outcome == "window_expired"
    assert len(opener.calls) == 1 and received == []


def test_real_loopback_server_waits_for_callback_worker_and_closes(signing_keys):
    private, keys = signing_keys
    token = _signed_token(private)
    response = _Response(json.dumps({"access_token": token, "token_type": "Bearer",
                                     "expires_in": 300, "scope": SCOPE}).encode())
    opener = _Opener(response)
    received = []
    login = DevOwnerAssistedLogin(POLICY, keys, received.append, token_opener=opener,
                                  monotonic=time.monotonic, random_bytes=_Random())
    outcomes = []
    ready = []
    listening = threading.Event()
    def on_ready(url):
        ready.append(url)
        assert url == "http://127.0.0.1:8787/"
        assert "?" not in url and "#" not in url
        probe = http.client.HTTPConnection("127.0.0.1", 8787, timeout=1)
        probe.connect()
        probe.close()
        listening.set()
    # Pass the readiness callback from the serving worker after bind/listen.
    server_thread = threading.Thread(target=lambda: outcomes.append(login.serve(ready_callback=on_ready)), daemon=True)
    server_thread.start()
    assert listening.wait(timeout=2), "listener did not signal bound socket"
    conn = http.client.HTTPConnection("127.0.0.1", 8787, timeout=2)
    conn.request("GET", "/")
    root = conn.getresponse()
    root_body = root.read()
    assert root.status == 200
    assert root.getheader("Content-Security-Policy").startswith("default-src 'none'")
    cap = root_body.decode().split('name=cap value="', 1)[1].split('"', 1)[0]
    conn.request("GET", "/start?cap=" + urllib.parse.quote(cap))
    started = conn.getresponse()
    started.read()
    assert started.status == 302
    state = urllib.parse.parse_qs(urllib.parse.urlsplit(started.getheader("Location")).query)["state"][0]
    conn.request("GET", "/callback?" + urllib.parse.urlencode({"code": "local-code", "state": state}))
    callback = conn.getresponse()
    callback_body = callback.read()
    conn.close()
    server_thread.join(timeout=3)
    assert not server_thread.is_alive()
    assert callback.status == 200 and callback_body == b"Login verified. You may close this tab."
    assert outcomes == ["verified"] and len(received) == 1 and len(opener.calls) == 1
    assert ready == ["http://127.0.0.1:8787/"]


def test_concurrent_callbacks_can_dispatch_at_most_one_exchange(signing_keys):
    login, opener, _response, received, _clock, start = _session()
    state = _start_params(start)["state"][0]
    barrier = threading.Barrier(3)
    outputs = []

    def run():
        barrier.wait()
        outputs.append(_callback(login, state))

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join(timeout=2)
    assert len(opener.calls) == 1
    assert len(received) == 1
    assert sorted(response.status for response in outputs) == [200, 410]


def test_window_expiration_and_clock_rollback_fail_closed(signing_keys):
    clock = _Clock(100.0)
    login, opener, _response, received, _clock, start = _session(clock=clock)
    state = _start_params(start)["state"][0]
    clock.value = 99.0
    result = _callback(login, state)
    assert result.status == 400 and login.terminal
    assert opener.calls == [] and received == []

    clock2 = _Clock(100.0)
    login2, opener2, _response2, received2, _clock2, start2 = _session(clock=clock2)
    state2 = _start_params(start2)["state"][0]
    clock2.value = 701.0
    expired = _callback(login2, state2)
    assert expired.status == 400 and login2.outcome == "window_expired"
    assert opener2.calls == [] and received2 == []


def test_policy_type_and_consumer_are_required_without_weakening_owner_pin(signing_keys):
    _private, keys = signing_keys
    with pytest.raises(AssistedLoginError, match="^configuration_invalid$"):
        DevOwnerAssistedLogin(object(), keys, lambda _token: None)
    with pytest.raises(AssistedLoginError, match="^configuration_invalid$"):
        DevOwnerAssistedLogin(POLICY, keys, None)
