import asyncio
import re
import time
from urllib.parse import urlencode

import jwt
import pytest

from mapit.durable_tenants import DurableTenantGuard
from mapit.private_enrollment import PrivateEnrollmentChannel
from mapit.tenant_router import InvitedTenantAuthority
from test_identity_binding import KEY_A, NOW, SUBJECT_A, TOKEN_A, _make_setup, _Publisher, _rsa_pair


def setup_channel(tmp_path, *, publisher=None, clock=None):
    setup = _make_setup(tmp_path)
    private, public = _rsa_pair()
    authority = InvitedTenantAuthority(setup["authority"]._policies, {"enroll-key": public}, environment="dev")
    guard = DurableTenantGuard(authority, setup["tenants"])
    registry = setup["factory"](selected_authority=authority, selected_guard=guard)
    policy = authority._policies[KEY_A]
    token = jwt.encode({"iss": policy.issuer_url, "aud": policy.audience,
        "sub": SUBJECT_A, "client_id": policy.client_id, "token_use": "access",
        "iat": int(time.time()) - 1, "exp": int(time.time()) + 300,
        "scope": policy.required_scope}, private, algorithm="RS256", headers={"kid": "enroll-key"})
    calls = []
    publisher = publisher if publisher is not None else _Publisher()
    def factory(**kwargs):
        calls.append(kwargs)
        return publisher
    channel = PrivateEnrollmentChannel(authority=authority, durable_guard=guard,
        registry=registry, publisher_factory=factory, port=8787, deadline=110,
        monotonic=clock if clock is not None else lambda: 100)
    return channel, token, calls, publisher, registry, authority, guard


def request(channel, *, body=None, method="GET", target="/", headers=None, peer="127.0.0.1"):
    fields = [("Host", "127.0.0.1:8787")]
    if body is not None:
        fields += [("Origin", "http://127.0.0.1:8787"),
                   ("Content-Type", "application/x-www-form-urlencoded"),
                   ("Content-Length", str(len(body)))]
    if headers is not None:
        fields = headers
    return asyncio.run(channel.request(method, target, fields, body or b"", peer=peer))


def form(channel, token, **changes):
    page = request(channel).body.decode()
    csrf = re.search("name='csrf' value='([^']+)'", page)[1]
    fields = dict(csrf=csrf, mcp=token, mapit=TOKEN_A, consent="yes")
    fields.update(changes)
    return urlencode(fields).encode()


def test_signed_invited_local_enrollment_and_no_token_reflection(tmp_path):
    channel, token, calls, publisher, registry, authority, guard = setup_channel(tmp_path)
    body = form(channel, token)
    response = request(channel, body=body, method="POST", target="/enroll")
    assert response.status == 200
    assert len(calls) == len(publisher.calls) == 1
    assert token.encode() not in response.body and TOKEN_A.encode() not in response.body
    grant = asyncio.run(authority.authenticate(token))
    assert registry.get_binding(grant, guard.capture(grant)).tenant_key == KEY_A
    assert request(channel, body=body, method="POST", target="/enroll").status == 400
    assert len(publisher.calls) == 1
    assert dict(response.headers)["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in dict(response.headers)["Content-Security-Policy"]


@pytest.mark.parametrize("case", ["host", "origin", "duplicate", "peer", "query", "consent", "csrf", "extra", "oversize", "getpost", "transfer"])
def test_invalid_request_never_authenticates_or_publishes(tmp_path, case):
    channel, token, calls, publisher, *_ = setup_channel(tmp_path)
    body = form(channel, token)
    headers = [("Host", "127.0.0.1:8787"), ("Origin", "http://127.0.0.1:8787"),
               ("Content-Type", "application/x-www-form-urlencoded"), ("Content-Length", str(len(body)))]
    peer, target, method = "127.0.0.1", "/enroll", "POST"
    if case == "host": headers[0] = ("Host", "evil.example")
    if case == "origin": headers[1] = ("Origin", "https://evil.example")
    if case == "duplicate": headers.append(headers[0])
    if case == "transfer": headers.append(("Transfer-Encoding", "chunked"))
    if case == "peer": peer = "192.0.2.1"
    if case == "query": target += "?token=canary"
    if case == "getpost": method = "GET"
    if case == "consent": body = form(channel, token, consent="no")
    if case == "csrf": body = form(channel, token, csrf="wrong")
    if case == "extra": body += b"&tenant=owner"
    if case == "oversize": body = b"x" * 32769
    headers[3] = ("Content-Length", str(len(body)))
    response = request(channel, body=body, method=method, target=target, headers=headers, peer=peer)
    assert response.status == 400
    assert calls == publisher.calls == []
    assert token.encode() not in response.body


def test_failed_publication_is_terminal_and_redacted(tmp_path):
    channel, token, calls, publisher, *_ = setup_channel(tmp_path, publisher=_Publisher(fail=True))
    body = form(channel, token)
    response = request(channel, body=body, method="POST", target="/enroll")
    assert response.status == 409
    assert b"publisher-canary" not in response.body
    assert request(channel, body=body, method="POST", target="/enroll").status == 400
    assert len(calls) == len(publisher.calls) == 1


def test_invalid_signature_consumes_channel_but_never_publishes(tmp_path):
    channel, token, calls, publisher, *_ = setup_channel(tmp_path)
    body = form(channel, "not-signed")
    assert request(channel, body=body, method="POST", target="/enroll").status == 409
    assert calls == publisher.calls == []
    assert request(channel).status == 400


def test_expiry_and_clock_rollback_reject_before_publication(tmp_path):
    now = [100]
    channel, token, calls, publisher, *_ = setup_channel(tmp_path, clock=lambda: now[0])
    body = form(channel, token)
    now[0] = 99
    assert request(channel, body=body, method="POST", target="/enroll").status == 400
    now[0] = 110
    assert request(channel).status == 400
    assert calls == publisher.calls == []


def test_revoked_invitation_cannot_publish(tmp_path):
    channel, token, calls, publisher, registry, authority, guard = setup_channel(tmp_path)
    body = form(channel, token)
    authority.revoke(KEY_A)
    assert request(channel, body=body, method="POST", target="/enroll").status == 409
    assert calls == publisher.calls == []


def test_window_expiry_after_commit_requires_inspection_not_resubmission(tmp_path):
    now = [100]
    publisher = _Publisher(after_publish=lambda: now.__setitem__(0, 110))
    channel, token, calls, _, registry, authority, guard = setup_channel(tmp_path,
        publisher=publisher, clock=lambda: now[0])
    body = form(channel, token)
    response = request(channel, body=body, method="POST", target="/enroll")
    assert response.status == 409 and "no vuelvas" in response.body.decode()
    grant = asyncio.run(authority.authenticate(token))
    assert registry.get_binding(grant, guard.capture(grant)).tenant_key == KEY_A
    assert len(calls) == len(publisher.calls) == 1
    assert request(channel, body=body, method="POST", target="/enroll").status == 400


def test_loopback_server_bounds_socket_before_header_parsing():
    import socket
    from http.server import BaseHTTPRequestHandler
    from mapit.private_enrollment import _LoopbackServer
    with _LoopbackServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as server:
        with socket.create_connection(server.server_address, timeout=1):
            connection, address = server.get_request()
            try:
                assert connection.gettimeout() == 2
                assert address[0] == "127.0.0.1"
            finally:
                connection.close()
