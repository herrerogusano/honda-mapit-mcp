"""Independent malformed-input and credential-pair holdouts."""
import asyncio

import pytest

from mapit.aws_enrollment_clients import create_enrollment_clients
from test_private_enrollment import form, request, setup_channel


@pytest.mark.parametrize("mutate", [
    lambda body: body + b"&mcp=duplicate",
    lambda body: body.replace(b"&consent=yes", b"&consent=%ZZ"),
    lambda body: body + b"&csrf=extra",
])
def test_malformed_or_duplicate_form_is_rejected_without_auth_or_publish(tmp_path, mutate):
    channel, token, factory_calls, publisher, *_ = setup_channel(tmp_path)
    body = mutate(form(channel, token))
    response = request(channel, body=body, method="POST", target="/enroll")
    assert response.status == 400
    assert factory_calls == publisher.calls == []
    assert token.encode() not in response.body


def test_header_shape_and_declared_body_length_fail_closed(tmp_path):
    channel, token, factory_calls, publisher, *_ = setup_channel(tmp_path)
    body = form(channel, token)
    headers = [
        ("Host", "127.0.0.1:8787"),
        ("Origin", "http://127.0.0.1:8787"),
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Content-Length", str(len(body) + 1)),
        ("Sec-Fetch-Site", "cross-site"),
    ]
    response = request(channel, body=body, method="POST", target="/enroll", headers=headers)
    assert response.status == 400
    assert factory_calls == publisher.calls == []


def test_enrollment_clock_exception_is_closed_without_reflection(tmp_path):
    calls = [0]

    def broken_clock():
        calls[0] += 1
        if calls[0] == 1:
            return 100
        raise RuntimeError("clock-secret-canary")

    channel, token, factory_calls, publisher, *_ = setup_channel(tmp_path, clock=broken_clock)
    response = request(channel)
    assert response.status == 400
    assert b"clock-secret-canary" not in response.body
    assert factory_calls == publisher.calls == []


def test_account_verifier_accepts_only_its_exact_ssm_client_and_one_sts_attempt(monkeypatch):
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    clients = []
    original = boto3.session.Session.client

    def capture(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        clients.append(result)
        return result

    monkeypatch.setattr(boto3.session.Session, "client", capture)
    pair = create_enrollment_clients(
        access_key="synthetic-access", secret_key="synthetic-secret",
        session_token="synthetic-session", deadline=110, monotonic=lambda: 100,
    )
    assert len(clients) == 2
    assert pair.account_verifier(clients[1], "123456789012") is False
    with Stubber(clients[1]) as stub:
        stub.add_response("get_caller_identity", {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/enrollment/operator",
            "UserId": "synthetic:user",
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }, {})
        assert pair.account_verifier(pair.ssm, "123456789012") is True
        assert pair.account_verifier(pair.ssm, "123456789012") is False
        stub.assert_no_pending_responses()
