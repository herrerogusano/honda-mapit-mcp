"""Independent bounded-event and response tests for the local Lambda adapter."""

import base64
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit import lambda_adapter
from mapit.lambda_adapter import create_synthetic_lambda_handler
from mapit.remote_http import dev_http_config


@pytest.fixture(scope="module")
def verification_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"independent-lambda-kid": public}


class _Context:
    def __init__(self, remaining_ms):
        self.remaining_ms = remaining_ms

    def get_remaining_time_in_millis(self):
        return self.remaining_ms


def _event(config, *, body="{}", headers=None):
    return {
        "version": "2.0",
        "rawPath": "/mcp",
        "rawQueryString": "",
        "headers": {"host": config.allowed_hosts[0], **(headers or {})},
        "requestContext": {"http": {"method": "POST", "path": "/mcp"}},
        "body": body,
        "isBase64Encoded": False,
    }


def _install_fake_app(monkeypatch, app):
    @asynccontextmanager
    async def lifespan(_app):
        yield

    app.router = SimpleNamespace(lifespan_context=lifespan)
    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", lambda *_args: app)


def test_extremely_large_integer_context_budget_fails_closed(verification_keys):
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, verification_keys)
    result = handler(_event(config), _Context(10**10_000))
    assert result["statusCode"] == 504
    assert result["body"] == '{"error":"request_timed_out"}'


@pytest.mark.parametrize("bad_value", ["bad\r\ninjected: x", "bad\x00header"])
def test_request_header_controls_fail_closed_before_app_creation(verification_keys, monkeypatch, bad_value):
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, verification_keys)
    app_created = False

    def factory(*_args):
        nonlocal app_created
        app_created = True
        raise AssertionError("rejected event must not construct the MCP app")

    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", factory)
    result = handler(_event(config, headers={"x-test": bad_value}), _Context(30_000))
    assert result["statusCode"] == 400
    assert app_created is False
    assert bad_value not in result["body"]


def test_multibyte_unencoded_request_is_capped_after_utf8_encoding(verification_keys, monkeypatch):
    config = dev_http_config(max_request_body_bytes=1024)
    handler = create_synthetic_lambda_handler(config, verification_keys)
    app_created = False

    def factory(*_args):
        nonlocal app_created
        app_created = True
        raise AssertionError("oversized event must not construct the MCP app")

    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", factory)
    result = handler(_event(config, body="é" * 600), _Context(30_000))
    assert result["statusCode"] == 413
    assert app_created is False


def test_response_event_limit_applies_even_after_first_bad_event(verification_keys, monkeypatch):
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, verification_keys)
    attempted_events = 0

    async def noisy_app(_scope, _receive, send):
        nonlocal attempted_events
        await send({"type": "http.response.start", "status": 200, "headers": [(b"x-test", b"bad\r\ninjection")]})
        for _ in range(5000):
            attempted_events += 1
            await send({"type": "not-an-asgi-event"})

    _install_fake_app(monkeypatch, noisy_app)
    result = handler(_event(config), _Context(30_000))
    assert result["statusCode"] == 502
    assert result["body"] == '{"error":"invalid_upstream_response"}'
    assert attempted_events <= 1024
    assert "injection" not in result["body"]


def test_proxy_envelope_cap_accounts_for_json_escaping(verification_keys, monkeypatch):
    config = dev_http_config(max_response_body_bytes=1024)
    handler = create_synthetic_lambda_handler(config, verification_keys)

    async def quoted_response(_scope, _receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        # The HTTP body is below the cap, but the escaped proxy envelope exceeds it.
        await send({"type": "http.response.body", "body": b'"' * 600, "more_body": False})

    _install_fake_app(monkeypatch, quoted_response)
    result = handler(_event(config), _Context(30_000))
    assert result["statusCode"] == 502
    assert result["body"] == '{"error":"invalid_upstream_response"}'
    assert "\\\"" not in result["body"]


def test_valid_base64_with_multibyte_utf8_bytes_is_not_double_counted(verification_keys, monkeypatch):
    config = dev_http_config(max_request_body_bytes=1024)
    handler = create_synthetic_lambda_handler(config, verification_keys)
    captured = {}

    async def safe_response(scope, _receive, send):
        captured.update(scope)
        await send({"type": "http.response.start", "status": 401, "headers": []})
        await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}', "more_body": False})

    _install_fake_app(monkeypatch, safe_response)
    body = "é".encode("utf-8")
    payload = _event(config, body=base64.b64encode(body).decode("ascii"))
    payload["isBase64Encoded"] = True
    result = handler(payload, _Context(30_000))
    assert result["statusCode"] == 401
    # Raw body bytes are intentionally not projected into request headers or context.
    assert captured["client"] is None
    assert captured["state"] == {}
