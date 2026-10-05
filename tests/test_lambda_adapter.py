from __future__ import annotations

import base64
import json
import time
from collections import UserDict

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.lambda_adapter import create_synthetic_lambda_handler
from mapit.remote_http import dev_http_config, prod_http_config


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, {"lambda-test-key": public}


def token(private, config, **override):
    now = int(time.time())
    claims = {
        "iss": config.issuer_url,
        "aud": config.audience,
        "sub": config.owner_subject,
        "client_id": config.client_id,
        "token_use": "access",
        "iat": now,
        "exp": now + 300,
        "scope": config.required_scope,
    }
    claims.update(override)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "lambda-test-key", "typ": "JWT"})


class Context:
    def __init__(self, remaining=30_000):
        self.remaining = remaining
        self.calls = 0

    def get_remaining_time_in_millis(self):
        self.calls += 1
        return self.remaining


def event(config, *, method="POST", path="/mcp", body="", headers=None, **overrides):
    host = config.allowed_hosts[0]
    selected_headers = {"host": host, **(headers or {})}
    payload = {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": "",
        "headers": selected_headers,
        "requestContext": {
            "http": {"method": method, "path": path},
            # Claims are deliberately present in some tests; they are never trusted.
            "authorizer": {"jwt": {"claims": {"sub": "forged"}}},
        },
        "body": body,
        "isBase64Encoded": False,
    }
    payload.update(overrides)
    return payload


def rpc(method, params=None, request_id=1):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}, separators=(",", ":"))


def invoke(handler, payload, remaining=30_000):
    return handler(payload, Context(remaining))


def test_handler_projects_valid_v2_requests_and_runs_all_synthetic_tools(signing_material):
    private, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    auth = {"authorization": f"Bearer {token(private, config)}", "content-type": "application/json", "accept": "application/json, text/event-stream"}

    initialized = invoke(handler, event(config, body=rpc("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "offline-test", "version": "1"}
    }), headers=auth))
    assert initialized["statusCode"] == 200
    init_json = json.loads(initialized["body"])
    assert init_json["result"]["serverInfo"]["name"]
    assert initialized["isBase64Encoded"] is False

    listed = invoke(handler, event(config, body=rpc("tools/list", request_id=2), headers=auth))
    assert listed["statusCode"] == 200
    names = {tool["name"] for tool in json.loads(listed["body"])["result"]["tools"]}
    assert len(names) == 10
    date_range = {"from_time": "2026-01-01", "to_time": "2026-02-01"}
    calls = (
        ("get_vehicle_status", {}),
        ("get_vehicle_details", {}),
        ("list_routes", date_range),
        ("get_route_detail", {"route_id": "synthetic-route"}),
        ("get_distance", date_range),
        ("compare_distance_periods", {"period_a": date_range, "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"}}),
        ("get_route_statistics", date_range),
        ("get_distance_breakdown", {**date_range, "group_by": "day"}),
        ("get_route_extremes", date_range),
        ("compare_route_periods", {"period_a": date_range, "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"}}),
    )
    for i, (name, arguments) in enumerate(calls, 3):
        response = invoke(handler, event(config, body=rpc("tools/call", {"name": name, "arguments": arguments}, i), headers=auth))
        assert response["statusCode"] == 200, name
        assert json.loads(response["body"])["result"]["isError"] is False, name


def test_handler_sequential_warm_style_invocations_create_fresh_loop(signing_material):
    private, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    auth = {"authorization": f"Bearer {token(private, config)}", "content-type": "application/json", "accept": "application/json, text/event-stream"}
    request = event(config, body=rpc("tools/list"), headers=auth)
    first = invoke(handler, request)
    second = invoke(handler, request)
    assert first["statusCode"] == second["statusCode"] == 200
    assert first["body"] == second["body"]


def test_metadata_route_and_sdk_auth_challenges_are_preserved(signing_material):
    private, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    metadata = invoke(handler, event(config, method="GET", path="/.well-known/oauth-protected-resource/mcp"))
    assert metadata["statusCode"] == 200
    assert json.loads(metadata["body"])["resource"] == config.resource_url
    missing = invoke(handler, event(config, body=rpc("tools/list")))
    assert missing["statusCode"] == 401
    assert "resource_metadata" in missing["headers"]["www-authenticate"]
    assert "no-store" in missing["headers"]["cache-control"]
    invalid = invoke(handler, event(config, body=rpc("tools/list"), headers={"authorization": "Bearer secret-not-a-token"}))
    assert invalid["statusCode"] == 401
    assert "secret-not-a-token" not in invalid["body"]
    wrong_scope = token(private, config, scope="other")
    denied = invoke(handler, event(config, body=rpc("tools/list"), headers={"authorization": f"Bearer {wrong_scope}"}))
    assert denied["statusCode"] == 403
    assert "insufficient_scope" in denied["body"]


def test_forged_authorizer_claims_are_not_authentication(signing_material):
    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    response = invoke(handler, event(config, body=rpc("tools/list")))
    assert response["statusCode"] == 401


def test_authentication_failures_do_not_dispatch_synthetic_services(signing_material, monkeypatch):
    from mapit import lambda_adapter
    from mapit.remote_http import create_synthetic_http_app as original_factory

    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    created = []
    def factory(*args):
        app = original_factory(*args)
        created.append(app.synthetic_services_provider)
        return app
    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", factory)
    for auth_header in (None, "Bearer invalid-token"):
        headers = {} if auth_header is None else {"authorization": auth_header}
        response = invoke(handler, event(config, body=rpc("tools/list"), headers=headers))
        assert response["statusCode"] == 401
    assert len(created) == 2
    assert all(provider.dispatch_count == 0 for provider in created)


def test_dev_token_does_not_cross_environment(signing_material):
    private, keys = signing_material
    dev, prod = dev_http_config(), prod_http_config()
    handler = create_synthetic_lambda_handler(prod, keys)
    response = invoke(handler, event(prod, body=rpc("tools/list"), headers={"authorization": f"Bearer {token(private, dev)}"}))
    assert response["statusCode"] == 401


def test_mcp_get_returns_method_allow_header(signing_material):
    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    response = invoke(handler, event(config, method="GET", path="/mcp"))
    assert response["statusCode"] == 405
    assert response["headers"]["allow"] == "POST"


@pytest.mark.parametrize("patch", [
    {"version": "1.0"},
    {"rawPath": "/stage/mcp"},
    {"rawQueryString": "x=1"},
    {"queryStringParameters": {"x": "1"}},
    {"cookies": ["sid=not-forwarded"]},
    {"isBase64Encoded": 1},
    {"isBase64Encoded": "false"},
    {"body": "%%%", "isBase64Encoded": True},
])
def test_malformed_event_shapes_fail_closed(patch, signing_material):
    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    response = invoke(handler, event(config, **patch))
    assert response["statusCode"] in {400, 404}
    assert response["headers"]["cache-control"] == "no-store"


def test_body_and_header_bounds_and_duplicate_security_fields(signing_material):
    _, keys = signing_material
    config = dev_http_config(max_request_body_bytes=1024)
    handler = create_synthetic_lambda_handler(config, keys)
    huge = invoke(handler, event(config, body="x" * 1025))
    assert huge["statusCode"] == 413
    encoded_huge = invoke(handler, event(config, body=base64.b64encode(b"x" * 1025).decode(), isBase64Encoded=True))
    assert encoded_huge["statusCode"] == 413
    duplicate = invoke(handler, event(config, headers={"Host": config.allowed_hosts[0], "host": config.allowed_hosts[0]}))
    assert duplicate["statusCode"] == 400
    ambiguous = invoke(handler, event(config, headers={"origin": "https://one.invalid, https://two.invalid"}))
    assert ambiguous["statusCode"] == 400
    # Accept is intentionally allowed to carry the protocol's comma-separated media types.
    allowed_accept = invoke(handler, event(config, headers={"accept": "application/json, text/event-stream"}))
    assert allowed_accept["statusCode"] == 401
    for unsafe in ("a\r\nb", "a\x00b"):
        assert invoke(handler, event(config, headers={"x-test": unsafe}))["statusCode"] == 400
    long_content_length = invoke(handler, event(config, body="{}", headers={"content-length": "9" * 5000}))
    assert long_content_length["statusCode"] == 400
    valid_base64 = invoke(handler, event(config, body=base64.b64encode(b"{}").decode(), isBase64Encoded=True,
                                         headers={"content-type": "application/json"}))
    assert valid_base64["statusCode"] == 401


def test_content_length_must_match_and_authorizer_context_is_not_mutated(signing_material):
    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    payload = event(config, body=rpc("tools/list"), headers={"content-length": "1"})
    before = json.dumps(payload, sort_keys=True)
    result = invoke(handler, payload)
    assert result["statusCode"] == 400
    assert json.dumps(payload, sort_keys=True) == before


@pytest.mark.parametrize(
    "remaining",
    [None, True, False, 0, -1, 999, 1000, 1001, 1.5, "30000", pytest.param(10**10000, id="overflow-int")],
)
def test_invalid_or_insufficient_remaining_time_fails_before_event_access(remaining):
    class ExplodingEvent:
        def get(self, *_args):
            raise AssertionError("event accessed before time context")

    class Ctx:
        def get_remaining_time_in_millis(self):
            return remaining

    handler = create_synthetic_lambda_handler(dev_http_config(), _dummy_keys())
    result = handler(ExplodingEvent(), Ctx())
    assert result["statusCode"] == 504


def _dummy_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return {"temporary": key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)}


def test_root_path_must_match_request_context_and_unknown_headers_are_not_forwarded(signing_material, monkeypatch):
    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)
    conflicting = event(config, body=rpc("tools/list"))
    conflicting["requestContext"]["http"]["path"] = "/stage/mcp"
    assert invoke(handler, conflicting)["statusCode"] == 404
    staged = event(config, body=rpc("tools/list"))
    staged["requestContext"]["stage"] = "named-stage"
    assert invoke(handler, staged)["statusCode"] == 400

    from mapit import lambda_adapter
    captured = {}
    async def fake_app(scope, _receive, send):
        captured.update(scope)
        await send({"type": "http.response.start", "status": 401, "headers": []})
        await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}', "more_body": False})
    class Router:
        @staticmethod
        def lifespan_context(_app):
            from contextlib import asynccontextmanager
            @asynccontextmanager
            async def manager():
                yield
            return manager()
    fake_app.router = Router()
    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", lambda *_: fake_app)
    response = invoke(handler, event(config, headers={"x-forwarded-for": "203.0.113.8", "accept": "a,b"}))
    assert response["statusCode"] == 401
    assert all(name != b"x-forwarded-for" for name, _ in captured["headers"])


def _fake_app(app_callable):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(_app):
        yield

    app_callable.router = type("Router", (), {"lifespan_context": staticmethod(lambda _app: lifespan(_app))})()
    return app_callable


def test_oversized_asgi_response_is_discarded_with_fixed_502(signing_material, monkeypatch):
    from mapit import lambda_adapter

    _, keys = signing_material
    config = dev_http_config(max_response_body_bytes=1024)
    handler = create_synthetic_lambda_handler(config, keys)
    async def oversized(_scope, _receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": b"s" * 2048, "more_body": False})
    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", lambda *_: _fake_app(oversized))
    result = invoke(handler, event(config, body="{}"))
    assert result["statusCode"] == 502
    assert "s" * 40 not in result["body"]


def test_deadline_discards_partial_asgi_body_without_claiming_hard_cancellation(signing_material, monkeypatch):
    import asyncio
    from mapit import lambda_adapter

    _, keys = signing_material
    config = dev_http_config(request_deadline_seconds=0.05)
    handler = create_synthetic_lambda_handler(config, keys)
    async def slow(_scope, _receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"partial-sensitive", "more_body": True})
        await asyncio.sleep(0.2)
    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", lambda *_: _fake_app(slow))
    result = invoke(handler, event(config, body="{}"))
    assert result["statusCode"] == 504
    assert "partial-sensitive" not in result["body"]


@pytest.mark.parametrize("response_mode", ["header_injection", "unfinished", "body_after_end", "too_many_events"])
def test_malformed_asgi_response_sequence_fails_closed(response_mode, signing_material, monkeypatch):
    from mapit import lambda_adapter

    _, keys = signing_material
    config = dev_http_config()
    handler = create_synthetic_lambda_handler(config, keys)

    async def malformed(_scope, _receive, send):
        headers = [(b"x-test", b"safe\r\nInjected: bad")] if response_mode == "header_injection" else []
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        if response_mode == "unfinished":
            await send({"type": "http.response.body", "body": b"partial", "more_body": True})
        elif response_mode == "body_after_end":
            await send({"type": "http.response.body", "body": b"first", "more_body": False})
            await send({"type": "http.response.body", "body": b"second", "more_body": False})
        elif response_mode == "too_many_events":
            for _ in range(1100):
                await send({"type": "http.response.body", "body": b"", "more_body": True})

    monkeypatch.setattr(lambda_adapter, "create_synthetic_http_app", lambda *_: _fake_app(malformed))
    result = invoke(handler, event(config, body="{}"))
    assert result["statusCode"] == 502
    assert "partial" not in result["body"]
