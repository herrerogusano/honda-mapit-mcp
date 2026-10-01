from __future__ import annotations

import asyncio
import time
from dataclasses import FrozenInstanceError, replace

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.auth.settings import AuthSettings

from mapit.mcp_server import create_server
from mapit.remote_http import (
    FixedRS256TokenVerifier,
    RemoteHTTPConfig,
    _BoundedHTTPMiddleware,
    create_synthetic_http_app,
    dev_http_config,
    prod_http_config,
)


@pytest.fixture(scope="module")
def signing_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, {"synthetic-kid": public_pem}


def _claims(config, **overrides):
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
    claims.update(overrides)
    return claims


def _token(private, config, **overrides):
    return jwt.encode(
        _claims(config, **overrides),
        private,
        algorithm="RS256",
        headers={"kid": "synthetic-kid", "typ": "JWT"},
    )


def _origin(config):
    return config.resource_url.removesuffix("/mcp")


def _async_test(function):
    awaitable = function() if callable(function) else function
    return asyncio.run(awaitable)


def test_dev_prod_profiles_are_immutable_and_isolated():
    dev, prod = dev_http_config(), prod_http_config()
    assert dev.environment == "dev" and prod.environment == "prod"
    assert dev.audience != prod.audience
    assert dev.issuer_url != prod.issuer_url
    assert dev.client_id != prod.client_id
    assert dev.owner_subject != prod.owner_subject
    with pytest.raises(FrozenInstanceError):
        dev.client_id = "different"
    with pytest.raises(ValueError):
        replace(dev, resource_url="https://evil.example.invalid/mcp")
    with pytest.raises(ValueError):
        dev_http_config(request_deadline_seconds=float("nan"))


def test_config_rejects_non_integer_caps_and_url_delimiter_injection():
    with pytest.raises(ValueError):
        dev_http_config(max_request_body_bytes=1024.5)
    with pytest.raises(ValueError):
        dev_http_config(max_response_body_bytes=True)
    with pytest.raises(ValueError):
        dev_http_config(max_token_bytes=512.0)
    with pytest.raises(ValueError):
        RemoteHTTPConfig(
            environment="dev",
            issuer_url="https://issuer.dev.example.invalid#",
            resource_url="https://mapit.dev.example.invalid/mcp",
            audience="https://mapit.dev.example.invalid/mcp",
            client_id="synthetic-dev-client",
            owner_subject="synthetic-dev-owner",
            allowed_hosts=("mapit.dev.example.invalid",),
            allowed_origins=("https://mapit.dev.example.invalid",),
        )


def test_fixed_verifier_accepts_only_valid_exact_dev_access_token(signing_material):
    private, keys = signing_material
    config = dev_http_config()
    verifier = FixedRS256TokenVerifier(config, keys)
    token = _token(private, config)
    access = _async_test(verifier.verify_token(token))
    assert access is not None
    assert access.client_id == config.client_id
    assert access.subject == config.owner_subject
    assert access.resource == config.audience
    assert access.scopes == [config.required_scope]
    assert access.claims == {"iss": config.issuer_url}


@pytest.mark.parametrize(
    "override",
    [
        {"iss": "https://wrong.example.invalid"},
        {"aud": ["https://mapit.dev.example.invalid/mcp"]},
        {"aud": "https://mapit.dev.example.invalid/mcp/"},
        {"client_id": "wrong-client"},
        {"sub": "wrong-owner"},
        {"token_use": "id"},
        {"exp": True},
        {"exp": 1.5},
        {"iat": True},
        {"iat": 1.5},
        {"nbf": 1.5},
        {"nbf": None},
    ],
)
def test_fixed_verifier_rejects_claim_mismatches_and_non_integer_times(signing_material, override):
    private, keys = signing_material
    config = dev_http_config()
    verifier = FixedRS256TokenVerifier(config, keys)
    assert _async_test(verifier.verify_token(_token(private, config, **override))) is None


def test_fixed_verifier_rejects_expired_future_not_before_missing_claim_and_wrong_scope(signing_material):
    private, keys = signing_material
    config = dev_http_config()
    verifier = FixedRS256TokenVerifier(config, keys)
    now = int(time.time())
    for overrides in (
        {"exp": now - 1, "iat": now - 10},
        {"iat": now + 10},
        {"nbf": now + 30},
        {"exp": None},
    ):
        assert _async_test(verifier.verify_token(_token(private, config, **overrides))) is None
    missing_scope = _async_test(verifier.verify_token(_token(private, config, scope="mapit:read extra")))
    assert missing_scope is not None
    assert missing_scope.scopes == []


def test_fixed_verifier_rejects_tampering_unknown_kid_and_oversized_token(signing_material):
    private, keys = signing_material
    config = dev_http_config(max_token_bytes=512)
    verifier = FixedRS256TokenVerifier(config, keys)
    valid = _token(private, config)
    assert _async_test(verifier.verify_token(valid)) is None  # Synthetic RS256 tokens exceed the deliberately tiny cap.
    normal_verifier = FixedRS256TokenVerifier(dev_http_config(), keys)
    assert _async_test(normal_verifier.verify_token(valid + "x")) is None
    unknown_kid = jwt.encode(
        _claims(dev_http_config()),
        private,
        algorithm="RS256",
        headers={"kid": "unknown"},
    )
    assert _async_test(normal_verifier.verify_token(unknown_kid)) is None


def test_key_injection_rejects_private_material_wrong_key_type_and_oversize(signing_material):
    private, keys = signing_material
    with pytest.raises(ValueError):
        FixedRS256TokenVerifier(dev_http_config(), {"kid": b"bad"})
    with pytest.raises(ValueError):
        FixedRS256TokenVerifier(
            dev_http_config(),
            {"kid": private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )},
        )
    with pytest.raises(ValueError):
        FixedRS256TokenVerifier(dev_http_config(), {"kid": b"x" * 8193})
    with pytest.raises(ValueError):
        FixedRS256TokenVerifier(dev_http_config(), {f"kid-{i}": keys["synthetic-kid"] for i in range(9)})


def test_signed_dev_token_cannot_cross_into_prod_policy(signing_material):
    private, keys = signing_material
    dev_token = _token(private, dev_http_config())
    verifier = FixedRS256TokenVerifier(prod_http_config(), keys)
    assert _async_test(verifier.verify_token(dev_token)) is None


def test_authenticated_server_requires_an_explicit_provider(signing_material):
    _, keys = signing_material
    config = dev_http_config()
    verifier = FixedRS256TokenVerifier(config, keys)
    settings = AuthSettings(
        issuer_url=config.issuer_url,
        resource_server_url=config.resource_url,
        validate_token_resource=True,
        required_scopes=[config.required_scope],
    )
    with pytest.raises(ValueError):
        create_server(auth_settings=settings, token_verifier=verifier)


def test_sdk_metadata_and_auth_protocol_dispatch_only_after_valid_scope(signing_material):
    private, keys = signing_material
    config = dev_http_config()
    app = create_synthetic_http_app(config, keys)
    provider = app.synthetic_services_provider
    token = _token(private, config)
    seen_responses = []

    async def capture(response):
        seen_responses.append(response)

    async def scenario():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url=_origin(config),
                event_hooks={"response": [capture]},
            ) as client:
                metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
                assert metadata.status_code == 200
                assert metadata.json()["resource"] == config.resource_url

                missing = await client.post("/mcp", json={"jsonrpc": "2.0"})
                bad_token = "synthetic-token-must-not-appear-in-errors"
                invalid = await client.post(
                    "/mcp", headers={"Authorization": f"Bearer {bad_token}"}, json={"jsonrpc": "2.0"}
                )
                wrong_scope = await client.post(
                    "/mcp",
                    headers={"Authorization": f"Bearer {_token(private, config, scope='other')}"},
                    json={"jsonrpc": "2.0"},
                )
                assert missing.status_code == 401
                assert "resource_metadata" in missing.headers.get("www-authenticate", "")
                assert invalid.status_code == 401
                assert bad_token.encode("ascii") not in invalid.content
                assert wrong_scope.status_code == 403
                assert provider.dispatch_count == 0

                async with httpx2.AsyncClient(
                    transport=httpx2.ASGITransport(app=app),
                    base_url=_origin(config),
                    headers={"Authorization": f"Bearer {token}"},
                    event_hooks={"response": [capture]},
                ) as authenticated:
                    async with streamable_http_client(config.resource_url, http_client=authenticated) as streams:
                        async with ClientSession(*streams) as session:
                            await session.initialize()
                            tools = await session.list_tools()
                            assert len(tools.tools) == 10
                            common_range = {"from_time": "2026-01-01", "to_time": "2026-02-01"}
                            calls = (
                                ("get_vehicle_status", {}),
                                ("get_vehicle_details", {}),
                                ("list_routes", common_range),
                                ("get_route_detail", {"route_id": "synthetic-route"}),
                                ("get_distance", common_range),
                                (
                                    "compare_distance_periods",
                                    {
                                        "period_a": common_range,
                                        "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"},
                                    },
                                ),
                                ("get_route_statistics", common_range),
                                ("get_distance_breakdown", {**common_range, "group_by": "day"}),
                                ("get_route_extremes", common_range),
                                (
                                    "compare_route_periods",
                                    {
                                        "period_a": common_range,
                                        "period_b": {"from_time": "2026-02-01", "to_time": "2026-03-01"},
                                    },
                                ),
                            )
                            for name, arguments in calls:
                                result = await session.call_tool(name, arguments)
                                assert not result.is_error, name
                assert provider.dispatch_count == 14
                assert seen_responses
                assert all(response.headers.get("mcp-session-id") is None for response in seen_responses)

                method = await client.get("/mcp")
                assert method.status_code == 405

    _async_test(scenario)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ({"Host": "evil.example.invalid"}, 400),
        ({"Origin": "https://evil.example.invalid"}, 400),
    ],
)
def test_host_and_origin_exact_allowlists_reject_before_dispatch(signing_material, headers, expected):
    private, keys = signing_material
    app = create_synthetic_http_app(dev_http_config(), keys)

    async def scenario():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url=_origin(dev_http_config()),
                headers={"Authorization": f"Bearer {_token(private, dev_http_config())}", **headers},
            ) as client:
                response = await client.post("/mcp", json={"jsonrpc": "2.0"})
                assert response.status_code == expected
        assert app.synthetic_services_provider.dispatch_count == 0

    _async_test(scenario)


def test_duplicate_authorization_header_is_rejected_without_dispatch(signing_material):
    private, keys = signing_material
    app = create_synthetic_http_app(dev_http_config(), keys)
    token = _token(private, dev_http_config())

    async def scenario():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url=_origin(dev_http_config()),
            ) as client:
                response = await client.post(
                    "/mcp",
                    headers=[("authorization", f"Bearer {token}"), ("Authorization", f"Bearer {token}")],
                    json={"jsonrpc": "2.0"},
                )
                assert response.status_code == 400
        assert app.synthetic_services_provider.dispatch_count == 0

    _async_test(scenario)


def test_request_body_limit_rejects_oversize_before_dispatch(signing_material):
    private, keys = signing_material
    config = dev_http_config(max_request_body_bytes=1024)
    app = create_synthetic_http_app(config, keys)

    async def scenario():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url=_origin(config),
                headers={"Authorization": f"Bearer {_token(private, config)}"},
            ) as client:
                response = await client.post("/mcp", content=b"x" * 1025)
                assert response.status_code == 413
        assert app.synthetic_services_provider.dispatch_count == 0

    _async_test(scenario)


def test_deadline_returns_sanitized_buffered_504_and_never_flushes_partial_response():
    config = dev_http_config(request_deadline_seconds=0.05)

    async def slow_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"partial-secret"})
        await asyncio.sleep(0.2)

    middleware = _BoundedHTTPMiddleware(slow_app, config)

    async def scenario():
        outgoing = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            outgoing.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [(b"host", b"mapit.dev.example.invalid")],
        }
        await middleware(scope, receive, send)
        assert outgoing[0]["status"] == 504
        assert b"partial-secret" not in b"".join(event.get("body", b"") for event in outgoing)

    _async_test(scenario)


def test_response_buffer_limit_fails_closed_without_partial_body():
    config = dev_http_config(max_response_body_bytes=1024)

    async def oversized_app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"s" * 1025})

    middleware = _BoundedHTTPMiddleware(oversized_app, config)

    async def scenario():
        outgoing = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            outgoing.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [(b"host", b"mapit.dev.example.invalid")],
        }
        await middleware(scope, receive, send)
        assert outgoing[0]["status"] == 502
        assert len(outgoing) == 2

    _async_test(scenario)


def test_header_count_and_aggregate_bytes_are_bounded_before_dispatch():
    config = dev_http_config()
    app_called = False

    async def app(scope, receive, send):
        nonlocal app_called
        app_called = True

    middleware = _BoundedHTTPMiddleware(app, config)

    async def invoke(headers):
        outgoing = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            outgoing.append(message)

        await middleware(
            {"type": "http", "method": "POST", "path": "/mcp", "headers": headers},
            receive,
            send,
        )
        return outgoing

    async def scenario():
        too_many = [(b"host", b"mapit.dev.example.invalid")] + [(b"x-test", b"a") for _ in range(64)]
        too_large = [(b"host", b"mapit.dev.example.invalid"), (b"x-test", b"a" * (32 * 1024))]
        assert (await invoke(too_many))[0]["status"] == 400
        assert (await invoke(too_large))[0]["status"] == 400
        assert app_called is False

    _async_test(scenario)


def test_request_receive_exception_returns_fixed_error_without_exception_text():
    config = dev_http_config()
    app_called = False

    async def app(scope, receive, send):
        nonlocal app_called
        app_called = True

    middleware = _BoundedHTTPMiddleware(app, config)

    async def scenario():
        outgoing = []

        async def receive():
            raise RuntimeError("synthetic-header-token-claim-secret")

        async def send(message):
            outgoing.append(message)

        await middleware(
            {
                "type": "http",
                "method": "POST",
                "path": "/mcp",
                "headers": [(b"host", b"mapit.dev.example.invalid")],
            },
            receive,
            send,
        )
        body = b"".join(event.get("body", b"") for event in outgoing)
        assert outgoing[0]["status"] == 400
        assert body == b'{"error":"invalid_request"}'
        assert b"synthetic-header-token-claim-secret" not in body
        assert app_called is False

    _async_test(scenario)
