from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import FrozenInstanceError

import httpx2
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from mapit.aws_dev_runtime import (
    CognitoDevPolicy,
    cognito_dev_policy,
    create_aws_dev_runtime,
    parse_cognito_jwks,
)
from mapit.lambda_adapter import create_synthetic_lambda_handler
from mapit.remote_http import create_synthetic_http_app, dev_http_config

POOL_ID = "eu-west-1_A1b2C3d4E"
API_ID = "a1b2c3d4e5"
CLIENT_ID = "SyntheticCognitoClient012345"
OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
KID = "dev-fixture-key-1"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk(public_key, kid=KID, **extra):
    numbers = public_key.public_numbers()
    entry = {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }
    entry.update(extra)
    return entry


@pytest.fixture(scope="module")
def key_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private, {"keys": [_jwk(private.public_key())]}


@pytest.fixture(scope="module")
def runtime(key_material):
    _, jwks = key_material
    policy = cognito_dev_policy(user_pool_id=POOL_ID, api_id=API_ID, client_id=CLIENT_ID, owner_subject=OWNER)
    return create_aws_dev_runtime(policy, json.dumps(jwks, separators=(",", ":")))


def _claims(policy, **overrides):
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
    return claims


def _token(private, policy, *, kid=KID, **claims):
    return jwt.encode(_claims(policy, **claims), private, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def _rpc(method, params=None, request_id=1):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}, separators=(",", ":"))


class _LambdaContext:
    def get_remaining_time_in_millis(self):
        return 30_000


def _lambda_event(policy, token, body, *, path="/mcp", method="POST", extra_headers=None):
    raw = body.encode("utf-8")
    headers = {
        "host": policy.api_host,
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
        "content-length": str(len(raw)),
        "accept": "application/json, text/event-stream",
    }
    headers.update(extra_headers or {})
    return {
        "version": "2.0",
        "rawPath": path,
        "rawQueryString": "",
        "headers": headers,
        "requestContext": {"stage": "$default", "http": {"method": method, "path": path}},
        "body": body,
        "isBase64Encoded": False,
    }


def _invoke_lambda(runtime, event):
    return runtime.lambda_handler(event, _LambdaContext())


def test_dev_policy_derives_exact_cognito_and_execute_api_contract(runtime):
    policy = runtime.policy
    assert policy.environment == "dev"
    assert policy.issuer_url == f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL_ID}"
    assert policy.api_host == f"{API_ID}.execute-api.eu-west-1.amazonaws.com"
    assert policy.resource_url == f"https://{policy.api_host}/mcp"
    assert policy.audience == policy.resource_url
    assert policy.required_scope == policy.resource_url + "/use"
    assert policy.allowed_hosts == (policy.api_host,)
    assert policy.allowed_origins == (f"https://{policy.api_host}",)
    assert policy.max_request_body_bytes == policy.max_response_body_bytes == 2 * 1024 * 1024
    assert policy.request_deadline_seconds == 15.0
    with pytest.raises(FrozenInstanceError):
        policy.api_id = "other-apiid"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"user_pool_id": "us-east-1_A1b2C3d4E"},
        {"user_pool_id": "eu-west-1_short"},
        {"user_pool_id": "eu-west-1_A1b2C3d4E?x=y"},
        {"api_id": "short"},
        {"api_id": "A1b2c3d4e5"},
        {"api_id": "a1b2c3d4e5/path"},
        {"client_id": "client-id/with/path"},
        {"owner_subject": "not-a-uuid"},
        {"owner_subject": "18D8CE2B-8F10-4D72-B80F-EA635B4C6189"},
    ],
)
def test_dev_policy_rejects_noncanonical_or_wrong_region_inputs(kwargs):
    values = {"user_pool_id": POOL_ID, "api_id": API_ID, "client_id": CLIENT_ID, "owner_subject": OWNER}
    values.update(kwargs)
    with pytest.raises(ValueError):
        cognito_dev_policy(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"max_request_body_bytes": 1024},
        {"max_response_body_bytes": True},
        {"max_token_bytes": 16},
        {"request_deadline_seconds": 16},
        {"request_deadline_seconds": True},
        {"request_deadline_seconds": float("inf")},
    ],
)
def test_dev_policy_bounds_cannot_be_weakened(overrides):
    with pytest.raises(ValueError):
        CognitoDevPolicy(POOL_ID, API_ID, CLIENT_ID, OWNER, **overrides)


def test_jwks_parser_returns_immutable_public_pem_snapshot(key_material):
    _, jwks = key_material
    source = json.dumps(jwks, separators=(",", ":"))
    parsed = parse_cognito_jwks(source)
    assert set(parsed) == {KID}
    assert parsed[KID].startswith(b"-----BEGIN PUBLIC KEY-----")
    with pytest.raises(TypeError):
        parsed["replacement"] = b"bad"
    runtime = create_aws_dev_runtime(cognito_dev_policy(
        user_pool_id=POOL_ID, api_id=API_ID, client_id=CLIENT_ID, owner_subject=OWNER
    ), source)
    assert runtime.public_keys[KID] == parsed[KID]


@pytest.mark.parametrize("document", [
    pytest.param(b'{"keys":[],"keys":[]}', id="duplicate-json-member"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS256","n":"AQAB","e":"Aw","d":"AQ"}]}', id="private-key-material"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS256","n":"AQAB","e":"Aw","x5u":"https://evil.invalid/key"}]}', id="unsafe-key-url"),
    pytest.param(b'{"keys":[{"kty":"EC","kid":"kid","use":"sig","alg":"RS256","n":"AQAB","e":"Aw"}]}', id="wrong-key-type"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"enc","alg":"RS256","n":"AQAB","e":"Aw"}]}', id="wrong-use"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS512","n":"AQAB","e":"Aw"}]}', id="wrong-algorithm"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS256","n":"%%%","e":"Aw"}]}', id="bad-modulus"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS256","n":"AQAB","e":"Aw"}]}', id="key-too-small"),
    pytest.param(b'{"keys":[{"kty":"RSA","kid":"kid","use":"sig","alg":"RS256","n":"AQAB","e":"Aw","extra":true}]}', id="unknown-field"),
])
def test_jwks_parser_rejects_unsafe_or_malformed_fixed_snapshots(document):
    with pytest.raises(ValueError):
        parse_cognito_jwks(document)


def test_jwks_parser_rejects_oversize_raw_and_unicode_text_before_snapshot():
    with pytest.raises(ValueError):
        parse_cognito_jwks(b"{" + b" " * (32 * 1024) + b"}")
    with pytest.raises(ValueError):
        parse_cognito_jwks("\u0800" * 11_000)


def test_jwks_parser_rejects_more_than_eight_keys(key_material):
    _, jwks = key_material
    many = {"keys": [dict(jwks["keys"][0], kid=f"k{i}") for i in range(9)]}
    with pytest.raises(ValueError):
        parse_cognito_jwks(json.dumps(many))


def test_jwks_parser_rejects_rsa_modulus_under_2048_bits():
    small_private = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    with pytest.raises(ValueError):
        parse_cognito_jwks(json.dumps({"keys": [_jwk(small_private.public_key())]}))


def test_jwks_parser_rejects_duplicate_valid_kids(key_material):
    _, jwks = key_material
    duplicated = {"keys": [jwks["keys"][0], dict(jwks["keys"][0])]}
    with pytest.raises(ValueError):
        parse_cognito_jwks(json.dumps(duplicated))


def test_jwks_parser_rejects_nonminimal_base64url_uint(key_material):
    _, jwks = key_material
    n_value = jwks["keys"][0]["n"]
    n_bytes = base64.urlsafe_b64decode(n_value + "=" * ((4 - len(n_value) % 4) % 4))
    nonminimal = dict(jwks["keys"][0], n=_b64u(b"\x00" + n_bytes))
    with pytest.raises(ValueError):
        parse_cognito_jwks(json.dumps({"keys": [nonminimal]}))


def test_existing_invalid_profile_factories_reject_dev_policy(key_material):
    _, jwks = key_material
    policy = cognito_dev_policy(user_pool_id=POOL_ID, api_id=API_ID, client_id=CLIENT_ID, owner_subject=OWNER)
    keys = parse_cognito_jwks(json.dumps(jwks))
    with pytest.raises(ValueError):
        create_synthetic_http_app(policy, keys)
    with pytest.raises(ValueError):
        create_synthetic_lambda_handler(policy, keys)
    with pytest.raises(ValueError):
        create_aws_dev_runtime(object(), json.dumps(jwks))


def test_http_app_uses_real_sdk_and_all_ten_synthetic_tools(runtime, key_material):
    private, _ = key_material
    policy, app = runtime.policy, runtime.http_app
    bearer = _token(private, policy)
    origin = policy.resource_url.removesuffix("/mcp")
    date_range = {"from_time": "2026-01-01", "to_time": "2026-02-01"}

    async def scenario():
        async with app.router.lifespan_context(app):
            async with httpx2.AsyncClient(
                transport=httpx2.ASGITransport(app=app),
                base_url=origin,
                headers={"authorization": f"Bearer {bearer}"},
            ) as client:
                metadata = await client.get("/.well-known/oauth-protected-resource/mcp")
                assert metadata.status_code == 200
                assert metadata.json()["resource"] == policy.resource_url
                assert metadata.json()["scopes_supported"] == [policy.required_scope]
                async with streamable_http_client(policy.resource_url, http_client=client) as streams:
                    async with ClientSession(*streams) as session:
                        await session.initialize()
                        tools = await session.list_tools()
                        assert len(tools.tools) == 10
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
                        for name, args in calls:
                            result = await session.call_tool(name, args)
                            assert not result.is_error, name

    asyncio.run(scenario())
    assert app.synthetic_services_provider.dispatch_count >= 14


def test_lambda_composition_warm_calls_and_ten_tools(runtime, key_material):
    private, _ = key_material
    policy = runtime.policy
    bearer = _token(private, policy)
    init = _invoke_lambda(runtime, _lambda_event(policy, bearer, _rpc("initialize", {
        "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "offline-dev", "version": "1"}
    })))
    assert init["statusCode"] == 200
    listed = _invoke_lambda(runtime, _lambda_event(policy, bearer, _rpc("tools/list", request_id=2)))
    assert listed["statusCode"] == 200
    assert len(json.loads(listed["body"])["result"]["tools"]) == 10
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
    for i, (name, args) in enumerate(calls, 3):
        result = _invoke_lambda(runtime, _lambda_event(policy, bearer, _rpc("tools/call", {"name": name, "arguments": args}, i)))
        assert result["statusCode"] == 200, name
        assert json.loads(result["body"])["result"]["isError"] is False, name
    # The same sync handler is safe when a Lambda execution environment is reused.
    warm_a = _invoke_lambda(runtime, _lambda_event(policy, bearer, _rpc("tools/list", request_id=30)))
    warm_b = _invoke_lambda(runtime, _lambda_event(policy, bearer, _rpc("tools/list", request_id=31)))
    assert warm_a["statusCode"] == warm_b["statusCode"] == 200


@pytest.mark.parametrize(
    "claims,expected",
    [
        ({"iss": "https://cognito-idp.us-east-1.amazonaws.com/other"}, 401),
        ({"aud": "https://wrong.execute-api.eu-west-1.amazonaws.com/mcp"}, 401),
        ({"scope": "other"}, 403),
        ({"scope": "https://different.example/use"}, 403),
        ({"scope": "https://x/use extra"}, 403),
        ({"client_id": "another-client"}, 401),
        ({"sub": "a2a25c3e-8106-4dad-99c9-3eb8cb8e6e4d"}, 401),
        ({"token_use": "id"}, 401),
        ({"exp": True}, 401),
        ({"iat": 1.25}, 401),
        ({"nbf": None}, 401),
    ],
)
def test_jwt_mismatches_and_unknown_rotated_kid_never_authorize(runtime, key_material, claims, expected):
    private, _ = key_material
    token = _token(private, runtime.policy, **claims)
    response = _invoke_lambda(runtime, _lambda_event(runtime.policy, token, _rpc("tools/list")))
    assert response["statusCode"] == expected
    rotated = _token(private, runtime.policy, kid="unknown-rotated-key")
    unknown = _invoke_lambda(runtime, _lambda_event(runtime.policy, rotated, _rpc("tools/list")))
    assert unknown["statusCode"] == 401


def test_missing_bearer_and_forged_authorizer_claims_do_not_dispatch(runtime, monkeypatch):
    from mapit import aws_dev_runtime

    created_providers = []
    original_builder = aws_dev_runtime._build_synthetic_http_app

    def recording_builder(policy, verifier):
        app = original_builder(policy, verifier)
        created_providers.append(app.synthetic_services_provider)
        return app

    monkeypatch.setattr(aws_dev_runtime, "_build_synthetic_http_app", recording_builder)
    event = _lambda_event(runtime.policy, "", _rpc("tools/list"))
    event["requestContext"]["authorizer"] = {"jwt": {"claims": {"sub": OWNER, "scope": runtime.policy.required_scope}}}
    event["headers"].pop("authorization")
    response = _invoke_lambda(runtime, event)
    assert response["statusCode"] == 401
    assert len(created_providers) == 1
    assert created_providers[0].dispatch_count == 0
