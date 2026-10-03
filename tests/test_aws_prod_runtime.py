import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_dev_runtime import CognitoDevPolicy, create_aws_dev_runtime
from mapit.aws_prod_runtime import CognitoProdPolicy, create_aws_prod_runtime
from mapit.aws_session_reader import AwsSessionReadResult
from mapit.cloud_provider import CloudServicesProvider
from mapit.config import MapitConfig

OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
POLICY = dict(user_pool_id="eu-west-1_A1b2C3d4E", api_id="a1b2c3d4e5",
              client_id="SyntheticProdClient012345", owner_subject=OWNER)
TOKEN = "synthetic-only-refresh-canary"


@pytest.fixture(scope="module")
def keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private.public_key().public_numbers()
    def encode(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    snapshot = json.dumps({"keys": [{"kty": "RSA", "kid": "prod-test", "use": "sig", "alg": "RS256",
                                     "n": encode(numbers.n), "e": encode(numbers.e)}]})
    return private, snapshot


class Context:
    def __init__(self, remaining=15000):
        self.remaining = remaining
    def get_remaining_time_in_millis(self):
        return self.remaining


class Upstream:
    def __init__(self):
        self.reads = 0
        self.auth_calls = 0
        self.mapit_calls = 0
        self.providers = []
        self.deadlines = []

    def read_refresh_token(self, *, deadline):
        assert time.monotonic() < deadline
        self.reads += 1
        return AwsSessionReadResult(True, "session_read_verified", 1, "Standard", TOKEN)

    def auth(self, url, headers, payload):
        self.auth_calls += 1
        target = headers["X-Amz-Target"].split(".")[-1]
        if target == "InitiateAuth":
            return {"AuthenticationResult": {"IdToken": "synthetic-id-token", "ExpiresIn": 3600}}
        if target == "GetId":
            return {"IdentityId": "eu-west-1:synthetic-identity"}
        return {"Credentials": {"AccessKeyId": "synthetic-key", "SecretKey": "synthetic-secret",
                                 "SessionToken": "synthetic-session", "Expiration": time.time() + 3600}}

    def mapit(self, method, url, headers):
        self.mapit_calls += 1
        assert method == "GET"
        return json.dumps({"vehicles": [{"id": "synthetic-vehicle",
                                          "device": {"state": {"status": "parked"}}}]}).encode()

    def build(self, deadline):
        self.deadlines.append(deadline)
        config = MapitConfig(
            user_pool_id="eu-west-1_A1b2C3d4E", user_pool_client_id="SyntheticMapitClient012345",
            identity_pool_id="eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
            discovery_enabled=False, http_timeout=2.0,
        )
        provider = CloudServicesProvider(config, self, self.auth, self.mapit, deadline=deadline)
        self.providers.append(provider)
        return provider


def token(private, policy, **overrides):
    now = int(time.time())
    claims = dict(iss=policy.issuer_url, aud=policy.audience, sub=OWNER, client_id=policy.client_id,
                  token_use="access", iat=now, exp=now + 300, scope=policy.required_scope)
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "prod-test", "typ": "JWT"})


def event(policy, access=None, *, method="tools/call", path="/mcp"):
    params = {} if method == "tools/list" else {"name": "get_vehicle_status", "arguments": {}}
    body = "" if path != "/mcp" else json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    )
    headers = {"host": policy.api_host, "content-type": "application/json",
               "accept": "application/json, text/event-stream", "content-length": str(len(body.encode()))}
    if access:
        headers["authorization"] = "Bearer " + access
    http_method = "GET" if path != "/mcp" else "POST"
    return {"version": "2.0", "rawPath": path, "rawQueryString": "", "headers": headers,
            "requestContext": {"stage": "$default", "http": {"method": http_method, "path": path}},
            "body": body, "isBase64Encoded": False}


def test_prod_type_is_distinct_and_dev_factory_remains_closed(keys):
    policy = CognitoProdPolicy(**POLICY)
    assert policy.environment == "prod" and policy.request_deadline_seconds == 14
    with pytest.raises(ValueError):
        create_aws_dev_runtime(policy, keys[1])
    with pytest.raises(ValueError):
        create_aws_prod_runtime(CognitoDevPolicy(**POLICY), keys[1], provider_builder=Upstream().build)


@pytest.mark.parametrize("deadline", [14.1, 15, True, float("inf"), 0])
def test_prod_deadline_preserves_serialization_reserve(deadline):
    with pytest.raises(ValueError):
        CognitoProdPolicy(**POLICY, request_deadline_seconds=deadline)


def test_construction_and_metadata_do_not_read_secret_or_authenticate(keys):
    upstream = Upstream()
    policy = CognitoProdPolicy(**POLICY)
    runtime = create_aws_prod_runtime(policy, keys[1], provider_builder=upstream.build)
    assert not upstream.providers and upstream.reads == 0
    response = runtime.lambda_handler(event(policy, path="/.well-known/oauth-protected-resource/mcp"), Context())
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["resource"] == policy.resource_url
    assert upstream.reads == upstream.auth_calls == upstream.mapit_calls == 0


@pytest.mark.parametrize("claims", [{"sub": "another-owner"}, {"client_id": "wrong-client"},
                                    {"aud": "https://other.invalid/mcp"}, {"token_use": "id"},
                                    {"scope": "wrong-scope"}, {"exp": 1}])
def test_negative_authorization_consumes_no_secret_or_upstream_attempt(keys, claims):
    upstream = Upstream()
    policy = CognitoProdPolicy(**POLICY)
    runtime = create_aws_prod_runtime(policy, keys[1], provider_builder=upstream.build)
    response = runtime.lambda_handler(event(policy, token(keys[0], policy, **claims)), Context())
    assert response["statusCode"] in (401, 403)
    assert upstream.reads == upstream.auth_calls == upstream.mapit_calls == 0
    assert TOKEN not in response["body"]


def test_each_tool_invocation_has_fresh_provider_without_warm_secret_cache(keys):
    upstream = Upstream()
    policy = CognitoProdPolicy(**POLICY)
    runtime = create_aws_prod_runtime(policy, keys[1], provider_builder=upstream.build)
    for _ in range(2):
        response = runtime.lambda_handler(event(policy, token(keys[0], policy)), Context())
        assert response["statusCode"] == 200
        payload = json.loads(response["body"])
        assert payload["result"].get("isError", False) is False
        assert payload["result"]["structuredContent"]["status"] == "parked"
        assert TOKEN not in response["body"]
    assert upstream.reads == 2 and upstream.auth_calls == 6 and upstream.mapit_calls == 2
    assert len(upstream.providers) == 2 and upstream.providers[0] is not upstream.providers[1]
    assert all(deadline <= time.monotonic() + 14 for deadline in upstream.deadlines)


@pytest.mark.parametrize(("enabled", "expected_count"), [(False, 10), (True, 12)])
def test_production_geographic_tools_require_explicit_opt_in(keys, enabled, expected_count):
    upstream = Upstream()
    policy = CognitoProdPolicy(**POLICY)
    runtime = create_aws_prod_runtime(
        policy, keys[1], provider_builder=upstream.build, geographic_queries=enabled
    )
    response = runtime.lambda_handler(event(policy, token(keys[0], policy), method="tools/list"), Context())
    assert response["statusCode"] == 200
    payload = json.loads(response["body"])
    tools = payload["result"]["tools"]
    assert len(tools) == expected_count
    names = {item["name"] for item in tools}
    assert ("geographic_summary" in names) is enabled
    assert ("summer_geographic_summary" in names) is enabled


@pytest.mark.parametrize("remaining", [0, 1000, True, None])
def test_insufficient_lambda_budget_does_not_construct_provider(keys, remaining):
    upstream = Upstream()
    policy = CognitoProdPolicy(**POLICY)
    runtime = create_aws_prod_runtime(policy, keys[1], provider_builder=upstream.build)
    response = runtime.lambda_handler(event(policy), Context(remaining))
    assert response["statusCode"] == 503 and upstream.providers == []
