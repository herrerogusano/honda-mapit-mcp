from __future__ import annotations

import base64
import io
import json
import time
import urllib.error

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit import multiuser_entrypoint as entry
from mapit.cloud_provider import CloudProviderError
from mapit.multiuser_common import session_parameter_name, table_name
from mapit.multiuser_runtime import (
    MSG_DELETE_DONE, MSG_DELETE_FAILED, MSG_DELETE_PREVIEW, MSG_NOT_LINKED,
    MSG_SESSION_EXPIRED, JwksCache, MultiuserPolicy, MultiuserTokenVerifier,
    TenantSessionMissing, create_multiuser_runtime, multiuser_policy,
)
from mapit.remote_http import SyntheticServicesProvider
from mapit.services import ServiceError

POOL = "eu-west-1_A1b2C3d4E"
API = "a1b2c3d4e5"
RESOURCE = f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"
ISSUER = f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL}"
CLIENTS = ("ClaudeClient0123", "CodexClient0123")
TENANT_A = "a" * 32
TENANT_B = "b" * 32
METADATA = "/.well-known/oauth-protected-resource/mcp"


def _jwk(private, kid):
    numbers = private.public_key().public_numbers()

    def encode(value):
        return base64.urlsafe_b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": encode(numbers.n), "e": encode(numbers.e)}


@pytest.fixture(scope="module")
def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048), rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )


def jwks_bytes(*pairs):
    return json.dumps({"keys": [_jwk(private, kid) for private, kid in pairs]}).encode()


class Fetcher:
    def __init__(self, document):
        self.document = document
        self.urls = []

    def __call__(self, url):
        self.urls.append(url)
        return self.document


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Context:
    def __init__(self, remaining=15000):
        self.remaining = remaining

    def get_remaining_time_in_millis(self):
        return self.remaining


def policy():
    return multiuser_policy(environment="dev", user_pool_id=POOL, resource_url=RESOURCE, client_ids=CLIENTS)


def token(private, kid="k1", drop=(), **overrides):
    now = int(time.time())
    claims = dict(iss=ISSUER, aud=RESOURCE, sub="11111111-2222-3333-4444-555555555555",
                  client_id=CLIENTS[0], token_use="access", iat=now, exp=now + 300,
                  scope=f"openid {RESOURCE}/use", mapit_tenant=TENANT_A, username="user-a")
    claims.update(overrides)
    for name in drop:
        claims.pop(name)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": kid, "typ": "JWT"})


def event(access=None, *, method="tools/call", name="get_vehicle_status", arguments=None, path="/mcp"):
    params = {} if method == "tools/list" else {"name": name, "arguments": arguments or {}}
    body = "" if path != "/mcp" else json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
    headers = {"host": f"{API}.execute-api.eu-west-1.amazonaws.com", "content-type": "application/json",
               "accept": "application/json, text/event-stream", "content-length": str(len(body.encode()))}
    if access:
        headers["authorization"] = "Bearer " + access
    return {"version": "2.0", "rawPath": path, "rawQueryString": "", "headers": headers,
            "requestContext": {"stage": "$default", "http": {"method": "GET" if path != "/mcp" else "POST", "path": path}},
            "body": body, "isBase64Encoded": False}


class Session:
    """Fake tenant provider handed back by services_factory."""

    def __init__(self, tenant, error=None, rejected=False):
        self.tenant = tenant
        self.error = error
        self.session_rejected = rejected
        self.services = SyntheticServicesProvider()

    def get(self):
        if self.error is not None:
            raise self.error
        return self.services


class Harness:
    def __init__(self, keys, *, error=None, rejected=False, missing=False, delete_result=True, geography=False):
        self.created = []
        self.relinks = []
        self.deletes = []
        self.error, self.rejected, self.missing, self.delete_result = error, rejected, missing, delete_result
        self.fetcher = Fetcher(jwks_bytes((keys[0], "k1")))
        self.runtime = create_multiuser_runtime(
            policy(), JwksCache(ISSUER, fetcher=self.fetcher),
            services_factory=self.factory, relink=self.relink, delete_account=self.delete,
            geographic_queries=geography,
        )

    def factory(self, tenant, deadline):
        assert deadline <= time.monotonic() + 14
        if self.missing:
            raise TenantSessionMissing()
        session = Session(tenant, self.error, self.rejected)
        self.created.append(session)
        return session

    def relink(self, tenant, username):
        self.relinks.append((tenant, username))

    def delete(self, tenant, username):
        self.deletes.append((tenant, username))
        return self.delete_result

    def call(self, access, **kwargs):
        return self.runtime.lambda_handler(event(access, **kwargs), Context())


def tool_result(response):
    assert response["statusCode"] == 200
    return json.loads(response["body"])["result"]


def tool_text(response):
    return tool_result(response)["content"][0]["text"]


# -- policy ---------------------------------------------------------------------

def test_policy_derives_scope_and_rejects_bad_bindings():
    selected = policy()
    assert selected.required_scope == RESOURCE + "/use" and selected.audience == RESOURCE
    assert selected.allowed_hosts == (f"{API}.execute-api.eu-west-1.amazonaws.com",)
    base = dict(environment="dev", issuer_url=ISSUER, resource_url=RESOURCE, client_ids=CLIENTS,
                allowed_hosts=selected.allowed_hosts, allowed_origins=selected.allowed_origins)
    for override in ({"environment": "stage"}, {"issuer_url": "https://evil.example/x"},
                     {"resource_url": "https://a1b2c3d4e5.execute-api.us-east-1.amazonaws.com/mcp"},
                     {"client_ids": ()}, {"client_ids": ("a", "b", "c", "d", "e")}, {"client_ids": ("a", "a")},
                     {"client_ids": ["a"]}, {"allowed_hosts": ("other.example",)},
                     {"allowed_origins": ("http://x.example",)}, {"request_deadline_seconds": 14.5},
                     {"request_deadline_seconds": True}, {"max_token_bytes": 9000}):
        with pytest.raises(ValueError):
            MultiuserPolicy(**{**base, **override})


# -- authentication ------------------------------------------------------------

def test_metadata_and_construction_do_not_touch_tenants(keys):
    harness = Harness(keys)
    response = harness.call(None, path=METADATA)
    assert response["statusCode"] == 200
    assert json.loads(response["body"])["resource"] == RESOURCE
    assert harness.created == [] and harness.fetcher.urls == [ISSUER + "/.well-known/jwks.json"]


def test_valid_token_lists_tools_including_delete_tool(keys):
    harness = Harness(keys)
    tools = tool_result(harness.call(token(keys[0]), method="tools/list"))["tools"]
    names = {item["name"] for item in tools}
    assert len(tools) == 11 and "borrar_mis_datos" in names and "get_vehicle_status" in names
    assert harness.created == []


def test_geography_opt_in_adds_two_tools(keys):
    harness = Harness(keys, geography=True)
    assert len(tool_result(harness.call(token(keys[0]), method="tools/list"))["tools"]) == 13


def test_valid_token_tool_call_uses_its_tenant(keys):
    harness = Harness(keys)
    result = tool_result(harness.call(token(keys[0])))
    assert result.get("isError", False) is False
    assert result["structuredContent"]["status"] == "SYNTHETIC"
    assert [item.tenant for item in harness.created] == [TENANT_A]


@pytest.mark.parametrize("claims", [
    {"aud": "https://other.execute-api.eu-west-1.amazonaws.com/mcp"},
    {"aud": [RESOURCE]},
    {"iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Other1234"},
    {"client_id": "UnknownClient"},
    {"scope": "openid"},
    {"scope": f"openid {RESOURCE}/use-extra"},
    {"token_use": "id"},
    {"exp": int(time.time()) - 10},
    {"iat": int(time.time()) + 600, "exp": int(time.time()) + 900},
    {"nbf": int(time.time()) + 600},
    {"mapit_tenant": "A" * 32},
    {"mapit_tenant": "a" * 31},
    {"mapit_tenant": 123},
    {"username": ""},
    {"username": "x" * 129},
])
def test_invalid_claims_are_unauthorized_without_tenant_access(keys, claims):
    harness = Harness(keys)
    response = harness.call(token(keys[0], **claims))
    assert response["statusCode"] == 401
    assert harness.created == [] and harness.relinks == []


@pytest.mark.parametrize("missing", ["mapit_tenant", "username", "scope", "sub"])
def test_missing_claims_are_unauthorized(keys, missing):
    harness = Harness(keys)
    assert harness.call(token(keys[0], drop=(missing,)))["statusCode"] == 401
    assert harness.created == []


def test_wrong_signing_key_and_missing_token_are_unauthorized(keys):
    harness = Harness(keys)
    assert harness.call(token(keys[1]))["statusCode"] == 401
    assert harness.call(None)["statusCode"] == 401
    hs = jwt.encode({"sub": "x"}, "secret-secret-secret-secret-secret", algorithm="HS256", headers={"kid": "k1"})
    assert harness.call(hs)["statusCode"] == 401
    assert harness.created == []


def test_second_client_is_accepted(keys):
    harness = Harness(keys)
    assert tool_result(harness.call(token(keys[0], client_id=CLIENTS[1]))).get("isError", False) is False


# -- tenant isolation and errors ---------------------------------------------------------

def test_tenants_get_their_own_provider_per_request(keys):
    harness = Harness(keys)
    tool_result(harness.call(token(keys[0])))
    tool_result(harness.call(token(keys[0], mapit_tenant=TENANT_B, username="user-b")))
    tool_result(harness.call(token(keys[0])))
    assert [item.tenant for item in harness.created] == [TENANT_A, TENANT_B, TENANT_A]
    assert len({id(item) for item in harness.created}) == 3


def test_compare_tool_reuses_one_provider_within_request(keys):
    harness = Harness(keys)
    period = {"from_time": "2026-01-01T00:00:00Z", "to_time": "2026-01-31T00:00:00Z"}
    result = tool_result(harness.call(token(keys[0]), name="compare_distance_periods",
                                      arguments={"period_a": period, "period_b": period}))
    assert result.get("isError", False) is False
    assert len(harness.created) == 1


def test_missing_parameter_returns_spanish_link_message(keys):
    harness = Harness(keys, missing=True)
    result = tool_result(harness.call(token(keys[0])))
    assert result["isError"] is True and MSG_NOT_LINKED in result["content"][0]["text"]
    assert harness.relinks == []


@pytest.mark.parametrize("error", [CloudProviderError("auth_failed"),
                                   ServiceError("internal_error", "the request could not be completed")])
def test_refresh_rejection_relinks_once_and_returns_expired_message(keys, error):
    harness = Harness(keys, error=error, rejected=True)
    result = tool_result(harness.call(token(keys[0])))
    assert result["isError"] is True and MSG_SESSION_EXPIRED in result["content"][0]["text"]
    assert harness.relinks == [(TENANT_A, "user-a")]


def test_other_failures_do_not_relink(keys):
    harness = Harness(keys, error=CloudProviderError("secret_read_failed"))
    result = tool_result(harness.call(token(keys[0])))
    assert result["isError"] is True and MSG_SESSION_EXPIRED not in result["content"][0]["text"]
    assert harness.relinks == []
    harness = Harness(keys, error=ServiceError("rate_limited", "MAPIT rate-limited the request"))
    result = tool_result(harness.call(token(keys[0])))
    assert result["isError"] is True and "rate_limited" in result["content"][0]["text"]
    assert harness.relinks == []


# -- borrar_mis_datos -----------------------------------------------------------------

def test_delete_tool_without_confirmation_explains_only(keys):
    harness = Harness(keys)
    result = tool_result(harness.call(token(keys[0]), name="borrar_mis_datos", arguments={"confirmar": False}))
    assert result.get("isError", False) is False and MSG_DELETE_PREVIEW in result["content"][0]["text"]
    assert harness.deletes == [] and harness.created == []


def test_delete_tool_with_confirmation_deletes_caller_only(keys):
    harness = Harness(keys)
    result = tool_result(harness.call(token(keys[0], mapit_tenant=TENANT_B, username="user-b"),
                                      name="borrar_mis_datos", arguments={"confirmar": True}))
    assert result.get("isError", False) is False and MSG_DELETE_DONE in result["content"][0]["text"]
    assert harness.deletes == [(TENANT_B, "user-b")]


def test_delete_tool_failure_is_reported(keys):
    harness = Harness(keys, delete_result=False)
    result = tool_result(harness.call(token(keys[0]), name="borrar_mis_datos", arguments={"confirmar": True}))
    assert result["isError"] is True and MSG_DELETE_FAILED in result["content"][0]["text"]


# -- JWKS cache ------------------------------------------------------------------------

def test_unknown_kid_refetch_is_throttled(keys):
    clock = Clock()
    fetcher = Fetcher(jwks_bytes((keys[0], "k1")))
    cache = JwksCache(ISSUER, fetcher=fetcher, monotonic=clock)
    cache.load()
    cache.load()
    assert len(fetcher.urls) == 1
    fetcher.document = jwks_bytes((keys[0], "k1"), (keys[1], "k2"))
    clock.now += 10
    assert cache.key_for("k2") is None and len(fetcher.urls) == 1
    clock.now += 300
    assert cache.key_for("k2") is not None and len(fetcher.urls) == 2
    clock.now += 10
    assert cache.key_for("k3") is None and len(fetcher.urls) == 2
    assert cache.key_for("k1") is not None and len(fetcher.urls) == 2


def test_verifier_accepts_rotated_key_after_interval(keys):
    import asyncio

    clock = Clock()
    fetcher = Fetcher(jwks_bytes((keys[0], "k1")))
    cache = JwksCache(ISSUER, fetcher=fetcher, monotonic=clock)
    cache.load()
    verifier = MultiuserTokenVerifier(policy(), cache)
    rotated = token(keys[1], kid="k2")
    assert asyncio.run(verifier.verify_token(rotated)) is None
    fetcher.document = jwks_bytes((keys[1], "k2"))
    clock.now += 301
    access = asyncio.run(verifier.verify_token(rotated))
    assert access is not None and access.claims == {"iss": ISSUER, "mapit_tenant": TENANT_A, "username": "user-a"}
    assert access.subject == "11111111-2222-3333-4444-555555555555" and access.client_id == CLIENTS[0]


def test_failed_refetch_keeps_previous_keys(keys):
    clock = Clock()
    fetcher = Fetcher(jwks_bytes((keys[0], "k1")))
    cache = JwksCache(ISSUER, fetcher=fetcher, monotonic=clock)
    cache.load()
    fetcher.document = b"not json"
    clock.now += 400
    assert cache.key_for("k9") is None
    assert cache.key_for("k1") is not None


def test_jwks_cache_rejects_non_cognito_issuer():
    with pytest.raises(ValueError):
        JwksCache("https://evil.example/pool", fetcher=Fetcher(b""))


# -- entrypoint ----------------------------------------------------------------------

CONFIG_JSON = json.dumps({
    "region": "eu-west-1", "user_pool_id": "eu-west-1_M1a2P3i4T",
    "user_pool_client_id": "MapitClient123456",
    "identity_pool_id": "eu-west-1:18d8ce2b-8f10-4d72-b80f-ea635b4c6189",
    "core_api_url": "https://core.prod.mapit.me", "geo_api_url": "https://geo.prod.mapit.me",
    "discovery_enabled": False, "http_timeout": 2.0,
})


def env_values(**overrides):
    values = {
        "AWS_LAMBDA_FUNCTION_NAME": "honda-mapit-mcp-dev-mcp", "AWS_REGION": "eu-west-1",
        "MAPIT_MCP_ENV": "dev", "MULTIUSER_ISSUER_URL": ISSUER, "MULTIUSER_RESOURCE_URL": RESOURCE,
        "MULTIUSER_CLIENT_IDS": ",".join(CLIENTS), "MULTIUSER_USER_POOL_ID": POOL,
        "MULTIUSER_TABLE": table_name("dev"), "MAPIT_CONFIG_JSON": CONFIG_JSON, "MULTIUSER_GEOGRAPHY": "0",
    }
    values.update(overrides)
    return {key: value for key, value in values.items() if value is not None}


class ClientError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeAws:
    def __init__(self, *, parameter=True, items=None):
        self.calls = []
        self.parameter = parameter
        self.items = items if items is not None else [
            {"email": {"S": "a@example.com"}, "tenant_id": {"S": TENANT_A}},
        ]

    def factory(self, service):
        fake = self

        class Client:
            def __getattr__(self, name):
                def call(**kwargs):
                    fake.calls.append((service, name, kwargs))
                    return fake.respond(service, name, kwargs)
                return call

        return Client()

    def respond(self, service, name, kwargs):
        if (service, name) == ("ssm", "get_parameter"):
            if not self.parameter:
                raise ClientError("ParameterNotFound")
            return {"Parameter": {"Name": kwargs["Name"], "Type": "SecureString", "Value": "refresh-canary",
                                  "Version": 3}}
        if (service, name) == ("dynamodb", "scan"):
            value = kwargs["ExpressionAttributeValues"][":t"]["S"]
            return {"Items": [item for item in self.items if item["tenant_id"]["S"] == value]}
        if (service, name) == ("cognito-idp", "admin_delete_user") and kwargs["Username"] == "gone":
            raise ClientError("UserNotFoundException")
        return {}


@pytest.fixture
def entrypoint(monkeypatch, keys):
    aws = FakeAws()
    fetcher = Fetcher(jwks_bytes((keys[0], "k1")))
    monkeypatch.setattr(entry, "_client_factory", aws.factory)
    monkeypatch.setattr(entry, "_jwks_fetcher", fetcher)
    monkeypatch.setattr(entry, "_CACHED_RUNTIME", None)
    monkeypatch.setattr(entry, "_CACHED_SIGNATURE", None)
    monkeypatch.setattr(entry, "_CACHED_CLIENTS", {})
    for name in entry.ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    for name, value in env_values().items():
        monkeypatch.setenv(name, value)
    return aws, fetcher


def test_entrypoint_serves_metadata_and_caches_runtime(entrypoint):
    aws, fetcher = entrypoint
    for _ in range(2):
        response = entry.handler(event(None, path=METADATA), Context())
        assert response["statusCode"] == 200
    assert len(fetcher.urls) == 1 and aws.calls == []


@pytest.mark.parametrize("overrides", [
    {"MAPIT_MCP_ENV": None}, {"MAPIT_MCP_ENV": "stage"}, {"AWS_REGION": "us-east-1"},
    {"AWS_LAMBDA_FUNCTION_NAME": "other"}, {"MULTIUSER_TABLE": "honda-mapit-mcp-prod-invitations"},
    {"MULTIUSER_ISSUER_URL": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_Other1234"},
    {"MULTIUSER_RESOURCE_URL": RESOURCE + "/"}, {"MULTIUSER_CLIENT_IDS": ""},
    {"MULTIUSER_CLIENT_IDS": "a,a"}, {"MULTIUSER_CLIENT_IDS": "a,b,c,d,e"}, {"MULTIUSER_CLIENT_IDS": "a, b"},
    {"MULTIUSER_GEOGRAPHY": "yes"}, {"MAPIT_CONFIG_JSON": None}, {"MAPIT_CONFIG_JSON": "{}"},
    {"MAPIT_CONFIG_JSON": CONFIG_JSON.replace("false", "true")},
    {"MAPIT_CONFIG_JSON": CONFIG_JSON[:-1] + ', "email": "x@example.com"}'},
    {"MAPIT_CONFIG_JSON": CONFIG_JSON.replace("core.prod.mapit.me", "core.evil.example")},
])
def test_entrypoint_environment_fails_closed(entrypoint, monkeypatch, overrides):
    aws, fetcher = entrypoint
    for name, value in overrides.items():
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    response = entry.handler(event(None, path=METADATA), Context())
    assert response["statusCode"] == 503 and response["body"] == '{"error":"service_unavailable"}'
    assert aws.calls == []


def test_entrypoint_jwks_failure_is_unavailable(entrypoint, monkeypatch):
    def failing(url):
        raise ValueError("jwks_fetch_failed")

    monkeypatch.setattr(entry, "_jwks_fetcher", failing)
    assert entry.handler(event(None, path=METADATA), Context())["statusCode"] == 503


def test_entrypoint_missing_parameter_message(entrypoint, keys):
    aws, _ = entrypoint
    aws.parameter = False
    result = tool_result(entry.handler(event(token(keys[0])), Context()))
    assert result["isError"] is True and MSG_NOT_LINKED in result["content"][0]["text"]
    assert aws.calls == [("ssm", "get_parameter", {"Name": session_parameter_name("dev", TENANT_A),
                                                    "WithDecryption": True})]


class FakeOpener:
    def __init__(self, error_type):
        self.error_type = error_type
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        body = json.dumps({"__type": self.error_type, "message": "Refresh Token has expired"}).encode()
        raise urllib.error.HTTPError(request.full_url, 400, "Bad Request", None, io.BytesIO(body))


@pytest.mark.parametrize(("kind", "rejected"), [("NotAuthorizedException", True),
                                                 ("TooManyRequestsException", False)])
def test_services_factory_detects_refresh_rejection(entrypoint, monkeypatch, kind, rejected):
    opener = FakeOpener(kind)
    monkeypatch.setattr(entry, "direct_opener", lambda: opener)
    settings = entry._settings(env_values())
    session = entry._build_services_factory(settings)(TENANT_A, time.monotonic() + 5)
    with pytest.raises(CloudProviderError):
        session.get()
    assert session.session_rejected is rejected
    assert len(opener.requests) == 1 and "refresh-canary" not in repr(session)


def test_entrypoint_relink_flow_on_rejection(entrypoint, monkeypatch, keys):
    aws, _ = entrypoint
    monkeypatch.setattr(entry, "direct_opener", lambda: FakeOpener("NotAuthorizedException"))
    result = tool_result(entry.handler(event(token(keys[0])), Context()))
    assert result["isError"] is True and MSG_SESSION_EXPIRED in result["content"][0]["text"]
    names = [(service, name) for service, name, _ in aws.calls]
    assert names == [("ssm", "get_parameter"), ("ssm", "delete_parameter"),
                     ("cognito-idp", "admin_delete_user"), ("dynamodb", "scan"), ("dynamodb", "update_item")]
    update = aws.calls[-1][2]
    assert update["Key"] == {"email": {"S": "a@example.com"}}
    assert update["ExpressionAttributeValues"][":s"] == {"S": "accepted"}
    assert update["ExpressionAttributeValues"][":t"] == {"S": TENANT_A}
    assert aws.calls[2][2] == {"UserPoolId": POOL, "Username": "user-a"}


def test_entrypoint_delete_account(entrypoint, keys):
    aws, _ = entrypoint
    result = tool_result(entry.handler(event(token(keys[0]), name="borrar_mis_datos",
                                             arguments={"confirmar": True}), Context()))
    assert result.get("isError", False) is False and MSG_DELETE_DONE in result["content"][0]["text"]
    names = [(service, name) for service, name, _ in aws.calls]
    assert names == [("ssm", "delete_parameter"), ("dynamodb", "scan"), ("dynamodb", "delete_item"),
                     ("cognito-idp", "admin_delete_user")]
    assert aws.calls[0][2] == {"Name": session_parameter_name("dev", TENANT_A)}


def test_account_actions_tolerate_already_deleted_and_reject_ambiguity(entrypoint):
    aws, _ = entrypoint
    relink, delete_account = entry._build_account_actions(entry._settings(env_values()))
    aws.items = []
    assert delete_account(TENANT_A, "gone") is True
    aws.items = [{"email": {"S": "a@example.com"}, "tenant_id": {"S": TENANT_A}},
                 {"email": {"S": "b@example.com"}, "tenant_id": {"S": TENANT_A}}]
    aws.calls.clear()
    assert relink(TENANT_A, "user-a") is False
    assert ("dynamodb", "update_item") not in [(s, n) for s, n, _ in aws.calls]
