from __future__ import annotations

import concurrent.futures
import json
import time
from dataclasses import replace

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.invited_lambda import create_invited_lambda_runtime
from mapit.services import Position, VehicleStatus
from mapit.tenant_router import tenant_key


SIMULATED_DEV_SUBJECT = "00000000-0000-4000-8000-000000000101"
SIMULATED_PROD_SUBJECT = "00000000-0000-4000-8000-000000000102"
UNKNOWN_SUBJECT = "00000000-0000-4000-8000-000000000199"
SIMULATED_DEV_POLICY = CognitoProdPolicy(
    "eu-west-1_SimDevPool01", "simdev1234", "SimulatedDevClient", SIMULATED_DEV_SUBJECT
)
SIMULATED_PROD_POLICY = CognitoProdPolicy(
    "eu-west-1_SimProdPool1", "simprod123", "SimulatedProdClient", SIMULATED_PROD_SUBJECT
)


class _Context:
    def get_remaining_time_in_millis(self):
        return 30_000


class _Provider:
    def __init__(self, label: str):
        self.label = label

    def get(self):
        label = self.label

        class Services:
            def get_vehicle_status(self):
                return VehicleStatus(status=label, position=Position())

        return Services()


def _key_material():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, {"independent-environment-key": public}


def _token(private, policy: CognitoProdPolicy, *, subject: str | None = None, **overrides):
    now = int(time.time())
    claims = {
        "iss": policy.issuer_url,
        "aud": policy.audience,
        "sub": subject or policy.owner_subject,
        "client_id": policy.client_id,
        "token_use": "access",
        "iat": now - 1,
        "exp": now + 300,
        "scope": policy.required_scope,
    }
    claims.update(overrides)
    return jwt.encode(claims, private, algorithm="RS256", headers={"kid": "independent-environment-key"})


def _event(policy: CognitoProdPolicy, bearer: str) -> dict:
    payload = {
        "jsonrpc": "2.0",
        "id": "synthetic",
        "method": "tools/call",
        "params": {"name": "get_vehicle_status", "arguments": {}},
    }
    return {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": "/mcp",
        "rawQueryString": "",
        "headers": {
            "host": policy.api_host,
            "accept": "application/json, text/event-stream",
            "content-type": "application/json",
            "authorization": f"Bearer {bearer}",
        },
        "requestContext": {
            "stage": "$default",
            "http": {"method": "POST", "path": "/mcp", "protocol": "HTTP/1.1"},
        },
        "body": json.dumps(payload, separators=(",", ":")),
        "isBase64Encoded": False,
    }


def _structured_status(response: dict) -> str:
    assert response["statusCode"] == 200
    body = json.loads(response["body"])
    return body["result"]["structuredContent"]["status"]


def _runtime(private, policy, label, calls):
    key = tenant_key(b"i" * 32, policy.issuer_url, policy.owner_subject)
    runtime = create_invited_lambda_runtime(
        policy,
        {key: policy},
        {"independent-environment-key": _key_material()[1]["independent-environment-key"]},
        provider_factory=lambda _key, _deadline: (calls.append(label) or _Provider(label)),
    )
    return runtime


def test_simulated_dev_and_prod_runtimes_accept_only_their_signed_environment_token():
    private, keys = _key_material()
    calls: list[str] = []
    dev_key = tenant_key(b"d" * 32, SIMULATED_DEV_POLICY.issuer_url, SIMULATED_DEV_SUBJECT)
    prod_key = tenant_key(b"p" * 32, SIMULATED_PROD_POLICY.issuer_url, SIMULATED_PROD_SUBJECT)
    dev = create_invited_lambda_runtime(
        SIMULATED_DEV_POLICY, {dev_key: SIMULATED_DEV_POLICY}, keys,
        provider_factory=lambda *_: (calls.append("simulated-dev") or _Provider("simulated-dev")),
    )
    prod = create_invited_lambda_runtime(
        SIMULATED_PROD_POLICY, {prod_key: SIMULATED_PROD_POLICY}, keys,
        provider_factory=lambda *_: (calls.append("simulated-prod") or _Provider("simulated-prod")),
    )

    dev_response = dev.handler(_event(SIMULATED_DEV_POLICY, _token(private, SIMULATED_DEV_POLICY)), _Context())
    prod_response = prod.handler(_event(SIMULATED_PROD_POLICY, _token(private, SIMULATED_PROD_POLICY)), _Context())
    assert [_structured_status(dev_response), _structured_status(prod_response)] == [
        "simulated-dev", "simulated-prod",
    ]
    assert calls == ["simulated-dev", "simulated-prod"]


def test_cross_environment_endpoint_client_and_unknown_subject_fail_before_provider():
    private, keys = _key_material()
    calls: list[str] = []
    dev_key = tenant_key(b"d" * 32, SIMULATED_DEV_POLICY.issuer_url, SIMULATED_DEV_SUBJECT)
    dev = create_invited_lambda_runtime(
        SIMULATED_DEV_POLICY, {dev_key: SIMULATED_DEV_POLICY}, keys,
        provider_factory=lambda *_: (calls.append("provider") or _Provider("provider")),
    )

    cross_environment = dev.handler(
        _event(SIMULATED_DEV_POLICY, _token(private, SIMULATED_PROD_POLICY)), _Context()
    )
    wrong_client = dev.handler(
        _event(SIMULATED_DEV_POLICY, _token(private, SIMULATED_DEV_POLICY, client_id="OtherClient")), _Context()
    )
    wrong_audience = dev.handler(
        _event(SIMULATED_DEV_POLICY, _token(private, SIMULATED_DEV_POLICY, aud="https://wrong.invalid")), _Context()
    )
    unknown_subject = dev.handler(
        _event(SIMULATED_DEV_POLICY, _token(private, SIMULATED_DEV_POLICY, subject=UNKNOWN_SUBJECT)), _Context()
    )
    assert [response["statusCode"] for response in (cross_environment, wrong_client, wrong_audience, unknown_subject)] == [401, 401, 401, 401]
    assert calls == []


def test_shared_runtime_warm_and_concurrent_requests_remain_tenant_isolated():
    private, keys = _key_material()
    policy_b = replace(SIMULATED_DEV_POLICY, owner_subject=SIMULATED_PROD_SUBJECT)
    key_a = tenant_key(b"s" * 32, SIMULATED_DEV_POLICY.issuer_url, SIMULATED_DEV_SUBJECT)
    key_b = tenant_key(b"s" * 32, policy_b.issuer_url, SIMULATED_PROD_SUBJECT)
    calls: list[str] = []
    runtime = create_invited_lambda_runtime(
        SIMULATED_DEV_POLICY,
        {key_a: SIMULATED_DEV_POLICY, key_b: policy_b},
        keys,
        provider_factory=lambda key, _deadline: (
            calls.append("A" if key == key_a else "B") or _Provider("A" if key == key_a else "B")
        ),
    )
    token_a = _token(private, SIMULATED_DEV_POLICY)
    token_b = _token(private, policy_b)

    def invoke(value):
        return runtime.handler(_event(SIMULATED_DEV_POLICY, value), _Context())

    assert _structured_status(invoke(token_a)) == "A"
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
        statuses = list(workers.map(invoke, (token_a, token_b)))
    assert [_structured_status(item) for item in statuses] == ["A", "B"]
    assert calls.count("A") == 2
    assert calls.count("B") == 1
