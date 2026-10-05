"""End-to-end isolation checks with fake SSM, Cognito and MAPIT transports."""
import asyncio
import base64
import json
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.aws_tenant_session_reader import AwsTenantSessionReader
from mapit.cloud_provider import CloudProviderError, CloudServicesProvider
from mapit.config import MapitConfig
from mapit.tenant_router import InvitedTenantAuthority, TenantIsolationError, TenantServicesRouter, tenant_key


ACCOUNT = "123456789012"
POOL = "eu-west-1_Abcdefghi"
CLIENT = "SyntheticTenantClient"
IDENTITY_POOL = "eu-west-1:12345678-1234-4234-8234-123456789abc"
SUBJECTS = (
    "00000000-0000-4000-8000-000000000141",
    "00000000-0000-4000-8000-000000000142",
)
TOKENS = {SUBJECTS[0]: "synthetic-refresh-A", SUBJECTS[1]: "synthetic-refresh-B"}
_LOGIN = f"cognito-idp.eu-west-1.amazonaws.com/{POOL}"


def _b64(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _jwt_exp():
    payload = _b64(json.dumps({"exp": int(time.time()) + 3600}).encode())
    return f"synthetic.{payload}.signature"


def _environment():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policies = {
        tenant_key(b"z" * 32, f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL}", subject):
        CognitoProdPolicy(POOL, "a1b2c3d4e5", CLIENT, subject)
        for subject in SUBJECTS
    }
    authority = InvitedTenantAuthority(policies, {"tenant-integration": public})
    async def authenticate_all():
        grants = {}
        for subject in SUBJECTS:
            policy = CognitoProdPolicy(POOL, "a1b2c3d4e5", CLIENT, subject)
            now = int(time.time())
            token = jwt.encode(
                {"iss": policy.issuer_url, "aud": policy.audience, "sub": subject,
                 "client_id": CLIENT, "token_use": "access", "iat": now - 1,
                 "exp": now + 300, "scope": policy.required_scope},
                private, algorithm="RS256", headers={"kid": "tenant-integration"},
            )
            grants[subject] = await authority.authenticate(token)
        return grants
    grants = asyncio.run(authenticate_all())
    config = MapitConfig(
        region="eu-west-1", user_pool_id=POOL, user_pool_client_id=CLIENT,
        identity_pool_id=IDENTITY_POOL, core_api_url="https://core.prod.mapit.me",
        geo_api_url="https://geo.prod.mapit.me", discovery_enabled=False, http_timeout=2,
    )
    key_to_subject = {grant.key: subject for subject, grant in grants.items()}
    return authority, grants, config, key_to_subject


class FakeSSM:
    def __init__(self, key_to_subject, *, corrupt_subject_for=None):
        self.key_to_subject = key_to_subject
        self.corrupt_subject_for = corrupt_subject_for
        self.calls = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        requested = kwargs["Name"].split("/tenants/", 1)[1].split("/", 1)[0]
        subject = self.key_to_subject[requested]
        returned_subject = self.corrupt_subject_for or subject
        returned_grant_key = next(key for key, item in self.key_to_subject.items() if item == returned_subject)
        path = f"/honda-mapit-mcp/prod/tenants/{returned_grant_key}/mapit-refresh-token"
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Parameter": {
                "Name": path,
                "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter{path}",
                "Type": "SecureString",
                "Value": TOKENS[returned_subject],
                "Version": 7,
                "DataType": "text",
            },
        }


class FakeCognito:
    def __init__(self):
        self.refresh_tokens = []
        self.targets = []
        self.current_subject = None

    def __call__(self, _url, headers, payload):
        target = headers["X-Amz-Target"]
        self.targets.append(target)
        if target.endswith("InitiateAuth"):
            refresh = payload["AuthParameters"]["REFRESH_TOKEN"]
            self.refresh_tokens.append(refresh)
            subject = next(subject for subject, token in TOKENS.items() if token == refresh)
            self.current_subject = subject
            access = f"access-for-{subject[-3:]}"
            return {"AuthenticationResult": {
                "IdToken": _jwt_exp(), "AccessToken": access, "ExpiresIn": 3600,
            }}
        if target.endswith("GetId"):
            return {"IdentityId": "eu-west-1:aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
        if target.endswith("GetCredentialsForIdentity"):
            return {"Credentials": {
                "AccessKeyId": "synthetic-access", "SecretKey": "synthetic-secret",
                "SessionToken": "synthetic-session",
                "Expiration": datetime.now(timezone.utc) + timedelta(hours=1),
            }}
        raise AssertionError("unexpected synthetic Cognito target")


def _mapit_transport_for(auth, requests):
    def transport(method, url, headers):
        requests.append((method, url))
        subject = auth.current_subject
        status = "synthetic-status-A" if subject == SUBJECTS[0] else "synthetic-status-B"
        return json.dumps({"vehicles": [{"id": "synthetic-vehicle", "device": {
            "state": {"status": status}
        }}]}).encode()
    return transport


def test_router_reader_provider_pipeline_keeps_tenant_sSM_auth_and_status_disjoint():
    authority, grants, config, key_to_subject = _environment()
    ssm = FakeSSM(key_to_subject)
    auth = FakeCognito()
    mapit_requests = []
    providers = []

    def provider_factory(key, deadline):
        subject = key_to_subject[key]
        grant = grants[subject]
        reader = AwsTenantSessionReader(
            authority, grant, ssm, account_id=ACCOUNT, version=7, tier="Standard"
        )
        provider = CloudServicesProvider(
            config, reader, auth, _mapit_transport_for(auth, mapit_requests), deadline=deadline
        )
        providers.append(provider)
        return provider

    router = TenantServicesRouter(authority, provider_factory)
    results = {}
    for subject in SUBJECTS:
        with router.bind(grants[subject]):
            results[subject] = router.get().get_vehicle_status().status
            # A second service call reuses only the same invocation-local provider.
            assert router.get().get_vehicle_status().status == results[subject]

    assert results == {SUBJECTS[0]: "synthetic-status-A", SUBJECTS[1]: "synthetic-status-B"}
    assert len(providers) == 2
    expected_names = [
        {"Name": f"/honda-mapit-mcp/prod/tenants/{grants[s].key}/mapit-refresh-token:7",
         "WithDecryption": True}
        for s in SUBJECTS
    ]
    assert ssm.calls == expected_names
    assert auth.refresh_tokens == [TOKENS[s] for s in SUBJECTS]
    assert len(auth.targets) == 6 and len(mapit_requests) == 4


def test_wrong_tenant_parameter_metadata_fails_before_any_cognito_auth():
    authority, grants, config, key_to_subject = _environment()
    grant_a, subject_a = grants[SUBJECTS[0]], SUBJECTS[0]
    ssm = FakeSSM(key_to_subject, corrupt_subject_for=SUBJECTS[1])
    auth = FakeCognito()
    reader = AwsTenantSessionReader(authority, grant_a, ssm, account_id=ACCOUNT, version=7, tier="Standard")
    provider = CloudServicesProvider(
        config, reader, auth, lambda *_: pytest.fail("MAPIT transport must not run"), deadline=time.monotonic() + 10
    )
    with pytest.raises(CloudProviderError) as error:
        provider.get()
    assert error.value.category == "secret_read_failed"
    assert len(ssm.calls) == 1 and auth.targets == [] and auth.refresh_tokens == []


def test_revoked_tenant_request_is_rejected_before_provider_factory_or_ssm():
    authority, grants, _config_value, key_to_subject = _environment()
    ssm = FakeSSM(key_to_subject)
    auth = FakeCognito()
    made = []
    def provider_factory(key, deadline):
        made.append(key)
        reader = AwsTenantSessionReader(authority, grants[key_to_subject[key]], ssm,
                                        account_id=ACCOUNT, version=7, tier="Standard")
        return CloudServicesProvider(
            MapitConfig(region="eu-west-1", user_pool_id=POOL, user_pool_client_id=CLIENT,
                        identity_pool_id=IDENTITY_POOL, core_api_url="https://core.prod.mapit.me",
                        geo_api_url="https://geo.prod.mapit.me", discovery_enabled=False, http_timeout=2),
            reader, auth, lambda *_: b"{}", deadline=time.monotonic() + 10,
        )
    router = TenantServicesRouter(authority, provider_factory)
    grant = grants[SUBJECTS[0]]
    with router.bind(grant):
        authority.revoke(grant.key)
        with pytest.raises(TenantIsolationError, match="tenant_unauthorized"):
            router.get()
    assert made == [] and ssm.calls == [] and auth.targets == []
