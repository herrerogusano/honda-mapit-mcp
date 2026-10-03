import asyncio
from concurrent.futures import ThreadPoolExecutor
import time
from threading import Event

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.aws_tenant_session_reader import AwsTenantSessionReader, AwsTenantSessionReaderError
from mapit.tenant_router import InvitedTenantAuthority, tenant_key


ACCOUNT = "123456789012"
POOL = "eu-west-1_AbCdEfGhI"
API = "a1b2c3d4e5"
CLIENT = "SyntheticClient"
SUBJECTS = (
    "00000000-0000-4000-8000-000000000041",
    "00000000-0000-4000-8000-000000000042",
)
BASE = "/honda-mapit-mcp/prod/mapit-refresh-token"
VERSION = 9
SECRET_A = "synthetic-tenant-a-refresh-token"
SECRET_B = "synthetic-tenant-b-refresh-token"


def _authority_and_grants():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policies = {
        tenant_key(b"q" * 32, f"https://cognito-idp.eu-west-1.amazonaws.com/{POOL}", subject):
        CognitoProdPolicy(POOL, API, CLIENT, subject)
        for subject in SUBJECTS
    }
    authority = InvitedTenantAuthority(policies, {"tenant-reader-key": public})
    grants = {}
    now = int(time.time())
    for subject in SUBJECTS:
        policy = CognitoProdPolicy(POOL, API, CLIENT, subject)
        token = jwt.encode(
            {
                "iss": policy.issuer_url, "aud": policy.audience, "sub": subject,
                "client_id": CLIENT, "token_use": "access", "iat": now - 1,
                "exp": now + 300, "scope": policy.required_scope,
            },
            private,
            algorithm="RS256",
            headers={"kid": "tenant-reader-key"},
        )
        grants[subject] = asyncio.run(authority.authenticate(token))
    return authority, grants


def _tenant_path(grant):
    return f"/honda-mapit-mcp/prod/tenants/{grant.key}/mapit-refresh-token"


def _response(path, *, account=ACCOUNT, value=SECRET_A, **changes):
    parameter = {
        "Name": path,
        "ARN": f"arn:aws:ssm:eu-west-1:{account}:parameter{path}",
        "Type": "SecureString",
        "Value": value,
        "Version": VERSION,
        "DataType": "text",
    }
    parameter.update(changes)
    return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": parameter}


class FakeClient:
    def __init__(self, *, account=ACCOUNT, response_path=None, value=SECRET_A, after_read=None, error=None):
        self.account = account
        self.response_path = response_path
        self.value = value
        self.after_read = after_read
        self.error = error
        self.calls = []
        self.response = None
        self.responses = []

    def get_parameter(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        path = self.response_path or kwargs["Name"].split(":", 1)[0]
        self.response = _response(path, account=self.account, value=self.value)
        self.responses.append(self.response)
        if self.after_read:
            self.after_read()
        return self.response


def _reader(authority, grant, client, *, version=VERSION, tier="Standard", clock=lambda: 10.0):
    return AwsTenantSessionReader(
        authority, grant, client, account_id=ACCOUNT, version=version, tier=tier, monotonic=clock
    )


def test_two_grants_read_only_their_exact_namespace_and_response_is_not_mutated():
    authority, grants = _authority_and_grants()
    client = FakeClient(value=SECRET_A)
    reader_a = _reader(authority, grants[SUBJECTS[0]], client)
    result_a = reader_a.read_refresh_token(deadline=100.0)
    client.value = SECRET_B
    reader_b = _reader(authority, grants[SUBJECTS[1]], client)
    result_b = reader_b.read_refresh_token(deadline=100.0)
    assert result_a.refresh_token == SECRET_A
    assert result_b.refresh_token == SECRET_B
    assert client.calls == [
        {"Name": f"{_tenant_path(grants[SUBJECTS[0]])}:{VERSION}", "WithDecryption": True},
        {"Name": f"{_tenant_path(grants[SUBJECTS[1]])}:{VERSION}", "WithDecryption": True},
    ]
    assert client.responses[0]["Parameter"]["Name"] == _tenant_path(grants[SUBJECTS[0]])
    assert client.responses[1]["Parameter"]["Name"] == _tenant_path(grants[SUBJECTS[1]])
    assert SECRET_A not in repr(reader_a) and SECRET_B not in repr(result_b)
    assert SECRET_A not in str(result_a.safe_projection())


@pytest.mark.parametrize(
    "response_path,account",
    [
        (BASE, ACCOUNT),  # legacy owner path is never accepted for a tenant
        ("/honda-mapit-mcp/prod/tenants/tenant-" + "0" * 64 + "/mapit-refresh-token", ACCOUNT),
        (None, "999999999999"),
    ],
)
def test_wrong_namespace_or_account_readback_fails_closed(response_path, account):
    authority, grants = _authority_and_grants()
    grant = grants[SUBJECTS[0]]
    client = FakeClient(account=account, response_path=response_path)
    reader = _reader(authority, grant, client)
    with pytest.raises(AwsTenantSessionReaderError) as error:
        reader.read_refresh_token(deadline=100.0)
    assert error.value.category == "tenant_reader_parameter_read_failed"
    assert len(client.calls) == 1
    assert SECRET_A not in str(error.value)


def test_revoked_or_forged_grant_fails_before_any_sdk_call():
    authority, grants = _authority_and_grants()
    grant = grants[SUBJECTS[0]]
    client = FakeClient()
    reader = _reader(authority, grant, client)
    authority.revoke(grant.key)
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_grant_invalid"):
        reader.read_refresh_token(deadline=100.0)
    assert client.calls == []


def test_revocation_during_read_suppresses_value_return():
    authority, grants = _authority_and_grants()
    grant = grants[SUBJECTS[0]]
    client = FakeClient(after_read=lambda: authority.revoke(grant.key))
    reader = _reader(authority, grant, client)
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_grant_invalid") as error:
        reader.read_refresh_token(deadline=100.0)
    assert len(client.calls) == 1
    assert SECRET_A not in str(error.value)
    assert error.value.__cause__ is None


def test_expired_deadline_does_not_read_and_client_exception_text_is_hidden():
    authority, grants = _authority_and_grants()
    grant = grants[SUBJECTS[0]]
    expired = FakeClient()
    reader = _reader(authority, grant, expired, clock=lambda: 12.0)
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_deadline_expired"):
        reader.read_refresh_token(deadline=12.0)
    assert expired.calls == []

    failed = FakeClient(error=RuntimeError("private-tenant-token-canary"))
    reader = _reader(authority, grant, failed)
    with pytest.raises(AwsTenantSessionReaderError) as error:
        reader.read_refresh_token(deadline=100.0)
    assert error.value.category == "tenant_reader_parameter_read_failed"
    assert "private-tenant-token-canary" not in str(error.value)
    assert error.value.__cause__ is None
    assert len(failed.calls) == 1


def test_reader_is_one_attempt_after_success_or_error():
    authority, grants = _authority_and_grants()
    grant = grants[SUBJECTS[0]]
    successful_client = FakeClient()
    successful = _reader(authority, grant, successful_client)
    assert successful.read_refresh_token(deadline=100.0).success is True
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_already_used"):
        successful.read_refresh_token(deadline=100.0)
    assert len(successful_client.calls) == 1

    failed_client = FakeClient(error=RuntimeError("synthetic error"))
    failed = _reader(authority, grant, failed_client)
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_parameter_read_failed"):
        failed.read_refresh_token(deadline=100.0)
    with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_already_used"):
        failed.read_refresh_token(deadline=100.0)
    assert len(failed_client.calls) == 1


def test_concurrent_reuse_dispatches_exactly_one_sdk_attempt():
    authority, grants = _authority_and_grants()
    started, release = Event(), Event()

    class BlockingClient(FakeClient):
        def get_parameter(self, **kwargs):
            self.calls.append(kwargs)
            started.set()
            assert release.wait(timeout=2)
            path = kwargs["Name"].split(":", 1)[0]
            return _response(path)

    client = BlockingClient()
    reader = _reader(authority, grants[SUBJECTS[0]], client)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reader.read_refresh_token, deadline=100.0)
        assert started.wait(timeout=2)
        second = pool.submit(reader.read_refresh_token, deadline=100.0)
        with pytest.raises(AwsTenantSessionReaderError, match="tenant_reader_already_used"):
            second.result(timeout=2)
        release.set()
        assert first.result(timeout=2).success is True
    assert len(client.calls) == 1


def test_grant_is_revalidated_after_client_method_lookup_before_dispatch():
    authority, grants = _authority_and_grants()
    grant = grants[SUBJECTS[0]]
    dispatched = []

    class RevokingClient:
        @property
        def get_parameter(self):
            authority.revoke(grant.key)
            return lambda **kwargs: dispatched.append(kwargs)

    reader = _reader(authority, grant, RevokingClient())
    with pytest.raises(AwsTenantSessionReaderError):
        reader.read_refresh_token(deadline=100.0)
    assert dispatched == []
