from __future__ import annotations

import sqlite3

import pytest

from mapit.durable_tenants import DurableTenantGuard, SQLiteTenantStore
from mapit.enrolled_provider import EnrolledCloudServicesProvider, EnrolledProviderError
from mapit.identity_binding import SecretPublicationReceipt
from mapit.mapit_identity import MapitIdentityVerifier

from test_identity_binding import (
    KEY_A, KEY_B, NOW, TOKEN_A, TOKEN_B, _AuthTransport, _make_setup,
)

ACCOUNT_ID = "123456789012"


class _PublishingSecrets:
    def __init__(self):
        self.values = {}
        self.calls = []

    def publish(self, *, path, version, refresh_token, create_only):
        self.calls.append((path, version, create_only))
        if create_only and path in self.values:
            raise RuntimeError("already exists")
        self.values[path] = refresh_token
        return SecretPublicationReceipt(path, version, True)


class _SSM:
    def __init__(self, values):
        self.values = values
        self.calls = []

    def get_parameter(self, *, Name, WithDecryption):
        self.calls.append((Name, WithDecryption))
        path = Name.rsplit(":", 1)[0]
        value = self.values[path]
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Parameter": {
                "Name": path,
                "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT_ID}:parameter{path}",
                "Type": "SecureString",
                "Value": value,
                "Version": 1,
                "DataType": "text",
            },
        }


class _Mapit:
    def __init__(self, status, distance, callback=None):
        self.status = status
        self.distance = distance
        self.callback = callback
        self.calls = []

    def __call__(self, method, url, headers):
        self.calls.append((method, url))
        if self.callback:
            self.callback()
        if url.endswith("/v1/account-summary"):
            return (
                '{"vehicles":[{"id":"synthetic-vehicle",'
                f'"device":{{"state":{{"status":"{self.status}"}}}}}}]}}'
            ).encode()
        return (
            '{"data":[{"id":"synthetic-route",'
            f'"startedAt":"2026-01-10T00:00:00Z","distance":{self.distance}'
            '}]}'
        ).encode()


class _SelectingAuth(_AuthTransport):
    def __init__(self, tokens):
        super().__init__(tokens[TOKEN_A])
        self.tokens = tokens

    def __call__(self, url, headers, payload):
        if headers["X-Amz-Target"].endswith("InitiateAuth"):
            self.id_token = self.tokens[payload["AuthParameters"]["REFRESH_TOKEN"]]
        return super().__call__(url, headers, payload)


def _binding(env, grant_key, token_key, publisher, auth=None):
    grant = env["grant_a"] if grant_key == KEY_A else env["grant_b"]
    snapshot = env["snapshot_a"] if grant_key == KEY_A else env["snapshot_b"]
    token = env["tokens"][token_key]
    auth = auth if auth is not None else _AuthTransport(token)
    registry = env["factory"](selected_auth=auth)
    binding = registry.enroll(grant, snapshot, token_key, publisher=publisher)
    return registry, grant, snapshot, binding


def test_two_enrolled_tenants_read_only_their_secret_and_keep_business_results_separate(tmp_path):
    env = _make_setup(tmp_path)
    publisher = _PublishingSecrets()
    registry_a, grant_a, snapshot_a, _ = _binding(env, KEY_A, TOKEN_A, publisher)
    registry_b, grant_b, snapshot_b, _ = _binding(env, KEY_B, TOKEN_B, publisher)
    ssm = _SSM(publisher.values)
    mapit_a, mapit_b = _Mapit("tenant-a", 11), _Mapit("tenant-b", 22)

    provider_a = EnrolledCloudServicesProvider(
        registry_a, authority=env["authority"], grant=grant_a,
        durable_guard=env["guard"], snapshot=snapshot_a, ssm_client=ssm,
        account_id=ACCOUNT_ID, auth_transport=_AuthTransport(env["tokens"][TOKEN_A]),
        mapit_transport=mapit_a, deadline=20.0, monotonic=lambda: 10.0,
    )
    provider_b = EnrolledCloudServicesProvider(
        registry_b, authority=env["authority"], grant=grant_b,
        durable_guard=env["guard"], snapshot=snapshot_b, ssm_client=ssm,
        account_id=ACCOUNT_ID, auth_transport=_AuthTransport(env["tokens"][TOKEN_B]),
        mapit_transport=mapit_b, deadline=20.0, monotonic=lambda: 10.0,
    )

    services_a, services_b = provider_a.get(), provider_b.get()
    assert services_a.get_vehicle_status().status == "tenant-a"
    assert services_b.get_vehicle_status().status == "tenant-b"
    assert services_a.get_distance("2026-01-01", "2026-02-01").distance == 11
    assert services_b.get_distance("2026-01-01", "2026-02-01").distance == 22
    assert [call[0] for call in ssm.calls] == [
        f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token:1",
        f"/honda-mapit-mcp/dev/tenants/{KEY_B}/mapit-refresh-token:1",
    ]
    assert len(mapit_a.calls) == len(mapit_b.calls) == 3


def test_reopened_registry_and_fresh_verifier_restore_enrolled_provider(tmp_path):
    env = _make_setup(tmp_path)
    publisher = _PublishingSecrets()
    _binding(env, KEY_A, TOKEN_A, publisher)
    env["connection"].close()

    connection = sqlite3.connect(tmp_path / "tenants.sqlite3")
    tenants = SQLiteTenantStore(connection)
    guard = DurableTenantGuard(env["authority"], tenants)
    snapshot = guard.capture(env["grant_a"])
    config = env["config"]
    verifier = MapitIdentityVerifier(
        config, {"mapit-test-key": env["mapit_public"]}, b"v" * 32, clock=lambda: NOW,
    )
    registry = env["factory"](
        connection=connection, selected_config=config, selected_verifier=verifier,
        selected_guard=guard, selected_auth=_AuthTransport(env["tokens"][TOKEN_A]),
    )
    provider = EnrolledCloudServicesProvider(
        registry, authority=env["authority"], grant=env["grant_a"], durable_guard=guard,
        snapshot=snapshot, ssm_client=_SSM(publisher.values), account_id=ACCOUNT_ID,
        auth_transport=_AuthTransport(env["tokens"][TOKEN_A]),
        mapit_transport=_Mapit("restored-a", 33), deadline=20.0, monotonic=lambda: 10.0,
    )
    assert provider.get().get_vehicle_status().status == "restored-a"


def test_crossed_stored_refresh_token_fails_before_identity_pool_or_business_calls(tmp_path):
    env = _make_setup(tmp_path)
    publisher = _PublishingSecrets()
    registry_a, grant_a, snapshot_a, _ = _binding(env, KEY_A, TOKEN_A, publisher)
    _binding(env, KEY_B, TOKEN_B, publisher)
    path_a = f"/honda-mapit-mcp/dev/tenants/{KEY_A}/mapit-refresh-token"
    publisher.values[path_a] = TOKEN_B
    auth, mapit = _SelectingAuth(env["tokens"]), _Mapit("must-not-escape", 99)
    provider = EnrolledCloudServicesProvider(
        registry_a, authority=env["authority"], grant=grant_a,
        durable_guard=env["guard"], snapshot=snapshot_a, ssm_client=_SSM(publisher.values),
        account_id=ACCOUNT_ID, auth_transport=auth, mapit_transport=mapit,
        deadline=20.0, monotonic=lambda: 10.0,
    )
    with pytest.raises(EnrolledProviderError, match="enrolled_provider_failed"):
        provider.get()
    assert len(auth.calls) == 1
    assert mapit.calls == []


def test_registry_revocation_discards_inflight_and_cached_business_results(tmp_path):
    env = _make_setup(tmp_path)
    publisher = _PublishingSecrets()
    registry, grant, snapshot, _ = _binding(env, KEY_A, TOKEN_A, publisher)
    mapit = _Mapit("should-be-discarded", 99, callback=lambda: registry.revoke(grant, snapshot))
    provider = EnrolledCloudServicesProvider(
        registry, authority=env["authority"], grant=grant, durable_guard=env["guard"],
        snapshot=snapshot, ssm_client=_SSM(publisher.values), account_id=ACCOUNT_ID,
        auth_transport=_AuthTransport(env["tokens"][TOKEN_A]), mapit_transport=mapit,
        deadline=20.0, monotonic=lambda: 10.0,
    )
    services = provider.get()
    with pytest.raises(EnrolledProviderError, match="enrolled_unauthorized"):
        services.get_vehicle_status()
    assert len(mapit.calls) == 1
    with pytest.raises(EnrolledProviderError, match="enrolled_unauthorized"):
        services.get_vehicle_status()
    assert len(mapit.calls) == 1
