"""Independent tenancy and result-binding regressions for geographic commands."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.services import GeographicRouteSummary
from mapit.telegram_geographic_commands import GeographicCommandError, dispatch_geographic_command
from mapit.tenant_router import InvitedTenantAuthority, TenantServicesRouter, tenant_key


SUBJECT_A = "00000000-0000-4000-8000-000000000101"
SUBJECT_B = "00000000-0000-4000-8000-000000000102"
BASE_POLICY = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUBJECT_A)
POLICY_A = BASE_POLICY
POLICY_B = replace(BASE_POLICY, owner_subject=SUBJECT_B)
KEY_MATERIAL = b"i" * 32
KEY_A = tenant_key(KEY_MATERIAL, POLICY_A.issuer_url, SUBJECT_A)
KEY_B = tenant_key(KEY_MATERIAL, POLICY_B.issuer_url, SUBJECT_B)


def _token(private_key, policy):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": policy.issuer_url,
            "aud": policy.audience,
            "sub": policy.owner_subject,
            "client_id": policy.client_id,
            "token_use": "access",
            "iat": now - 1,
            "exp": now + 300,
            "scope": policy.required_scope,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "tenant-isolation-test-key"},
    )


def _summary(*, matched, inside, outside, distance_km, area_source="ign_menorca_municipalities_union_2026_10_03",
             from_time="2026-06-01T00:00:00.000Z", to_time="2026-07-01T00:00:00.000Z"):
    return GeographicRouteSummary(
        from_time=from_time,
        to_time=to_time,
        area_source=area_source,
        area_type="MultiPolygon",
        matched_routes=matched,
        fully_inside_routes=inside,
        outside_routes=outside,
        crossing_routes=0,
        unknown_routes=0,
        fully_inside_distance=distance_km * 1000,
        fully_inside_distance_km=distance_km,
        inferred_marked_inside_routes=0,
        not_marked_inferred_inside_routes=inside,
        inference_unknown_inside_routes=0,
    )


class _Services:
    def __init__(self, summary):
        self.summary = summary
        self.calls = 0

    def get_geographic_summary(self, *args):
        self.calls += 1
        return self.summary


class _Provider:
    def __init__(self, services):
        self.services = services

    def get(self):
        return self.services


def test_two_authenticated_tenants_get_only_their_own_geographic_counts():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    authority = InvitedTenantAuthority(
        {KEY_A: POLICY_A, KEY_B: POLICY_B}, {"tenant-isolation-test-key": public}
    )
    grant_a = asyncio.run(authority.authenticate(_token(private, POLICY_A)))
    grant_b = asyncio.run(authority.authenticate(_token(private, POLICY_B)))
    services = {
        KEY_A: _Services(_summary(matched=1, inside=1, outside=0, distance_km=1.25)),
        KEY_B: _Services(_summary(matched=2, inside=0, outside=2, distance_km=0.0)),
    }
    factory_keys = []

    def factory(key, deadline):
        factory_keys.append(key)
        return _Provider(services[key])

    router = TenantServicesRouter(authority, factory)
    command = "/kms Menorca | 2026-06-01 | 2026-07-01"
    answer_a = dispatch_geographic_command(command, grant_a, router)
    answer_b = dispatch_geographic_command(command, grant_b, router)

    assert "Rutas: 1; dentro: 1; fuera: 0" in answer_a
    assert "1.25 km" in answer_a
    assert "Rutas: 2; dentro: 0; fuera: 2" in answer_b
    assert "1.25 km" not in answer_b
    assert factory_keys == [KEY_A, KEY_B]
    assert services[KEY_A].calls == services[KEY_B].calls == 1


@pytest.mark.parametrize(
    ("area_source", "from_time", "to_time"),
    [
        ("ign_amb_36_municipalities_union_2026_10_03", "2026-06-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z"),
        ("ign_menorca_municipalities_union_2026_10_03", "2026-05-01T00:00:00.000Z", "2026-06-01T00:00:00.000Z"),
        ("ign_menorca_municipalities_union_2026_10_03", "2026-06-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z"),
    ],
)
def test_dispatch_rejects_summary_not_bound_to_requested_area_and_period(area_source, from_time, to_time):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    authority = InvitedTenantAuthority({KEY_A: POLICY_A}, {"tenant-isolation-test-key": public})
    grant = asyncio.run(authority.authenticate(_token(private, POLICY_A)))
    service = _Services(
        _summary(matched=1, inside=1, outside=0, distance_km=1.0,
                 area_source=area_source, from_time=from_time, to_time=to_time)
    )
    factories = []
    router = TenantServicesRouter(
        authority,
        lambda key, deadline: factories.append(key) or _Provider(service),
    )

    with pytest.raises(GeographicCommandError) as error:
        dispatch_geographic_command("/kms Menorca | 2026-06-01 | 2026-07-01", grant, router)
    assert error.value.category == "summary_unavailable"
    assert factories == [KEY_A]
    assert service.calls == 1
