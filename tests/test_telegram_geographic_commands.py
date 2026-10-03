import asyncio
import time
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.services import GeographicRouteSummary
from mapit.telegram_geographic_commands import (
    GeographicCommandError,
    _format_summary,
    dispatch_geographic_command,
)
from mapit.tenant_router import InvitedTenantAuthority, TenantServicesRouter, tenant_key


SUBJECT = "00000000-0000-4000-8000-000000000021"
POLICY = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUBJECT)
KEY = tenant_key(b"t" * 32, POLICY.issuer_url, SUBJECT)


def _auth_and_grant():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    authority = InvitedTenantAuthority({KEY: POLICY}, {"test-key": public})
    now = int(time.time())
    signed = jwt.encode(
        {
            "iss": POLICY.issuer_url, "aud": POLICY.audience, "sub": SUBJECT,
            "client_id": POLICY.client_id, "token_use": "access", "iat": now - 1,
            "exp": now + 300, "scope": POLICY.required_scope,
        },
        private,
        algorithm="RS256",
        headers={"kid": "test-key"},
    )
    return authority, asyncio.run(authority.authenticate(signed))


def _summary(from_time="2026-06-01T00:00:00.000Z", to_time="2026-09-01T00:00:00.000Z", area_source="ign_menorca_municipalities_union_2026_10_03"):
    return GeographicRouteSummary(
        from_time=from_time,
        to_time=to_time,
        area_source=area_source,
        area_type="MultiPolygon",
        matched_routes=4,
        fully_inside_routes=2,
        outside_routes=1,
        crossing_routes=1,
        unknown_routes=0,
        fully_inside_distance=12000.0,
        fully_inside_distance_km=12.0,
        inferred_marked_inside_routes=1,
        not_marked_inferred_inside_routes=0,
        inference_unknown_inside_routes=1,
    )


class Services:
    def __init__(self):
        self.calls = []

    def get_geographic_summary(self, from_time, to_time, area, source):
        self.calls.append(("period", from_time, to_time, source))
        return _summary(from_time, to_time, source)

    def get_summer_geographic_summary(self, area, year, *, area_source):
        self.calls.append(("summer", year, area_source))
        from mapit.geography import summer_window_utc
        start, end = summer_window_utc(year)
        return _summary(start, end, area_source)


class Provider:
    def __init__(self, services):
        self.services = services

    def get(self):
        return self.services


def _router(services, factory_calls):
    authority, grant = _auth_and_grant()

    def factory(key, deadline):
        factory_calls.append(key)
        return Provider(services)

    return authority, grant, TenantServicesRouter(authority, factory)


def test_help_requires_authenticated_context_but_does_not_fetch_provider():
    services, factories = Services(), []
    authority, grant, router = _router(services, factories)
    answer = dispatch_geographic_command("/ayuda", grant, router)
    assert "/verano" in answer and "/kms" in answer
    assert factories == [] and services.calls == []
    forged = replace(grant, expires_at=grant.expires_at + 1)
    with pytest.raises(GeographicCommandError) as error:
        dispatch_geographic_command("/ayuda", forged, router)
    assert error.value.category == "tenant_context_invalid"
    assert factories == []


def test_kms_dispatches_fixed_area_period_and_formats_only_safe_metrics():
    services, factories = Services(), []
    _, grant, router = _router(services, factories)
    answer = dispatch_geographic_command(
        "/kms Menorca | 2026-06-01T00:00:00Z | 2026-07-01T00:00:00Z",
        grant,
        router,
    )
    assert services.calls == [("period", "2026-06-01T00:00:00.000Z", "2026-07-01T00:00:00.000Z", "ign_menorca_municipalities_union_2026_10_03")]
    assert "12.00 km" in answer and "dentro: 2" in answer and "desconocido 1" in answer
    assert SUBJECT not in answer and KEY not in answer and "route" not in answer.lower()


def test_summer_accepts_fixed_named_areas_with_spaces_and_optional_year():
    services, factories = Services(), []
    _, grant, router = _router(services, factories)
    answer = dispatch_geographic_command("/verano Àrea Metropolitana de Barcelona 2026", grant, router)
    assert "12.00 km" in answer
    assert services.calls[0][0:2] == ("summer", 2026)
    assert services.calls[0][2] == "ign_amb_36_municipalities_union_2026_10_03"


@pytest.mark.parametrize(
    ("command", "category"),
    [
        ("/kms alrededores | 2026-06-01 | 2026-06-02", "unknown_area"),
        ("/kms Menorca | 2026-06-01 | 2026-10-01", "invalid_period"),
        ("/kms Menorca | not-a-date | 2026-06-02", "invalid_period"),
        ("/verano Menorca 2040", "unsupported_year"),
        ("/verano Menorca extra", "unknown_area"),
        ("/kms Menorca | 2026-06-01 | 2026-06-02 extra", "invalid_period"),
    ],
)
def test_invalid_commands_fail_before_provider_factory(command, category):
    services, factories = Services(), []
    _, grant, router = _router(services, factories)
    with pytest.raises(GeographicCommandError) as error:
        dispatch_geographic_command(command, grant, router)
    assert error.value.category == category
    assert factories == [] and services.calls == []


def test_provider_failures_are_redacted_and_bad_summary_is_rejected():
    services, factories = Services(), []
    _, grant, router = _router(services, factories)
    services.get_geographic_summary = lambda *args: (_ for _ in ()).throw(RuntimeError("private-route-canary"))
    with pytest.raises(GeographicCommandError) as error:
        dispatch_geographic_command("/kms Menorca | 2026-06-01 | 2026-06-02", grant, router)
    assert error.value.category == "tenant_context_invalid"
    assert "private-route-canary" not in str(error.value)

    services, factories = Services(), []
    _, grant, router = _router(services, factories)
    services.get_geographic_summary = lambda *args: {"matched_routes": 1, "coordinates": "secret"}
    with pytest.raises(GeographicCommandError) as error:
        dispatch_geographic_command("/kms Menorca | 2026-06-01 | 2026-06-02", grant, router)
    assert error.value.category == "summary_unavailable"


@pytest.mark.parametrize("changes", [
    {"from_time": "private-route-id-canary"},
    {"matched_routes": 2001},
    {"fully_inside_routes": 3},
    {"not_marked_inferred_inside_routes": 2},
    {"fully_inside_distance_km": float("nan")},
])
def test_malformed_typed_summary_fails_closed_without_echoing_values(changes):
    values = _summary().model_dump()
    values.update(changes)
    malformed = GeographicRouteSummary.model_construct(**values)
    with pytest.raises(GeographicCommandError) as error:
        _format_summary(
            malformed,
            expected_source="ign_menorca_municipalities_union_2026_10_03",
            expected_from="2026-06-01T00:00:00.000Z",
            expected_to="2026-09-01T00:00:00.000Z",
        )
    assert error.value.category == "summary_unavailable"
    assert "private-route-id-canary" not in str(error.value)
