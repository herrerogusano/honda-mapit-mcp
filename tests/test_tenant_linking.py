import asyncio
import time
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.tenant_linking import (
    TenantLinkChallengeRegistry,
    TenantLinkError,
    TrustedPrivateTelegramPair,
)
from mapit.tenant_router import InvitedTenantAuthority, tenant_key


SUB_A = "00000000-0000-4000-8000-000000000031"
SUB_B = "00000000-0000-4000-8000-000000000032"
POLICY = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", SUB_A)


def _authority_and_grants(subjects=(SUB_A, SUB_B)):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policies = {
        tenant_key(b"t" * 32, POLICY.issuer_url, subject):
            CognitoProdPolicy(POLICY.user_pool_id, POLICY.api_id, POLICY.client_id, subject)
        for subject in subjects
    }
    authority = InvitedTenantAuthority(policies, {"test-key": public})
    now = int(time.time())
    grants = {}
    for key, policy in policies.items():
        signed = jwt.encode(
            {
                "iss": policy.issuer_url, "aud": policy.audience, "sub": policy.owner_subject,
                "client_id": policy.client_id, "token_use": "access", "iat": now - 1,
                "exp": now + 300, "scope": policy.required_scope,
            },
            private,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )
        grants[policy.owner_subject] = asyncio.run(authority.authenticate(signed))
    return authority, grants


def _token(index):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    return "".join(alphabet[(index + offset) % len(alphabet)] for offset in range(43))


def test_private_pair_validation_and_repr_redact_identifiers():
    pair = TrustedPrivateTelegramPair(123456789, 123456789)
    assert "123456789" not in repr(pair)
    with pytest.raises(TenantLinkError, match="tenant_link_pair_invalid"):
        TrustedPrivateTelegramPair(123456789, 987654321)
    with pytest.raises(TenantLinkError, match="tenant_link_pair_invalid"):
        TrustedPrivateTelegramPair(True, True)
    with pytest.raises(TenantLinkError, match="tenant_link_pair_invalid"):
        TrustedPrivateTelegramPair(-123, -123)


def test_issue_keeps_only_digest_and_consume_resolves_only_with_fresh_exact_grant():
    authority, grants = _authority_and_grants()
    grant_a, grant_b = grants[SUB_A], grants[SUB_B]
    pair_a = TrustedPrivateTelegramPair(111, 111)
    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=lambda: _token(1))
    challenge = asyncio.run(registry.issue(pair_a))
    assert challenge not in repr(registry)
    assert challenge.encode("ascii") not in repr(registry._pending).encode("utf-8")
    assert all(len(entry.digest) == 32 for entry in registry._pending)

    opaque = asyncio.run(registry.consume_bind(challenge, pair_a, grant_a))
    assert opaque == grant_a.key
    assert asyncio.run(registry.resolve(pair_a, grant_a)) == grant_a.key
    with pytest.raises(TenantLinkError, match="tenant_link_challenge_invalid"):
        asyncio.run(registry.consume_bind(challenge, pair_a, grant_a))
    with pytest.raises(TenantLinkError, match="tenant_link_not_found"):
        asyncio.run(registry.resolve(pair_a, grant_b))
    assert "111" not in repr(registry) and SUB_A not in repr(registry)


def test_challenge_is_bound_to_exact_pair_and_wrong_pair_does_not_consume():
    authority, grants = _authority_and_grants()
    pair_a, pair_b = TrustedPrivateTelegramPair(101, 101), TrustedPrivateTelegramPair(202, 202)
    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=lambda: _token(2))
    challenge = asyncio.run(registry.issue(pair_a))
    with pytest.raises(TenantLinkError, match="tenant_link_challenge_invalid"):
        asyncio.run(registry.consume_bind(challenge, pair_b, grants[SUB_A]))
    assert asyncio.run(registry.consume_bind(challenge, pair_a, grants[SUB_A])) == grants[SUB_A].key


def test_tenant_and_private_pair_links_are_one_to_one_until_explicit_unlink():
    authority, grants = _authority_and_grants()
    pair_a, pair_b = TrustedPrivateTelegramPair(301, 301), TrustedPrivateTelegramPair(302, 302)
    tokens = iter((_token(3), _token(4), _token(5)))
    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=lambda: next(tokens))
    asyncio.run(registry.consume_bind(asyncio.run(registry.issue(pair_a)), pair_a, grants[SUB_A]))

    with pytest.raises(TenantLinkError, match="tenant_link_already_bound"):
        asyncio.run(registry.consume_bind(asyncio.run(registry.issue(pair_b)), pair_b, grants[SUB_A]))
    with pytest.raises(TenantLinkError, match="tenant_link_already_bound"):
        asyncio.run(registry.consume_bind(asyncio.run(registry.issue(pair_a)), pair_a, grants[SUB_B]))

    assert asyncio.run(registry.unlink(grants[SUB_A])) is True
    with pytest.raises(TenantLinkError, match="tenant_link_not_found"):
        asyncio.run(registry.resolve(pair_a, grants[SUB_A]))
    assert asyncio.run(registry.consume_bind(asyncio.run(registry.issue(pair_b)), pair_b, grants[SUB_A])) == grants[SUB_A].key
    assert asyncio.run(registry.unlink(grants[SUB_B])) is False


def test_expiration_clock_rollback_and_invalid_grants_fail_closed():
    authority, grants = _authority_and_grants()
    now = [100.0]
    pair = TrustedPrivateTelegramPair(401, 401)
    registry = TenantLinkChallengeRegistry(authority, clock=lambda: now[0], _challenge_factory=lambda: _token(6))
    challenge = asyncio.run(registry.issue(pair))
    now[0] = 400.001
    with pytest.raises(TenantLinkError, match="tenant_link_challenge_expired"):
        asyncio.run(registry.consume_bind(challenge, pair, grants[SUB_A]))

    now[0] = 500.0
    challenge2 = asyncio.run(registry.issue(pair))
    now[0] = 499.0
    with pytest.raises(TenantLinkError, match="tenant_link_clock_rollback"):
        asyncio.run(registry.consume_bind(challenge2, pair, grants[SUB_A]))

    forged = type(grants[SUB_A])(grants[SUB_A].key, grants[SUB_A].expires_at, b"x" * 32)
    with pytest.raises(TenantLinkError, match="tenant_link_grant_invalid"):
        asyncio.run(registry.resolve(pair, forged))


def test_pending_capacity_and_token_collision_are_bounded():
    authority, _ = _authority_and_grants()
    counter = [0]

    def unique_token():
        counter[0] += 1
        return _token(counter[0])

    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=unique_token)
    for number in range(16):
        pair = TrustedPrivateTelegramPair(1000 + number, 1000 + number)
        asyncio.run(registry.issue(pair))
    with pytest.raises(TenantLinkError, match="tenant_link_registry_full"):
        asyncio.run(registry.issue(TrustedPrivateTelegramPair(2000, 2000)))
    assert len(registry._pending) == 16

    collision = TenantLinkChallengeRegistry(authority, _challenge_factory=lambda: _token(99))
    asyncio.run(collision.issue(TrustedPrivateTelegramPair(3001, 3001)))
    with pytest.raises(TenantLinkError, match="tenant_link_configuration_invalid"):
        asyncio.run(collision.issue(TrustedPrivateTelegramPair(3002, 3002)))


def test_binding_capacity_matches_maximum_verified_invitation_set():
    subjects = tuple(f"00000000-0000-4000-8000-{number:012d}" for number in range(100, 116))
    authority, grants = _authority_and_grants(subjects)
    registry = TenantLinkChallengeRegistry(
        authority,
        _challenge_factory=lambda: _token(200 + len(registry._pending) + len(registry._by_tenant)),
    )

    async def bind_all():
        for index, subject in enumerate(subjects):
            pair = TrustedPrivateTelegramPair(10_000 + index, 10_000 + index)
            challenge = await registry.issue(pair)
            assert await registry.consume_bind(challenge, pair, grants[subject]) == grants[subject].key

    asyncio.run(bind_all())
    assert len(registry._by_tenant) == 16
    assert len(registry._by_pair) == 16


def test_concurrent_consumption_is_atomic():
    authority, grants = _authority_and_grants()
    pair = TrustedPrivateTelegramPair(501, 501)
    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=lambda: _token(7))
    challenge = asyncio.run(registry.issue(pair))

    async def consume_twice():
        return await asyncio.gather(
            registry.consume_bind(challenge, pair, grants[SUB_A]),
            registry.consume_bind(challenge, pair, grants[SUB_A]),
            return_exceptions=True,
        )

    results = asyncio.run(consume_twice())
    assert sum(isinstance(item, str) for item in results) == 1
    failures = [item for item in results if isinstance(item, Exception)]
    assert len(failures) == 1 and isinstance(failures[0], TenantLinkError)
    assert failures[0].category == "tenant_link_challenge_invalid"
    assert asyncio.run(registry.resolve(pair, grants[SUB_A])) == grants[SUB_A].key


def test_consumed_challenge_digest_blocks_factory_reuse_even_after_unlink():
    authority, grants = _authority_and_grants()
    pair = TrustedPrivateTelegramPair(701, 701)
    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=lambda: _token(300))
    challenge = asyncio.run(registry.issue(pair))
    asyncio.run(registry.consume_bind(challenge, pair, grants[SUB_A]))
    assert asyncio.run(registry.unlink(grants[SUB_A])) is True
    with pytest.raises(TenantLinkError, match="tenant_link_configuration_invalid"):
        asyncio.run(registry.issue(TrustedPrivateTelegramPair(702, 702)))
    assert len(registry._consumed) == 1


def test_consumed_digest_history_is_bounded_without_eviction():
    authority, grants = _authority_and_grants()
    counter = [0]

    def next_challenge():
        value = f"{counter[0]:04d}" + _token(400 + counter[0])[4:]
        counter[0] += 1
        return value

    registry = TenantLinkChallengeRegistry(authority, _challenge_factory=next_challenge)

    async def consume_and_unlink(count):
        for index in range(count):
            pair = TrustedPrivateTelegramPair(8000 + index, 8000 + index)
            challenge = await registry.issue(pair)
            await registry.consume_bind(challenge, pair, grants[SUB_A])
            assert await registry.unlink(grants[SUB_A]) is True

    asyncio.run(consume_and_unlink(64))
    assert len(registry._consumed) == 64
    pair = TrustedPrivateTelegramPair(9000, 9000)
    challenge = asyncio.run(registry.issue(pair))
    with pytest.raises(TenantLinkError, match="tenant_link_registry_full"):
        asyncio.run(registry.consume_bind(challenge, pair, grants[SUB_A]))
    assert len(registry._consumed) == 64
    assert len(registry._by_tenant) == 0
