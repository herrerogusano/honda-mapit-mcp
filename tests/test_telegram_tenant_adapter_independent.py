import asyncio
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.telegram_tenant_adapter import BoundedTenantTelegramAdapter
from mapit.tenant_linking import TenantLinkChallengeRegistry, TenantLinkError, TrustedPrivateTelegramPair
from mapit.tenant_router import InvitedTenantAuthority, TenantServicesRouter, tenant_key


async def _authority_grants():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    policies = {}
    for index in (1, 2):
        subject = f"00000000-0000-4000-8000-{index:012d}"
        policy = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", subject)
        policies[tenant_key(b"i" * 32, policy.issuer_url, subject)] = policy
    authority = InvitedTenantAuthority(policies, {"independent": public})

    async def authenticate():
        grants = {}
        for policy in policies.values():
            now = int(time.time())
            token = jwt.encode(
                {"iss": policy.issuer_url, "aud": policy.audience, "sub": policy.owner_subject,
                 "client_id": policy.client_id, "token_use": "access", "iat": now - 1,
                 "exp": now + 300, "scope": policy.required_scope},
                private, algorithm="RS256", headers={"kid": "independent"},
            )
            grants[policy.owner_subject] = await authority.authenticate(token)
        return grants

    return authority, await authenticate()


def _token():
    return "A" * 43


def test_consumed_challenge_digest_cannot_be_reissued_during_its_ttl():
    async def scenario():
        authority, grants = await _authority_grants()
        pairs = [TrustedPrivateTelegramPair(701, 701), TrustedPrivateTelegramPair(702, 702)]
        registry = TenantLinkChallengeRegistry(
            authority, _challenge_factory=_token, clock=lambda: 50.0
        )
        challenge = await registry.issue(pairs[0])
        await registry.consume_bind(challenge, pairs[0], grants[next(iter(grants))])
        with pytest.raises(TenantLinkError, match="tenant_link_configuration_invalid"):
            await registry.issue(pairs[1])

    asyncio.run(scenario())


def test_revoke_between_business_result_and_send_suppresses_delivery(monkeypatch):
    async def scenario():
        authority, grants = await _authority_grants()
        subject, grant = next(iter(grants.items()))
        pair = TrustedPrivateTelegramPair(801, 801)
        registry = TenantLinkChallengeRegistry(authority, _challenge_factory=_token)
        challenge = await registry.issue(pair)
        await registry.consume_bind(challenge, pair, grant)
        router = TenantServicesRouter(authority, lambda *_: pytest.fail("help path must not create provider"))
        class Resolver:
            async def __call__(self, _update):
                return grant
        class Sender:
            calls = []
            async def send_message(self, *args):
                self.calls.append(args)
        sender = Sender()
        adapter = BoundedTenantTelegramAdapter(registry, router, Resolver(), sender)

        import mapit.telegram_tenant_adapter as module
        def revoke_after_business(_text, _grant, _router):
            authority.revoke(grant.key)
            return "synthetic result"
        monkeypatch.setattr(module, "dispatch_geographic_command", revoke_after_business)
        result = await adapter.handle({"update_id": 801, "user_id": 801, "chat_id": 801,
                                       "chat_type": "private", "text": "/ayuda"})
        assert result.category == "command_failed" and not result.sent
        assert sender.calls == []

    asyncio.run(scenario())


def test_concurrent_duplicate_is_serialized_and_sent_once():
    async def scenario():
        authority, grants = await _authority_grants()
        _, grant = next(iter(grants.items()))
        pair = TrustedPrivateTelegramPair(901, 901)
        registry = TenantLinkChallengeRegistry(authority, _challenge_factory=_token)
        challenge = await registry.issue(pair)
        await registry.consume_bind(challenge, pair, grant)
        router = TenantServicesRouter(authority, lambda *_: pytest.fail("help path must not create provider"))
        entered = asyncio.Event()
        release = asyncio.Event()
        resolver_calls = []
        class Resolver:
            async def __call__(self, _update):
                resolver_calls.append(True)
                entered.set()
                await release.wait()
                return grant
        class Sender:
            calls = []
            async def send_message(self, *args):
                self.calls.append(args)
        sender = Sender()
        adapter = BoundedTenantTelegramAdapter(registry, router, Resolver(), sender)
        update = {"update_id": 902, "user_id": 901, "chat_id": 901,
                  "chat_type": "private", "text": "/ayuda"}
        first = asyncio.create_task(adapter.handle(update))
        await entered.wait()
        second = asyncio.create_task(adapter.handle(update))
        await asyncio.sleep(0)
        release.set()
        first_result, second_result = await asyncio.gather(first, second)
        assert {first_result.category, second_result.category} == {"success", "duplicate_update"}
        assert len(resolver_calls) == 1 and len(sender.calls) == 1

    asyncio.run(scenario())


def test_cancelled_update_remains_consumed_and_is_not_retried():
    async def scenario():
        authority, grants = await _authority_grants()
        _, grant = next(iter(grants.items()))
        pair = TrustedPrivateTelegramPair(1001, 1001)
        registry = TenantLinkChallengeRegistry(authority, _challenge_factory=_token)
        challenge = await registry.issue(pair)
        await registry.consume_bind(challenge, pair, grant)
        router = TenantServicesRouter(authority, lambda *_: pytest.fail("help path must not create provider"))
        entered = asyncio.Event()
        class Resolver:
            async def __call__(self, _update):
                entered.set()
                await asyncio.Event().wait()
        class Sender:
            calls = []
            async def send_message(self, *args):
                self.calls.append(args)
        sender = Sender()
        adapter = BoundedTenantTelegramAdapter(registry, router, Resolver(), sender)
        update = {"update_id": 1002, "user_id": 1001, "chat_id": 1001,
                  "chat_type": "private", "text": "/ayuda"}
        task = asyncio.create_task(adapter.handle(update))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        retry = await adapter.handle(update)
        assert retry.category == "duplicate_update" and sender.calls == []

    asyncio.run(scenario())
