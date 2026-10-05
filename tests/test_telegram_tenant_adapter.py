import asyncio
import time
from dataclasses import replace

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from mapit.aws_prod_runtime import CognitoProdPolicy
from mapit.telegram_tenant_adapter import BoundedTenantTelegramAdapter
from mapit.tenant_linking import TenantLinkChallengeRegistry, TrustedPrivateTelegramPair
from mapit.tenant_router import InvitedTenantAuthority, TenantServicesRouter, tenant_key


def test_bound_delivery_rejects_swapped_grant_and_does_not_retry_ambiguous_send():
    async def scenario():
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        policies, grants, pairs = {}, {}, {}
        for index in (1, 2):
            subject = f"00000000-0000-4000-8000-{index:012d}"
            policy = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient", subject)
            key = tenant_key(b"s" * 32, policy.issuer_url, subject)
            policies[key] = policy
            pairs[index] = TrustedPrivateTelegramPair(user_id=100 + index, chat_id=100 + index)
        authority = InvitedTenantAuthority(policies, {"test": public})
        for index, policy in enumerate(policies.values(), 1):
            now = int(time.time())
            token = jwt.encode({"iss": policy.issuer_url, "aud": policy.audience,
                "sub": policy.owner_subject, "client_id": policy.client_id, "token_use": "access",
                "iat": now - 1, "exp": now + 300, "scope": policy.required_scope},
                private, algorithm="RS256", headers={"kid": "test"})
            grants[index] = await authority.authenticate(token)
        registry = TenantLinkChallengeRegistry(authority)
        for index in (1, 2):
            challenge = await registry.issue(pairs[index])
            await registry.consume_bind(challenge, pairs[index], grants[index])
        factories = []
        def factory(*args):
            factories.append(args)
            raise AssertionError("help must not read a MAPIT provider")
        router = TenantServicesRouter(authority, factory)
        selected = grants[1]
        async def resolver(update):
            return selected
        class Sender:
            calls = []
            fail = False
            async def send_message(self, chat_id, text):
                self.calls.append((chat_id, text))
                if self.fail:
                    raise RuntimeError("synthetic-secret-never-in-result")
        sender = Sender()
        adapter = BoundedTenantTelegramAdapter(registry, router, resolver, sender)
        def update(number, pair=1, text="/ayuda", chat_type="private"):
            return {"update_id": number, "user_id": pairs[pair].user_id,
                    "chat_id": pairs[pair].chat_id, "chat_type": chat_type, "text": text}
        good = await adapter.handle(update(1))
        assert good.sent and good.category == "success" and sender.calls[0][0] == 101
        assert (await adapter.handle(update(1))).category == "duplicate_update"
        assert (await adapter.handle(update(2, pair=2))).category == "unauthorized"
        selected = replace(grants[1], expires_at=grants[1].expires_at + 1)
        assert (await adapter.handle(update(3))).category == "unauthorized"
        selected = grants[1]
        assert (await adapter.handle(update(4, text="/verano Sabadell"))).category == "command_failed"
        assert (await adapter.handle(update(5, chat_type="group"))).category == "invalid_update"
        bot_update = {"update_id": 50, "message": {"from": {"id": 101, "is_bot": True},
                      "chat": {"id": 101, "type": "private"}, "text": "/ayuda"}}
        assert (await adapter.handle(bot_update)).category == "invalid_update"
        sender.fail = True
        failed = await adapter.handle(update(6))
        assert failed.category == "sender_failed_no_retry" and not failed.sent
        assert "synthetic-secret" not in repr(failed)
        assert (await adapter.handle(update(6))).category == "duplicate_update"
        assert len(sender.calls) == 2 and factories == []
        await registry.unlink(grants[1])
        assert (await adapter.handle(update(7))).category == "unauthorized"
        assert len(sender.calls) == 2
    asyncio.run(scenario())


def test_batch_receipts_fail_closed_at_capacity_even_without_a_valid_grant():
    async def scenario():
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        policy = CognitoProdPolicy("eu-west-1_AbCdEfGhI", "a1b2c3d4e5", "SyntheticClient",
                                  "00000000-0000-4000-8000-000000000001")
        key = tenant_key(b"s" * 32, policy.issuer_url, policy.owner_subject)
        authority = InvitedTenantAuthority({key: policy}, {"test": public})
        registry = TenantLinkChallengeRegistry(authority)
        calls = []
        async def resolver(update):
            calls.append(True)
            return None
        class Sender:
            async def send_message(self, *args):
                raise AssertionError("must not send")
        router = TenantServicesRouter(authority, lambda *args: None)
        adapter = BoundedTenantTelegramAdapter(registry, router, resolver, Sender())
        for index in range(64):
            assert (await adapter.handle({"update_id": index, "user_id": 101, "chat_id": 101,
                "chat_type": "private", "text": "/ayuda"})).category == "unauthorized"
        assert (await adapter.handle({"update_id": 64, "user_id": 101, "chat_id": 101,
            "chat_type": "private", "text": "/ayuda"})).category == "batch_capacity_exhausted"
        assert len(calls) == 64
    asyncio.run(scenario())
