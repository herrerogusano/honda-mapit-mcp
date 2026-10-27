from __future__ import annotations

import copy
import hashlib
import json

import pytest

from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts import dev_owner_login_context as context
from scripts.dev_owner_oauth_bootstrap import DevOwnerOAuthBootstrapCoordinator, _canonical
from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings


def receipt():
    auth = {"account": "123456789012", "expected_caller_arn": "arn:aws:iam::123456789012:user/operator",
        "source_sha": "a" * 40, "run_id": 123, "start": 1800000000, "end": 1800000600, "ci_run_id": 456}
    binding = {"schema": 1, "kind": "dev-owner-oauth-authority", "account_id": auth["account"],
        "operator_user_arn": auth["expected_caller_arn"], "owner_pool_id": "eu-west-1_abcdefghijk",
        "api_id": "abcdefghij", "callback_url": context.CALLBACK, "context_sha256": "b" * 64,
        "run_uuid": "123e4567-e89b-42d3-a456-426614174000", "github_owner_id": 1,
        "github_repository_id": 2, "authorization_sha256": hashlib.sha256(_canonical(auth)).hexdigest(),
        "state_directory": "private-state"}
    class NoIO:
        def __getattr__(self, _name):
            return lambda **_kw: pytest.fail("IO during parse")
    class Journal:
        load = save = locked = lambda *_: pytest.fail("unexpected journal IO")
    coordinator = DevOwnerOAuthBootstrapCoordinator(
        {"cloudformation": NoIO(), "cognito": NoIO()}, Journal(),
        account_id=auth["account"], operator_user_arn=auth["expected_caller_arn"],
        owner_pool_id=binding["owner_pool_id"], api_id=binding["api_id"], callback_url=context.CALLBACK,
        source_sha=auth["source_sha"], run_id=binding["run_uuid"], authorized_from_epoch=auth["start"],
        authorized_until_epoch=auth["end"], expected_context_sha256=binding["context_sha256"],
        context_reader=lambda *_: pytest.fail("IO"), source_checker=lambda: pytest.fail("IO"),
        readback_validator=lambda *_: pytest.fail("IO"))
    state = {"schema": 1, "kind": "dev-owner-oauth-bootstrap", "authority_sha256": coordinator.authority_sha256,
        "template_sha256": coordinator.template_sha256, "phase": "readback_verified",
        "last_observed_epoch": auth["start"] + 10,
        "intent": {"token": coordinator._request_token(), "stack_name": context.STACK_NAME,
            "template_sha256": coordinator.template_sha256},
        "ack_stack_id": f'arn:aws:cloudformation:eu-west-1:{auth["account"]}:stack/{context.STACK_NAME}/123e4567-e89b-42d3-a456-426614174001',
        "readback": {"verified": True, "client_id": "newdevclient12345", "readback_sha256": "c" * 64}}
    trusted = CognitoProdPolicy(binding["owner_pool_id"], "prodapi123", "prodclient1234",
        "12345678-1234-1234-1234-123456789abc")
    return auth, binding, state, trusted


def parse(parts):
    return context.parse_accepted_owner_login_context(*parts[:3], trusted_owner_policy=parts[3])


def test_expired_receipt_is_evidence_not_renewed_creation_authority():
    parts = receipt()
    before = copy.deepcopy(parts[:3])
    accepted = parse(parts)
    assert accepted.policy.owner_subject == parts[3].owner_subject
    assert accepted.policy.user_pool_id == parts[3].user_pool_id
    assert accepted.policy.api_id != parts[3].api_id
    assert accepted.policy.client_id != parts[3].client_id
    assert accepted.policy.environment == "dev"
    assert parts[:3] == before
    assert repr(accepted) == "AcceptedOwnerLoginContext(<redacted>)"


@pytest.mark.parametrize("where,field,value", [
    (0, "source_sha", "d" * 40), (0, "end", 1800000601),
    (1, "account_id", "999999999999"), (1, "owner_pool_id", "eu-west-1_999999999"),
    (1, "callback_url", "http://127.0.0.1:8786/callback"),
    (1, "api_id", "prodapi123"), (1, "github_owner_id", True),
    (1, "authorization_sha256", "e" * 64), (1, "run_uuid", "invalid"),
    (2, "phase", "create_acknowledged"), (2, "authority_sha256", "f" * 64),
    (2, "template_sha256", "f" * 64), (2, "ack_stack_id", "wrong-stack"),
])
def test_mixed_or_unaccepted_receipt_rejected(where, field, value):
    parts = receipt()
    parts[where][field] = value
    with pytest.raises(context.OwnerLoginContextError, match="^owner_login_context_unverified$"):
        parse(parts)


def test_production_client_not_accepted_as_new_dev_client():
    parts = receipt()
    parts[2]["readback"]["client_id"] = parts[3].client_id
    with pytest.raises(context.OwnerLoginContextError):
        parse(parts)


class SDK(OwnerOAuthSdkBindings):
    def __init__(self, accepted):
        self.accepted = accepted
        self.account, self.caller = accepted.account, accepted.operator
        self.changed = None
        self.calls_seen = []

    def capture_context(self, exclude_client_id=None):
        self.calls_seen.append("context")
        assert exclude_client_id == self.accepted.policy.client_id
        return {"verified": True, "account_id": self.account,
            "owner_pool_id": self.accepted.policy.user_pool_id, "api_id": self.accepted.policy.api_id,
            "context_sha256": "d" * 64 if self.changed == "old_context" else self.accepted.context_digest}

    def _stack(self, name, count):
        self.calls_seen.append("stack")
        assert name == context.STACK_NAME and count == 3
        resources = {
            "McpResourceServer": {"ResourceType": "AWS::Cognito::UserPoolResourceServer", "PhysicalResourceId": "resource"},
            "McpUserPoolClient": {"ResourceType": "AWS::Cognito::UserPoolClient", "PhysicalResourceId": self.accepted.policy.client_id},
            "McpManagedLoginBranding": {"ResourceType": "AWS::Cognito::ManagedLoginBranding", "PhysicalResourceId": "branding"}}
        if self.changed == "client":
            resources["McpUserPoolClient"]["PhysicalResourceId"] = "differentclient1234"
        if self.changed == "resource":
            resources["McpUserPoolClient"]["ResourceType"] = "AWS::Other::Type"
        return resources, {"stack_id": "bad" if self.changed == "stack" else self.accepted.stack_id,
            "template_sha256": "d" * 64 if self.changed == "template" else self.accepted.template_digest}

    def validate_candidate(self, stack, template, run, start, end, physical):
        self.calls_seen.append("candidate")
        assert (stack, run, start, end) == (self.accepted.stack_id, self.accepted.run_id, self.accepted.start, self.accepted.end)
        assert template["Resources"]["McpUserPoolClient"]["Properties"]["CallbackURLs"] == [context.CALLBACK]
        return {"verified": True, "client_id": self.accepted.policy.client_id,
            "readback_sha256": "d" * 64 if self.changed == "candidate" else self.accepted.readback_digest}


def test_fresh_readonly_metadata_accepts_exact_old_context_and_new_client():
    accepted = parse(receipt())
    sdk = SDK(accepted)
    assert context.verify_current_context(accepted, sdk) is True
    assert sdk.calls_seen == ["context", "stack", "candidate"]


@pytest.mark.parametrize("change", ["old_context", "client", "resource", "stack", "template", "candidate"])
def test_readback_drift_fails_closed_without_cloud_writes(change):
    accepted = parse(receipt())
    sdk = SDK(accepted)
    sdk.changed = change
    with pytest.raises(context.OwnerLoginContextError):
        context.verify_current_context(accepted, sdk)


def test_readback_rejects_cross_account_before_calls():
    accepted = parse(receipt())
    sdk = SDK(accepted)
    sdk.account = "999999999999"
    with pytest.raises(context.OwnerLoginContextError):
        context.verify_current_context(accepted, sdk)
    assert sdk.calls_seen == []


def public_jwks():
    from cryptography.hazmat.primitives.asymmetric import rsa
    import jwt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    document = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    document.pop("key_ops", None)
    document.update(kid="owner", use="sig", alg="RS256")
    return json.dumps({"keys": [document]}).encode()


def test_preparation_orders_fresh_gates_and_constructs_only_after_readback():
    accepted = parse(receipt())
    sdk = SDK(accepted)
    events = []
    def source():
        events.append("source")
        return True
    def protection(**kwargs):
        assert kwargs == {"expected_owner_id": 1, "expected_repository_id": 2}
        events.append("protections")
        return 1, 2
    def channel(policy, keys, consumer):
        assert policy == accepted.policy and set(keys) == {"owner"}
        assert sdk.calls_seen == ["context", "stack", "candidate"]
        events.append("channel")
        return "ready"
    assert context.prepare_assisted_owner_login(accepted, sdk, public_jwks=public_jwks(),
        source_checker=source, protection_checker=protection, token_consumer=lambda _: None,
        channel_factory=channel) == "ready"
    assert events == ["source", "protections", "source", "protections", "channel"]


@pytest.mark.parametrize("gate", ["source", "protections", "readback", "jwks", "second_source"])
def test_preparation_failures_never_start_listener_or_request_tokens(gate):
    accepted = parse(receipt())
    sdk = SDK(accepted)
    sdk.changed = "old_context" if gate == "readback" else None
    count = 0
    def source():
        nonlocal count
        count += 1
        return not (gate == "source" or (gate == "second_source" and count == 2))
    with pytest.raises(context.OwnerLoginContextError):
        context.prepare_assisted_owner_login(accepted, sdk,
            public_jwks=b"invalid" if gate == "jwks" else public_jwks(),
            source_checker=source, protection_checker=lambda **_: (1, 99) if gate == "protections" else (1, 2),
            token_consumer=lambda _: pytest.fail("consumer called"),
            channel_factory=lambda *_: pytest.fail("listener constructed"))
    if gate in {"source", "protections", "jwks"}:
        assert sdk.calls_seen == []
