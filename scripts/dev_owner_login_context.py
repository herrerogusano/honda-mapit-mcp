"""Read-only bridge from the consumed OAuth receipt to a human DEV login.

Historical create authority is evidence only, never renewed or executed here.
The owner subject must come from a separately trusted production policy, not
from the candidate callback/token. A login establishes identity, not invitation.
No file, credential, SDK, browser or network IO occurs on import.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
import weakref
from collections.abc import Mapping

from mapit.aws_dev_runtime import CognitoDevPolicy, parse_cognito_jwks
from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts.build_aws_dev_owner_oauth import build_dev_owner_oauth_template, STACK_NAME
from scripts.dev_owner_oauth_bootstrap import DevOwnerOAuthBootstrapCoordinator, _canonical
from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings
from scripts.run_aws_retained_dev_bootstrap import validate_authorization

CALLBACK = "http://127.0.0.1:8787/callback"
# Identity registration, not value equality: dataclasses.replace must not turn
# an accepted receipt into authority for a different subject or cloud binding.
# Weak references retain no login token or long-lived private context.
_ACCEPTED = weakref.WeakValueDictionary()


class OwnerLoginContextError(ValueError):
    def __init__(self):
        super().__init__("owner_login_context_unverified")


@dataclass(frozen=True, repr=False)
class AcceptedOwnerLoginContext:
    policy: CognitoDevPolicy = field(repr=False)
    account: str
    operator: str
    stack_id: str
    run_id: str
    start: int
    end: int
    context_digest: str
    readback_digest: str
    template_digest: str
    github_owner_id: int
    github_repository_id: int

    def __repr__(self):
        return "AcceptedOwnerLoginContext(<redacted>)"


def parse_accepted_owner_login_context(auth, binding, state, *,
                                       trusted_owner_policy: CognitoProdPolicy) -> AcceptedOwnerLoginContext:
    """Validate an immutable completed receipt, allowing its old window to expire.

    This pure parser neither checks current source nor establishes current cloud
    state. Use a fresh source/protection gate and ``verify_current_context``
    before listening. Inputs must be loaded from ACL-verified private locations.
    """
    try:
        auth = validate_authorization(auth)
        if (type(trusted_owner_policy) is not CognitoProdPolicy
                or not isinstance(binding, Mapping) or not isinstance(state, Mapping)
                or binding.get("schema") != 1 or type(binding.get("schema")) is not int
                or binding.get("kind") != "dev-owner-oauth-authority"
                or binding.get("account_id") != auth["account"]
                or binding.get("operator_user_arn") != auth["expected_caller_arn"]
                or binding.get("owner_pool_id") != trusted_owner_policy.user_pool_id
                or binding.get("api_id") == trusted_owner_policy.api_id
                or binding.get("callback_url") != CALLBACK
                or binding.get("authorization_sha256") != hashlib.sha256(_canonical(auth)).hexdigest()
                or not 0 < auth["end"] - auth["start"] <= 600):
            raise ValueError
        client = state.get("readback", {}).get("client_id")
        if (type(client) is not str or re.fullmatch(r"[A-Za-z0-9]{8,128}", client) is None
                or client == trusted_owner_policy.client_id):
            raise ValueError
        # Reuse the original strict journal validator without dispatching any
        # step. Its immutable binding, intent, template and receipt checks must
        # not drift into a weaker second interpretation of historical evidence.
        class Journal:
            def load(self):
                return state

            def save(self, _value):
                raise ValueError

            def locked(self):
                raise ValueError

        class NoIO:
            def __getattr__(self, _name):
                return lambda **_kwargs: (_ for _ in ()).throw(ValueError())

        coordinator = DevOwnerOAuthBootstrapCoordinator(
            {"cloudformation": NoIO(), "cognito": NoIO()}, Journal(),
            account_id=auth["account"], operator_user_arn=auth["expected_caller_arn"],
            owner_pool_id=binding["owner_pool_id"], api_id=binding["api_id"],
            callback_url=CALLBACK, source_sha=auth["source_sha"], run_id=binding["run_uuid"],
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
            expected_context_sha256=binding["context_sha256"],
            context_reader=lambda *_: None, source_checker=lambda: False,
            readback_validator=lambda *_: None,
        )
        accepted = coordinator._load()
        if accepted["phase"] != "readback_verified":
            raise ValueError
        for name in ("github_owner_id", "github_repository_id"):
            if type(binding.get(name)) is not int or binding[name] <= 0:
                raise ValueError
        policy = CognitoDevPolicy(binding["owner_pool_id"], binding["api_id"],
            client, trusted_owner_policy.owner_subject, request_deadline_seconds=14.0)
        context = AcceptedOwnerLoginContext(policy, auth["account"], auth["expected_caller_arn"],
            accepted["ack_stack_id"], binding["run_uuid"], auth["start"], auth["end"],
            binding["context_sha256"], accepted["readback"]["readback_sha256"],
            coordinator.template_sha256, binding["github_owner_id"], binding["github_repository_id"])
        _ACCEPTED[id(context)] = context
        return context
    except Exception:
        raise OwnerLoginContextError() from None


def verify_current_context(context: AcceptedOwnerLoginContext, sdk: OwnerOAuthSdkBindings) -> bool:
    """Bounded fresh metadata only; no bootstrap execution or historical writes."""
    try:
        if (type(context) is not AcceptedOwnerLoginContext or _ACCEPTED.get(id(context)) is not context
                or not isinstance(sdk, OwnerOAuthSdkBindings)
                or sdk.account != context.account or sdk.caller != context.operator):
            raise ValueError
        current = sdk.capture_context(exclude_client_id=context.policy.client_id)
        if current != {"verified": True, "account_id": context.account,
                "owner_pool_id": context.policy.user_pool_id, "api_id": context.policy.api_id,
                "context_sha256": context.context_digest}:
            raise ValueError
        resources, stack = sdk._stack(STACK_NAME, 3)
        expected_types = {"McpResourceServer": "AWS::Cognito::UserPoolResourceServer",
            "McpUserPoolClient": "AWS::Cognito::UserPoolClient",
            "McpManagedLoginBranding": "AWS::Cognito::ManagedLoginBranding"}
        if (stack["stack_id"] != context.stack_id or stack["template_sha256"] != context.template_digest
                or set(resources) != set(expected_types)
                or any(resources[name]["ResourceType"] != kind for name, kind in expected_types.items())
                or resources["McpUserPoolClient"]["PhysicalResourceId"] != context.policy.client_id):
            raise ValueError
        template = build_dev_owner_oauth_template(account_id=context.account,
            api_id=context.policy.api_id, owner_pool_id=context.policy.user_pool_id, callback_url=CALLBACK)
        result = sdk.validate_candidate(context.stack_id, template, context.run_id, context.start,
            context.end, {name: value["PhysicalResourceId"] for name, value in resources.items()})
        if result != {"verified": True, "client_id": context.policy.client_id,
                "readback_sha256": context.readback_digest}:
            raise ValueError
        return True
    except Exception:
        raise OwnerLoginContextError() from None


def prepare_assisted_owner_login(context: AcceptedOwnerLoginContext, sdk: OwnerOAuthSdkBindings, *,
                                 public_jwks: bytes, source_checker, protection_checker,
                                 token_consumer, channel_factory=None):
    """Compose the listener only after fresh source, protections and readback.

    All capabilities are explicit. The source callback must validate the current
    clean develop commit and its integrated CI, not the expired create commit.
    The caller obtains public JWKS from the pinned issuer using direct TLS.
    This function neither binds a socket nor opens a browser. The returned
    channel's short exchange lease begins only on the human callback.
    """
    try:
        if (type(context) is not AcceptedOwnerLoginContext or _ACCEPTED.get(id(context)) is not context
                or not callable(source_checker)
                or not callable(protection_checker) or not callable(token_consumer)
                or type(public_jwks) is not bytes):
            raise ValueError
        keys = parse_cognito_jwks(public_jwks)

        def source_and_protections():
            if source_checker() is not True:
                raise ValueError
            if protection_checker(expected_owner_id=context.github_owner_id,
                    expected_repository_id=context.github_repository_id) != (
                        context.github_owner_id, context.github_repository_id):
                raise ValueError

        source_and_protections()
        verify_current_context(context, sdk)
        source_and_protections()
        if channel_factory is None:
            from scripts.dev_owner_assisted_login import DevOwnerAssistedLogin
            channel_factory = DevOwnerAssistedLogin
        return channel_factory(context.policy, keys, token_consumer)
    except Exception:
        raise OwnerLoginContextError() from None


__all__ = ["AcceptedOwnerLoginContext", "OwnerLoginContextError",
    "parse_accepted_owner_login_context", "verify_current_context", "prepare_assisted_owner_login"]
