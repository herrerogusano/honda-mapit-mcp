from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts import dev_owner_login_context as login_context
from scripts.dev_owner_oauth_bootstrap import DevOwnerOAuthBootstrapCoordinator
from scripts.dev_owner_login_context import CALLBACK
from scripts.build_aws_dev_owner_oauth import STACK_NAME
from scripts.dev_owner_enrolled_login_lineage import (
    OwnerEnrolledLoginLineageError,
    credential_snapshot_from_explicit_credentials,
    is_registered_owner_enrolled_lineage,
    validate_owner_enrolled_login_lineage,
)
from test_dev_owner_enrolled_delivery import Harness as DeliveryHarness
from test_dev_owner_login_context import receipt as owner_receipt


def _context_for_delivery(delivery):
    parts = owner_receipt()
    auth, binding, state, _trusted = parts
    auth["expected_caller_arn"] = delivery.auth["operator_arn"]
    binding["operator_user_arn"] = delivery.auth["operator_arn"]
    binding["owner_pool_id"] = delivery.auth["owner_pool_id"]
    binding["api_id"] = delivery.auth["owner_resource_uri"].split(".")[0].split("//", 1)[1]
    binding["context_sha256"] = delivery.auth["owner_context_sha256"]
    binding["authorization_sha256"] = hashlib.sha256(json.dumps(
        auth, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("ascii")).hexdigest()
    trusted = CognitoProdPolicy(binding["owner_pool_id"], "prodapi123", "prodclient1234",
        "12345678-1234-1234-1234-123456789abc")
    class NoIO:
        def __getattr__(self, _name):
            return lambda **_kwargs: pytest.fail("unexpected provider call")
    class Journal:
        def load(self):
            return state
        def save(self, _value):
            raise AssertionError("unexpected journal mutation")
        def locked(self):
            raise AssertionError("unexpected journal lock")
    coordinator = DevOwnerOAuthBootstrapCoordinator(
        {"cloudformation": NoIO(), "cognito": NoIO()}, Journal(),
        account_id=auth["account"], operator_user_arn=auth["expected_caller_arn"],
        owner_pool_id=binding["owner_pool_id"], api_id=binding["api_id"], callback_url=CALLBACK,
        source_sha=auth["source_sha"], run_id=binding["run_uuid"],
        authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
        expected_context_sha256=binding["context_sha256"],
        context_reader=lambda *_: None, source_checker=lambda: False,
        readback_validator=lambda *_: None)
    state.update({
        "authority_sha256": coordinator.authority_sha256,
        "template_sha256": coordinator.template_sha256,
        "intent": {"token": coordinator._request_token(), "stack_name": STACK_NAME,
                   "template_sha256": coordinator.template_sha256},
        "readback": {"verified": True, "client_id": delivery.auth["owner_client_id"],
                     "readback_sha256": "c" * 64},
    })
    return login_context.parse_accepted_owner_login_context(auth, binding, state,
        trusted_owner_policy=trusted)


def _owner_identity(context, account):
    policy = context.policy
    return {
        "account_id": account,
        "owner_pool_id": policy.user_pool_id,
        "client_id": policy.client_id,
        "owner_subject": policy.owner_subject,
        "api_id": policy.api_id,
        "issuer": policy.issuer_url,
        "resource_uri": policy.resource_url,
        "audience": policy.audience,
        "scope": policy.required_scope,
    }


def _accepted_lineage_fixture():
    delivery = DeliveryHarness()
    context = _context_for_delivery(delivery)
    assert context.context_digest == delivery.auth["owner_context_sha256"]
    delivery.coordinator.preflight()
    delivery.coordinator.publish()
    delivery.coordinator.update()
    delivery.coordinator.readback()
    snapshot = credential_snapshot_from_explicit_credentials(SimpleNamespace(
        access_key="AKIA1234567890ABCDE", secret_key="s" * 40, token="t" * 32))
    state = copy.deepcopy(delivery.update_journal.state)
    identity = _owner_identity(context, delivery.auth["account_id"])
    # The adapter's current state is the exact closed state already exercised
    # by the delivery fixture; it is kept distinct from the journal envelope.
    current_state = delivery.coordinator._current_state("accepted", delivery.coordinator.binding)
    accepted_context_sha = state["receipt"]["owner_context_sha256"]
    current = {"state": current_state, "owner_identity": identity,
               "current_context_sha256": accepted_context_sha, "credential_snapshot": snapshot}
    owner = {"owner_identity": dict(identity), "current_context_sha256": accepted_context_sha,
             "credential_snapshot": snapshot}
    return delivery, context, state, current, owner


def test_accepted_delivery_and_same_owner_identity_produce_redacted_lineage():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    lineage = validate_owner_enrolled_login_lineage(
        original_context=context, delivery_authority=delivery.auth,
        accepted_receipts=delivery.coordinator.accepted,
        accepted_update_state=state, current_runtime_readback=current,
        owner_identity_readback=owner)
    assert lineage.policy == context.policy
    assert lineage.owner_context_sha256 == state["receipt"]["owner_context_sha256"]
    assert lineage.owner_context_sha256 != context.context_digest
    assert lineage.target_template_sha256 == state["receipt"]["target_template_sha256"]
    assert is_registered_owner_enrolled_lineage(lineage)
    assert repr(lineage) == "OwnerEnrolledLoginLineage(<redacted>)"
    assert repr(current["credential_snapshot"]) == "CredentialSnapshot(<redacted>)"


def test_historical_context_authenticity_and_original_identity_are_required():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    forged = replace(context, policy=replace(context.policy, owner_subject="00000000-0000-4000-8000-000000000099"))
    with pytest.raises(OwnerEnrolledLoginLineageError, match="owner_context_invalid"):
        validate_owner_enrolled_login_lineage(original_context=forged, delivery_authority=delivery.auth,
            accepted_receipts=delivery.coordinator.accepted, accepted_update_state=state,
            current_runtime_readback=current, owner_identity_readback=owner)


@pytest.mark.parametrize("field,value", [
    ("owner_pool_id", "eu-west-1_OtherPool123"),
    ("client_id", "OtherClient12345678"),
    ("owner_subject", "00000000-0000-4000-8000-000000000099"),
    ("api_id", "zyxwvutsrq"),
    ("resource_uri", "https://other.execute-api.eu-west-1.amazonaws.com/mcp"),
    ("scope", "https://wrong.example/use"),
])
def test_owner_pool_client_subject_api_and_scope_must_match_original(field, value):
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    current["owner_identity"][field] = value
    with pytest.raises(OwnerEnrolledLoginLineageError, match="current_readback_invalid"):
        validate_owner_enrolled_login_lineage(original_context=context, delivery_authority=delivery.auth,
            accepted_receipts=delivery.coordinator.accepted, accepted_update_state=state,
            current_runtime_readback=current, owner_identity_readback=owner)


def test_credential_snapshot_must_be_same_registered_capability_object():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    owner["credential_snapshot"] = credential_snapshot_from_explicit_credentials(SimpleNamespace(
        access_key="AKIA9999999999ABCDE", secret_key="x" * 40, token="y" * 32))
    with pytest.raises(OwnerEnrolledLoginLineageError, match="credential_binding_invalid"):
        validate_owner_enrolled_login_lineage(original_context=context, delivery_authority=delivery.auth,
            accepted_receipts=delivery.coordinator.accepted, accepted_update_state=state,
            current_runtime_readback=current, owner_identity_readback=owner)


@pytest.mark.parametrize("mutation", [
    lambda state: state.update(phase="acknowledged"),
    lambda state: state["receipt"].update(artifact_sha256="0" * 64),
    lambda state: state["binding"].update(target_template_sha256="0" * 64),
    lambda state: state["binding"]["accepted"]["invitation"].update(revision=True),
    lambda state: state["binding"]["accepted"]["key_publication"].update(version=True),
])
def test_delivery_state_requires_exact_accepted_target_and_integer_versions(mutation):
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    mutated = copy.deepcopy(state)
    mutation(mutated)
    with pytest.raises(OwnerEnrolledLoginLineageError):
        validate_owner_enrolled_login_lineage(original_context=context, delivery_authority=delivery.auth,
            accepted_receipts=delivery.coordinator.accepted, accepted_update_state=mutated,
            current_runtime_readback=current, owner_identity_readback=owner)


def test_current_readback_must_be_fresh_exact_accepted_closed_state():
    delivery, context, state, current, owner = _accepted_lineage_fixture()
    current["state"]["api_disabled"] = False
    with pytest.raises(OwnerEnrolledLoginLineageError, match="current_readback_invalid"):
        validate_owner_enrolled_login_lineage(original_context=context, delivery_authority=delivery.auth,
            accepted_receipts=delivery.coordinator.accepted, accepted_update_state=state,
            current_runtime_readback=current, owner_identity_readback=owner)


def test_credentials_are_never_rendered_and_bad_credential_input_is_closed():
    secret = "super-secret-session-material" * 2
    snap = credential_snapshot_from_explicit_credentials(SimpleNamespace(
        access_key="AKIA1234567890ABCDE", secret_key="s" * 40, token=secret))
    assert secret not in repr(snap)
    with pytest.raises(OwnerEnrolledLoginLineageError, match="credential_binding_invalid"):
        credential_snapshot_from_explicit_credentials(SimpleNamespace(
            access_key="short", secret_key="s" * 40, token=secret))
