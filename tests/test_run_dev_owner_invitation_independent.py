from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import run_dev_owner_invitation as invitation
from scripts.run_aws_closed_rehearsal import MemoryJournal
from tests.test_run_dev_owner_invitation import (
    _Dynamo, _SourceClients, _binding, _make_paths, _patch_accepted_receipts, _runtime_proof,
)


def test_fresh_invitation_journal_cannot_be_nested_under_historical_state(tmp_path, monkeypatch):
    private, _state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    nested = owner_state / "fresh-invitation-state"
    nested.mkdir()
    binding = _binding(nested)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state, binding["owner_tenant_key"])

    clients_created = []
    protections = []
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        nested, acl_checker=lambda _: True,
        client_factory=lambda: clients_created.append(True) or {},
        source_validator=lambda *_: None,
        protection_reader=lambda **kwargs: protections.append(kwargs) or (11, 22),
        journal_factory=lambda _: MemoryJournal(), wall_clock=lambda: binding["authorized_from_epoch"] + 1,
    )

    assert result["ok"] is False
    assert result["category"] == "journal_consumed"
    assert clients_created == []
    assert protections == []
    assert not (nested / "rehearsal-state.json").exists()


def test_guarded_table_proxy_rejects_any_non_owner_table_before_dispatch():
    class Dynamo:
        def __init__(self):
            self.calls = []

        def get_item(self, **kwargs):
            self.calls.append(("get_item", kwargs))
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def put_item(self, **kwargs):
            self.calls.append(("put_item", kwargs))
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    ddb = Dynamo()
    clients = {name: SimpleNamespace() for name in invitation._GuardedClients._SERVICES}
    clients["dynamodb"] = ddb
    start = 1_900_000_000
    ticks = iter(float(value) for value in range(100, 130))
    guard = invitation._GuardedClients(
        clients, owner_key="tenant-" + "f" * 64, account_id="123456789012",
        start=start, end=start + 600, wall_clock=lambda: start + 1, monotonic=lambda: next(ticks),
    )
    client = guard.wrap()["dynamodb"]
    expected_table = "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants"

    client.get_item(TableName=expected_table, Key={"key": {"S": "tenant-" + "f" * 64}},
                    ConsistentRead=True, ReturnConsumedCapacity="NONE")
    with pytest.raises(ValueError):
        client.get_item(TableName="arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-mapit-identity-bindings",
                        Key={"key": {"S": "tenant-" + "f" * 64}},
                        ConsistentRead=True, ReturnConsumedCapacity="NONE")
    guard.armed = True
    with pytest.raises(ValueError):
        client.put_item(TableName="arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-mapit-identity-bindings",
                        Item={"key": {"S": "tenant-" + "f" * 64}, "status": {"S": "active"},
                              "revision": {"N": "1"}},
                        ConditionExpression="attribute_not_exists(#key)",
                        ExpressionAttributeNames={"#key": "key"}, ReturnValues="NONE",
                        ReturnConsumedCapacity="NONE")
    assert [method for method, _ in ddb.calls] == ["get_item"]


def test_second_protection_read_must_match_authority_before_intent_or_write(tmp_path, monkeypatch):
    _private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state,
                             binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    monkeypatch.setattr(invitation, "_verify_current_bootstrap", lambda *_a, **_k: None)

    protection_results = iter([(11, 22), (11, 999)])
    protection_calls = []
    clients_created = []
    journal = MemoryJournal()
    ddb = _Dynamo()
    clients = _SourceClients(ddb).mapping()
    proof = _runtime_proof()
    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True,
        client_factory=lambda: clients_created.append(True) or clients,
        source_validator=lambda *_: None,
        protection_reader=lambda **kwargs: protection_calls.append(kwargs) or next(protection_results),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: proof,
        journal_factory=lambda _: journal,
        wall_clock=lambda: binding["authorized_from_epoch"] + 1,
    )

    assert result["ok"] is False
    assert result["category"] == "github_protection_failed"
    assert len(protection_calls) == 2
    assert clients_created == [True]
    assert journal.value is None
    assert [name for name, _ in ddb.calls] == ["get"]


def test_malformed_final_identity_read_keeps_intent_and_never_dispatches_cas(tmp_path, monkeypatch):
    _private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state,
                             binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    monkeypatch.setattr(invitation, "_verify_current_bootstrap", lambda *_a, **_k: None)

    ddb = _Dynamo()
    clients = _SourceClients(ddb).mapping()
    identities = iter([
        {"Account": binding["account_id"], "Arn": binding["operator_user_arn"],
         "ResponseMetadata": {"HTTPStatusCode": 200}},
        {"Account": binding["account_id"], "Arn": binding["operator_user_arn"],
         "ResponseMetadata": {"HTTPStatusCode": 200}},
        {"Account": binding["account_id"], "Arn": binding["operator_user_arn"],
         "ResponseMetadata": {"HTTPStatusCode": 200.0}},
    ])
    clients["sts"].get_caller_identity = lambda: next(identities)
    journal = MemoryJournal()
    proof = _runtime_proof()

    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: clients,
        source_validator=lambda *_: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: proof,
        journal_factory=lambda _: journal,
        wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(1000, 1500)).__next__,
    )

    assert result["ok"] is False and result["category"] == "current_state_unverified"
    assert journal.value["phase"] == "intent_saved"
    assert [name for name, _ in ddb.calls] == ["get", "get"]
    assert not any(name == "put" for name, _ in ddb.calls)


def test_runtime_evidence_must_bind_full_mapit_bootstrap_identity_before_row_read(tmp_path, monkeypatch):
    _private, state, owner_state, mapit_state, synthetic_state, files = _make_paths(tmp_path)
    binding = _binding(state)
    files["authority.json"].write_text(json.dumps(binding))
    _patch_accepted_receipts(monkeypatch, files, owner_state, mapit_state,
                             binding["owner_tenant_key"])
    monkeypatch.setattr(invitation, "_validate_clients", lambda _clients: None)
    monkeypatch.setattr(invitation, "OwnerOAuthSdkBindings", lambda *_a, **_k: object())
    monkeypatch.setattr(invitation, "_verify_current_bootstrap", lambda *_a, **_k: None)
    ddb = _Dynamo()
    clients = _SourceClients(ddb).mapping()
    wrong_proof = _runtime_proof()
    wrong_proof["source_sha"] = "9" * 40
    journal = MemoryJournal()

    result = invitation.run_authorized_invitation(
        files["authority.json"], files["owner-release.json"], files["owner-auth.json"],
        files["owner-binding.json"], owner_state, files["mapit-authority.json"], mapit_state,
        files["runtime.json"], files["synthetic-binding.json"], files["synthetic-auth.json"], synthetic_state,
        state, acl_checker=lambda _: True, client_factory=lambda: clients,
        source_validator=lambda *_: None, protection_reader=lambda **_: (11, 22),
        runtime_verifier_factory=lambda **_: lambda *_a, **_k: wrong_proof,
        journal_factory=lambda _: journal,
        wall_clock=lambda: binding["authorized_from_epoch"] + 1,
        monotonic=iter(range(1000, 1500)).__next__,
    )

    assert result["ok"] is False and result["category"] == "current_state_unverified"
    assert result["stage"] == "runtime_readback"
    assert ddb.calls == []
    assert journal.value is None


@pytest.mark.parametrize("name", ["AWS_CONFIG_FILE", "BOTO_CONFIG"])
def test_default_client_factory_rejects_redirected_credential_config_before_session(monkeypatch, name):
    import sys

    session_calls = []
    monkeypatch.setenv(name, "synthetic-config-path")
    monkeypatch.setitem(sys.modules, "boto3",
                       SimpleNamespace(Session=lambda **_: session_calls.append(True)))

    with pytest.raises(invitation.OwnerInvitationError) as exc:
        invitation._default_clients()

    assert exc.value.category == "client_setup_failed"
    assert session_calls == []
