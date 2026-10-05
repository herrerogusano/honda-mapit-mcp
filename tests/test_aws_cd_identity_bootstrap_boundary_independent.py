"""Independent regressions for the narrow IAM boundary readback repair."""

import pytest

from mapit.aws_cd_identity_bootstrap import CdIdentityBootstrapCoordinator, CdIdentityBootstrapError
from test_aws_cd_identity_bootstrap import (
    ACCOUNT,
    OWNER,
    PROVIDER,
    REPO,
    SOURCE_SHA,
    Journal,
    _observations,
    _preflight_clients,
    _readback_clients,
    _response,
)
from test_aws_cd_identity_bootstrap_independent import _created_coordinator


ALIAS = "Policy"
UNKNOWN = "PermissionsBoundaryAnythingElse"
VERIFY_SHA = "b" * 40
_MISSING = object()


def _coordinator(clients, journal, *, verification_source_sha=None):
    return CdIdentityBootstrapCoordinator(
        clients,
        journal,
        account_id=ACCOUNT,
        provider_arn=PROVIDER,
        owner_id=OWNER,
        repository_id=REPO,
        observed_subjects=_observations(),
        source_sha=SOURCE_SHA,
        authorized_from_epoch=900,
        authorized_until_epoch=1800,
        verification_source_sha=verification_source_sha,
        wall_clock=lambda: 1000.0,
        monotonic=lambda: 1.0,
    )


def _replace_readback(coordinator, *, role_mutation=None, policy_mutation=None,
                      version_mutation=None, attached_mutation=None):
    clients = _readback_clients(coordinator)
    iam = clients["iam"]
    role = iam.methods["get_role"][0]["Role"]
    boundary = role["PermissionsBoundary"]
    if role_mutation == "missing_type":
        boundary.pop("PermissionsBoundaryType")
    elif role_mutation is not None:
        boundary[role_mutation[0]] = role_mutation[1]
    if policy_mutation is not None:
        iam.methods["get_policy"][0]["Policy"].update(policy_mutation)
    if version_mutation is not None:
        iam.methods["get_policy_version"][0]["PolicyVersion"].update(version_mutation)
    if attached_mutation is not None:
        iam.methods["list_attached_role_policies"][0]["AttachedPolicies"] = attached_mutation
    return clients


def test_observed_policy_alias_accepts_only_with_exact_boundary_arn_and_full_policy_readback():
    coordinator, journal = _created_coordinator()
    clients = _replace_readback(
        coordinator,
        role_mutation=("PermissionsBoundaryType", ALIAS),
    )
    coordinator.clients = clients

    result = coordinator.run_step("check-create")

    assert result["ok"] is True
    assert result["category"] == "stack_and_identity_verified"
    calls = clients["iam"].calls
    assert ("get_policy", {"PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-cd-boundary"}) in calls
    assert ("get_policy_version", {
        "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-cd-boundary",
        "VersionId": "v1",
    }) in calls
    assert journal.load()["phase"] == "create_readback_verified"


@pytest.mark.parametrize("bad_type", [None, False, 1, UNKNOWN, "", _MISSING])
def test_missing_nonstring_or_unknown_boundary_type_is_rejected_without_journal_commit(bad_type):
    coordinator, journal = _created_coordinator()
    if bad_type is _MISSING:
        clients = _replace_readback(coordinator, role_mutation="missing_type")
    else:
        clients = _replace_readback(coordinator, role_mutation=("PermissionsBoundaryType", bad_type))
    coordinator.clients = clients
    state_before = journal.load()
    saves_before = journal.saves

    result = coordinator.run_step("check-create")

    assert result["ok"] is False
    assert result["category"] == "identity_readback_mismatch"
    assert journal.load() == state_before
    assert journal.saves == saves_before


@pytest.mark.parametrize("mutation", [
    {"role": ("PermissionsBoundaryArn", f"arn:aws:iam::{ACCOUNT}:policy/other-boundary")},
    {"policy": {"Arn": f"arn:aws:iam::{ACCOUNT}:policy/other-boundary"}},
    {"policy": {"PolicyName": "other-boundary"}},
    {"policy": {"Path": "/other/"}},
    {"policy": {"DefaultVersionId": "v2"}},
    {"version": {"VersionId": "v2"}},
    {"version": {"IsDefaultVersion": False}},
    {"version": {"Document": {"Version": "2012-10-17", "Statement": []}}},
    {"attached": [{"PolicyName": "unexpected", "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/extra"}]},
])
def test_alias_does_not_relax_exact_arn_policy_document_or_attachment_checks(mutation):
    coordinator, journal = _created_coordinator()
    role_mutation = mutation.get("role")
    clients = _replace_readback(
        coordinator,
        role_mutation=role_mutation or ("PermissionsBoundaryType", ALIAS),
        policy_mutation=mutation.get("policy"),
        version_mutation=mutation.get("version"),
        attached_mutation=mutation.get("attached"),
    )
    coordinator.clients = clients
    state_before = journal.load()
    saves_before = journal.saves

    result = coordinator.run_step("check-create")

    assert result["ok"] is False
    assert result["category"] == "identity_readback_mismatch"
    assert journal.load() == state_before
    assert journal.saves == saves_before


def test_different_verification_sha_is_readback_only_and_preserves_creation_bindings():
    original, journal = _created_coordinator()
    old_state = journal.load()
    preserved = {
        key: old_state[key]
        for key in (
            "source_sha", "template_sha256", "authorized_from_epoch",
            "authorized_until_epoch", "client_request_token", "run_id",
        )
    }
    clients = _readback_clients(original)
    verifier = _coordinator(clients, journal, verification_source_sha=VERIFY_SHA)

    result = verifier.run_step("check-create")

    assert result["ok"] is True
    state = journal.load()
    assert {key: state[key] for key in preserved} == preserved
    assert state["verification_source_sha"] == VERIFY_SHA
    assert state["source_sha"] == SOURCE_SHA
    saves_after_readback = journal.saves

    no_write_clients = _preflight_clients()
    blocked = _coordinator(no_write_clients, journal, verification_source_sha=VERIFY_SHA)
    result = blocked.run_step("create")
    assert result["ok"] is False
    assert result["category"] == "binding_invalid"
    assert not any(client.calls for client in no_write_clients.values())
    assert journal.saves == saves_after_readback


def test_different_verification_sha_blocks_new_preflight_before_calls_or_journal_write():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal, verification_source_sha=VERIFY_SHA)

    result = coordinator.run_step("preflight")

    assert result["ok"] is False
    assert result["category"] == "binding_invalid"
    assert not any(client.calls for client in clients.values())
    assert journal.state is None
    assert journal.saves == 0


@pytest.mark.parametrize("invalid_sha", ["B" * 40, "b" * 39, "g" * 40, True])
def test_verification_sha_must_be_canonical_lowercase_40_hex(invalid_sha):
    with pytest.raises(CdIdentityBootstrapError, match="binding_invalid"):
        _coordinator(_preflight_clients(), Journal(), verification_source_sha=invalid_sha)


def test_existing_mismatched_verification_sha_blocks_readback_before_any_call():
    original, journal = _created_coordinator()
    state = journal.load()
    state["verification_source_sha"] = "c" * 40
    journal.save(state)
    clients = _readback_clients(original)
    coordinator = _coordinator(clients, journal, verification_source_sha=VERIFY_SHA)
    saves_before = journal.saves

    result = coordinator.run_step("check-create")

    assert result["ok"] is False
    assert result["category"] == "binding_invalid"
    assert not any(client.calls for client in clients.values())
    assert journal.saves == saves_before
