"""Independent edge regressions for the closed identity bootstrap core."""

import pytest

from test_aws_cd_identity_bootstrap import (
    ACCOUNT,
    STACK_NAME,
    STACK_ARN,
    AwsError,
    Journal,
    ScriptedClient,
    _coordinator,
    _preflight_clients,
    _readback_clients,
    _response,
)


def _created_coordinator():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    clients["cloudformation"] = ScriptedClient({
        "create_stack": _response(StackId=STACK_ARN),
    })
    coordinator.clients = clients
    assert coordinator.run_step("create")["ok"]
    return coordinator, journal


def test_saved_create_intent_crash_reconciles_readonly_without_replaying_create():
    coordinator, journal = _created_coordinator()
    state = journal.load()
    state["phase"] = "create_intent_saved"
    state["create_intent"] = {
        "stack_name": STACK_NAME,
        "client_request_token": state["client_request_token"],
        "template_sha256": coordinator.template_sha256,
        "run_id": state["run_id"],
    }
    journal.save(state)

    clients = _readback_clients(coordinator)
    cfn = clients["cloudformation"]
    cfn.methods["describe_stack_events"] = _response(StackEvents=[{
        "StackId": STACK_ARN,
        "ClientRequestToken": state["client_request_token"],
    }])
    coordinator.clients = clients

    result = coordinator.run_step("check-create")
    assert result["ok"] is True
    assert result["category"] == "stack_and_identity_verified"
    assert "create_stack" not in [name for name, _ in cfn.calls]


def test_saved_intent_with_no_observed_stack_stays_ambiguous_and_never_replays_create():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    state = journal.load()
    state["phase"] = "create_intent_saved"
    state["create_intent"] = {
        "stack_name": STACK_NAME,
        "client_request_token": state["client_request_token"],
        "template_sha256": coordinator.template_sha256,
        "run_id": state["run_id"],
    }
    journal.save(state)
    cfn = ScriptedClient({
        "describe_stacks": AwsError("ValidationError", f"Stack with id {STACK_NAME} does not exist"),
    })
    clients["cloudformation"] = cfn
    coordinator.clients = clients

    result = coordinator.run_step("check-create")
    assert result["ok"] is False
    assert result["category"] == "stack_absence_unverified"
    assert [name for name, _ in cfn.calls] == ["describe_stacks"]
    assert journal.load()["phase"] == "create_intent_saved"


def test_stack_absence_requires_exact_validation_error_message():
    clients = _preflight_clients()
    clients["cloudformation"] = ScriptedClient({
        "describe_stacks": AwsError(
            "ValidationError", f"Unexpected: Stack with id {STACK_NAME} does not exist"
        ),
    })
    journal = Journal()
    result = _coordinator(clients, journal).run_step("preflight")
    assert result["ok"] is False
    assert result["category"] == "stack_absence_unverified"
    assert journal.state is None


def test_readback_rejects_role_arn_as_cloudformation_physical_role_id():
    coordinator, _journal = _created_coordinator()
    clients = _readback_clients(coordinator)
    rows = clients["cloudformation"].methods["describe_stack_resources"]["StackResources"]
    role_row = next(row for row in rows if row["LogicalResourceId"] == "DevCdIdentityRole")
    role_row["PhysicalResourceId"] = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-cd"
    coordinator.clients = clients

    result = coordinator.run_step("check-create")
    assert result["ok"] is False
    assert result["category"] == "identity_readback_mismatch"


def test_readback_rejects_truncated_attached_policy_listing():
    coordinator, _journal = _created_coordinator()
    coordinator.clients = _readback_clients(coordinator, mutate="truncated-attached-dev")

    result = coordinator.run_step("check-create")
    assert result["ok"] is False
    assert result["category"] == "identity_readback_mismatch"


def test_botocore_iam_model_has_boundary_type_on_role_not_policy():
    botocore_session = pytest.importorskip("botocore.session")

    model = botocore_session.get_session().get_service_model("iam")
    get_role = model.operation_model("GetRole").output_shape.members["Role"]
    boundary = get_role.members["PermissionsBoundary"]
    assert set(boundary.members) == {"PermissionsBoundaryArn", "PermissionsBoundaryType"}
    assert boundary.members["PermissionsBoundaryType"].metadata["enum"] == ["PermissionsBoundaryPolicy"]

    get_policy = model.operation_model("GetPolicy").output_shape.members["Policy"]
    assert "PolicyName" in get_policy.members
    assert "Arn" in get_policy.members
    assert "Type" not in get_policy.members
