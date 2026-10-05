"""Intermediate cleanup is pending, never evidence of update acceptance."""
import pytest

from test_aws_prod_geography_upgrade import make_core, RUN_ID


@pytest.mark.parametrize("status", ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"])
def test_owned_update_transition_is_pending_without_receipts_or_other_reads(status):
    core, journal = make_core(retained_recovery=True)
    core._step_started = core.monotonic()
    state = core._save_new_state()
    state.update(preflight_verified=True, close_verified=True,
                 update_intent={"client_request_token": "00000000-0000-4000-8000-000000000000"},
                 update_acknowledged=True)
    journal.save(state)
    calls = []
    def read(service, method, **kwargs):
        calls.append((service, method))
        assert (service, method) == ("cloudformation", "describe_stacks")
        return {"Stacks": [{"StackId": core.stack_arn, "StackName": "honda-mapit-mcp-prod",
                            "RoleARN": core.delivery_authorization.service_role_arn,
                            "Tags": [{"Key": "ProductionRunId", "Value": RUN_ID}],
                            "EnableTerminationProtection": True, "StackStatus": status}]}
    core._call = read
    result = core.run_step("check-update")
    assert result["category"] == "update_pending" and result.get("verified") is not True
    assert journal.load() == state and len(calls) == 1


@pytest.mark.parametrize("change", ["role", "owner", "protection"])
def test_cleanup_does_not_bypass_ownership(change):
    core, journal = make_core(retained_recovery=True)
    core._step_started = core.monotonic()
    state = core._save_new_state()
    stack = {"StackId": core.stack_arn, "StackName": "honda-mapit-mcp-prod",
             "RoleARN": core.delivery_authorization.service_role_arn,
             "Tags": [{"Key": "ProductionRunId", "Value": RUN_ID}],
             "EnableTerminationProtection": True, "StackStatus": "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"}
    if change == "role":
        stack["RoleARN"] = "unexpected-role"
    elif change == "owner":
        stack["Tags"] = []
    else:
        stack["EnableTerminationProtection"] = False
    core._call = lambda *_args, **_kwargs: {"Stacks": [stack]}
    with pytest.raises(ValueError, match="stack_not_owned"):
        core._owned_stack(state, core.new_template, allow_in_progress=True)


def test_cleanup_is_not_accepted_as_stable_preflight():
    core, _ = make_core(retained_recovery=True)
    core._step_started = core.monotonic()
    state = core._save_new_state()
    core._call = lambda *_args, **_kwargs: {"Stacks": [{
        "StackId": core.stack_arn, "StackName": "honda-mapit-mcp-prod",
        "RoleARN": core.delivery_authorization.service_role_arn,
        "Tags": [{"Key": "ProductionRunId", "Value": RUN_ID}],
        "EnableTerminationProtection": True, "StackStatus": "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"}]}
    with pytest.raises(ValueError, match="stack_not_owned"):
        core._owned_stack(state, core.old_template)
