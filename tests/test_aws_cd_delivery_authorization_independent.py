"""Independent, injected-client checks for the optional prod delivery binding."""

import hashlib

import pytest

from mapit.aws_prod_geography_upgrade import (
    AUTHORIZATION_CUTOFF_EPOCH,
    ProdGeographyUpgradeError,
    _canonical,
)
from test_aws_cd_delivery_authorization import ROLE, START, authorization, fresh_core
from test_aws_prod_geography_upgrade import (
    ACCOUNT,
    API,
    FUNCTION,
    RUN_ID,
    STACK_UUID,
    Journal,
    make_core,
)

STACK_ARN = (
    f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/"
    f"honda-mapit-mcp-prod/{STACK_UUID}"
)


def _service_role():
    return ROLE


def _expected_executor_arn(source_sha):
    return (
        f"arn:aws:sts::{ACCOUNT}:assumed-role/honda-mapit-mcp-prod-cd-executor/"
        f"hm-cd-prod-{source_sha[:16]}"
    )


def test_legacy_default_contract_stays_separate_and_expired():
    wall = [AUTHORIZATION_CUTOFF_EPOCH - 1]
    legacy, journal = make_core(wall_clock=lambda: wall[0])
    assert legacy.delivery_authorization is None
    legacy._step_started = legacy.monotonic()
    state = legacy._save_new_state()
    assert state["kind"] == "prod_geography_upgrade"
    assert "delivery_binding" not in state
    wall[0] = AUTHORIZATION_CUTOFF_EPOCH + 1
    with pytest.raises(ProdGeographyUpgradeError, match="authorization_expired"):
        legacy._guard()

    delivery, _ = fresh_core()
    delivery.journal = journal
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        delivery._state()


def test_exact_source_derived_caller_role_session_is_required_before_owned_stack_reads():
    authorization_value = authorization()
    expected_arn = _expected_executor_arn(authorization_value.source_sha)

    def configured(caller_arn):
        core, _journal = fresh_core(authorization_value)
        owned_calls = []
        core._call = lambda service, method, **kwargs: {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "Account": ACCOUNT,
            "Arn": caller_arn,
            "UserId": "synthetic-user",
        }
        core._owned_stack = lambda *_args, **_kwargs: owned_calls.append(1)
        core._function = lambda **_kwargs: None
        core._api = lambda **_kwargs: None
        core._capacity = lambda: None
        core._tripwire = lambda: {"synthetic": True}
        result = core.run_step("preflight")
        return core, result, owned_calls

    core, result, owned_calls = configured(expected_arn)
    assert result["category"] == "preflight_verified"
    assert owned_calls == [1]
    assert core.journal.load()["delivery_binding"]["source_sha"] == authorization_value.source_sha

    for caller_arn in (
        expected_arn.replace("hm-cd-prod-", "hm-cd-prod-0000000000000000"),
        expected_arn.replace("honda-mapit-mcp-prod-cd-executor", "honda-mapit-mcp-dev-cd"),
        expected_arn.replace(ACCOUNT, "999999999999"),
    ):
        core, result, owned_calls = configured(caller_arn)
        assert result["category"] == "identity_mismatch"
        assert owned_calls == []


def _stack_readback(core, role_arn):
    expected_resources = core.old_template["Resources"]
    resource_rows = []
    for logical_id, resource in expected_resources.items():
        physical = {
            "McpApi": API,
            "McpHandler": FUNCTION,
        }.get(logical_id, f"synthetic-{logical_id.lower()}")
        resource_rows.append({
            "LogicalResourceId": logical_id,
            "ResourceType": resource["Type"],
            "ResourceStatus": "UPDATE_COMPLETE",
            "PhysicalResourceId": physical,
        })
    stack = {
        "StackId": STACK_ARN,
        "StackName": "honda-mapit-mcp-prod",
        "RoleARN": role_arn,
        "Tags": [{"Key": "ProductionRunId", "Value": core.prod_run_id}],
        "EnableTerminationProtection": True,
        "StackStatus": "UPDATE_COMPLETE",
    }
    responses = {
        "describe_stacks": {"Stacks": [stack]},
        "get_template": {"TemplateBody": core.old_template},
        "describe_stack_resources": {"StackResources": resource_rows},
    }
    calls = []

    def call(_service, method, **kwargs):
        calls.append((method, kwargs))
        return {**responses[method], "ResponseMetadata": {"HTTPStatusCode": 200}}

    return call, calls


def test_owned_stack_requires_exact_cfn_service_role_readback():
    core, _journal = fresh_core()
    state = {"prod_run_id": core.prod_run_id}
    core._call, calls = _stack_readback(core, _service_role())
    assert core._owned_stack(state, core.old_template)["RoleARN"] == _service_role()
    assert [name for name, _ in calls] == [
        "describe_stacks", "get_template", "describe_stack_resources"
    ]

    for wrong_role in (None, "", ROLE + "/extra", ROLE.replace(ACCOUNT, "999999999999")):
        core._call, calls = _stack_readback(core, wrong_role)
        with pytest.raises(ProdGeographyUpgradeError, match="stack_not_owned"):
            core._owned_stack(state, core.old_template)
        assert [name for name, _ in calls] == ["describe_stacks"]


def test_update_stack_passes_only_exact_reviewed_cfn_service_role():
    core, journal = fresh_core()
    core._step_started = core.monotonic()
    state = core._save_new_state()
    tripwire = {"fixed": True}
    state.update(
        preflight_verified=True,
        close_verified=True,
        tripwire_fingerprint=hashlib.sha256(_canonical(tripwire)).hexdigest(),
    )
    journal.save(state)
    core._owned_stack = lambda *_args, **_kwargs: {}
    core._api = lambda **_kwargs: None
    core._function = lambda **_kwargs: None
    core._capacity = lambda: None
    core._tripwire = lambda: tripwire

    class CloudFormation:
        def __init__(self):
            self.calls = []

        def update_stack(self, **kwargs):
            self.calls.append(kwargs)
            return {"StackId": STACK_ARN, "ResponseMetadata": {"HTTPStatusCode": 200}}

    cfn = CloudFormation()
    core.clients["cloudformation"] = cfn

    result = core.run_step("request-update")

    assert result["category"] == "update_pending"
    assert len(cfn.calls) == 1
    assert cfn.calls[0]["RoleARN"] == _service_role()
    assert cfn.calls[0]["StackName"] == STACK_ARN
    assert set(cfn.calls[0]) == {
        "StackName", "TemplateBody", "Parameters", "Capabilities", "ClientRequestToken", "RoleARN"
    }
    assert journal.load()["kind"] == "prod_cd_delivery"
    assert journal.load()["delivery_binding"] == {
        "source_sha": "a" * 40,
        "service_role_arn": _service_role(),
    }
