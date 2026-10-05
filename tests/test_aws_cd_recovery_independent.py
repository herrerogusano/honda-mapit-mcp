"""Independent synthetic checks for the retained-recovery core mode."""

from __future__ import annotations

import copy

import pytest

from mapit.aws_prod_geography_upgrade import ProdGeographyUpgradeError
from test_aws_prod_geography_upgrade import make_core


class CloudFormation:
    def __init__(self, core, status, resource_status="UPDATE_ROLLBACK_COMPLETE"):
        self.core = core
        self.status = status
        self.resource_status = resource_status
        self.calls = []

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        auth = self.core.delivery_authorization
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Stacks": [{
            "StackId": self.core.stack_arn,
            "StackName": "honda-mapit-mcp-prod",
            "StackStatus": self.status,
            "RoleARN": auth.service_role_arn if auth else None,
            "Tags": [{"Key": "ProductionRunId", "Value": self.core.prod_run_id}],
            "EnableTerminationProtection": True,
        }]}

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "TemplateBody": copy.deepcopy(self.core.old_template)}

    def describe_stack_resources(self, **kwargs):
        self.calls.append(("describe_stack_resources", kwargs))
        rows = []
        for logical, resource in self.core.old_template["Resources"].items():
            physical = {
                "McpApi": self.core.api_id,
                "McpHandler": self.core.function_name,
            }.get(logical, "synthetic-physical-" + logical)
            rows.append({
                "LogicalResourceId": logical,
                "ResourceType": resource["Type"],
                "PhysicalResourceId": physical,
                "ResourceStatus": self.resource_status,
            })
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "StackResources": rows}


def test_rollback_complete_is_accepted_only_in_explicit_recovery_mode():
    recovery, _ = make_core(retained_recovery=True, same_artifact=True)
    cf = CloudFormation(recovery, "UPDATE_ROLLBACK_COMPLETE")
    recovery.clients["cloudformation"] = cf
    assert recovery._owned_stack({}, recovery.old_template)["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE"
    assert [name for name, _ in cf.calls] == ["describe_stacks", "get_template", "describe_stack_resources"]

    ordinary, _ = make_core()
    ordinary_cf = CloudFormation(ordinary, "UPDATE_ROLLBACK_COMPLETE")
    ordinary.clients["cloudformation"] = ordinary_cf
    with pytest.raises(ProdGeographyUpgradeError, match="stack_not_owned"):
        ordinary._owned_stack({}, ordinary.old_template)
    assert [name for name, _ in ordinary_cf.calls] == ["describe_stacks"]


@pytest.mark.parametrize("status", ["UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"])
def test_recovery_mode_rejects_nonterminal_rollback_status_without_template_reads(status):
    recovery, _ = make_core(retained_recovery=True, same_artifact=True)
    cf = CloudFormation(recovery, status)
    recovery.clients["cloudformation"] = cf
    with pytest.raises(ProdGeographyUpgradeError, match="stack_not_owned"):
        recovery._owned_stack({}, recovery.old_template)
    assert [name for name, _ in cf.calls] == ["describe_stacks"]


def test_retained_recovery_binding_is_not_adopted_from_ordinary_or_tampered_journal():
    ordinary, old_journal = make_core()
    ordinary._step_started = ordinary.monotonic()
    ordinary_state = ordinary._save_new_state()

    recovery, recovery_journal = make_core(retained_recovery=True, same_artifact=True)
    recovery._step_started = recovery.monotonic()
    fresh_state = recovery._save_new_state()
    recovery_journal.value = copy.deepcopy(ordinary_state)
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        recovery._state()

    recovery_journal.value = copy.deepcopy(fresh_state)
    recovery_journal.value["delivery_binding"]["retained_recovery"] = False
    with pytest.raises(ProdGeographyUpgradeError, match="journal_invalid"):
        recovery._state()
