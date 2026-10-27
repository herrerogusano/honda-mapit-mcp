import copy

import pytest

from tests import test_aws_retained_dev_delivery_update as update
from tests import test_aws_retained_dev_delivery_recovery as recovery


@pytest.mark.parametrize("kind", ["update", "recovery"])
@pytest.mark.parametrize("include_stack", [True, False])
def test_only_the_exact_top_level_stack_event_proves_the_operation(kind, include_stack):
    if kind == "update":
        coordinator, cfn = update._coordinator()
    else:
        coordinator, cfn, _, _ = recovery._coordinator()
    original = cfn.describe_stack_events

    def events(**kwargs):
        reply = original(**kwargs)
        resource = copy.deepcopy(reply["StackEvents"][0])
        resource.update({"ResourceType": "AWS::Lambda::Function", "LogicalResourceId": "McpHandler",
                         "PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler"})
        reply["StackEvents"] = ([reply["StackEvents"][0]] if include_stack else []) + [resource]
        return reply

    cfn.describe_stack_events = events
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_acknowledged"
    result = coordinator.run_step("check-update")
    assert result["category"] == ("readback_verified" if include_stack else "update_outcome_unknown")
