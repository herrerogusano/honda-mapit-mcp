"""Independent checks for prod-only shutdown bindings in the closed draft."""

import json

from scripts.build_aws_prod_controls import fixed_prod_controls_template


def test_prod_control_workflow_and_trust_are_bound_only_to_prod_targets():
    template = fixed_prod_controls_template("a1b2c3d4e5")
    resources = template["Resources"]
    machine = resources["ShutdownStateMachine"]["Properties"]
    definition = json.loads(machine["DefinitionString"])

    assert machine["StateMachineName"] == "honda-mapit-mcp-prod-shutdown"
    assert "prod" in definition["Comment"].casefold()
    assert "dev" not in definition["Comment"].casefold()
    assert definition["States"]["DisableApiEndpoint"]["Parameters"] == {
        "ApiId": "a1b2c3d4e5",
        "DisableExecuteApiEndpoint": True,
    }
    assert definition["States"]["ReserveFunctionConcurrency"]["Parameters"] == {
        "FunctionName": "honda-mapit-mcp-prod-handler",
        "ReservedConcurrentExecutions": 0,
    }

    workflow_role = resources["ShutdownWorkflowRole"]["Properties"]
    statements = workflow_role["Policies"][0]["PolicyDocument"]["Statement"]
    assert statements[0]["Resource"]["Fn::Sub"].endswith("/apis/a1b2c3d4e5")
    assert statements[1]["Resource"]["Fn::Sub"].endswith("/apis/a1b2c3d4e5")
    assert "honda-mapit-mcp-prod-handler" in statements[2]["Resource"]["Fn::Sub"]

    event_target = resources["RequestTripwireAlarmRule"]["Properties"]["Targets"][0]
    assert event_target["Id"] == "StartFixedProdShutdownWorkflow"
    assert event_target["Arn"] == {"Fn::GetAtt": ["ShutdownStateMachine", "Arn"]}
    trust_arn = workflow_role["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["ArnLike"]["aws:SourceArn"]["Fn::Sub"]
    assert trust_arn.endswith(":stateMachine:honda-mapit-mcp-prod-shutdown")
    assert workflow_role["Policies"][0]["PolicyName"] == "fixed-prod-shutdown-api-and-function"
