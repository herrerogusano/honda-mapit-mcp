from __future__ import annotations

import pytest

from mapit.aws_prod_geography_upgrade import ProdGeographyUpgradeError
from scripts.build_aws_prod_controls import fixed_prod_controls_template
from test_aws_prod_geography_upgrade import ACCOUNT, API, MACHINE, make_core


def _configure_tripwire(core, threshold):
    resources = fixed_prod_controls_template(API)["Resources"]
    alarm = dict(resources["RequestTripwireAlarm"]["Properties"])
    alarm["Threshold"] = threshold
    alarm.update(ActionsEnabled=True, AlarmActions=[], OKActions=[], InsufficientDataActions=[])
    pattern = {
        "source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"],
        "account": [ACCOUNT], "region": ["eu-west-1"],
        "resources": [f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-prod-request-tripwire"],
        "detail": {"alarmName": ["honda-mapit-mcp-prod-request-tripwire"], "state": {"value": ["ALARM"]}},
    }
    target = {
        "Id": "StartFixedProdShutdownWorkflow", "Arn": MACHINE,
        "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-request-tripwire",
        "Input": "{}", "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
    }
    definition = resources["ShutdownStateMachine"]["Properties"]["DefinitionString"]

    def call(service, method, **kwargs):
        metadata = {"ResponseMetadata": {"HTTPStatusCode": 200}}
        if method == "describe_alarms":
            return {"MetricAlarms": [alarm], **metadata}
        if method == "describe_rule":
            return {
                "Name": "honda-mapit-mcp-prod-request-tripwire-alarm-rule",
                "Arn": f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/honda-mapit-mcp-prod-request-tripwire-alarm-rule",
                "State": "ENABLED", "EventPattern": pattern, **metadata,
            }
        if method == "list_targets_by_rule":
            return {"Targets": [target], **metadata}
        if method == "describe_state_machine":
            return {
                "stateMachineArn": MACHINE, "name": "honda-mapit-mcp-prod-shutdown",
                "roleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-shutdown-workflow",
                "status": "ACTIVE", "type": "STANDARD", "definition": definition, **metadata,
            }
        raise AssertionError(method)

    core._step_started = core.monotonic()
    core._call = call


def test_cloudwatch_double_threshold_is_accepted_but_bool_is_rejected():
    core, _ = make_core()
    _configure_tripwire(core, 100.0)
    tripwire = core._tripwire()
    assert tripwire["alarm"]["Threshold"] == 100
    assert type(tripwire["alarm"]["Threshold"]) is int

    _configure_tripwire(core, True)
    with pytest.raises(ProdGeographyUpgradeError) as error:
        core._tripwire()
    assert error.value.category == "tripwire_unverified"
