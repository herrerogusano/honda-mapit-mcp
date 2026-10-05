import json

import pytest

from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template
from scripts.build_aws_prod_bootstrap import fixed_prod_bootstrap_template
from scripts.build_aws_prod_controls import fixed_prod_controls_template


def test_prod_bootstrap_closed_identity_reused_and_region_stack_isolation():
    template = fixed_prod_bootstrap_template()
    resources = template["Resources"]
    assert len(resources) == 5
    assert all(not r["Type"].startswith("AWS::Cognito") for r in resources.values())
    assert resources["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    function = resources["McpHandler"]["Properties"]
    assert function["ReservedConcurrentExecutions"] == 0
    assert function["Runtime"] == "python3.13" and function["Architectures"] == ["arm64"]
    assert function["Timeout"] == 15 and function["MemorySize"] == 256
    assert "503" in function["Code"]["ZipFile"]
    assert template["Parameters"]["EnvironmentName"]["AllowedValues"] == ["prod"]
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"][1]["Fn::Equals"][1] == "honda-mapit-mcp-prod"
    assert "UserPoolId" not in template["Outputs"]
    assert resources["McpHandlerLogGroup"]["Properties"]["RetentionInDays"] == 7


def test_prod_role_reads_only_exact_session_no_extra_kms_or_local_defaults():
    resources = fixed_prod_bootstrap_template()["Resources"]
    role = resources["McpHandlerRole"]["Properties"]
    assert not role.get("ManagedPolicyArns")
    statements = role["Policies"][0]["PolicyDocument"]["Statement"]
    assert len(statements) == 2
    assert statements[1]["Action"] == "ssm:GetParameter"
    assert statements[1]["Resource"]["Fn::Sub"].endswith("parameter/honda-mapit-mcp/prod/mapit-refresh-token")
    raw = json.dumps(statements)
    assert "ssm:Put" not in raw and "kms:" not in raw and '"Resource": "*"' not in raw


def test_prod_bootstrap_best_effort_throttle_no_billable_custom_metrics():
    stage = fixed_prod_bootstrap_template()["Resources"]["McpApiStage"]["Properties"]
    assert stage["DefaultRouteSettings"] == {"ThrottlingBurstLimit": 2, "ThrottlingRateLimit": 1.0,
                                              "DetailedMetricsEnabled": False}
    assert "AccessLogSettings" not in stage


def test_prod_controls_exact_separate_stop_targets_and_no_deletion_scheduler():
    template = fixed_prod_controls_template("a1b2c3d4e5")
    resources = template["Resources"]
    assert len(resources) == 5
    assert all(r["Type"] not in ("AWS::Lambda::Function", "AWS::Scheduler::Schedule",
                                 "AWS::Scheduler::ScheduleGroup") for r in resources.values())
    raw = json.dumps(template)
    assert "honda-mapit-mcp-dev" not in raw
    assert "development" not in raw and "fixed-dev-shutdown" not in raw and "StartFixedDev" not in raw
    assert "fixed-target dev shutdown" not in raw
    assert "honda-mapit-mcp-prod-handler" in raw
    assert "deleteStack" not in raw and "DeleteFunction" not in raw
    assert "ReservedConcurrentExecutions" in raw and "DisableExecuteApiEndpoint" in raw
    alarm = resources["RequestTripwireAlarm"]["Properties"]
    assert alarm["ActionsEnabled"] is False and alarm["MetricName"] == "Count"
    assert alarm["Dimensions"][0]["Value"] == "a1b2c3d4e5"
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert template["Conditions"]["SupportedRegion"]["Fn::And"][1]["Fn::Equals"][1] == "honda-mapit-mcp-prod-controls"


@pytest.mark.parametrize("api_id", ["", "bad", "A1b2c3d4e5", "a1b2c3d4e5/path"])
def test_prod_controls_reject_unsafe_targets(api_id):
    with pytest.raises(ValueError):
        fixed_prod_controls_template(api_id)


def test_dev_scaffold_stays_closed_and_unmodified():
    before = fixed_bootstrap_template()
    fixed_prod_bootstrap_template()
    fixed_prod_controls_template("a1b2c3d4e5")
    assert fixed_bootstrap_template() == before
    assert before["Parameters"]["EnvironmentName"]["Default"] == "dev"
