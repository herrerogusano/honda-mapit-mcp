from __future__ import annotations

import copy
import json

from scripts.build_aws_retained_dev_support import (
    build_retained_dev_artifacts,
    build_retained_dev_controls,
)
from scripts.build_aws_dev_runtime_template import fixed_runtime_bucket_template
from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control


def _all_strings(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _all_strings(key)
            yield from _all_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _all_strings(child)
    elif isinstance(value, str):
        yield value


def test_controls_are_exactly_five_disabled_loop_targets_with_region_and_stack_binding():
    template = build_retained_dev_controls("a1b2c3d4e5")
    resources = template["Resources"]
    assert {row["Type"] for row in resources.values()} == {
        "AWS::IAM::Role", "AWS::StepFunctions::StateMachine",
        "AWS::CloudWatch::Alarm", "AWS::Events::Rule",
    }
    assert len(resources) == 5
    assert all(row.get("Condition") == "SupportedRegion" for row in resources.values())
    assert template["Conditions"]["SupportedRegion"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev-retained-controls"]},
    ]

    alarm = resources["RequestTripwireAlarm"]["Properties"]
    rule = resources["RequestTripwireAlarmRule"]["Properties"]
    assert alarm["ActionsEnabled"] is False
    assert rule["State"] == "DISABLED"
    assert rule["Targets"][0]["RetryPolicy"] == {
        "MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60,
    }

    state_machine = json.loads(resources["ShutdownStateMachine"]["Properties"]["DefinitionString"])
    serialized = json.dumps(template, sort_keys=True)
    assert state_machine["TimeoutSeconds"] == 45
    assert state_machine["States"]["DisableApiEndpoint"]["Parameters"] == {
        "ApiId": "a1b2c3d4e5", "DisableExecuteApiEndpoint": True,
    }
    assert state_machine["States"]["ReserveFunctionConcurrency"]["Parameters"] == {
        "FunctionName": "honda-mapit-mcp-dev-retained-handler",
        "ReservedConcurrentExecutions": 0,
    }
    assert "Scheduler" not in serialized
    assert "AWS::Lambda::Function" not in serialized
    assert "honda-mapit-mcp-prod" not in serialized
    assert "honda-mapit-mcp-dev-handler" not in serialized


def test_artifacts_expire_only_tagged_terminal_journals_and_never_allow_business_access():
    template = build_retained_dev_artifacts()
    assert set(template["Resources"]) == {"RuntimeArtifactBucket", "RuntimeArtifactBucketPolicy"}
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"][1] == {
        "Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev-retained-runtime-artifacts"]
    }
    bucket = template["Resources"]["RuntimeArtifactBucket"]
    properties = bucket["Properties"]
    assert bucket["DeletionPolicy"] == bucket["UpdateReplacePolicy"] == "Retain"
    assert properties["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"] == {"SSEAlgorithm": "AES256"}
    assert all(properties["PublicAccessBlockConfiguration"].values())
    rule = properties["LifecycleConfiguration"]["Rules"]
    assert rule == [{
        "Id": "DevTerminalJournalRetention", "Status": "Enabled", "Prefix": "journals/",
        "TagFilters": [{"Key": "cd-terminal", "Value": "true"}], "ExpirationInDays": 30,
    }]
    policy = template["Resources"]["RuntimeArtifactBucketPolicy"]["Properties"]["PolicyDocument"]
    assert all(statement.get("Effect") == "Deny" for statement in policy["Statement"])
    assert "Allow" not in json.dumps(policy)
    encoded = "\n".join(_all_strings(template))
    assert "password" not in encoded.lower()
    assert "token" not in encoded.lower()
    assert "secret" not in encoded.lower()
    assert "honda-mapit-mcp-prod" not in encoded


def test_support_factories_do_not_mutate_either_source_factory_or_each_other():
    source_controls = build_dev_shutdown_control(AwsDevShutdownPolicy("a1b2c3d4e5"), "2030-01-01T00:00:00")
    source_artifacts = fixed_runtime_bucket_template()
    controls = build_retained_dev_controls("a1b2c3d4e5")
    artifacts = build_retained_dev_artifacts()
    controls["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] = "ENABLED"
    artifacts["Resources"]["RuntimeArtifactBucket"]["Properties"]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = False
    assert build_dev_shutdown_control(AwsDevShutdownPolicy("a1b2c3d4e5"), "2030-01-01T00:00:00") == source_controls
    assert fixed_runtime_bucket_template() == source_artifacts
    assert build_retained_dev_controls("a1b2c3d4e5")["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert build_retained_dev_artifacts()["Resources"]["RuntimeArtifactBucket"]["Properties"]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    assert copy.deepcopy(build_retained_dev_controls("a1b2c3d4e5")) == build_retained_dev_controls("a1b2c3d4e5")
