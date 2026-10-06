from __future__ import annotations

import json

import pytest

from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
from mapit.aws_dev_shutdown_control import build_dev_shutdown_control
from scripts.build_aws_dev_runtime_template import fixed_runtime_bucket_template
from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts, build_retained_dev_controls


def test_controls_are_fixed_target_disabled_and_independent_of_lambda_capacity():
    template = build_retained_dev_controls("a1b2c3d4e5")
    resources = template["Resources"]
    assert len(resources) == 5
    assert not any(r["Type"] == "AWS::Lambda::Function" for r in resources.values())
    assert resources["RequestTripwireAlarm"]["Properties"]["ActionsEnabled"] is False
    assert resources["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert "ShutdownSchedule" not in resources
    encoded = json.dumps(template)
    assert "honda-mapit-mcp-prod" not in encoded
    assert "honda-mapit-mcp-dev-handler" not in encoded
    assert "honda-mapit-mcp-dev-retained-handler" in encoded
    assert "honda-mapit-mcp-dev-retained-controls" in encoded
    assert template["Metadata"]["FreshScheduledCloseRequiredBeforeActivation"] is True


@pytest.mark.parametrize("api", [None, "", "wrong", "a1b2c3d4e5/path", "https://prod.invalid"])
def test_bad_api_binding_is_rejected(api):
    with pytest.raises(ValueError):
        build_retained_dev_controls(api)


def test_artifacts_are_private_encrypted_and_only_terminal_journals_expire():
    template = build_retained_dev_artifacts()
    assert len(template["Resources"]) == 2
    bucket = template["Resources"]["RuntimeArtifactBucket"]
    props = bucket["Properties"]
    assert bucket["DeletionPolicy"] == bucket["UpdateReplacePolicy"] == "Retain"
    assert all(props["PublicAccessBlockConfiguration"].values())
    assert props["BucketEncryption"]["ServerSideEncryptionConfiguration"][0]["ServerSideEncryptionByDefault"] == {"SSEAlgorithm": "AES256"}
    rule = props["LifecycleConfiguration"]["Rules"][0]
    assert rule["Prefix"] == "journals/"
    assert rule["TagFilters"] == [{"Key": "cd-terminal", "Value": "true"}]
    assert rule["ExpirationInDays"] == 30
    assert props["BucketName"] == {"Fn::Sub": "honda-mapit-mcp-dev-retained-${AWS::AccountId}-${AWS::Region}"}
    assert "honda-mapit-mcp-dev-retained-runtime-artifacts" in json.dumps(template)
    assert "honda-mapit-mcp-prod" not in json.dumps(template)


def test_support_factories_do_not_mutate_originals_and_return_fresh_trees():
    controls = build_dev_shutdown_control(AwsDevShutdownPolicy("a1b2c3d4e5"), "2030-01-01T00:00:00")
    bucket = fixed_runtime_bucket_template()
    first = build_retained_dev_controls("a1b2c3d4e5")
    first["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] = "ENABLED"
    second = build_retained_dev_artifacts()
    second["Resources"]["RuntimeArtifactBucket"]["Properties"]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = False
    assert build_retained_dev_controls("a1b2c3d4e5")["Resources"]["RequestTripwireAlarmRule"]["Properties"]["State"] == "DISABLED"
    assert build_retained_dev_artifacts()["Resources"]["RuntimeArtifactBucket"]["Properties"]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] is True
    assert build_dev_shutdown_control(AwsDevShutdownPolicy("a1b2c3d4e5"), "2030-01-01T00:00:00") == controls
    assert fixed_runtime_bucket_template() == bucket
