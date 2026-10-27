from __future__ import annotations

from dataclasses import replace

import pytest

from scripts.aws_retained_dev_delivery_preflight import (
    MAX_CALLS,
    DeliveryPreflightError,
    RetainedDevStackCreationTags,
    RetainedDevDeliveryPreflight,
    _alarm_config_matches,
    _expected_cd_role_properties,
    _owned_resource_tags,
    _resource_rows_match,
)
from scripts.aws_retained_dev_controls_bootstrap import _resolve_internal_template
from scripts.build_aws_retained_dev_support import build_retained_dev_controls
from scripts.cd_retained_dev_delivery_contract import DeliveryContractError, _thaw
from tests.test_cd_retained_dev_delivery_contract import _binding


def _saved_state(binding, **overrides):
    value = {
        "schema": 1,
        "kind": "retained-dev-delivery-preflight",
        "version": 1,
        "binding_sha256": binding.binding_sha256,
        "account_id": binding.account_id,
        "source_sha": binding.source_sha,
        "last_observed_epoch": binding.authorized_from_epoch,
        "closed": True,
        "read_calls": 1,
    }
    value.update(overrides)
    return value


def test_saved_state_cannot_reopen_outside_window_or_beyond_call_budget():
    binding = _binding()
    checker = RetainedDevDeliveryPreflight.__new__(RetainedDevDeliveryPreflight)
    checker.binding = binding
    assert checker._valid_saved_state(_saved_state(binding, last_observed_epoch=binding.authorized_until_epoch)) is False
    assert checker._valid_saved_state(_saved_state(binding, read_calls=MAX_CALLS + 1)) is False


def test_response_pagination_flag_must_be_a_real_boolean():
    binding = _binding()

    class Client:
        def get_bucket_location(self, **kwargs):
            return {"LocationConstraint": "eu-west-1", "IsTruncated": "false", "ResponseMetadata": {"HTTPStatusCode": 200}}

    checker = RetainedDevDeliveryPreflight(
        {name: Client() for name in ("sts", "cloudformation", "lambda", "apigatewayv2", "iam", "s3", "sfn", "events", "cloudwatch")},
        type("Journal", (), {"load": lambda self: None, "compare_and_set": lambda self, expected, value: True, "locked": lambda self: iter(())})(),
        binding=binding,
        wall_clock=lambda: 1900000001,
        monotonic=lambda: 1.0,
    )
    checker._started = 1.0
    with pytest.raises(DeliveryPreflightError, match="aws_response_invalid"):
        checker._call("s3", "get_bucket_location", Bucket=binding.artifact_bucket, ExpectedBucketOwner=binding.account_id)


def test_receipt_bucket_must_bind_to_the_top_level_artifact_bucket():
    binding = _binding()
    receipt = _thaw(binding.artifact_receipt)
    receipt["resource"]["bucket"] = "honda-mapit-mcp-dev-retained-999999999999-eu-west-1"
    with pytest.raises(DeliveryContractError, match="receipt_binding_invalid"):
        replace(binding, artifact_receipt=receipt)


def test_normative_iam_documents_use_resolved_sdk_shape_not_cfn_intrinsics():
    binding = _binding()
    template = build_retained_dev_controls(binding.api_receipt["resource"]["api_id"])
    role = next(resource["Properties"] for resource in template["Resources"].values() if resource.get("Type") == "AWS::IAM::Role")
    resolved = _resolve_internal_template(role, binding.account_id)
    assert resolved["AssumeRolePolicyDocument"] != role["AssumeRolePolicyDocument"]
    assert isinstance(resolved["AssumeRolePolicyDocument"], dict)
    cd = _expected_cd_role_properties(binding, binding.api_receipt["resource"]["api_id"], "arn:aws:states:eu-west-1:123456789012:stateMachine:honda-mapit-mcp-dev-retained-shutdown")
    assert set(cd) == {"executor", "cloudformation", "executor_boundary", "cloudformation_boundary"}
    assert isinstance(cd["executor"]["Policies"][0]["PolicyDocument"], dict)


def test_alarm_normative_check_ignores_only_service_owned_dynamic_fields():
    expected = build_retained_dev_controls("a1b2c3d4e5")["Resources"]["RequestTripwireAlarm"]["Properties"]
    actual = dict(expected)
    actual.update({"AlarmArn": "arn:aws:cloudwatch:eu-west-1:123456789012:alarm:fixed", "StateValue": "OK", "StateUpdatedTimestamp": "2026-10-06T00:00:00.000Z"})
    assert _alarm_config_matches(actual, expected)
    changed = dict(actual)
    changed["Threshold"] = 101
    assert not _alarm_config_matches(changed, expected)


def test_creation_tags_are_receipt_bound_not_delivery_uuid_bound():
    binding = _binding()
    stack = RetainedDevStackCreationTags.from_receipt(
        stack_kind="app",
        stack_arn=binding.app_stack_arn,
        account_id=binding.account_id,
        tags=[
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "retained-dev"},
            {"Key": "OperatorRunId", "Value": "7"},
        ],
    )
    assert stack.operator_run_id == 7
    assert stack.operator_run_id != binding.run_id
    assert not _owned_resource_tags(
        [{"Key": "Project", "Value": "honda-mapit-mcp"}],
        [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}],
        stack=stack,
        logical_id="McpHandler",
    )


def test_physical_resource_ids_are_factory_normative_not_receipt_selected():
    expected_types = {"McpApi": "AWS::ApiGatewayV2::Api"}
    common = {"LogicalResourceId": "McpApi", "ResourceType": expected_types["McpApi"], "ResourceStatus": "CREATE_COMPLETE", "StackId": "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555", "StackName": "honda-mapit-mcp-dev-retained"}
    assert _resource_rows_match([{**common, "PhysicalResourceId": "a1b2c3d4e5"}], stack_arn=common["StackId"], stack_name=common["StackName"], expected_types=expected_types, physical_ids={"McpApi": "a1b2c3d4e5"})
    assert not _resource_rows_match([{**common, "PhysicalResourceId": "foreign-api"}], stack_arn=common["StackId"], stack_name=common["StackName"], expected_types=expected_types, physical_ids={"McpApi": "a1b2c3d4e5"})
