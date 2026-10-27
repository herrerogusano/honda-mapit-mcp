from __future__ import annotations

from dataclasses import replace
import pytest

from scripts.cd_retained_dev_delivery_contract import DeliveryContractError, DeliveryIntent, RetainedDevDeliveryBinding


def _binding():
    resources = {
        "controls": {"stack_id": "controls-stack", "stack_status": "CREATE_COMPLETE", "termination_protection": True, "role_arn": None, "resource_types": ["AWS::Lambda::Function"], "resources": [], "template": {}, "stack_tags": [], "stack_events": [], "shutdown_state_machine": {}, "shutdown_state_machine_tags": [], "tripwire_rule": {}, "tripwire_rule_tags": [], "tripwire_targets": [], "tripwire_alarm": {}, "tripwire_alarm_tags": [], "control_roles": {}},
        "artifact": {"stack_id": "artifact-stack", "stack_status": "CREATE_COMPLETE", "termination_protection": True, "role_arn": None, "resource_types": ["AWS::S3::Bucket"], "resources": [], "template": {}, "stack_tags": [], "stack_events": [], "bucket": "honda-mapit-mcp-dev-retained-123456789012-eu-west-1", "location": "eu-west-1", "public_access_block": {}, "encryption": {}, "ownership": {}, "versioning": {}, "lifecycle": {}, "policy_status": {}, "tags": [], "policy": {}},
        "prior-template": {"stack_id": "app-stack", "template_sha256": "a" * 64, "stack_status": "UPDATE_COMPLETE", "termination_protection": True, "role_arn": None, "resource_types": ["AWS::Lambda::Function"], "resources": [], "template": {}, "stack_tags": []},
        "prior-code": {"function_name": "honda-mapit-mcp-dev-retained-handler", "code_sha256": "b" * 64, "source": "source"},
        "lambda": {"function_name": "honda-mapit-mcp-dev-retained-handler", "code_sha256": "b" * 64, "reserved_concurrency": 0, "state": "Active", "configuration": {}, "tags": []},
        "api": {"api_id": "a1b2c3d4e5", "name": "honda-mapit-mcp-dev-retained", "protocol": "HTTP", "disabled": True, "routes_empty": True},
        "iam": {"role_name": "honda-mapit-mcp-dev-retained-cfn-update", "role_arn": "arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cfn-update", "path": "/", "tags": [], "trust_policy": {}, "policy_name": "honda-mapit-mcp-dev-retained-cfn-update", "policy_document": {}, "attached_policy_names": [], "boundary_arn": "arn:aws:iam::123456789012:policy/honda-mapit-mcp-dev-retained-boundary", "boundary_name": "honda-mapit-mcp-dev-retained-boundary", "boundary_path": "/", "boundary_document": {}, "boundary_version_id": "v1", "boundary_type": "PermissionsBoundaryPolicy"},
    }
    resources["controls"]["stack_id"] = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-controls/33333333-4444-4333-8444-555555555555"
    resources["artifact"]["stack_id"] = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4333-8444-555555555555"
    resources["prior-template"]["stack_id"] = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
    common = lambda kind: {"kind": kind, "observed_at_epoch": 1900000001, "source": "aws-readback", "resource": resources[kind], "closure": {"state": "closed", "checks": {"verified": True}}, "permissions": {"mode": "read_only", "checks": {"verified": True}}}
    return RetainedDevDeliveryBinding(
        account_id="123456789012", source_sha="a" * 40,
        run_id="123e4567-e89b-12d3-a456-426614174000",
        authorized_from_epoch=1900000000, authorized_until_epoch=1900003000,
        expected_caller_arn="arn:aws:iam::123456789012:role/operator",
        app_stack_arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555",
        artifact_stack_arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4333-8444-555555555555", controls_stack_arn="arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained-controls/33333333-4444-4333-8444-555555555555", artifact_bucket="honda-mapit-mcp-dev-retained-123456789012-eu-west-1",
        cfn_role_arn="arn:aws:iam::123456789012:role/honda-mapit-mcp-dev-retained-cfn-update", controls_receipt=common("controls"),
        artifact_receipt=common("artifact"), prior_template_receipt=common("prior-template"),
        prior_code_receipt=common("prior-code"), lambda_receipt=common("lambda"), api_receipt=common("api"),
        iam_receipt=common("iam"),
    )


def test_binding_is_bounded_and_has_complete_receipts():
    binding = _binding()
    assert len(binding.binding_sha256) == 64


@pytest.mark.parametrize("field,value", [("account_id", "bad"), ("source_sha", "0" * 40), ("run_id", "not-a-uuid"), ("authorized_until_epoch", 1900000000), ("expected_caller_arn", "arn:aws:iam::123456789012:root")])
def test_binding_rejects_invalid_immutable_fields(field, value):
    with pytest.raises(DeliveryContractError):
        replace(_binding(), **{field: value})


def test_receipt_size_is_bounded():
    with pytest.raises(DeliveryContractError):
        replace(_binding(), controls_receipt={"x": "a" * 70000})


def test_intent_is_content_addressed_and_no_arbitrary_key():
    intent = DeliveryIntent("update", "123e4567-e89b-12d3-a456-426614174000", "a" * 64, "runtime/" + "b" * 64 + ".zip", "c" * 64)
    assert intent.operation == "update"
    with pytest.raises(DeliveryContractError):
        DeliveryIntent("update", intent.run_id, intent.template_sha256, "other/file.zip", intent.prior_closed_template_sha256)


@pytest.mark.parametrize("field,value", [("account_id", "000000000000"), ("app_stack_arn", _binding().app_stack_arn.replace("11111111-2222-4333-8444-555555555555", "not-a-uuid")), ("artifact_stack_arn", "arn:aws:cloudformation:eu-west-1:123456789012:stack/other/22222222-3333-4333-8444-555555555555"), ("artifact_bucket", "other-bucket"), ("cfn_role_arn", "arn:aws:iam::123456789012:role/other")])
def test_namespace_and_identifier_bindings_fail_closed(field, value):
    with pytest.raises(DeliveryContractError):
        replace(_binding(), **{field: value})


def test_empty_receipt_is_not_a_complete_readback():
    with pytest.raises(DeliveryContractError):
        replace(_binding(), controls_receipt={})


@pytest.mark.parametrize("path,value", [("closure", {"state": "open", "checks": {"verified": True}}), ("closure", {"state": "unknown", "checks": {"verified": True}}), ("permissions", {"mode": "bounded_write", "checks": {"verified": True}}), ("permissions", {"mode": "unknown", "checks": {"verified": True}})])
def test_receipts_require_closed_read_only_provenance(path, value):
    receipt = {"kind": "controls", "observed_at_epoch": 1900000001, "source": "aws-readback", "resource": _binding().controls_receipt["resource"], "closure": {"state": "closed", "checks": {"verified": True}}, "permissions": {"mode": "read_only", "checks": {"verified": True}}}
    receipt[path] = value
    with pytest.raises(DeliveryContractError):
        replace(_binding(), controls_receipt=receipt)


def test_nested_receipts_are_detached_immutable_and_repr_redacted():
    binding = _binding()
    assert "123456789012" not in repr(binding)
    with pytest.raises(TypeError):
        binding.controls_receipt["resource"] = {"changed": True}
