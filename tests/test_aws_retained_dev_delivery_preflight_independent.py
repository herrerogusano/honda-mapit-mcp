from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
import json

from scripts.aws_retained_dev_delivery_preflight import RetainedDevDeliveryPreflight
from scripts.cd_retained_dev_delivery_contract import RetainedDevDeliveryBinding, _thaw
from tests.test_cd_retained_dev_delivery_contract import _binding


class Journal:
    def __init__(self, state=None):
        self.state = copy.deepcopy(state)

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def compare_and_set(self, expected_version, value):
        current = self.state.get("version") if isinstance(self.state, dict) else None
        if current != expected_version:
            return False
        candidate = copy.deepcopy(value)
        candidate["version"] = (expected_version or 0) + 1
        self.state = candidate
        return True


def _prepared_binding() -> RetainedDevDeliveryBinding:
    original = _binding()
    values = {key: _thaw(value) for key, value in original.__dict__.items()}
    values["prior_template_receipt"]["resource"]["template_sha256"] = hashlib.sha256(
        json.dumps({}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    values["prior_code_receipt"]["resource"]["code_sha256"] = "c" * 64
    values["lambda_receipt"]["resource"]["function_name"] = "honda-mapit-mcp-dev-retained-handler"
    values["api_receipt"]["resource"]["api_id"] = "a1b2c3d4e5"
    values["iam_receipt"]["resource"]["role_name"] = "honda-mapit-mcp-dev-retained-cfn-update"
    values["controls_receipt"]["resource"]["stack_id"] = values["controls_stack_arn"]
    values["artifact_receipt"]["resource"]["stack_id"] = values["artifact_stack_arn"]
    values["prior_template_receipt"]["resource"]["stack_id"] = values["app_stack_arn"]
    values["prior_template_receipt"]["resource"]["resources"] = [{"LogicalResourceId": "Handler", "PhysicalResourceId": "honda-mapit-mcp-dev-retained-handler", "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "UPDATE_COMPLETE", "StackId": values["app_stack_arn"], "StackName": "honda-mapit-mcp-dev-retained"}]
    values["controls_receipt"]["resource"]["resources"] = [{"LogicalResourceId": "Control", "PhysicalResourceId": "control", "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "CREATE_COMPLETE", "StackId": values["controls_stack_arn"], "StackName": "honda-mapit-mcp-dev-retained-controls"}]
    values["artifact_receipt"]["resource"]["resources"] = [{"LogicalResourceId": "Bucket", "PhysicalResourceId": values["artifact_bucket"], "ResourceType": "AWS::S3::Bucket", "ResourceStatus": "CREATE_COMPLETE", "StackId": values["artifact_stack_arn"], "StackName": "honda-mapit-mcp-dev-retained-runtime-artifacts"}]
    controls_resource = values["controls_receipt"]["resource"]
    controls_resource["stack_events"] = []
    controls_resource["shutdown_state_machine"] = {"stateMachineArn": "arn:aws:states:eu-west-1:123456789012:stateMachine:honda-mapit-mcp-dev-retained-shutdown", "name": "honda-mapit-mcp-dev-retained-shutdown"}
    controls_resource["shutdown_state_machine_tags"] = []
    controls_resource["tripwire_rule"] = {"Name": "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule", "Arn": "arn:aws:events:eu-west-1:123456789012:rule/honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"}
    controls_resource["tripwire_rule_tags"] = []
    controls_resource["tripwire_targets"] = []
    controls_resource["tripwire_alarm"] = {"AlarmName": "honda-mapit-mcp-dev-retained-request-tripwire", "AlarmArn": "arn:aws:cloudwatch:eu-west-1:123456789012:alarm:honda-mapit-mcp-dev-retained-request-tripwire"}
    controls_resource["tripwire_alarm_tags"] = []
    controls_resource["control_roles"] = {}
    values["artifact_receipt"]["resource"]["stack_events"] = []
    values["artifact_receipt"]["resource"]["lifecycle"] = {}
    values["lambda_receipt"]["resource"]["tags"] = []
    return RetainedDevDeliveryBinding(**values)


class ReadOnlyClients:
    def __init__(self, binding: RetainedDevDeliveryBinding, *, api_id: str | None = None):
        self.binding = binding
        self.api_id = api_id
        self.calls: list[tuple[str, str, dict]] = []

    @staticmethod
    def _meta(value):
        value["ResponseMetadata"] = {"HTTPStatusCode": 200}
        return value

    def client(self, service):
        parent = self

        class Client:
            def __getattr__(self, method):
                def call(**kwargs):
                    parent.calls.append((service, method, kwargs))
                    if service == "sts" and method == "get_caller_identity":
                        return parent._meta({"Account": parent.binding.account_id, "Arn": parent.binding.expected_caller_arn})
                    if service == "cloudformation" and method == "describe_stacks":
                        if "runtime-artifacts" in str(kwargs.get("StackName")):
                            resource = parent.binding.artifact_receipt["resource"]
                            return parent._meta({"Stacks": [{"StackName": "honda-mapit-mcp-dev-retained-runtime-artifacts", "StackId": resource["stack_id"], "StackStatus": resource["stack_status"], "EnableTerminationProtection": resource["termination_protection"], "RoleARN": resource["role_arn"], "Tags": resource["stack_tags"]}]})
                        if "retained-controls" in str(kwargs.get("StackName")):
                            resource = parent.binding.controls_receipt["resource"]
                            return parent._meta({"Stacks": [{"StackName": "honda-mapit-mcp-dev-retained-controls", "StackId": resource["stack_id"], "StackStatus": resource["stack_status"], "EnableTerminationProtection": resource["termination_protection"], "RoleARN": resource["role_arn"], "Tags": resource["stack_tags"]}]})
                        resource = parent.binding.prior_template_receipt["resource"]
                        return parent._meta({"Stacks": [{"StackName": "honda-mapit-mcp-dev-retained", "StackId": parent.binding.app_stack_arn, "StackStatus": resource["stack_status"], "EnableTerminationProtection": resource["termination_protection"], "RoleARN": resource["role_arn"], "Tags": resource["stack_tags"]}]})
                    if service == "cloudformation" and method == "describe_stack_resources":
                        if "runtime-artifacts" in str(kwargs.get("StackName")):
                            rows = parent.binding.artifact_receipt["resource"]["resources"]
                        elif "retained-controls" in str(kwargs.get("StackName")):
                            rows = parent.binding.controls_receipt["resource"]["resources"]
                        else:
                            rows = parent.binding.prior_template_receipt["resource"]["resources"]
                        return parent._meta({"StackResources": rows})
                    if service == "cloudformation" and method == "get_template":
                        return parent._meta({"TemplateBody": {}})
                    if service == "lambda" and method == "get_function_configuration":
                        return parent._meta({"State": "Active"})
                    if service == "lambda" and method == "get_function_concurrency":
                        return parent._meta({"ReservedConcurrentExecutions": 0})
                    if service == "lambda" and method == "get_function":
                        return parent._meta({"Configuration": {"CodeSha256": "c" * 64}})
                    if service == "lambda" and method == "list_tags":
                        return parent._meta({"Tags": parent.binding.lambda_receipt["resource"]["tags"]})
                    if service == "cloudformation" and method == "describe_stack_events":
                        if "runtime-artifacts" in str(kwargs.get("StackName")):
                            return parent._meta({"StackEvents": parent.binding.artifact_receipt["resource"]["stack_events"]})
                        return parent._meta({"StackEvents": parent.binding.controls_receipt["resource"]["stack_events"]})
                    if service == "apigatewayv2" and method == "get_api":
                        return parent._meta({"ApiId": parent.api_id or parent.binding.api_receipt["resource"]["api_id"], "DisableExecuteApiEndpoint": True, "ProtocolType": "HTTP", "Name": parent.binding.api_receipt["resource"]["name"]})
                    if service == "apigatewayv2" and method == "get_routes":
                        return parent._meta({"Items": []})
                    if service == "iam" and method == "get_role":
                        expected = parent.binding.iam_receipt["resource"]
                        return parent._meta({"Role": {"Arn": parent.binding.cfn_role_arn, "RoleName": expected["role_name"], "Path": "/", "AssumeRolePolicyDocument": expected["trust_policy"], "PermissionsBoundary": {"PermissionsBoundaryArn": expected["boundary_arn"], "PermissionsBoundaryType": expected["boundary_type"]}}})
                    if service == "iam" and method == "list_role_tags":
                        return parent._meta({"Tags": parent.binding.iam_receipt["resource"]["tags"]})
                    if service == "iam" and method == "list_role_policies":
                        return parent._meta({"PolicyNames": parent.binding.iam_receipt["resource"]["attached_policy_names"]})
                    if service == "iam" and method == "get_role_policy":
                        expected = parent.binding.iam_receipt["resource"]
                        return parent._meta({"RoleName": expected["role_name"], "PolicyName": expected["policy_name"], "PolicyDocument": expected["policy_document"]})
                    if service == "iam" and method == "list_attached_role_policies":
                        return parent._meta({"AttachedPolicies": [], "IsTruncated": False})
                    if service == "iam" and method == "get_policy":
                        expected = parent.binding.iam_receipt["resource"]
                        return parent._meta({"Policy": {"Arn": expected["boundary_arn"], "PolicyName": expected["boundary_name"], "Path": expected["boundary_path"], "DefaultVersionId": expected["boundary_version_id"]}})
                    if service == "iam" and method == "get_policy_version":
                        expected = parent.binding.iam_receipt["resource"]
                        return parent._meta({"PolicyVersion": {"VersionId": expected["boundary_version_id"], "IsDefaultVersion": True, "Document": expected["boundary_document"]}})
                    if service == "s3":
                        expected = parent.binding.artifact_receipt["resource"]
                        values = {"get_bucket_location": {"LocationConstraint": "eu-west-1"}, "get_public_access_block": {"PublicAccessBlockConfiguration": expected["public_access_block"]}, "get_bucket_encryption": {"ServerSideEncryptionConfiguration": expected["encryption"]}, "get_bucket_ownership_controls": {"OwnershipControls": expected["ownership"]}, "get_bucket_versioning": {"Status": expected["versioning"]}, "get_bucket_lifecycle_configuration": {"Rules": expected["lifecycle"]}, "get_bucket_policy_status": {"PolicyStatus": expected["policy_status"]}, "get_bucket_tagging": {"TagSet": expected["tags"]}, "get_bucket_policy": {"Policy": expected["policy"]}}
                        return parent._meta(values.get(method, {}))
                    return parent._meta({})

                return call

        return Client()


def _run(binding, journal, *, api_id=None):
    import pytest
    pytest.importorskip("botocore.session")
    transport = ReadOnlyClients(binding, api_id=api_id)
    clients = {name: transport.client(name) for name in ("sts", "cloudformation", "lambda", "apigatewayv2", "iam", "s3", "sfn", "events", "cloudwatch")}
    result = RetainedDevDeliveryPreflight(
        clients,
        journal,
        binding=binding,
        wall_clock=lambda: 1900000001,
        monotonic=lambda: 1.0,
    ).run()
    return result, transport


def test_preflight_cannot_claim_success_without_controls_and_artifact_readbacks():
    binding = _prepared_binding()
    journal = Journal()
    result, transport = _run(binding, journal)

    # The delivery contract requires exact app/artifact/control/role readbacks;
    # matching only the application's lambda/API/role subset is insufficient.
    assert result["ok"] is False
    assert journal.state is None
    assert transport.calls == []


def test_preflight_rejects_api_response_for_the_wrong_api_id_even_when_disabled():
    binding = _prepared_binding()
    result, _ = _run(binding, Journal(), api_id="other-api")
    assert result["ok"] is False
    assert result["category"] == "receipt_normative_mismatch"


def test_preflight_rejects_unrecognised_existing_journal_state():
    binding = _prepared_binding()
    journal = Journal({"binding_sha256": binding.binding_sha256, "schema": 999, "foreign": True})
    result, _ = _run(binding, journal)
    assert result["ok"] is False
    assert result["category"] == "journal_invalid"
    assert journal.state["schema"] == 999


def test_saved_state_must_bind_account_and_source_to_the_current_envelope():
    binding = _prepared_binding()
    state = {
        "schema": 1,
        "kind": "retained-dev-delivery-preflight",
        "version": 1,
        "binding_sha256": binding.binding_sha256,
        "account_id": binding.account_id,
        "source_sha": binding.source_sha,
        "last_observed_epoch": 1900000001,
        "closed": True,
        "read_calls": 1,
    }
    for field, replacement in (("account_id", "210987654321"), ("source_sha", "b" * 40)):
        altered = dict(state)
        altered[field] = replacement
        checker = RetainedDevDeliveryPreflight.__new__(RetainedDevDeliveryPreflight)
        checker.account_id = binding.account_id
        checker.source_sha = binding.source_sha
        assert not checker._valid_saved_state(altered)


def test_paginated_iam_read_without_explicit_false_truncation_fails_closed():
    binding = _prepared_binding()
    checker = RetainedDevDeliveryPreflight.__new__(RetainedDevDeliveryPreflight)
    checker.clients = {"iam": type("Iam", (), {"list_role_tags": lambda self, **kwargs: {"Tags": [], "ResponseMetadata": {"HTTPStatusCode": 200}}})()}
    checker.binding = binding
    checker.wall_clock = lambda: 1900000001
    checker.monotonic = lambda: 1.0
    checker._started = 1.0
    checker._last_mono = 1.0
    checker._last_wall = 0.0
    checker._last_epoch = 0
    checker._calls = 0
    try:
        checker._call("iam", "list_role_tags", RoleName="role")
    except Exception as exc:
        assert getattr(exc, "category", None) == "aws_response_invalid"
    else:
        raise AssertionError("missing IsTruncated accepted")
