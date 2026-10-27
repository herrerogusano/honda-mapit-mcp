"""Offline realistic SDK-shape exercise for the retained-dev preflight.

This fixture is deliberately separate from the preflight implementation.  It
uses the current factories and boto3 response shapes, with no AWS client or
network.  Lambda ``ListTags`` is represented as a map and includes only the
exact stack-propagated/operator and CloudFormation-owned tags derived from the
fresh original-stack receipt.
"""

from __future__ import annotations

import base64
import copy
from contextlib import contextmanager
from dataclasses import replace
import hashlib
import json
from typing import Any

from scripts.aws_retained_dev_controls_bootstrap import _expected_physical, _expected_service_arns, _resolve_internal_template
from scripts.aws_retained_dev_delivery_preflight import (
    RetainedDevDeliveryPreflight,
    _canonical,
    _expected_cd_role_properties,
)
from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts, build_retained_dev_controls
from tests.test_cd_retained_dev_delivery_contract import _binding


ACCOUNT = "123456789012"
API_ID = "a1b2c3d4e5"
RUN_ID = "123e4567-e89b-12d3-a456-426614174000"
APP_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/22222222-3333-4333-8444-555555555555"
CONTROL_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-controls/33333333-4444-4333-8444-555555555555"
CFN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
BUCKET = f"honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
CODE_SHA = "c" * 64
CODE_B64 = base64.b64encode(bytes.fromhex(CODE_SHA)).decode("ascii")


class Journal:
    def __init__(self) -> None:
        self.state: dict[str, Any] | None = None

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def compare_and_set(self, expected_version, value):
        current = self.state.get("version") if isinstance(self.state, dict) else None
        if current != expected_version:
            return False
        self.state = copy.deepcopy(value)
        self.state["version"] = (expected_version or 0) + 1
        return True


def _receipt(kind: str, resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": kind,
        "observed_at_epoch": 1900000001,
        "source": "aws-readback",
        "resource": resource,
        "closure": {"state": "closed", "checks": {"verified": True}},
        "permissions": {"mode": "read_only", "checks": {"verified": True}},
    }


def _rows(stack_id: str, stack_name: str, template: dict[str, Any], physical_ids: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {"LogicalResourceId": logical, "PhysicalResourceId": physical_ids[logical], "ResourceType": resource["Type"],
         "ResourceStatus": "CREATE_COMPLETE", "StackId": stack_id, "StackName": stack_name}
        for logical, resource in template["Resources"].items()
    ]


def _resolved_role(props: dict[str, Any]) -> dict[str, Any]:
    resolved = _resolve_internal_template(props, ACCOUNT)
    return {"RoleName": resolved["RoleName"], "Path": "/", "AssumeRolePolicyDocument": resolved["AssumeRolePolicyDocument"], "Tags": resolved.get("Tags", [])}


def _fixture(lambda_tag_shape: str = "rows"):
    controls_template = build_retained_dev_controls(API_ID)
    artifact_template = build_retained_dev_artifacts()
    app_template = build_retained_dev_template()
    control_types = {key: value["Type"] for key, value in controls_template["Resources"].items()}
    artifact_types = {key: value["Type"] for key, value in artifact_template["Resources"].items()}
    app_types = {key: value["Type"] for key, value in app_template["Resources"].items()}

    control_roles: dict[str, Any] = {}
    for resource in controls_template["Resources"].values():
        if resource["Type"] != "AWS::IAM::Role":
            continue
        props = resource["Properties"]
        resolved = _resolve_internal_template(props, ACCOUNT)
        control_roles[resolved["RoleName"]] = {
            "role": _resolved_role(props),
            "tags": resolved.get("Tags", []),
            "policy_names": [item["PolicyName"] for item in resolved["Policies"]],
            "attached_policies": [],
            "inline_policies": {item["PolicyName"]: item["PolicyDocument"] for item in resolved["Policies"]},
        }
    shutdown_props = _resolve_internal_template(controls_template["Resources"]["ShutdownStateMachine"]["Properties"], ACCOUNT)
    rule_props = _resolve_internal_template(controls_template["Resources"]["RequestTripwireAlarmRule"]["Properties"], ACCOUNT)
    shutdown_arn = _expected_service_arns(ACCOUNT)["ShutdownStateMachine"]
    shutdown = {"stateMachineArn": shutdown_arn, "name": "honda-mapit-mcp-dev-retained-shutdown", "status": "ACTIVE", "type": "STANDARD", "roleArn": _expected_service_arns(ACCOUNT)["ShutdownWorkflowRole"], "definition": json.loads(shutdown_props["DefinitionString"]), "loggingConfiguration": {"level": "OFF", "includeExecutionData": False, "destinations": []}, "tracingConfiguration": {"enabled": False}}
    rule = {"Name": "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule", "Arn": _expected_service_arns(ACCOUNT)["RequestTripwireAlarmRule"], "State": "DISABLED", "EventPattern": json.dumps(rule_props["EventPattern"], separators=(",", ":"))}
    alarm = {key: value for key, value in controls_template["Resources"]["RequestTripwireAlarm"]["Properties"].items() if key != "Tags"}
    alarm["AlarmArn"] = f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-dev-retained-request-tripwire"
    control_resource = {
        "stack_id": CONTROL_STACK, "stack_status": "CREATE_COMPLETE", "termination_protection": True, "role_arn": CFN_ROLE,
        "resource_types": list(control_types.values()), "resources": _rows(CONTROL_STACK, "honda-mapit-mcp-dev-retained-controls", controls_template, _expected_physical(ACCOUNT)),
        "template": controls_template, "stack_tags": [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-controls"}, {"Key": "OperatorRunId", "Value": "9"}], "stack_events": [], "shutdown_state_machine": shutdown,
        "shutdown_state_machine_tags": [{"key": row["Key"], "value": row["Value"]} for row in [*shutdown_props["Tags"], {"Key": "OperatorRunId", "Value": "9"}, {"Key": "aws:cloudformation:stack-id", "Value": CONTROL_STACK}, {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-controls"}, {"Key": "aws:cloudformation:logical-id", "Value": "ShutdownStateMachine"}]], "tripwire_rule": rule,
        "tripwire_rule_tags": [*rule_props["Tags"], {"Key": "OperatorRunId", "Value": "9"}, {"Key": "aws:cloudformation:stack-id", "Value": CONTROL_STACK}, {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-controls"}, {"Key": "aws:cloudformation:logical-id", "Value": "RequestTripwireAlarmRule"}], "tripwire_targets": [rule_props["Targets"][0]], "tripwire_alarm": alarm,
        "tripwire_alarm_tags": [*controls_template["Resources"]["RequestTripwireAlarm"]["Properties"]["Tags"], {"Key": "OperatorRunId", "Value": "9"}, {"Key": "aws:cloudformation:stack-id", "Value": CONTROL_STACK}, {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-controls"}, {"Key": "aws:cloudformation:logical-id", "Value": "RequestTripwireAlarm"}], "control_roles": control_roles,
    }

    bucket_props = artifact_template["Resources"]["RuntimeArtifactBucket"]["Properties"]
    artifact_tags = [*bucket_props["Tags"], {"Key": "OperatorRunId", "Value": "8"}, {"Key": "aws:cloudformation:stack-id", "Value": ARTIFACT_STACK}, {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-runtime-artifacts"}, {"Key": "aws:cloudformation:logical-id", "Value": "RuntimeArtifactBucket"}]
    artifact_resource = {
        "stack_id": ARTIFACT_STACK, "stack_status": "CREATE_COMPLETE", "termination_protection": True, "role_arn": CFN_ROLE,
        "resource_types": list(artifact_types.values()), "resources": _rows(ARTIFACT_STACK, "honda-mapit-mcp-dev-retained-runtime-artifacts", artifact_template, {"RuntimeArtifactBucket": BUCKET, "RuntimeArtifactBucketPolicy": BUCKET}),
        "template": artifact_template, "stack_tags": [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-artifacts"}, {"Key": "OperatorRunId", "Value": "8"}], "bucket": BUCKET, "location": "eu-west-1",
        "public_access_block": bucket_props["PublicAccessBlockConfiguration"],
        "encryption": {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
        "ownership": bucket_props["OwnershipControls"], "versioning": None,
        "lifecycle": [{"ID": "DevTerminalJournalRetention", "Status": "Enabled", "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}}, "Expiration": {"Days": 30}}],
        "policy_status": {"IsPublic": False}, "tags": artifact_tags,
        "policy": {"Version": "2012-10-17", "Statement": [{"Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]},
        "stack_events": [],
    }

    handler = app_template["Resources"]["McpHandler"]["Properties"]
    lambda_config = {key: handler[key] for key in ("FunctionName", "Role", "Runtime", "Handler", "Architectures", "MemorySize", "Timeout")}
    lambda_config["Role"] = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"
    app_stack_tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev"},
        {"Key": "OperatorRunId", "Value": "7"},
    ]
    lambda_tag_rows = [
        *handler["Tags"],
        {"Key": "OperatorRunId", "Value": "7"},
        {"Key": "aws:cloudformation:stack-id", "Value": APP_STACK},
        {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained"},
        {"Key": "aws:cloudformation:logical-id", "Value": "McpHandler"},
    ]
    lambda_tags = lambda_tag_rows if lambda_tag_shape == "rows" else {row["Key"]: row["Value"] for row in lambda_tag_rows}
    lambda_resource = {"function_name": handler["FunctionName"], "code_sha256": CODE_B64, "reserved_concurrency": 0, "state": "Active", "configuration": lambda_config, "tags": lambda_tag_rows}
    api_resource = {"api_id": API_ID, "name": "honda-mapit-mcp-dev-retained-api", "protocol": "HTTP", "disabled": True, "routes_empty": True}
    prior_resource = {"stack_id": APP_STACK, "template_sha256": hashlib.sha256(_canonical(app_template)).hexdigest(), "stack_status": "UPDATE_COMPLETE", "termination_protection": True, "role_arn": None, "resource_types": list(app_types.values()), "resources": _rows(APP_STACK, "honda-mapit-mcp-dev-retained", app_template, {"McpApi": API_ID, "McpApiStage": "$default", "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role", "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler", "McpHandler": "honda-mapit-mcp-dev-retained-handler"}), "template": app_template, "stack_tags": app_stack_tags}
    prior_code = {"function_name": handler["FunctionName"], "code_sha256": CODE_B64, "source": "offline"}

    # The CD role factory is already resolved except for its CFN boundary Ref.
    role_props = _expected_cd_role_properties(_binding(), API_ID, shutdown_arn)["cloudformation"]
    boundary_props = _expected_cd_role_properties(_binding(), API_ID, shutdown_arn)["cloudformation_boundary"]
    role_resolved = copy.deepcopy(role_props); role_resolved["PermissionsBoundary"] = {"PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/{boundary_props['ManagedPolicyName']}"}
    boundary_resolved = _resolve_internal_template(boundary_props, ACCOUNT)
    iam_resource = {"role_name": role_props["RoleName"], "role_arn": CFN_ROLE, "path": "/", "tags": role_props["Tags"], "trust_policy": role_resolved["AssumeRolePolicyDocument"], "policy_name": role_resolved["Policies"][0]["PolicyName"], "policy_document": role_resolved["Policies"][0]["PolicyDocument"], "attached_policy_names": [], "boundary_arn": f"arn:aws:iam::{ACCOUNT}:policy/{boundary_props['ManagedPolicyName']}", "boundary_name": boundary_props["ManagedPolicyName"], "boundary_path": "/", "boundary_document": boundary_resolved["PolicyDocument"], "boundary_version_id": "v1", "boundary_type": "Policy"}

    base = _binding()
    return replace(base, controls_receipt=_receipt("controls", control_resource), artifact_receipt=_receipt("artifact", artifact_resource), prior_template_receipt=_receipt("prior-template", prior_resource), prior_code_receipt=_receipt("prior-code", prior_code), lambda_receipt=_receipt("lambda", lambda_resource), api_receipt=_receipt("api", api_resource), iam_receipt=_receipt("iam", iam_resource)), {
        "controls": control_resource, "artifact": artifact_resource, "prior": prior_resource, "lambda": lambda_resource, "lambda_tags_response": lambda_tags, "api": api_resource, "iam": iam_resource, "shutdown": shutdown, "rule": rule, "alarm": alarm,
    }


class Clients:
    def __init__(self, binding, values):
        self.binding, self.values = binding, values

    def client(self, service):
        parent = self

        class Client:
            def __getattr__(self, method):
                def call(**kwargs):
                    response: dict[str, Any]
                    values = parent.values
                    if service == "sts" and method == "get_caller_identity": response = {"Account": ACCOUNT, "Arn": parent.binding.expected_caller_arn}
                    elif service == "cloudformation" and method == "describe_stacks":
                        name = str(kwargs.get("StackName")); resource, stack_name = (values["control"], "honda-mapit-mcp-dev-retained-controls") if "controls" in name else (values["artifact"], "honda-mapit-mcp-dev-retained-runtime-artifacts") if "artifacts" in name else (values["prior"], "honda-mapit-mcp-dev-retained")
                        response = {"Stacks": [{"StackName": stack_name, "StackId": resource["stack_id"], "StackStatus": resource["stack_status"], "EnableTerminationProtection": resource["termination_protection"], "RoleARN": resource["role_arn"], "Tags": resource["stack_tags"]}]}
                    elif service == "cloudformation" and method == "describe_stack_resources":
                        name = str(kwargs.get("StackName")); response = {"StackResources": values["control"]["resources"] if "controls" in name else values["artifact"]["resources"] if "artifacts" in name else values["prior"]["resources"]}
                    elif service == "cloudformation" and method == "get_template":
                        name = str(kwargs.get("StackName")); response = {"TemplateBody": values["control"]["template"] if "controls" in name else values["artifact"]["template"] if "artifacts" in name else values["prior"]["template"]}
                    elif service == "cloudformation" and method == "describe_stack_events":
                        name = str(kwargs.get("StackName")); response = {"StackEvents": values["control"]["stack_events"] if "controls" in name else values["artifact"]["stack_events"]}
                    elif service == "s3":
                        a = values["artifact"]; response = {"get_bucket_location": {"LocationConstraint": a["location"]}, "get_public_access_block": {"PublicAccessBlockConfiguration": a["public_access_block"]}, "get_bucket_encryption": {"ServerSideEncryptionConfiguration": a["encryption"]}, "get_bucket_ownership_controls": {"OwnershipControls": a["ownership"]}, "get_bucket_versioning": {"Status": a["versioning"]}, "get_bucket_lifecycle_configuration": {"Rules": a["lifecycle"]}, "get_bucket_policy_status": {"PolicyStatus": a["policy_status"]}, "get_bucket_tagging": {"TagSet": a["tags"]}, "get_bucket_policy": {"Policy": a["policy"]}}[method]
                    elif service == "sfn" and method == "describe_state_machine": response = values["shutdown"]
                    elif service == "sfn" and method == "list_tags_for_resource": response = {"tags": values["control"]["shutdown_state_machine_tags"]}
                    elif service == "events" and method == "describe_rule": response = values["rule"]
                    elif service == "events" and method == "list_tags_for_resource": response = {"Tags": values["control"]["tripwire_rule_tags"]}
                    elif service == "events" and method == "list_targets_by_rule": response = {"Targets": values["control"]["tripwire_targets"]}
                    elif service == "cloudwatch" and method == "describe_alarms": response = {"MetricAlarms": [values["alarm"]]}
                    elif service == "cloudwatch" and method == "list_tags_for_resource": response = {"Tags": values["control"]["tripwire_alarm_tags"]}
                    elif service == "apigatewayv2" and method == "get_routes": response = {"Items": []}
                    elif service == "apigatewayv2" and method == "get_api": response = {"ApiId": API_ID, "DisableExecuteApiEndpoint": True, "ProtocolType": "HTTP", "Name": values["api"]["name"]}
                    elif service == "lambda" and method == "get_function_configuration": response = {**values["lambda"]["configuration"], "State": "Active", "LastUpdateStatus": "Successful"}
                    elif service == "lambda" and method == "get_function_concurrency": response = {"ReservedConcurrentExecutions": 0}
                    elif service == "lambda" and method == "get_function": response = {"Configuration": {"CodeSha256": CODE_B64}}
                    elif service == "lambda" and method == "list_tags": response = {"Tags": values["lambda_tags_response"]}
                    elif service == "iam" and method in {"get_role", "list_role_tags", "list_role_policies", "get_role_policy", "list_attached_role_policies", "get_policy", "get_policy_version"}: response = parent._iam(method, kwargs, values)
                    else: response = {}
                    response["ResponseMetadata"] = {"HTTPStatusCode": 200}
                    return response
                return call

        return Client()

    def _iam(self, method, kwargs, values):
        role_name = kwargs.get("RoleName")
        if role_name in values["control"]["control_roles"]:
            observed = values["control"]["control_roles"][role_name]
            role = observed["role"]
            if method == "get_role": return {"Role": role}
            if method == "list_role_tags": return {"Tags": observed["tags"], "IsTruncated": False}
            if method == "list_role_policies": return {"PolicyNames": observed["policy_names"], "IsTruncated": False}
            if method == "get_role_policy":
                name = kwargs.get("PolicyName")
                return {"RoleName": role_name, "PolicyName": name, "PolicyDocument": observed["inline_policies"][name]}
            if method == "list_attached_role_policies": return {"AttachedPolicies": [], "IsTruncated": False}
        i = values["iam"]
        if method == "get_role": return {"Role": {"RoleName": i["role_name"], "Arn": i["role_arn"], "Path": "/", "AssumeRolePolicyDocument": i["trust_policy"], "PermissionsBoundary": {"PermissionsBoundaryArn": i["boundary_arn"], "PermissionsBoundaryType": "Policy"}}}
        if method == "list_role_tags": return {"Tags": i["tags"], "IsTruncated": False}
        if method == "list_role_policies": return {"PolicyNames": [i["policy_name"]], "IsTruncated": False}
        if method == "get_role_policy": return {"RoleName": i["role_name"], "PolicyName": i["policy_name"], "PolicyDocument": i["policy_document"]}
        if method == "list_attached_role_policies": return {"AttachedPolicies": [], "IsTruncated": False}
        if method == "get_policy": return {"Policy": {"Arn": i["boundary_arn"], "PolicyName": i["boundary_name"], "Path": "/", "DefaultVersionId": "v1"}}
        return {"PolicyVersion": {"VersionId": "v1", "IsDefaultVersion": True, "Document": i["boundary_document"]}}


def _run(lambda_tag_shape="rows", mutate=None):
    import pytest
    pytest.importorskip("botocore.session")
    binding, values = _fixture(lambda_tag_shape)
    if mutate is not None:
        mutate(values)
    values = {**values, "control": values.pop("controls")}
    clients = {name: Clients(binding, values).client(name) for name in ("sts", "cloudformation", "lambda", "apigatewayv2", "iam", "s3", "sfn", "events", "cloudwatch")}
    return RetainedDevDeliveryPreflight(clients, Journal(), binding=binding, wall_clock=lambda: 1900000001, monotonic=lambda: 1.0).run()


def test_realistic_sdk_row_fixture_reaches_bounded_preflight_without_aws():
    # This is a model-shape result, not an acceptance of any account state.
    assert _run("rows") == {"ok": True, "category": "preflight_verified", "calls": 51}


def test_real_boto3_lambda_tag_map_is_accepted_and_row_shape_remains_strict():
    result = _run("map")
    assert result == {"ok": True, "category": "preflight_verified", "calls": 51}
    from scripts.aws_retained_dev_delivery_preflight import _tags_equal
    assert _tags_equal(
        [{"Key": "Project", "Value": "honda-mapit-mcp"}],
        [{"Key": "Project", "Value": "honda-mapit-mcp"}],
    )
    assert not _tags_equal(
        [{"Key": "Project", "Value": "honda-mapit-mcp"}],
        {"Project": "honda-mapit-mcp"},
    )


def test_foreign_operator_run_id_is_rejected_by_live_preflight_readback():
    result = _run("map", lambda values: values["lambda_tags_response"].update(OperatorRunId="8"))
    assert result == {"ok": False, "category": "lambda_not_closed", "calls": 44}


def test_foreign_cloudformation_stack_tag_is_rejected_by_live_preflight_readback():
    result = _run(
        "map",
        lambda values: values["lambda_tags_response"].update(
            **{"aws:cloudformation:stack-id": "foreign-stack"}
        ),
    )
    assert result == {"ok": False, "category": "lambda_not_closed", "calls": 44}


def test_matching_alarm_configuration_cannot_hide_foreign_live_arn():
    result = _run("map", lambda values: values["alarm"].update(
        AlarmArn="arn:aws:cloudwatch:eu-west-1:999999999999:alarm:honda-mapit-mcp-dev-retained-request-tripwire",
    ))
    assert result["ok"] is False
    assert result["category"] == "controls_readback_mismatch"


def test_pinned_botocore_confirms_lambda_map_and_iam_list_tag_shapes():
    import pytest
    pytest.importorskip("botocore.session")
    from botocore.session import get_session

    session = get_session()
    lambda_tags = session.get_service_model("lambda").operation_model("ListTags").output_shape.members["Tags"]
    iam_tags = session.get_service_model("iam").operation_model("ListRoleTags").output_shape.members["Tags"]
    assert lambda_tags.type_name == "map"
    assert iam_tags.type_name == "list"
    assert iam_tags.member.type_name == "structure"
