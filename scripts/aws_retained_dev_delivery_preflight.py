"""Injected, read-only retained-dev delivery preflight.

This increment performs no publication or CloudFormation update.  All clients
and the bounded CAS journal are injected; responses are reduced to metadata
receipts and never retained in the journal.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import math
import re
import time
from urllib.parse import unquote_to_bytes
from typing import Any, Callable

from scripts.cd_retained_dev_delivery_contract import RetainedDevDeliveryBinding, DeliveryContractError, _thaw
from scripts.aws_retained_dev_controls_bootstrap import (
    _expected_physical,
    _expected_service_arns,
    _resolve_internal_template,
)
from scripts.aws_retained_dev_delivery_update import RetainedDevCreationTagBinding, _lambda_tags_equal

REGION = "eu-west-1"
STACK_NAME = "honda-mapit-mcp-dev-retained"
MAX_CALLS = 96
MAX_STEP_SECONDS = 30.0
_STACK = re.compile(rf"arn:aws:cloudformation:{REGION}:[0-9]{{12}}:stack/{STACK_NAME}/[0-9a-f]{{8}}-[0-9a-f]{{4}}-[1-5][0-9a-f]{{3}}-[89ab][0-9a-f]{{3}}-[0-9a-f]{{12}}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SDK_MODEL_SPECS = {
    "sts": {
        "get_caller_identity": ("GetCallerIdentity", set(), {"Account", "Arn"}),
    },
    "cloudformation": {
        "describe_stacks": ("DescribeStacks", {"StackName"}, {"Stacks"}),
        "describe_stack_resources": ("DescribeStackResources", {"StackName"}, {"StackResources"}),
        "get_template": ("GetTemplate", {"StackName", "TemplateStage"}, {"TemplateBody"}),
        "describe_stack_events": ("DescribeStackEvents", {"StackName"}, {"StackEvents"}),
    },
    "s3": {
        "get_bucket_location": ("GetBucketLocation", {"Bucket", "ExpectedBucketOwner"}, {"LocationConstraint"}),
        "get_public_access_block": ("GetPublicAccessBlock", {"Bucket", "ExpectedBucketOwner"}, {"PublicAccessBlockConfiguration"}),
        "get_bucket_encryption": ("GetBucketEncryption", {"Bucket", "ExpectedBucketOwner"}, {"ServerSideEncryptionConfiguration"}),
        "get_bucket_ownership_controls": ("GetBucketOwnershipControls", {"Bucket", "ExpectedBucketOwner"}, {"OwnershipControls"}),
        "get_bucket_versioning": ("GetBucketVersioning", {"Bucket", "ExpectedBucketOwner"}, {"Status"}),
        "get_bucket_lifecycle_configuration": ("GetBucketLifecycleConfiguration", {"Bucket", "ExpectedBucketOwner"}, {"Rules"}),
        "get_bucket_policy_status": ("GetBucketPolicyStatus", {"Bucket", "ExpectedBucketOwner"}, {"PolicyStatus"}),
        "get_bucket_tagging": ("GetBucketTagging", {"Bucket", "ExpectedBucketOwner"}, {"TagSet"}),
        "get_bucket_policy": ("GetBucketPolicy", {"Bucket", "ExpectedBucketOwner"}, {"Policy"}),
    },
    "lambda": {
        "get_function_configuration": ("GetFunctionConfiguration", {"FunctionName"}, {"State"}),
        "get_function_concurrency": ("GetFunctionConcurrency", {"FunctionName"}, {"ReservedConcurrentExecutions"}),
        "get_function": ("GetFunction", {"FunctionName"}, {"Configuration"}),
        "list_tags": ("ListTags", {"Resource"}, {"Tags"}),
    },
    "apigatewayv2": {
        "get_routes": ("GetRoutes", {"ApiId"}, {"Items"}),
        "get_api": ("GetApi", {"ApiId"}, {"ApiId", "DisableExecuteApiEndpoint", "ProtocolType", "Name"}),
    },
    "iam": {
        "get_role": ("GetRole", {"RoleName"}, {"Role"}),
        "list_role_tags": ("ListRoleTags", {"RoleName"}, {"Tags", "IsTruncated"}),
        "list_role_policies": ("ListRolePolicies", {"RoleName"}, {"PolicyNames", "IsTruncated"}),
        "get_role_policy": ("GetRolePolicy", {"RoleName", "PolicyName"}, {"RoleName", "PolicyName", "PolicyDocument"}),
        "list_attached_role_policies": ("ListAttachedRolePolicies", {"RoleName"}, {"AttachedPolicies", "IsTruncated"}),
        "get_policy": ("GetPolicy", {"PolicyArn"}, {"Policy"}),
        "get_policy_version": ("GetPolicyVersion", {"PolicyArn", "VersionId"}, {"PolicyVersion"}),
    },
    "sfn": {
        "describe_state_machine": ("DescribeStateMachine", {"stateMachineArn"}, {"stateMachineArn", "name"}),
        "list_tags_for_resource": ("ListTagsForResource", {"resourceArn"}, {"tags"}),
    },
    "events": {
        "describe_rule": ("DescribeRule", {"Name"}, {"Name", "Arn"}),
        "list_targets_by_rule": ("ListTargetsByRule", {"Rule"}, {"Targets"}),
        "list_tags_for_resource": ("ListTagsForResource", {"ResourceARN"}, {"Tags"}),
    },
    "cloudwatch": {
        "describe_alarms": ("DescribeAlarms", {"AlarmNames"}, {"MetricAlarms"}),
        "list_tags_for_resource": ("ListTagsForResource", {"ResourceARN"}, {"Tags"}),
    },
}
_PAGINATED_READS = frozenset({
    ("iam", "list_role_tags"), ("iam", "list_role_policies"),
    ("iam", "list_attached_role_policies"),
})

_STACK_TAG_SPECS = {
    "app": (STACK_NAME, "retained-dev"),
    "artifact": ("honda-mapit-mcp-dev-retained-runtime-artifacts", "retained-dev-artifacts"),
    "controls": ("honda-mapit-mcp-dev-retained-controls", "retained-dev-controls"),
}


@dataclass(frozen=True)
class RetainedDevStackCreationTags:
    """The immutable creation-tag proof for one retained-dev stack.

    The operator run id is read from that stack's original private receipt. It
    is deliberately not taken from the later delivery binding, whose UUID is a
    separate operation namespace.
    """

    stack_kind: str
    stack_name: str
    stack_arn: str
    purpose: str
    operator_run_id: int

    @classmethod
    def from_receipt(
        cls,
        *,
        stack_kind: str,
        stack_arn: str,
        account_id: str,
        tags: Any,
    ) -> "RetainedDevStackCreationTags":
        if stack_kind not in _STACK_TAG_SPECS or type(stack_arn) is not str or type(account_id) is not str:
            raise DeliveryPreflightError("creation_tags_invalid")
        stack_name, purpose = _STACK_TAG_SPECS[stack_kind]
        expected_prefix = f"arn:aws:cloudformation:{REGION}:{account_id}:stack/{stack_name}/"
        suffix = stack_arn[len(expected_prefix):] if stack_arn.startswith(expected_prefix) else ""
        if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", suffix) is None:
            raise DeliveryPreflightError("creation_tags_invalid")
        values: dict[str, str] = {}
        if not isinstance(tags, (list, tuple)):
            raise DeliveryPreflightError("creation_tags_invalid")
        for row in tags:
            if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or type(row["Key"]) is not str or type(row["Value"]) is not str or row["Key"] in values:
                raise DeliveryPreflightError("creation_tags_invalid")
            values[row["Key"]] = row["Value"]
        if set(values) != {"Project", "Environment", "Purpose", "OperatorRunId"} or values["Project"] != "honda-mapit-mcp" or values["Environment"] != "dev" or values["Purpose"] != purpose or re.fullmatch(r"[1-9][0-9]*", values["OperatorRunId"]) is None:
            raise DeliveryPreflightError("creation_tags_invalid")
        operator_run_id = int(values["OperatorRunId"])
        if str(operator_run_id) != values["OperatorRunId"]:
            raise DeliveryPreflightError("creation_tags_invalid")
        return cls(stack_kind, stack_name, stack_arn, purpose, operator_run_id)

    def rows(self) -> list[dict[str, str]]:
        return [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": self.purpose},
            {"Key": "OperatorRunId", "Value": str(self.operator_run_id)},
        ]


def _owned_resource_tags(actual: Any, expected: Any, *, stack: RetainedDevStackCreationTags, logical_id: str) -> bool:
    """Compare base tags plus only known CFN/creation propagation tags."""
    if not isinstance(expected, list) or not isinstance(actual, (list, tuple, Mapping)):
        return False
    def normalize(value: Any) -> dict[str, str] | None:
        if isinstance(value, Mapping):
            if any(type(k) is not str or type(v) is not str for k, v in value.items()):
                return None
            return dict(value)
        result: dict[str, str] = {}
        for row in value:
            if not isinstance(row, Mapping) or set(row) not in ({"Key", "Value"}, {"key", "value"}):
                return None
            key_name, value_name = ("Key", "Value") if "Key" in row else ("key", "value")
            if type(row[key_name]) is not str or type(row[value_name]) is not str or row[key_name] in result:
                return None
            result[row[key_name]] = row[value_name]
        return result
    base = normalize(expected)
    observed = normalize(actual)
    if base is None or observed is None:
        return False
    allowed = dict(base)
    allowed.update({
        "OperatorRunId": str(stack.operator_run_id),
        "aws:cloudformation:stack-id": stack.stack_arn,
        "aws:cloudformation:stack-name": stack.stack_name,
        "aws:cloudformation:logical-id": logical_id,
    })
    return set(observed) <= set(allowed) and all(observed.get(key) == value for key, value in base.items()) and all(observed.get(key) == value for key, value in allowed.items() if key in observed)


def _resource_rows_match(rows: Any, *, stack_arn: str, stack_name: str, expected_types: Mapping[str, str], physical_ids: Mapping[str, str]) -> bool:
    if type(rows) is not list or set(physical_ids) != set(expected_types) or len(rows) != len(expected_types):
        return False
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str or row["LogicalResourceId"] in seen:
            return False
        logical = row["LogicalResourceId"]
        seen.add(logical)
        if row.get("ResourceType") != expected_types.get(logical) or row.get("PhysicalResourceId") != physical_ids.get(logical) or row.get("ResourceStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or row.get("StackId") != stack_arn or row.get("StackName") != stack_name:
            return False
    return seen == set(expected_types)


def _stack_events_projection(rows: Any, *, stack_arn: str, stack_name: str) -> bool:
    """Validate stable event identity while ignoring service timestamps/reasons."""
    if type(rows) is not list or len(rows) > 64:
        return False
    for row in rows:
        if not isinstance(row, Mapping) or row.get("StackId") != stack_arn or row.get("StackName") not in {None, stack_name}:
            return False
        if "Timestamp" in row and not isinstance(row["Timestamp"], (str, datetime)):
            return False
        if "EventId" in row and not isinstance(row["EventId"], str):
            return False
        if "ResourceStatus" in row and not isinstance(row["ResourceStatus"], str):
            return False
    return True


def _shutdown_matches(actual: Any, expected: Any, *, account_id: str) -> bool:
    if not isinstance(actual, Mapping) or not isinstance(expected, Mapping):
        return False
    expected_definition = _document(expected.get("DefinitionString"))
    actual_definition = _document(actual.get("definition"))
    logging = actual.get("loggingConfiguration")
    tracing = actual.get("tracingConfiguration")
    return (
        actual.get("stateMachineArn") == _expected_service_arns(account_id)["ShutdownStateMachine"]
        and actual.get("name") == "honda-mapit-mcp-dev-retained-shutdown"
        and actual.get("status") == "ACTIVE"
        and actual.get("type") == "STANDARD"
        and actual.get("roleArn") == _expected_service_arns(account_id)["ShutdownWorkflowRole"]
        and expected_definition is not None and actual_definition is not None and _same(actual_definition, expected_definition)
        and isinstance(logging, Mapping) and logging.get("level", logging.get("Level")) == "OFF"
        and logging.get("includeExecutionData", False) is False and logging.get("destinations", []) == []
        and isinstance(tracing, Mapping) and tracing.get("enabled", tracing.get("Enabled")) is False
    )


def _rule_matches(actual: Any, expected: Any, *, account_id: str) -> bool:
    return (
        isinstance(actual, Mapping) and isinstance(expected, Mapping)
        and actual.get("Name") == "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"
        and actual.get("Arn") == _expected_service_arns(account_id)["RequestTripwireAlarmRule"]
        and actual.get("State") == "DISABLED"
        and _same(_document(actual.get("EventPattern")), expected.get("EventPattern"))
    )


class DeliveryPreflightError(ValueError):
    def __init__(self, category: str):
        self.category = category
        super().__init__(category)


def validate_botocore_models() -> None:
    """Validate operation names and known shapes without constructing a client."""
    try:
        from botocore import xform_name
        from botocore.session import get_session
        session = get_session()
        service_names = {"sfn": "stepfunctions"}
        for service, operations in _SDK_MODEL_SPECS.items():
            service_name = service_names.get(service, service)
            model = session.get_service_model(service_name)
            for method, (operation, inputs, outputs) in operations.items():
                if xform_name(operation) != method:
                    raise DeliveryPreflightError("sdk_model_invalid")
                shape = model.operation_model(operation)
                if not inputs.issubset(shape.input_shape.members) or not outputs.issubset(shape.output_shape.members):
                    raise DeliveryPreflightError("sdk_model_invalid")
    except DeliveryPreflightError:
        raise
    except Exception:
        raise DeliveryPreflightError("sdk_model_invalid") from None


def _ok(value: Any) -> bool:
    metadata = value.get("ResponseMetadata") if isinstance(value, Mapping) else None
    return isinstance(metadata, Mapping) and type(metadata.get("HTTPStatusCode")) is int and metadata.get("HTTPStatusCode") == 200


def _canonical(value: Any) -> bytes:
    try:
        def detached(item: Any) -> Any:
            if isinstance(item, Mapping):
                return {str(key): detached(val) for key, val in item.items()}
            if isinstance(item, (list, tuple)):
                return [detached(val) for val in item]
            return item
        return json.dumps(detached(value), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except Exception:
        raise DeliveryPreflightError("receipt_invalid") from None


def _same(left: Any, right: Any) -> bool:
    try:
        return _canonical(left) == _canonical(right)
    except DeliveryPreflightError:
        return False


def _without_metadata(value: Any) -> Any:
    """Return an SDK payload without volatile response metadata."""
    if not isinstance(value, Mapping):
        return value
    return {key: item for key, item in value.items() if key != "ResponseMetadata"}


def _resource_types(rows: Any) -> list[str] | None:
    if not isinstance(rows, (list, tuple)) or not rows:
        return None
    result: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or type(row.get("ResourceType")) is not str or not row["ResourceType"]:
            return None
        result.append(row["ResourceType"])
    return sorted(result)


def _document(value: Any) -> Any:
    """Decode AWS policy JSON only from mapping or bounded valid JSON text."""
    if isinstance(value, Mapping):
        return value
    if type(value) is not str or len(value.encode("utf-8", "strict")) > 64 * 1024:
        raise DeliveryPreflightError("iam_document_invalid")
    raw = value
    if "%" in raw:
        if re.search(r"%(?![0-9A-Fa-f]{2})", raw):
            raise DeliveryPreflightError("iam_document_invalid")
        try:
            decoded = unquote_to_bytes(raw)
        except Exception:
            raise DeliveryPreflightError("iam_document_invalid") from None
        if len(decoded) > 64 * 1024:
            raise DeliveryPreflightError("iam_document_invalid")
        try:
            raw = decoded.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise DeliveryPreflightError("iam_document_invalid") from None
    try:
        return json.loads(raw, object_pairs_hook=_strict_pairs)
    except Exception:
        raise DeliveryPreflightError("iam_document_invalid") from None


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _rows_equal(actual: Any, expected: Any) -> bool:
    if not isinstance(actual, (list, tuple)) or not isinstance(expected, (list, tuple)):
        return False
    def ordered(rows: list[Any]) -> list[Any] | None:
        if any(not isinstance(row, Mapping) or type(row.get("LogicalResourceId")) is not str for row in rows):
            return None
        return sorted(rows, key=lambda row: row["LogicalResourceId"])
    left, right = ordered(actual), ordered(expected)
    return left is not None and right is not None and _same(left, right)


def _tags_equal(actual: Any, expected: Any) -> bool:
    if not isinstance(expected, (list, tuple)):
        return False
    def normalize(rows: list[Any] | tuple[Any, ...]) -> dict[str, str] | None:
        result: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or type(row["Key"]) is not str or type(row["Value"]) is not str or row["Key"] in result:
                return None
            result[row["Key"]] = row["Value"]
        return result
    if isinstance(actual, Mapping):
        if any(type(key) is not str or type(value) is not str for key, value in actual.items()):
            return False
        left = dict(actual)
    elif isinstance(actual, (list, tuple)):
        left = normalize(actual)
    else:
        return False
    right = normalize(expected)
    return left is not None and left == right


def _lambda_tags_equal_for_stack(
    actual: Any,
    expected: Any,
    *,
    stack_arn: str,
    creation_tag_binding: RetainedDevCreationTagBinding,
) -> bool:
    """Validate Lambda's map-shaped ListTags against the closed app receipt.

    The receipt stores tag rows, while the Lambda SDK returns a map.  Only the
    exact creation binding derived from the original stack receipt can admit
    ``OperatorRunId``; CloudFormation's three resource tags are derived from
    the same immutable stack identity.  No generic extra-tag allowance is
    introduced here.
    """
    if isinstance(actual, (list, tuple)):
        rows: dict[str, str] = {}
        for row in actual:
            if not isinstance(row, Mapping) or set(row) != {"Key", "Value"} or type(row["Key"]) is not str or type(row["Value"]) is not str or row["Key"] in rows:
                return False
            rows[row["Key"]] = row["Value"]
        actual = rows
    if isinstance(expected, tuple):
        expected = list(expected)
    return _lambda_tags_equal(actual, expected, stack_arn=stack_arn, creation_tag_binding=creation_tag_binding)


def _alarm_config_matches(actual: Any, expected: Any) -> bool:
    """Compare only stable CloudWatch alarm configuration fields.

    ``DescribeAlarms`` adds state, history, timestamps, and ARN fields which
    are service-owned and change between reads.  The factory owns the fields
    below; dynamic response fields are deliberately not part of equality.
    """
    if not isinstance(actual, Mapping) or not isinstance(expected, Mapping):
        return False
    fields = (
        "AlarmName", "Namespace", "MetricName", "ActionsEnabled", "Period",
        "Statistic", "Threshold", "ComparisonOperator", "EvaluationPeriods",
        "DatapointsToAlarm", "TreatMissingData",
    )
    if any(actual.get(field) != expected.get(field) for field in fields):
        return False
    dimensions = actual.get("Dimensions")
    expected_dimensions = expected.get("Dimensions")
    if not isinstance(dimensions, list) or not isinstance(expected_dimensions, list):
        return False
    normalize = lambda rows: [(row.get("Name"), row.get("Value")) for row in rows] if all(isinstance(row, Mapping) and set(row) >= {"Name", "Value"} for row in rows) else None
    return normalize(dimensions) == normalize(expected_dimensions)


def _expected_cd_role_properties(binding: RetainedDevDeliveryBinding, api_id: str, shutdown_arn: str) -> dict[str, Mapping[str, Any]]:
    """Build the fixed CD role policies from validated resource bindings."""
    from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles

    subject = "repo:herrerogusano/honda-mapit-mcp:environment:dev"
    template = build_cd_retained_dev_roles(
        account_id=binding.account_id,
        provider_arn=f"arn:aws:iam::{binding.account_id}:oidc-provider/token.actions.githubusercontent.com",
        owner_id="1",
        repository_id="1",
        observed_dev_subject_format="legacy_environment",
        observed_dev_subject_sha256=hashlib.sha256(subject.encode("ascii")).hexdigest(),
        stack_arn=binding.app_stack_arn,
        artifact_stack_arn=binding.artifact_stack_arn,
        handler_arn=f"arn:aws:lambda:{REGION}:{binding.account_id}:function:honda-mapit-mcp-dev-retained-handler",
        api_arn=f"arn:aws:apigateway:{REGION}::/apis/{api_id}",
        shutdown_state_machine_arn=shutdown_arn,
        artifact_bucket_arn=f"arn:aws:s3:::{binding.artifact_bucket}",
        execution_role_arn=f"arn:aws:iam::{binding.account_id}:role/honda-mapit-mcp-dev-retained-handler-role",
    )
    return {
        "executor": template["Resources"]["RetainedDevCdExecutorRole"]["Properties"],
        "cloudformation": template["Resources"]["RetainedDevCdCloudFormationRole"]["Properties"],
        "executor_boundary": template["Resources"]["RetainedDevCdExecutorBoundary"]["Properties"],
        "cloudformation_boundary": template["Resources"]["RetainedDevCdCloudFormationBoundary"]["Properties"],
    }


def _normative_receipts(binding: RetainedDevDeliveryBinding) -> tuple[RetainedDevStackCreationTags, RetainedDevStackCreationTags, RetainedDevStackCreationTags]:
    """Reject self-consistent but non-factory inventory before AWS reads."""
    try:
        from scripts.build_aws_retained_dev_runtime import RUNTIME_HANDLER
        from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts, build_retained_dev_controls
        controls = _thaw(binding.controls_receipt)["resource"]
        artifact = _thaw(binding.artifact_receipt)["resource"]
        lambda_receipt = _thaw(binding.lambda_receipt)["resource"]
        prior_template_receipt = _thaw(binding.prior_template_receipt)["resource"]
        api = _thaw(binding.api_receipt)["resource"]
        iam = _thaw(binding.iam_receipt)["resource"]
        app_creation = RetainedDevStackCreationTags.from_receipt(
            stack_kind="app", stack_arn=binding.app_stack_arn, account_id=binding.account_id,
            tags=prior_template_receipt.get("stack_tags"),
        )
        artifact_creation = RetainedDevStackCreationTags.from_receipt(
            stack_kind="artifact", stack_arn=binding.artifact_stack_arn, account_id=binding.account_id,
            tags=artifact.get("stack_tags"),
        )
        controls_creation = RetainedDevStackCreationTags.from_receipt(
            stack_kind="controls", stack_arn=binding.controls_stack_arn, account_id=binding.account_id,
            tags=controls.get("stack_tags"),
        )
        expected_controls = build_retained_dev_controls(api["api_id"])
        expected_artifacts = build_retained_dev_artifacts()
        from scripts.build_aws_retained_dev import build_retained_dev_template
        expected_app = build_retained_dev_template()
        if not _same(controls.get("template"), expected_controls) or not _same(artifact.get("template"), expected_artifacts):
            raise DeliveryPreflightError("receipt_normative_mismatch")
        if not _same(prior_template_receipt.get("template"), expected_app):
            raise DeliveryPreflightError("prior_template_mismatch")
        if prior_template_receipt.get("role_arn") is not None:
            raise DeliveryPreflightError("app_stack_mismatch")
        control_types = {logical: item.get("Type") for logical, item in expected_controls.get("Resources", {}).items() if isinstance(item, Mapping)}
        artifact_types = {logical: item.get("Type") for logical, item in expected_artifacts.get("Resources", {}).items() if isinstance(item, Mapping)}
        app_types = {logical: item.get("Type") for logical, item in expected_app.get("Resources", {}).items() if isinstance(item, Mapping)}
        if not _resource_rows_match(controls.get("resources"), stack_arn=binding.controls_stack_arn, stack_name=controls_creation.stack_name, expected_types=control_types, physical_ids=_expected_physical(binding.account_id)):
            raise DeliveryPreflightError("controls_readback_mismatch")
        if not _resource_rows_match(artifact.get("resources"), stack_arn=binding.artifact_stack_arn, stack_name=artifact_creation.stack_name, expected_types=artifact_types, physical_ids={"RuntimeArtifactBucket": binding.artifact_bucket, "RuntimeArtifactBucketPolicy": binding.artifact_bucket}):
            raise DeliveryPreflightError("artifact_readback_mismatch")
        app_physical = {
            "McpApi": api["api_id"], "McpApiStage": "$default",
            "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
            "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler",
            "McpHandler": "honda-mapit-mcp-dev-retained-handler",
        }
        if not _resource_rows_match(prior_template_receipt.get("resources"), stack_arn=binding.app_stack_arn, stack_name=app_creation.stack_name, expected_types=app_types, physical_ids=app_physical):
            raise DeliveryPreflightError("app_resource_mismatch")
        expected_control_roles: dict[str, Mapping[str, Any]] = {}
        for resource in expected_controls.get("Resources", {}).values():
            if isinstance(resource, Mapping) and resource.get("Type") == "AWS::IAM::Role":
                props = resource.get("Properties")
                if not isinstance(props, Mapping) or type(props.get("RoleName")) is not str:
                    raise DeliveryPreflightError("controls_readback_mismatch")
                expected_control_roles[props["RoleName"]] = props
        supplied_control_roles = controls.get("control_roles")
        if not isinstance(supplied_control_roles, Mapping) or set(supplied_control_roles) != set(expected_control_roles):
            raise DeliveryPreflightError("controls_readback_mismatch")
        for role_name, expected_role in expected_control_roles.items():
            observed = supplied_control_roles[role_name]
            if not isinstance(observed, Mapping):
                raise DeliveryPreflightError("controls_readback_mismatch")
            actual_role = observed.get("role")
            resolved_role = _resolve_internal_template(expected_role, binding.account_id)
            expected_policies = resolved_role.get("Policies")
            if (
                not isinstance(actual_role, Mapping)
                or actual_role.get("RoleName") != role_name
                or actual_role.get("Path") not in {None, "/"}
                or not _same(_document(actual_role.get("AssumeRolePolicyDocument")), resolved_role.get("AssumeRolePolicyDocument"))
                or not _owned_resource_tags(observed.get("tags"), resolved_role.get("Tags"), stack=controls_creation, logical_id=role_name)
                or not isinstance(expected_policies, list)
                or observed.get("policy_names") != [item.get("PolicyName") for item in expected_policies]
                or observed.get("attached_policies") != []
            ):
                raise DeliveryPreflightError("controls_readback_mismatch")
            inline = observed.get("inline_policies")
            expected_inline = {item.get("PolicyName"): item.get("PolicyDocument") for item in expected_policies}
            if not isinstance(inline, Mapping) or set(inline) != set(expected_inline) or any(not _same(_document(inline.get(name)), document) for name, document in expected_inline.items()):
                raise DeliveryPreflightError("controls_readback_mismatch")
        service_arns = _expected_service_arns(binding.account_id)
        shutdown_props = _resolve_internal_template(expected_controls["Resources"]["ShutdownStateMachine"]["Properties"], binding.account_id)
        shutdown = controls.get("shutdown_state_machine")
        if not isinstance(shutdown, Mapping):
            raise DeliveryPreflightError("controls_readback_mismatch")
        expected_definition = _document(shutdown_props.get("DefinitionString"))
        actual_definition = _document(shutdown.get("definition"))
        logging = shutdown.get("loggingConfiguration")
        tracing = shutdown.get("tracingConfiguration")
        if (
            shutdown.get("stateMachineArn") != service_arns["ShutdownStateMachine"]
            or shutdown.get("name") != "honda-mapit-mcp-dev-retained-shutdown"
            or shutdown.get("type") != "STANDARD"
            or shutdown.get("roleArn") != service_arns["ShutdownWorkflowRole"]
            or expected_definition is None or actual_definition is None or not _same(actual_definition, expected_definition)
            or not isinstance(logging, Mapping) or logging.get("level", logging.get("Level")) != "OFF"
            or logging.get("includeExecutionData", False) is not False
            or logging.get("destinations", []) != []
            or not isinstance(tracing, Mapping) or tracing.get("enabled", tracing.get("Enabled")) is not False
        ):
            raise DeliveryPreflightError("controls_readback_mismatch")
        expected_rule = _resolve_internal_template(expected_controls["Resources"]["RequestTripwireAlarmRule"]["Properties"], binding.account_id)
        rule = controls.get("tripwire_rule")
        if not isinstance(rule, Mapping) or rule.get("Name") != "honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule" or rule.get("Arn") != service_arns["RequestTripwireAlarmRule"] or rule.get("State") != "DISABLED" or not _same(_document(rule.get("EventPattern")), expected_rule.get("EventPattern")):
            raise DeliveryPreflightError("controls_readback_mismatch")
        targets = controls.get("tripwire_targets")
        expected_targets = expected_rule.get("Targets")
        if type(targets) is not list or type(expected_targets) is not list or len(targets) != 1 or len(expected_targets) != 1:
            raise DeliveryPreflightError("controls_readback_mismatch")
        expected_target = expected_targets[0]
        target = targets[0]
        if not isinstance(target, Mapping) or target.get("Id") != expected_target.get("Id") or target.get("Arn") != service_arns["ShutdownStateMachine"] or target.get("RoleArn") != service_arns["RequestTripwireEventRole"] or target.get("Input") != "{}" or target.get("RetryPolicy") != expected_target.get("RetryPolicy"):
            raise DeliveryPreflightError("controls_readback_mismatch")
        expected_alarm = expected_controls["Resources"]["RequestTripwireAlarm"]["Properties"]
        alarm = controls.get("tripwire_alarm")
        if not isinstance(alarm, Mapping) or alarm.get("AlarmName") != "honda-mapit-mcp-dev-retained-request-tripwire" or alarm.get("AlarmArn") != service_arns["RequestTripwireAlarm"] or not _alarm_config_matches(alarm, expected_alarm):
            raise DeliveryPreflightError("controls_readback_mismatch")
        if not _owned_resource_tags(controls.get("shutdown_state_machine_tags"), shutdown_props.get("Tags"), stack=controls_creation, logical_id="ShutdownStateMachine") or not _owned_resource_tags(controls.get("tripwire_rule_tags"), expected_rule.get("Tags"), stack=controls_creation, logical_id="RequestTripwireAlarmRule") or not _owned_resource_tags(controls.get("tripwire_alarm_tags"), expected_alarm.get("Tags"), stack=controls_creation, logical_id="RequestTripwireAlarm"):
            raise DeliveryPreflightError("controls_readback_mismatch")
        bucket = expected_artifacts["Resources"]["RuntimeArtifactBucket"]["Properties"]
        bucket_name = binding.artifact_bucket
        expected_encryption = {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}
        expected_lifecycle = [{"ID": "DevTerminalJournalRetention", "Status": "Enabled", "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}}, "Expiration": {"Days": 30}}]
        expected_policy = {"Version": "2012-10-17", "Statement": [{"Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]}
        expected_tags = [
            {"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "retained-dev-artifacts"}, {"Key": "OperatorRunId", "Value": str(artifact_creation.operator_run_id)},
            {"Key": "aws:cloudformation:stack-id", "Value": binding.artifact_stack_arn},
            {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-runtime-artifacts"},
            {"Key": "aws:cloudformation:logical-id", "Value": "RuntimeArtifactBucket"},
        ]
        if (
            artifact.get("location") != REGION
            or not _same(artifact.get("public_access_block"), bucket.get("PublicAccessBlockConfiguration"))
            or not _same(artifact.get("encryption"), expected_encryption)
            or not _same(artifact.get("ownership"), bucket.get("OwnershipControls"))
            or not _same(artifact.get("lifecycle"), expected_lifecycle)
            or artifact.get("versioning") not in (None, "")
            or artifact.get("policy_status") != {"IsPublic": False}
            or not _tags_equal(artifact.get("tags"), expected_tags)
            or not _same(artifact.get("policy"), expected_policy)
        ):
            raise DeliveryPreflightError("artifact_readback_mismatch")
        expected_tags = [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
            {"Key": "Environment", "Value": "dev"},
            {"Key": "Purpose", "Value": "retained-dev"},
        ]
        prior_handler_props = prior_template_receipt.get("template", {}).get("Resources", {}).get("McpHandler", {}).get("Properties", {})
        prior_code = prior_handler_props.get("Code") if isinstance(prior_handler_props, Mapping) else None
        expected_handler = "index.handler" if isinstance(prior_code, Mapping) and set(prior_code) == {"ZipFile"} else RUNTIME_HANDLER
        expected_config = {
            "FunctionName": "honda-mapit-mcp-dev-retained-handler",
            "Role": f"arn:aws:iam::{binding.account_id}:role/honda-mapit-mcp-dev-retained-handler-role",
            "Runtime": "python3.13", "Handler": expected_handler,
            "Architectures": ["arm64"], "MemorySize": 256, "Timeout": 20,
        }
        if (
            lambda_receipt.get("function_name") != expected_config["FunctionName"]
            or lambda_receipt.get("reserved_concurrency") != 0
            or lambda_receipt.get("state") != "Active"
            or not _same(lambda_receipt.get("configuration"), expected_config)
            or not _lambda_tags_equal_for_stack(
                lambda_receipt.get("tags"), expected_tags,
                stack_arn=binding.app_stack_arn,
                creation_tag_binding=RetainedDevCreationTagBinding(stack_arn=binding.app_stack_arn, operator_run_id=app_creation.operator_run_id),
            )
        ):
            raise DeliveryPreflightError("lambda_not_closed")
        if (
            api.get("name") != "honda-mapit-mcp-dev-retained-api"
            or api.get("protocol") != "HTTP" or api.get("disabled") is not True
            or api.get("routes_empty") is not True
        ):
            raise DeliveryPreflightError("api_binding_mismatch")
        # The application CFN role is normative: Lambda trust/log policy and
        # the CD factory's exact CloudFormation trust/boundary/policy are not
        # caller-selected receipt assertions.
        from scripts.build_aws_retained_dev import build_retained_dev_template
        app = expected_app
        handler_role = app["Resources"]["McpHandlerRole"]["Properties"]
        controls_shutdown = controls.get("shutdown_state_machine")
        if not isinstance(controls_shutdown, Mapping):
            raise DeliveryPreflightError("controls_readback_mismatch")
        role_properties = _expected_cd_role_properties(binding, api["api_id"], controls_shutdown["stateMachineArn"])
        expected_role = role_properties["cloudformation"]
        expected_boundary = role_properties["cloudformation_boundary"]
        expected_policy = expected_role["Policies"][0]
        if (
            iam.get("role_name") != "honda-mapit-mcp-dev-retained-cfn-update"
            or iam.get("role_arn") != binding.cfn_role_arn or iam.get("path") != "/"
            or not _same(_document(iam.get("trust_policy")), _resolve_internal_template(expected_role["AssumeRolePolicyDocument"], binding.account_id))
            or not _tags_equal(iam.get("tags"), expected_role["Tags"])
            or iam.get("policy_name") != expected_policy["PolicyName"]
            or not _same(_document(iam.get("policy_document")), _resolve_internal_template(expected_policy["PolicyDocument"], binding.account_id))
            or iam.get("boundary_name") != expected_boundary["ManagedPolicyName"]
            or iam.get("boundary_path") != "/"
            or iam.get("boundary_arn") != f"arn:aws:iam::{binding.account_id}:policy/{expected_boundary['ManagedPolicyName']}"
            or not _same(_document(iam.get("boundary_document")), _resolve_internal_template(expected_boundary["PolicyDocument"], binding.account_id))
            or iam.get("boundary_version_id") != "v1"
            or iam.get("boundary_type") not in {"Policy", "PermissionsBoundaryPolicy"}
            or iam.get("attached_policy_names") != []
        ):
            raise DeliveryPreflightError("iam_binding_mismatch")
        return app_creation, artifact_creation, controls_creation
    except DeliveryPreflightError as exc:
        if exc.category == "creation_tags_invalid":
            raise DeliveryPreflightError("receipt_normative_mismatch") from None
        raise
    except Exception:
        raise DeliveryPreflightError("receipt_normative_mismatch") from None


class RetainedDevDeliveryPreflight:
    def __init__(self, clients: Mapping[str, Any], journal: Any, *, binding: RetainedDevDeliveryBinding, wall_clock: Callable[[], float] = time.time, monotonic: Callable[[], float] = time.monotonic):
        required = {"sts", "cloudformation", "lambda", "apigatewayv2", "iam", "s3", "sfn", "events", "cloudwatch"}
        if not isinstance(clients, Mapping) or set(clients) != required or any(clients.get(key) is None for key in required):
            raise DeliveryPreflightError("clients_invalid")
        if not all(callable(getattr(journal, key, None)) for key in ("load", "compare_and_set", "locked")):
            raise DeliveryPreflightError("journal_invalid")
        if not isinstance(binding, RetainedDevDeliveryBinding):
            raise DeliveryPreflightError("binding_invalid")
        self.clients, self.journal, self.binding = dict(clients), journal, binding
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self._started: float | None = None; self._last_mono = 0.0; self._last_wall = 0.0; self._last_epoch = 0; self._calls = 0

    def _now(self) -> None:
        value = self.wall_clock()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0 or value < self._last_wall:
            raise DeliveryPreflightError("window_invalid")
        self._last_wall = float(value)
        self._last_epoch = int(value)
        if self._last_epoch < self.binding.authorized_from_epoch or self._last_epoch >= self.binding.authorized_until_epoch:
            raise DeliveryPreflightError("window_expired")

    def _budget(self) -> None:
        value = self.monotonic()
        if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value < self._last_mono or self._started is None or value - self._started >= MAX_STEP_SECONDS:
            raise DeliveryPreflightError("window_expired")
        self._last_mono = float(value)
        if self._calls >= MAX_CALLS: raise DeliveryPreflightError("call_budget_exhausted")

    def _call(self, service: str, method: str, **kwargs: Any) -> Mapping[str, Any]:
        self._budget(); self._now(); self._calls += 1
        try: value = getattr(self.clients[service], method)(**kwargs)
        except Exception: self._now(); raise DeliveryPreflightError("aws_call_failed") from None
        if not _ok(value) or not isinstance(value, Mapping) or (service, method) in _PAGINATED_READS and (type(value.get("IsTruncated")) is not bool or value.get("IsTruncated") is not False) or ("IsTruncated" in value and type(value["IsTruncated"]) is not bool) or value.get("IsTruncated") is True or "NextToken" in value or "Marker" in value:
            raise DeliveryPreflightError("aws_response_invalid")
        self._now(); self._budget(); return value

    def _save(self, state: Mapping[str, Any]) -> None:
        self._budget(); self._now()
        candidate = dict(state)
        expected_version = candidate.pop("_expected_version", None)
        if type(expected_version) is not int and expected_version is not None:
            raise DeliveryPreflightError("journal_invalid")
        candidate.setdefault("version", (expected_version or 0) + 1)
        try:
            if self.journal.compare_and_set(expected_version, candidate) is not True:
                raise DeliveryPreflightError("journal_conflict")
        except DeliveryPreflightError: raise
        except Exception: raise DeliveryPreflightError("journal_failed") from None
        self._now(); self._budget()

    def _expected(self, name: str) -> Mapping[str, Any]:
        return getattr(self.binding, name)

    def _valid_saved_state(self, value: Any) -> bool:
        if value is None:
            return True
        if not isinstance(value, Mapping):
            return False
        fields = {"schema", "kind", "version", "binding_sha256", "account_id", "source_sha", "last_observed_epoch", "closed", "read_calls"}
        if set(value) != fields:
            return False
        binding = getattr(self, "binding", None)
        account_id = binding.account_id if binding is not None else getattr(self, "account_id", None)
        source_sha = binding.source_sha if binding is not None else getattr(self, "source_sha", None)
        return (
            value.get("schema") == 1
            and value.get("kind") == "retained-dev-delivery-preflight"
            and type(value.get("version")) is int and value["version"] > 0
            and type(value.get("binding_sha256")) is str and _SHA256.fullmatch(value["binding_sha256"]) is not None
            and value.get("account_id") == account_id
            and value.get("source_sha") == source_sha
            and type(value.get("last_observed_epoch")) is int and self.binding.authorized_from_epoch <= value["last_observed_epoch"] < self.binding.authorized_until_epoch
            and value.get("closed") is True
            and type(value.get("read_calls")) is int and 0 < value["read_calls"] <= MAX_CALLS
        )

    def run(self) -> dict[str, Any]:
        try:
            validate_botocore_models()
            with self.journal.locked():
                initial = self.monotonic()
                if type(initial) not in (int, float) or isinstance(initial, bool) or not math.isfinite(initial) or initial < 0: raise DeliveryPreflightError("window_invalid")
                self._started = self._last_mono = float(initial); self._last_wall = 0.0; self._calls = 0
                self._now()
                prior = self.journal.load()
                self._now(); self._budget()
                if not self._valid_saved_state(prior):
                    raise DeliveryPreflightError("journal_invalid")
                if isinstance(prior, Mapping) and self._last_epoch < prior["last_observed_epoch"]:
                    raise DeliveryPreflightError("window_invalid")
                if isinstance(prior, Mapping) and prior.get("binding_sha256") != self.binding.binding_sha256: raise DeliveryPreflightError("journal_binding_mismatch")
                _normative_receipts(self.binding)
                expected_version = prior.get("version") if isinstance(prior, Mapping) else None
                self._now()
                identity = self._call("sts", "get_caller_identity")
                if identity.get("Account") != self.binding.account_id or identity.get("Arn") != self.binding.expected_caller_arn: raise DeliveryPreflightError("caller_mismatch")
                stack = self._call("cloudformation", "describe_stacks", StackName=STACK_NAME).get("Stacks")
                if type(stack) is not list or len(stack) != 1 or not isinstance(stack[0], Mapping) or stack[0].get("StackId") != self.binding.app_stack_arn or stack[0].get("StackStatus") not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} or stack[0].get("EnableTerminationProtection") is not True: raise DeliveryPreflightError("app_stack_mismatch")
                resources = self._call("cloudformation", "describe_stack_resources", StackName=STACK_NAME).get("StackResources")
                prior_template_resource = self.binding.prior_template_receipt["resource"]
                if _resource_types(resources) != sorted(prior_template_resource["resource_types"]) or not _rows_equal(resources, prior_template_resource["resources"]): raise DeliveryPreflightError("app_resource_mismatch")
                if stack[0].get("Tags") is None or not _tags_equal(stack[0].get("Tags"), prior_template_resource["stack_tags"]): raise DeliveryPreflightError("app_tags_mismatch")
                try:
                    creation_tag_binding = RetainedDevCreationTagBinding.from_stack_tags(
                        stack_arn=self.binding.app_stack_arn,
                        stack_name=STACK_NAME,
                        tags=prior_template_resource["stack_tags"],
                    )
                except Exception:
                    raise DeliveryPreflightError("app_tags_mismatch") from None
                if stack[0].get("StackName") != STACK_NAME or prior_template_resource["stack_id"] != stack[0]["StackId"] or prior_template_resource["stack_status"] != stack[0]["StackStatus"] or prior_template_resource["termination_protection"] is not stack[0]["EnableTerminationProtection"] or stack[0].get("RoleARN") != prior_template_resource["role_arn"]: raise DeliveryPreflightError("app_stack_mismatch")
                template = self._call("cloudformation", "get_template", StackName=STACK_NAME, TemplateStage="Original").get("TemplateBody")
                prior_template = prior_template_resource.get("template_sha256")
                if type(prior_template) is not str or hashlib.sha256(_canonical(template)).hexdigest() != prior_template or not _same(template, prior_template_resource["template"]): raise DeliveryPreflightError("prior_template_mismatch")
                controls = self.binding.controls_receipt["resource"]
                control_stack = self._call("cloudformation", "describe_stacks", StackName=self.binding.controls_stack_arn).get("Stacks")
                if type(control_stack) is not list or len(control_stack) != 1 or not isinstance(control_stack[0], Mapping) or control_stack[0].get("StackName") != "honda-mapit-mcp-dev-retained-controls" or control_stack[0].get("StackId") != controls["stack_id"] or control_stack[0].get("StackStatus") != controls["stack_status"] or control_stack[0].get("EnableTerminationProtection") is not controls["termination_protection"] or control_stack[0].get("RoleARN") != controls["role_arn"] or not _tags_equal(control_stack[0].get("Tags"), controls["stack_tags"]): raise DeliveryPreflightError("controls_readback_mismatch")
                control_rows = self._call("cloudformation", "describe_stack_resources", StackName=self.binding.controls_stack_arn).get("StackResources")
                if _resource_types(control_rows) != sorted(controls["resource_types"]) or not _rows_equal(control_rows, controls["resources"]): raise DeliveryPreflightError("controls_readback_mismatch")
                control_template = self._call("cloudformation", "get_template", StackName=self.binding.controls_stack_arn, TemplateStage="Original").get("TemplateBody")
                try:
                    from scripts.build_aws_retained_dev_support import build_retained_dev_controls
                    expected_control_template = build_retained_dev_controls(self.binding.api_receipt["resource"]["api_id"])
                except Exception:
                    raise DeliveryPreflightError("controls_factory_invalid") from None
                if not _same(control_template, controls["template"]) or not _same(control_template, expected_control_template): raise DeliveryPreflightError("controls_readback_mismatch")
                expected_control_roles: dict[str, Mapping[str, Any]] = {}
                for resource in expected_control_template.get("Resources", {}).values():
                    if isinstance(resource, Mapping) and resource.get("Type") == "AWS::IAM::Role":
                        props = resource.get("Properties")
                        if not isinstance(props, Mapping) or type(props.get("RoleName")) is not str:
                            raise DeliveryPreflightError("controls_readback_mismatch")
                        expected_control_roles[props["RoleName"]] = _resolve_internal_template(props, self.binding.account_id)
                if set(controls["control_roles"]) != set(expected_control_roles):
                    raise DeliveryPreflightError("controls_readback_mismatch")
                control_events = self._call("cloudformation", "describe_stack_events", StackName=self.binding.controls_stack_arn).get("StackEvents")
                if not _stack_events_projection(control_events, stack_arn=self.binding.controls_stack_arn, stack_name="honda-mapit-mcp-dev-retained-controls"): raise DeliveryPreflightError("controls_readback_mismatch")
                artifact_stack = self._call("cloudformation", "describe_stacks", StackName=self.binding.artifact_stack_arn).get("Stacks")
                if type(artifact_stack) is not list or len(artifact_stack) != 1 or not isinstance(artifact_stack[0], Mapping): raise DeliveryPreflightError("artifact_readback_mismatch")
                artifact = self.binding.artifact_receipt["resource"]
                if artifact_stack[0].get("StackName") != "honda-mapit-mcp-dev-retained-runtime-artifacts" or artifact_stack[0].get("StackId") != artifact["stack_id"] or artifact_stack[0].get("StackStatus") != artifact["stack_status"] or artifact_stack[0].get("EnableTerminationProtection") is not artifact["termination_protection"] or artifact_stack[0].get("RoleARN") != artifact["role_arn"] or not _tags_equal(artifact_stack[0].get("Tags"), artifact["stack_tags"]): raise DeliveryPreflightError("artifact_readback_mismatch")
                artifact_rows = self._call("cloudformation", "describe_stack_resources", StackName=self.binding.artifact_stack_arn).get("StackResources")
                if _resource_types(artifact_rows) != sorted(artifact["resource_types"]) or not _rows_equal(artifact_rows, artifact["resources"]): raise DeliveryPreflightError("artifact_readback_mismatch")
                artifact_template = self._call("cloudformation", "get_template", StackName=self.binding.artifact_stack_arn, TemplateStage="Original").get("TemplateBody")
                try:
                    from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts
                    expected_artifact_template = build_retained_dev_artifacts()
                except Exception:
                    raise DeliveryPreflightError("artifact_factory_invalid") from None
                if not _same(artifact_template, artifact["template"]) or not _same(artifact_template, expected_artifact_template): raise DeliveryPreflightError("artifact_readback_mismatch")
                artifact_events = self._call("cloudformation", "describe_stack_events", StackName=self.binding.artifact_stack_arn).get("StackEvents")
                if not _stack_events_projection(artifact_events, stack_arn=self.binding.artifact_stack_arn, stack_name="honda-mapit-mcp-dev-retained-runtime-artifacts"): raise DeliveryPreflightError("artifact_readback_mismatch")
                artifact_bucket = self.binding.artifact_bucket
                for method in ("get_bucket_location", "get_public_access_block", "get_bucket_encryption", "get_bucket_ownership_controls", "get_bucket_versioning", "get_bucket_lifecycle_configuration", "get_bucket_policy_status", "get_bucket_tagging", "get_bucket_policy"):
                    response = self._call("s3", method, Bucket=artifact_bucket, ExpectedBucketOwner=self.binding.account_id)
                    key = {"get_bucket_location": "LocationConstraint", "get_public_access_block": "PublicAccessBlockConfiguration", "get_bucket_encryption": "ServerSideEncryptionConfiguration", "get_bucket_ownership_controls": "OwnershipControls", "get_bucket_versioning": "Status", "get_bucket_lifecycle_configuration": "Rules", "get_bucket_policy_status": "PolicyStatus", "get_bucket_tagging": "TagSet", "get_bucket_policy": "Policy"}[method]
                    expected = {"location": REGION, "public_access_block": artifact["public_access_block"], "encryption": artifact["encryption"], "ownership": artifact["ownership"], "versioning": artifact["versioning"], "lifecycle": artifact["lifecycle"], "policy_status": artifact["policy_status"], "tags": artifact["tags"], "policy": artifact["policy"]}[{"get_bucket_location": "location", "get_public_access_block": "public_access_block", "get_bucket_encryption": "encryption", "get_bucket_ownership_controls": "ownership", "get_bucket_versioning": "versioning", "get_bucket_lifecycle_configuration": "lifecycle", "get_bucket_policy_status": "policy_status", "get_bucket_tagging": "tags", "get_bucket_policy": "policy"}[method]]
                    actual_value = _document(response.get(key)) if method == "get_bucket_policy" else response.get(key)
                    if not _same(actual_value, expected): raise DeliveryPreflightError("artifact_readback_mismatch")
                shutdown = controls["shutdown_state_machine"]
                actual_shutdown = _without_metadata(self._call("sfn", "describe_state_machine", stateMachineArn=_expected_service_arns(self.binding.account_id)["ShutdownStateMachine"]))
                shutdown_props = _resolve_internal_template(expected_control_template["Resources"]["ShutdownStateMachine"]["Properties"], self.binding.account_id)
                if not _shutdown_matches(actual_shutdown, shutdown_props, account_id=self.binding.account_id): raise DeliveryPreflightError("controls_readback_mismatch")
                shutdown_tags = self._call("sfn", "list_tags_for_resource", resourceArn=shutdown["stateMachineArn"])
                if not _owned_resource_tags(shutdown_tags.get("tags"), shutdown_props.get("Tags"), stack=RetainedDevStackCreationTags.from_receipt(stack_kind="controls", stack_arn=self.binding.controls_stack_arn, account_id=self.binding.account_id, tags=controls["stack_tags"]), logical_id="ShutdownStateMachine"): raise DeliveryPreflightError("controls_readback_mismatch")
                rule = controls["tripwire_rule"]
                actual_rule = _without_metadata(self._call("events", "describe_rule", Name="honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule"))
                expected_rule = _resolve_internal_template(expected_control_template["Resources"]["RequestTripwireAlarmRule"]["Properties"], self.binding.account_id)
                if not _rule_matches(actual_rule, expected_rule, account_id=self.binding.account_id): raise DeliveryPreflightError("controls_readback_mismatch")
                rule_tags = self._call("events", "list_tags_for_resource", ResourceARN=rule["Arn"])
                control_creation = RetainedDevStackCreationTags.from_receipt(stack_kind="controls", stack_arn=self.binding.controls_stack_arn, account_id=self.binding.account_id, tags=controls["stack_tags"])
                if not _owned_resource_tags(rule_tags.get("Tags"), expected_rule.get("Tags"), stack=control_creation, logical_id="RequestTripwireAlarmRule"): raise DeliveryPreflightError("controls_readback_mismatch")
                targets = self._call("events", "list_targets_by_rule", Rule=rule["Name"])
                expected_targets = expected_rule.get("Targets")
                if type(targets.get("Targets")) is not list or type(expected_targets) is not list or len(targets["Targets"]) != 1 or len(expected_targets) != 1 or not _same(targets["Targets"][0], expected_targets[0]): raise DeliveryPreflightError("controls_readback_mismatch")
                alarm = controls["tripwire_alarm"]
                alarm_reply = self._call("cloudwatch", "describe_alarms", AlarmNames=[alarm["AlarmName"]])
                alarms = alarm_reply.get("MetricAlarms")
                expected_alarm = expected_control_template.get("Resources", {}).get("RequestTripwireAlarm", {}).get("Properties", {})
                if not isinstance(alarms, list) or len(alarms) != 1 or not isinstance(alarms[0], Mapping) or alarms[0].get("AlarmArn") != _expected_service_arns(self.binding.account_id)["RequestTripwireAlarm"] or not _alarm_config_matches(alarms[0], expected_alarm): raise DeliveryPreflightError("controls_readback_mismatch")
                alarm_tags = self._call("cloudwatch", "list_tags_for_resource", ResourceARN=alarm["AlarmArn"])
                expected_alarm_props = expected_control_template["Resources"]["RequestTripwireAlarm"]["Properties"]
                if not _owned_resource_tags(alarm_tags.get("Tags"), expected_alarm_props.get("Tags"), stack=control_creation, logical_id="RequestTripwireAlarm"): raise DeliveryPreflightError("controls_readback_mismatch")
                for role_name, expected_role in controls["control_roles"].items():
                    role_reply = _without_metadata(self._call("iam", "get_role", RoleName=role_name))
                    tags_reply = self._call("iam", "list_role_tags", RoleName=role_name)
                    policy_names_reply = self._call("iam", "list_role_policies", RoleName=role_name)
                    attached_reply = self._call("iam", "list_attached_role_policies", RoleName=role_name)
                    expected_props = expected_control_roles[role_name]
                    actual_role = role_reply.get("Role")
                    if (
                        not isinstance(actual_role, Mapping)
                        or actual_role.get("RoleName") != role_name
                        or actual_role.get("Path") not in {None, "/"}
                        or not _same(_document(actual_role.get("AssumeRolePolicyDocument")), expected_props.get("AssumeRolePolicyDocument"))
                        or not _owned_resource_tags(tags_reply.get("Tags"), expected_props.get("Tags"), stack=control_creation, logical_id=role_name)
                    ):
                        raise DeliveryPreflightError("controls_readback_mismatch")
                    expected_policies = expected_props.get("Policies")
                    if not isinstance(expected_policies, list) or sorted(policy_names_reply.get("PolicyNames", [])) != sorted(item.get("PolicyName") for item in expected_policies) or attached_reply.get("AttachedPolicies") != []:
                        raise DeliveryPreflightError("controls_readback_mismatch")
                    for policy in expected_policies:
                        policy_name, policy_document = policy.get("PolicyName"), policy.get("PolicyDocument")
                        inline_reply = self._call("iam", "get_role_policy", RoleName=role_name, PolicyName=policy_name)
                        inline_snapshot = {"RoleName": inline_reply.get("RoleName"), "PolicyName": inline_reply.get("PolicyName"), "PolicyDocument": _document(inline_reply.get("PolicyDocument"))}
                        if inline_snapshot.get("RoleName") != role_name or inline_snapshot.get("PolicyName") != policy_name or not _same(inline_snapshot.get("PolicyDocument"), policy_document): raise DeliveryPreflightError("controls_readback_mismatch")
                api_expected = self.binding.api_receipt["resource"]
                routes = self._call("apigatewayv2", "get_routes", ApiId=api_expected["api_id"])
                if routes.get("Items") != [] or api_expected["routes_empty"] is not True: raise DeliveryPreflightError("api_routes_not_closed")
                api = self._call("apigatewayv2", "get_api", ApiId=api_expected["api_id"])
                if api.get("DisableExecuteApiEndpoint") is not api_expected["disabled"] or api.get("ProtocolType") != api_expected["protocol"] or api.get("ApiId") != api_expected["api_id"] or api.get("Name") != api_expected["name"]: raise DeliveryPreflightError("api_binding_mismatch")
                config = self._call("lambda", "get_function_configuration", FunctionName=self.binding.lambda_receipt["resource"]["function_name"])
                lambda_expected = self.binding.lambda_receipt["resource"]
                concurrency = self._call("lambda", "get_function_concurrency", FunctionName=lambda_expected["function_name"])
                if concurrency.get("ReservedConcurrentExecutions") != lambda_expected["reserved_concurrency"] or config.get("State") != lambda_expected["state"] or not _same({key: config.get(key) for key in lambda_expected["configuration"]}, lambda_expected["configuration"]): raise DeliveryPreflightError("lambda_not_closed")
                function = self._call("lambda", "get_function", FunctionName=self.binding.lambda_receipt["resource"]["function_name"])
                code_sha = function.get("Configuration", {}).get("CodeSha256") if isinstance(function.get("Configuration"), Mapping) else None
                if code_sha != self.binding.prior_code_receipt["resource"].get("code_sha256") or code_sha != lambda_expected["code_sha256"]: raise DeliveryPreflightError("prior_code_mismatch")
                lambda_tags = self._call("lambda", "list_tags", Resource=lambda_expected["function_name"])
                if not _lambda_tags_equal_for_stack(
                    lambda_tags.get("Tags"), lambda_expected["tags"],
                    stack_arn=self.binding.app_stack_arn,
                    creation_tag_binding=creation_tag_binding,
                ):
                    raise DeliveryPreflightError("lambda_not_closed")
                iam_expected = self.binding.iam_receipt["resource"]
                cd_roles = _expected_cd_role_properties(self.binding, api_expected["api_id"], controls["shutdown_state_machine"]["stateMachineArn"])
                expected_cd_role = cd_roles["cloudformation"]
                expected_cd_boundary = cd_roles["cloudformation_boundary"]
                expected_cd_policy = expected_cd_role["Policies"][0]
                role = self._call("iam", "get_role", RoleName=iam_expected["role_name"])
                role_row = role.get("Role")
                if not isinstance(role_row, Mapping) or role_row.get("Arn") != iam_expected["role_arn"] or role_row.get("Arn") != self.binding.cfn_role_arn or role_row.get("RoleName") != iam_expected["role_name"] or role_row.get("Path") != iam_expected["path"] or not _same(_document(role_row.get("AssumeRolePolicyDocument")), _resolve_internal_template(expected_cd_role["AssumeRolePolicyDocument"], self.binding.account_id)): raise DeliveryPreflightError("iam_binding_mismatch")
                role_tags = self._call("iam", "list_role_tags", RoleName=iam_expected["role_name"]).get("Tags")
                if not _tags_equal(role_tags, expected_cd_role["Tags"]): raise DeliveryPreflightError("iam_binding_mismatch")
                boundary = role_row.get("PermissionsBoundary")
                expected_boundary_arn = f"arn:aws:iam::{self.binding.account_id}:policy/{expected_cd_boundary['ManagedPolicyName']}"
                if not isinstance(boundary, Mapping) or boundary.get("PermissionsBoundaryArn") != expected_boundary_arn or boundary.get("PermissionsBoundaryType") not in {"Policy", "PermissionsBoundaryPolicy"}: raise DeliveryPreflightError("iam_boundary_mismatch")
                role_name = iam_expected["role_name"]
                policies = self._call("iam", "list_role_policies", RoleName=role_name)
                if policies.get("PolicyNames") != [expected_cd_policy["PolicyName"]] or expected_cd_policy["PolicyName"] not in policies["PolicyNames"]: raise DeliveryPreflightError("iam_policy_mismatch")
                inline = self._call("iam", "get_role_policy", RoleName=role_name, PolicyName=expected_cd_policy["PolicyName"])
                if inline.get("RoleName") != role_name or inline.get("PolicyName") != expected_cd_policy["PolicyName"] or not _same(_document(inline.get("PolicyDocument")), _resolve_internal_template(expected_cd_policy["PolicyDocument"], self.binding.account_id)): raise DeliveryPreflightError("iam_policy_mismatch")
                attached = self._call("iam", "list_attached_role_policies", RoleName=role_name)
                if attached.get("AttachedPolicies") != [] or attached.get("IsTruncated") is not False: raise DeliveryPreflightError("iam_policy_mismatch")
                boundary_policy = self._call("iam", "get_policy", PolicyArn=expected_boundary_arn).get("Policy")
                if not isinstance(boundary_policy, Mapping) or boundary_policy.get("Arn") != expected_boundary_arn or boundary_policy.get("PolicyName") != expected_cd_boundary["ManagedPolicyName"] or boundary_policy.get("Path") != "/" or boundary_policy.get("DefaultVersionId") != iam_expected["boundary_version_id"]: raise DeliveryPreflightError("iam_boundary_mismatch")
                boundary_version = self._call("iam", "get_policy_version", PolicyArn=expected_boundary_arn, VersionId=iam_expected["boundary_version_id"])
                if not isinstance(boundary_version.get("PolicyVersion"), Mapping) or boundary_version["PolicyVersion"].get("VersionId") != iam_expected["boundary_version_id"] or boundary_version["PolicyVersion"].get("IsDefaultVersion") is not True or not _same(_document(boundary_version["PolicyVersion"].get("Document")), _resolve_internal_template(expected_cd_boundary["PolicyDocument"], self.binding.account_id)): raise DeliveryPreflightError("iam_boundary_mismatch")
                receipt = {"schema": 1, "kind": "retained-dev-delivery-preflight", "version": (prior.get("version", 0) + 1) if isinstance(prior, Mapping) else 1, "binding_sha256": self.binding.binding_sha256, "account_id": self.binding.account_id, "source_sha": self.binding.source_sha, "last_observed_epoch": self._last_epoch, "closed": True, "read_calls": self._calls, "_expected_version": expected_version}
                self._save(receipt)
                return {"ok": True, "category": "preflight_verified", "calls": self._calls}
        except DeliveryPreflightError as exc:
            return {"ok": False, "category": exc.category, "calls": self._calls}
        except Exception:
            return {"ok": False, "category": "preflight_failed", "calls": self._calls}


__all__ = ["RetainedDevDeliveryPreflight", "DeliveryPreflightError", "validate_botocore_models"]
