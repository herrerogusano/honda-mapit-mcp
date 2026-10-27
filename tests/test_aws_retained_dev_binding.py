from copy import deepcopy
from types import SimpleNamespace

import pytest

from scripts.aws_retained_dev_binding import RetainedDevBindingError, read_bootstrap_resource_binding
from scripts.aws_retained_dev_bootstrap import FUNCTION_NAME, LOG_GROUP_NAME, ROLE_NAME, STACK_NAME
from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.aws_retained_dev_delivery_update import RetainedDevCreationTagBinding, RetainedDevUpdateError

ACCOUNT = "123456789012"
CALLER = f"arn:aws:sts::{ACCOUNT}:assumed-role/operator/session"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/123e4567-e89b-42d3-a456-426614174000"


def fixture():
    kinds = {
        "McpApi": ("AWS::ApiGatewayV2::Api", "abcdefghij"),
        "McpApiStage": ("AWS::ApiGatewayV2::Stage", "$default"),
        "McpHandlerRole": ("AWS::IAM::Role", ROLE_NAME),
        "McpHandlerLogGroup": ("AWS::Logs::LogGroup", LOG_GROUP_NAME),
        "McpHandler": ("AWS::Lambda::Function", FUNCTION_NAME),
    }
    bodies = {
        "get_caller_identity": {"Account": ACCOUNT, "Arn": CALLER},
        "describe_stacks": {"Stacks": [{
            "StackId": STACK, "StackName": STACK_NAME, "StackStatus": "CREATE_COMPLETE",
            "EnableTerminationProtection": True,
            "Tags": [{"Key": k, "Value": v} for k, v in {
                "Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": "7",
            }.items()],
        }]},
        "get_template": {"TemplateBody": build_retained_dev_template()},
        "describe_stack_resources": {"StackResources": [{
            "LogicalResourceId": k, "ResourceType": kind, "PhysicalResourceId": name,
            "ResourceStatus": "CREATE_COMPLETE", "StackId": STACK, "StackName": STACK_NAME,
        } for k, (kind, name) in kinds.items()]},
    }
    replies = {k: {**v, "ResponseMetadata": {"HTTPStatusCode": 200}} for k, v in bodies.items()}
    calls = []

    def method(name):
        def invoke(**kwargs):
            calls.append((name, kwargs))
            return deepcopy(replies[name])
        return invoke

    clients = {
        "sts": SimpleNamespace(get_caller_identity=method("get_caller_identity")),
        "cloudformation": SimpleNamespace(**{k: method(k) for k in bodies if k != "get_caller_identity"}),
    }
    return clients, replies, calls


def run(clients, **kwargs):
    args = dict(account=ACCOUNT, caller_arn=CALLER, stack_id=STACK, creation_run_id=7, monotonic=lambda: 100.0)
    args.update(kwargs)
    return read_bootstrap_resource_binding(clients, **args)


def test_exact_private_binding_four_reads_no_write():
    clients, _, calls = fixture()
    binding = run(clients)
    assert binding.api_id == "abcdefghij"
    assert binding.execution_role_arn == f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}"
    assert repr(binding) == "RetainedDevBinding(private=True)"
    assert len(calls) == 4
    assert all(name.startswith(("get_", "describe_")) for name, _ in calls)
    with pytest.raises(AttributeError):
        binding.api_id = "other"


def test_creation_tag_binding_comes_from_verified_receipt_not_a_later_uuid():
    clients, _, _ = fixture()
    verified = run(clients)
    tag_binding = RetainedDevCreationTagBinding.from_verified_bootstrap_binding(verified)
    assert tag_binding.stack_arn == STACK
    assert tag_binding.operator_run_id == 7
    assert tag_binding.extra_tags() == {"OperatorRunId": "7"}
    with pytest.raises(RetainedDevUpdateError, match="creation_tag_binding_invalid"):
        RetainedDevCreationTagBinding.from_verified_bootstrap_binding(object())


@pytest.mark.parametrize("field,value", [
    ("account", "000"), ("caller_arn", f"arn:aws:iam::{ACCOUNT}:root"),
    ("stack_id", STACK.replace("dev-retained", "prod")), ("creation_run_id", True),
    ("creation_run_id", 0), ("monotonic", lambda: float("nan")),
])
def test_input_rejected_before_read(field, value):
    clients, _, calls = fixture()
    with pytest.raises(RetainedDevBindingError, match="^retained_dev_binding_unverified$"):
        run(clients, **{field: value})
    assert not calls


@pytest.mark.parametrize("operation", ["get_caller_identity", "describe_stacks", "get_template", "describe_stack_resources"])
@pytest.mark.parametrize("bad", ["metadata", "pagination"])
def test_transport_evidence_required(operation, bad):
    clients, replies, _ = fixture()
    if bad == "metadata":
        replies[operation].pop("ResponseMetadata")
    else:
        replies[operation]["NextToken"] = "private"
    with pytest.raises(RetainedDevBindingError):
        run(clients)


@pytest.mark.parametrize("field,value", [
    ("StackName", "other"), ("StackStatus", "UPDATE_COMPLETE"),
    ("EnableTerminationProtection", False), ("RoleARN", "other"),
])
def test_stack_drift_rejected(field, value):
    clients, replies, _ = fixture()
    replies["describe_stacks"]["Stacks"][0][field] = value
    with pytest.raises(RetainedDevBindingError):
        run(clients)


def test_template_drift_rejected():
    clients, replies, calls = fixture()
    replies["get_template"]["TemplateBody"]["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] = 1
    with pytest.raises(RetainedDevBindingError):
        run(clients)
    assert len(calls) == 3


@pytest.mark.parametrize("field,value", [
    ("StackId", "other"), ("StackName", "prod"), ("ResourceStatus", "UPDATE_COMPLETE"),
    ("PhysicalResourceId", "bad"), ("LogicalResourceId", "McpHandler"),
])
def test_resource_drift_rejected(field, value):
    clients, replies, _ = fixture()
    replies["describe_stack_resources"]["StackResources"][0][field] = value
    with pytest.raises(RetainedDevBindingError):
        run(clients)


def test_late_read_rejected_and_not_retried():
    clients, _, calls = fixture()
    times = iter([100.0, 100.0, 130.0])
    with pytest.raises(RetainedDevBindingError):
        run(clients, monotonic=lambda: next(times))
    assert len(calls) == 1


def test_provider_text_not_exposed():
    clients, _, _ = fixture()
    clients["sts"].get_caller_identity = lambda: (_ for _ in ()).throw(RuntimeError("private-credential"))
    with pytest.raises(RetainedDevBindingError) as exc:
        run(clients)
    assert str(exc.value) == "retained_dev_binding_unverified"
