from __future__ import annotations

import copy
import json

from scripts.aws_dev_identity_binding_bootstrap import REGION, RUNTIME_POLICY_NAME
from scripts.build_aws_dev_identity_binding_bootstrap import (
    CONFIG_PARAMETER,
    OPERATOR_BOUNDARY_NAME,
    OPERATOR_ROLE_NAME,
    RUNTIME_ROLE_NAME,
    STACK_NAME,
)
from tests.test_aws_dev_identity_binding_bootstrap import (
    ACCOUNT,
    _AwsError,
    _bootstrap_fixture,
)


def _ok(**fields):
    return {**fields, "ResponseMetadata": {"HTTPStatusCode": 200}}


def test_factory_derived_bootstrap_readback_accepts_exact_created_stack_and_resources():
    coordinator, journal, evidence = _bootstrap_fixture()
    assert coordinator.run_step("preflight")["ok"] is True

    stack_id = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK_NAME}/12345678-1234-1234-1234-123456789abc"
    cf = coordinator.clients["cloudformation"]
    previous_cf = cf._dispatch

    def create_stack(method, kwargs):
        if method == "create_stack":
            assert journal.state["intent"]["token"] == kwargs["ClientRequestToken"]
            return _ok(StackId=stack_id)
        return previous_cf(method, kwargs)

    cf._dispatch = create_stack
    created = coordinator.run_step("create")
    assert created["ok"] is True and created["category"] == "create_acknowledged"

    template = copy.deepcopy(coordinator.template)
    boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/{OPERATOR_BOUNDARY_NAME}"
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{RUNTIME_ROLE_NAME}"
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "mapit-identity-bindings"},
        {"Key": "OperatorRunId", "Value": str(coordinator.run_id)},
    ]
    resource_types = {
        "MapitIdentityBindings": "AWS::DynamoDB::Table",
        "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
        "IdentityEnrollerRole": "AWS::IAM::Role",
        "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy",
    }
    physical = {
        "MapitIdentityBindings": "honda-mapit-mcp-dev-identity-bindings",
        "IdentityEnrollerBoundary": boundary_arn,
        "IdentityEnrollerRole": OPERATOR_ROLE_NAME,
        "RuntimeIdentityBindingPolicy": f"{RUNTIME_ROLE_NAME}:{RUNTIME_POLICY_NAME}",
    }
    resources = [
        {"LogicalResourceId": name, "ResourceType": kind, "ResourceStatus": "CREATE_COMPLETE",
         "StackId": stack_id, "StackName": STACK_NAME, "PhysicalResourceId": physical[name]}
        for name, kind in resource_types.items()
    ]
    table_arn = f"arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/honda-mapit-mcp-dev-identity-bindings"
    table = {
        "TableName": "honda-mapit-mcp-dev-identity-bindings",
        "TableArn": table_arn,
        "TableStatus": "ACTIVE",
        "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
        "OnDemandThroughput": {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100},
        "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}],
        "DeletionProtectionEnabled": True,
        "SSEDescription": {"Status": "ENABLED"},
        "GlobalSecondaryIndexes": [],
        "LocalSecondaryIndexes": [],
    }
    operator_role = template["Resources"]["IdentityEnrollerRole"]["Properties"]
    boundary_doc = template["Resources"]["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
    runtime_doc = template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]["PolicyDocument"]
    inline_name = operator_role["Policies"][0]["PolicyName"]
    inline_doc = operator_role["Policies"][0]["PolicyDocument"]
    key_arn = coordinator.binding["ssm_key_arn"]

    def dispatch(service, method, kwargs):
        if service == "cloudformation" and method == "describe_stacks":
            return _ok(Stacks=[{"StackId": stack_id, "StackName": STACK_NAME,
                                "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True,
                                "RoleARN": None, "Tags": tags}])
        if service == "cloudformation" and method == "get_template":
            assert kwargs == {"StackName": STACK_NAME, "TemplateStage": "Original"}
            return _ok(TemplateBody=json.dumps(template))
        if service == "cloudformation" and method == "describe_stack_events":
            token = journal.state["intent"]["token"]
            return _ok(StackEvents=[{"StackId": stack_id, "StackName": STACK_NAME,
                                    "ClientRequestToken": token}])
        if service == "cloudformation" and method == "describe_stack_resources":
            return _ok(StackResources=resources)
        if service == "dynamodb" and method == "describe_table":
            return _ok(Table=table)
        if service == "dynamodb" and method == "list_tags_of_resource":
            return _ok(Tags=[{"Key": "Project", "Value": "honda-mapit-mcp"},
                             {"Key": "Environment", "Value": "dev"},
                             {"Key": "Purpose", "Value": "mapit-identity-bindings"}])
        if service == "dynamodb" and method == "get_item":
            assert kwargs == {"TableName": table_arn,
                              "Key": {"key": {"S": "identity-bindings-v1"}},
                              "ConsistentRead": True, "ReturnConsumedCapacity": "NONE"}
            return _ok()
        if service == "iam" and method == "get_role" and kwargs["RoleName"] == OPERATOR_ROLE_NAME:
            return _ok(Role={"RoleName": OPERATOR_ROLE_NAME,
                             "Arn": f"arn:aws:iam::{ACCOUNT}:role/{OPERATOR_ROLE_NAME}",
                             "Path": "/", "MaxSessionDuration": 3600,
                             "PermissionsBoundary": {"PermissionsBoundaryArn": boundary_arn,
                                                     "PermissionsBoundaryType": "Policy"},
                             "AssumeRolePolicyDocument": operator_role["AssumeRolePolicyDocument"]})
        if service == "iam" and method == "get_role_policy" and kwargs["RoleName"] == OPERATOR_ROLE_NAME:
            assert kwargs["PolicyName"] == inline_name
            return _ok(PolicyDocument=inline_doc)
        if service == "iam" and method == "get_policy":
            assert kwargs == {"PolicyArn": boundary_arn}
            return _ok(Policy={"Arn": boundary_arn, "PolicyName": OPERATOR_BOUNDARY_NAME,
                               "Path": "/", "DefaultVersionId": "v1"})
        if service == "iam" and method == "get_policy_version":
            assert kwargs == {"PolicyArn": boundary_arn, "VersionId": "v1"}
            return _ok(PolicyVersion={"Document": boundary_doc})
        if service == "iam" and method == "get_role_policy" and kwargs["RoleName"] == RUNTIME_ROLE_NAME:
            assert kwargs["PolicyName"] == RUNTIME_POLICY_NAME
            return _ok(PolicyDocument=runtime_doc)
        if service == "iam" and method == "list_role_policies":
            assert kwargs == {"RoleName": RUNTIME_ROLE_NAME}
            return _ok(PolicyNames=sorted({
                "honda-mapit-mcp-dev-retained-owned-log-writes",
                "honda-mapit-mcp-dev-retained-tenant-read",
                RUNTIME_POLICY_NAME,
            }), IsTruncated=False)
        if service == "kms" and method == "describe_key":
            assert kwargs == {"KeyId": "alias/aws/ssm"}
            return _ok(KeyMetadata={"Arn": key_arn, "AWSAccountId": ACCOUNT,
                                    "KeyManager": "AWS", "Enabled": True,
                                    "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT"})
        if service == "ssm" and method == "get_parameter":
            assert kwargs["WithDecryption"] is False
            raise _AwsError("ParameterNotFound", 400)
        if service == "sts" and method == "get_caller_identity":
            return _ok(Account=ACCOUNT, Arn=coordinator.caller, UserId="AIDEXAMPLE")
        raise AssertionError((service, method, kwargs))

    for service, client in coordinator.clients.items():
        client._dispatch = lambda method, kwargs, service=service: dispatch(service, method, kwargs)

    result = coordinator.run_step("readback")
    assert result == {"step": "readback", "ok": True, "category": "readback_verified", "calls": 19}
    assert journal.state["acknowledged"] is True
    assert journal.state["readback"] is True
    assert journal.state["readback_receipt"] == {
        "stack_id": stack_id,
        "template_sha256": coordinator.template_sha256,
    }


def test_readback_pending_stops_after_identity_and_stack_status_without_mutation():
    coordinator, journal, _ = _bootstrap_fixture()
    assert coordinator.run_step("preflight")["ok"] is True
    stack_id = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK_NAME}/12345678-1234-1234-1234-123456789abc"
    cf = coordinator.clients["cloudformation"]
    old_dispatch = cf._dispatch

    def create_stack(method, kwargs):
        if method == "create_stack":
            return _ok(StackId=stack_id)
        return old_dispatch(method, kwargs)

    cf._dispatch = create_stack
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    before = copy.deepcopy(journal.state)
    calls = []

    def dispatch(service, method, kwargs):
        calls.append((service, method, kwargs))
        if service == "sts" and method == "get_caller_identity":
            return _ok(Account=ACCOUNT, Arn=coordinator.caller, UserId="AIDEXAMPLE")
        if service == "cloudformation" and method == "describe_stacks":
            return _ok(Stacks=[{"StackId": stack_id, "StackName": STACK_NAME,
                                "StackStatus": "CREATE_IN_PROGRESS"}])
        raise AssertionError("pending stack must not trigger deeper readback")

    for service, client in coordinator.clients.items():
        client._dispatch = lambda method, kwargs, service=service: dispatch(service, method, kwargs)

    result = coordinator.run_step("readback")
    assert result == {"step": "readback", "ok": False, "category": "stack_in_progress", "calls": 2}
    assert [(service, method) for service, method, _ in calls] == [
        ("sts", "get_caller_identity"),
        ("cloudformation", "describe_stacks"),
    ]
    assert journal.state == before
