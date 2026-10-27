from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json

import pytest

from scripts.aws_retained_dev_bootstrap import (
    API_NAME,
    FUNCTION_NAME,
    LOG_GROUP_NAME,
    POLICY_NAME,
    REGION,
    ROLE_NAME,
    STACK_NAME,
    RetainedDevBootstrapCoordinator,
    RetainedDevBootstrapError,
)

ACCOUNT = "123456789012"
SOURCE_SHA = "a" * 40
RUN_ID = 2026100601
CALLER_ARN = f"arn:aws:sts::{ACCOUNT}:assumed-role/operator/session"
STACK_ID = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK_NAME}/123e4567-e89b-42d3-a456-426614174000"


class Journal:
    def __init__(self):
        self.state = None
        self.saves = 0

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return deepcopy(self.state)

    def save(self, value):
        self.state = deepcopy(value)
        self.saves += 1


class AwsError(Exception):
    def __init__(self, code, message="synthetic"):
        self.response = {"Error": {"Code": code, "Message": message}}
        super().__init__(message)


class Client:
    def __init__(self, methods):
        self.methods = methods
        self.calls = []

    def __getattr__(self, name):
        if name in {"meta", "region_name"}:
            return None
        if name not in self.methods:
            raise AssertionError(f"unexpected method: {name}")

        def call(**kwargs):
            self.calls.append((name, kwargs))
            result = self.methods[name]
            if isinstance(result, list):
                if not result:
                    raise AssertionError(f"no scripted result: {name}")
                result = result.pop(0)
            if isinstance(result, BaseException):
                raise result
            return deepcopy(result)

        return call


def response(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _preflight_clients():
    return {
        "sts": Client({"get_caller_identity": response(Account=ACCOUNT, Arn=CALLER_ARN)}),
        "cloudformation": Client({"describe_stacks": AwsError("ValidationError", f"Stack with id {STACK_NAME} does not exist")}),
        "lambda": Client({"get_function": AwsError("ResourceNotFoundException")}),
        "logs": Client({"describe_log_groups": response(logGroups=[])}),
        "iam": Client({"get_role": AwsError("NoSuchEntity")}),
        "apigatewayv2": Client({"get_apis": response(Items=[]) }),
    }


def _coordinator(clients=None, journal=None, *, wall=lambda: 1000.0):
    return RetainedDevBootstrapCoordinator(
        clients or _preflight_clients(), journal or Journal(), account_id=ACCOUNT,
        source_sha=SOURCE_SHA, run_id=RUN_ID, expected_caller_arn=CALLER_ARN, authorized_from_epoch=900,
        authorized_until_epoch=1800, wall_clock=wall,
    )


def test_preflight_is_closed_fixed_and_persists_no_private_response_in_safe_result():
    clients = _preflight_clients()
    journal = Journal()
    coordinator = _coordinator(clients, journal)
    result = coordinator.run_step("preflight")
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 6}
    assert journal.state["stack_name"] == STACK_NAME
    assert journal.state["source_sha"] == SOURCE_SHA
    assert journal.state["run_id"] == RUN_ID
    assert "123456789012" not in json.dumps(result)
    template = coordinator.template
    assert set(template["Resources"]) == {"McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler"}
    assert template["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert type(template["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"]) is int
    assert template["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0


def test_create_intent_is_saved_before_one_named_iam_create_and_never_replayed():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    cfn = Client({"create_stack": response(StackId=STACK_ID)})
    coordinator.clients["cloudformation"] = cfn
    result = coordinator.run_step("create")
    assert result == {"step": "create", "ok": True, "category": "create_acknowledged", "calls": 2}
    method, kwargs = cfn.calls[0]
    assert method == "create_stack"
    assert kwargs["StackName"] == STACK_NAME
    assert kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert kwargs["TemplateBody"]
    assert kwargs["ClientRequestToken"] == str(RUN_ID)
    assert {row["Key"]: row["Value"] for row in kwargs["Tags"]} == {
        "Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": str(RUN_ID)
    }
    assert journal.state["phase"] == "create_acknowledged"
    assert coordinator.run_step("create")["category"] == "create_intent_conflict"
    assert len(cfn.calls) == 1


def _readback_clients(coordinator, *, status="CREATE_COMPLETE", mutate=None):
    template = deepcopy(coordinator.template)
    if mutate == "template":
        template["Metadata"]["tampered"] = True
    resources = [
        {"LogicalResourceId": "McpApi", "ResourceType": "AWS::ApiGatewayV2::Api", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": "api123"},
        {"LogicalResourceId": "McpApiStage", "ResourceType": "AWS::ApiGatewayV2::Stage", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": "$default"},
        {"LogicalResourceId": "McpHandlerRole", "ResourceType": "AWS::IAM::Role", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": ROLE_NAME},
        {"LogicalResourceId": "McpHandlerLogGroup", "ResourceType": "AWS::Logs::LogGroup", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": LOG_GROUP_NAME},
        {"LogicalResourceId": "McpHandler", "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": FUNCTION_NAME},
    ]
    stack = {"StackId": STACK_ID, "StackName": STACK_NAME, "StackStatus": status, "EnableTerminationProtection": True, "Tags": [
        {"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev"}, {"Key": "OperatorRunId", "Value": str(RUN_ID)},
    ]}
    cfn = Client({
        "describe_stacks": response(Stacks=[stack]),
        "get_template": response(TemplateBody=template),
        "describe_stack_resources": response(StackResources=resources),
    })
    role_props = coordinator.template["Resources"]["McpHandlerRole"]["Properties"]
    policy_doc = deepcopy(role_props["Policies"][0]["PolicyDocument"])
    policy_doc["Statement"][0]["Resource"] = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{LOG_GROUP_NAME}:*"
    function = {"FunctionName": FUNCTION_NAME, "FunctionArn": f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION_NAME}",
                "Runtime": "python3.13", "Handler": "index.handler", "MemorySize": 256,
                "Timeout": 20, "State": "Active", "LastUpdateStatus": "Successful", "Architectures": ["arm64"],
                "Role": f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}"}
    logs = {"logGroups": [{"logGroupName": LOG_GROUP_NAME, "retentionInDays": 7}]}
    iam_role = {"Role": {"RoleName": ROLE_NAME, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}",
                          "AssumeRolePolicyDocument": deepcopy(role_props["AssumeRolePolicyDocument"])} }
    return {
        "sts": Client({"get_caller_identity": response(Account=ACCOUNT, Arn=CALLER_ARN)}),
        "cloudformation": cfn,
        "apigatewayv2": Client({"get_api": response(ApiId="api123", Name=API_NAME, ProtocolType="HTTP", DisableExecuteApiEndpoint=True), "get_routes": response(Items=[]),
                                 "get_stage": response(StageName="$default", AutoDeploy=True, DefaultRouteSettings={"DetailedMetricsEnabled": False, "ThrottlingBurstLimit": 1, "ThrottlingRateLimit": 1})}),
        "lambda": Client({"get_function_configuration": [response(**function), response(**function)], "get_function_concurrency": response(ReservedConcurrentExecutions=0)}),
        "logs": Client({"describe_log_groups": response(**logs)}),
        "iam": Client({"get_role": response(**iam_role), "list_attached_role_policies": response(AttachedPolicies=[], IsTruncated=False), "list_role_policies": response(PolicyNames=[POLICY_NAME], IsTruncated=False), "get_role_policy": response(RoleName=ROLE_NAME, PolicyName=POLICY_NAME, PolicyDocument=policy_doc)}),
    }


def test_readback_pending_is_safe_and_complete_validates_every_resource_and_runtime_boundary():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    clients["cloudformation"] = Client({"create_stack": response(StackId=STACK_ID)})
    coordinator.clients = clients
    assert coordinator.run_step("create")["ok"]
    coordinator.clients = _readback_clients(coordinator, status="CREATE_IN_PROGRESS")
    pending = coordinator.run_step("readback")
    assert pending["category"] == "create_in_progress" and pending["ok"] is False
    coordinator.clients = _readback_clients(coordinator)
    result = coordinator.run_step("readback")
    assert result == {"step": "readback", "ok": True, "category": "readback_verified", "calls": 15}
    assert journal.state["readback_verified"] is True


def _created_coordinator_for_readback():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    coordinator.clients["cloudformation"] = Client({"create_stack": response(StackId=STACK_ID)})
    assert coordinator.run_step("create")["ok"]
    return coordinator, journal


def test_readback_ignores_volatile_request_metadata_but_rejects_malformed_runtime_shapes():
    coordinator, _journal = _created_coordinator_for_readback()
    clients = _readback_clients(coordinator)
    configs = clients["lambda"].methods["get_function_configuration"]
    configs[0]["ResponseMetadata"]["RequestId"] = "first"
    configs[1]["ResponseMetadata"]["RequestId"] = "second"
    coordinator.clients = clients
    assert coordinator.run_step("readback")["ok"]

    coordinator, _journal = _created_coordinator_for_readback()
    clients = _readback_clients(coordinator)
    clients["lambda"].methods["get_function_configuration"][0]["Environment"] = "malformed"
    coordinator.clients = clients
    assert coordinator.run_step("readback")["category"] == "stack_readback_mismatch"


@pytest.mark.parametrize("source_sha", ["A" * 40, "a" * 39, "g" * 40, True])
def test_binding_and_authority_are_fail_closed(source_sha):
    with pytest.raises(RetainedDevBootstrapError) as exc:
        RetainedDevBootstrapCoordinator(_preflight_clients(), Journal(), account_id=ACCOUNT, source_sha=source_sha,
                                        run_id=RUN_ID, expected_caller_arn=CALLER_ARN, authorized_from_epoch=900, authorized_until_epoch=1800)
    assert exc.value.category == "binding_invalid"


def test_authority_window_is_bounded_to_one_hour():
    with pytest.raises(RetainedDevBootstrapError) as exc:
        RetainedDevBootstrapCoordinator(_preflight_clients(), Journal(), account_id=ACCOUNT, source_sha=SOURCE_SHA,
                                        run_id=RUN_ID, expected_caller_arn=CALLER_ARN, authorized_from_epoch=900, authorized_until_epoch=4501)
    assert exc.value.category == "window_invalid"


def test_unrelated_validation_error_does_not_prove_stack_absent():
    clients = _preflight_clients()
    clients["cloudformation"] = Client({"describe_stacks": AwsError("ValidationError", "malformed request")})
    result = _coordinator(clients, Journal()).run_step("preflight")
    assert result["category"] == "stack_absence_unverified"


def test_ambiguous_create_is_not_replayed_and_safe_error_does_not_echo_secret():
    journal = Journal()
    clients = _preflight_clients()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    clients["cloudformation"] = Client({"create_stack": AwsError("InternalFailure", "canary-secret")})
    coordinator.clients = clients
    result = coordinator.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert journal.state["phase"] == "create_outcome_unknown"
    assert coordinator.run_step("create")["category"] == "create_intent_conflict"
    assert len(clients["cloudformation"].calls) == 1
    assert "canary-secret" not in json.dumps(result)


def test_no_cloud_write_when_authority_expired():
    clients = _preflight_clients()
    result = _coordinator(clients, Journal(), wall=lambda: 1800.0).run_step("preflight")
    assert result["category"] == "window_expired"
    assert sum(len(client.calls) for client in clients.values()) == 0


def test_missing_optional_preflight_clients_are_allowed_but_readback_requires_runtime_clients():
    clients = {name: _preflight_clients()[name] for name in ("sts", "cloudformation", "lambda", "logs", "iam", "apigatewayv2")}
    journal = Journal()
    coordinator = _coordinator(clients, journal)
    assert coordinator.run_step("preflight")["ok"]
    clients["cloudformation"] = Client({"create_stack": response(StackId=STACK_ID)})
    coordinator.clients = clients
    assert coordinator.run_step("create")["ok"]
    coordinator.clients = _readback_clients(coordinator)
    for name in ("lambda", "logs", "iam", "apigatewayv2"):
        coordinator.clients.pop(name)
    assert coordinator.run_step("readback")["category"] == "readback_clients_missing"
