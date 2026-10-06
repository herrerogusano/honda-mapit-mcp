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
CALLER_ARN = f"arn:aws:iam::{ACCOUNT}:role/retained-dev-bootstrap"
SOURCE = "b" * 40
RUN_ID = 2026100607
STACK_ID = f"arn:aws:cloudformation:{REGION}:{ACCOUNT}:stack/{STACK_NAME}/123e4567-e89b-42d3-a456-426614174000"


class Journal:
    def __init__(self, state=None):
        self.state = deepcopy(state)

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return deepcopy(self.state)

    def save(self, value):
        self.state = deepcopy(value)


class AwsError(Exception):
    def __init__(self, code, message):
        self.response = {"Error": {"Code": code, "Message": message}}
        super().__init__(message)


class Client:
    def __init__(self, **methods):
        self.methods = {name: list(values) if isinstance(values, list) else [values] for name, values in methods.items()}
        self.calls = []
        self.meta = type("Meta", (), {"region_name": REGION})()

    def __getattr__(self, name):
        if name not in self.methods:
            raise AssertionError(f"unexpected operation {name}")

        def call(**kwargs):
            self.calls.append((name, kwargs))
            result = self.methods[name].pop(0)
            if isinstance(result, BaseException):
                raise result
            return deepcopy(result)

        return call


def ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def ok_request(request_id, **body):
    result = ok(**body)
    result["ResponseMetadata"]["RequestId"] = request_id
    return result


def preflight_clients():
    clients = {
        "sts": Client(get_caller_identity=[ok(Account=ACCOUNT, Arn=CALLER_ARN) for _ in range(20)]),
        "cloudformation": Client(describe_stacks=AwsError("ValidationError", f"Stack with id {STACK_NAME} does not exist")),
        "lambda": Client(get_function=AwsError("ResourceNotFoundException", "not found")),
        "logs": Client(describe_log_groups=ok(logGroups=[])),
        "iam": Client(get_role=AwsError("NoSuchEntity", "not found")),
        "apigatewayv2": Client(get_apis=ok(Items=[])),
    }
    clients["iam"].meta.region_name = "us-east-1"
    clients["iam"].meta.endpoint_url = "https://iam.amazonaws.com"
    return clients


def make_coordinator(clients=None, journal=None, *, now=1000.0):
    return RetainedDevBootstrapCoordinator(
        clients or preflight_clients(), journal or Journal(), account_id=ACCOUNT,
        source_sha=SOURCE, run_id=RUN_ID, expected_caller_arn=CALLER_ARN, authorized_from_epoch=900,
        authorized_until_epoch=1800, wall_clock=lambda: now,
    )


def test_bootstrap_binding_and_template_are_fixed_without_cloud_construction():
    coordinator = make_coordinator()
    assert set(coordinator.template["Resources"]) == {
        "McpApi", "McpApiStage", "McpHandlerRole", "McpHandlerLogGroup", "McpHandler",
    }
    assert coordinator.template["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert coordinator.template["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert coordinator.template["Metadata"]["NotDeployReady"] is True
    assert "boto3" not in open("scripts/aws_retained_dev_bootstrap.py", encoding="utf-8").read()
    with pytest.raises(RetainedDevBootstrapError) as exc:
        RetainedDevBootstrapCoordinator(
            preflight_clients(), Journal(), account_id=ACCOUNT, source_sha="A" * 40,
            run_id=RUN_ID, expected_caller_arn=CALLER_ARN,
            authorized_from_epoch=900, authorized_until_epoch=1800,
        )
    assert exc.value.category == "binding_invalid"


def test_clients_bind_iam_to_its_global_endpoint_and_other_clients_to_eu_west_1():
    clients = preflight_clients()
    clients["iam"].meta.region_name = "us-east-1"
    clients["iam"].meta.endpoint_url = "https://iam.amazonaws.com"
    assert make_coordinator(clients, Journal()) is not None

    clients = preflight_clients()
    clients["iam"].meta.region_name = "us-east-1"
    clients["iam"].meta.endpoint_url = "https://iam.example.invalid"
    with pytest.raises(RetainedDevBootstrapError) as exc:
        make_coordinator(clients, Journal())
    assert exc.value.category == "binding_invalid"

    clients = preflight_clients()
    clients["iam"].meta.region_name = REGION
    clients["iam"].meta.endpoint_url = None
    with pytest.raises(RetainedDevBootstrapError) as exc:
        make_coordinator(clients, Journal())
    assert exc.value.category == "binding_invalid"

    clients = preflight_clients()
    clients["cloudformation"].meta.region_name = "us-east-1"
    with pytest.raises(RetainedDevBootstrapError) as exc:
        make_coordinator(clients, Journal())
    assert exc.value.category == "binding_invalid"


def test_preflight_create_has_exact_targets_and_uncertain_create_is_never_replayed():
    clients = preflight_clients()
    journal = Journal()
    coordinator = make_coordinator(clients, journal)
    result = coordinator.run_step("preflight")
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 6}
    assert clients["cloudformation"].calls[0] == ("describe_stacks", {"StackName": STACK_NAME})
    assert journal.state["source_sha"] == SOURCE

    create = Client(create_stack=ok(StackId=STACK_ID))
    coordinator.clients["cloudformation"] = create
    result = coordinator.run_step("create")
    assert result == {"step": "create", "ok": True, "category": "create_acknowledged", "calls": 2}
    method, kwargs = create.calls[0]
    assert method == "create_stack"
    assert kwargs["StackName"] == STACK_NAME
    assert kwargs["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert kwargs["EnableTerminationProtection"] is True
    assert kwargs["ClientRequestToken"] == str(RUN_ID)
    assert {item["Key"]: item["Value"] for item in kwargs["Tags"]} == {
        "Project": "honda-mapit-mcp", "Environment": "dev",
        "Purpose": "retained-dev", "OperatorRunId": str(RUN_ID),
    }
    assert coordinator.run_step("create")["category"] == "create_intent_conflict"
    assert len(create.calls) == 1

    # A provider-side uncertainty is terminal in the journal, not permission to retry.
    journal2 = Journal()
    coordinator2 = make_coordinator(preflight_clients(), journal2)
    assert coordinator2.run_step("preflight")["ok"]
    uncertain = Client(create_stack=AwsError("InternalFailure", "secret-provider-detail"))
    coordinator2.clients["cloudformation"] = uncertain
    result = coordinator2.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert journal2.state["phase"] == "create_outcome_unknown"
    assert coordinator2.run_step("create")["category"] == "create_intent_conflict"
    assert len(uncertain.calls) == 1
    assert "secret-provider-detail" not in json.dumps(result)


def test_readback_requires_exact_runtime_identity_and_reserved_zero():
    journal = Journal()
    coordinator = make_coordinator(preflight_clients(), journal)
    assert coordinator.run_step("preflight")["ok"]
    coordinator.clients["cloudformation"] = Client(create_stack=ok(StackId=STACK_ID))
    assert coordinator.run_step("create")["ok"]

    resources = [
        {"LogicalResourceId": "McpApi", "ResourceType": "AWS::ApiGatewayV2::Api", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": "api-id"},
        {"LogicalResourceId": "McpApiStage", "ResourceType": "AWS::ApiGatewayV2::Stage", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": "$default"},
        {"LogicalResourceId": "McpHandlerRole", "ResourceType": "AWS::IAM::Role", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": ROLE_NAME},
        {"LogicalResourceId": "McpHandlerLogGroup", "ResourceType": "AWS::Logs::LogGroup", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": LOG_GROUP_NAME},
        {"LogicalResourceId": "McpHandler", "ResourceType": "AWS::Lambda::Function", "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": FUNCTION_NAME},
    ]
    stack = {"StackId": STACK_ID, "StackName": STACK_NAME, "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True, "Tags": [
        {"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev"}, {"Key": "OperatorRunId", "Value": str(RUN_ID)},
    ]}
    role_props = coordinator.template["Resources"]["McpHandlerRole"]["Properties"]
    actual_policy_doc = deepcopy(role_props["Policies"][0]["PolicyDocument"])
    actual_policy_doc["Statement"][0]["Resource"] = (
        f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{LOG_GROUP_NAME}:*"
    )
    cfn = Client(
        describe_stacks=ok(Stacks=[stack]),
        get_template=ok(TemplateBody=json.dumps(coordinator.template, separators=(",", ":"))),
        describe_stack_resources=ok(StackResources=resources),
    )
    coordinator.clients = {
        "sts": Client(get_caller_identity=ok(Account=ACCOUNT, Arn=CALLER_ARN)),
        "cloudformation": cfn,
        "apigatewayv2": Client(
            get_api=ok(ApiId="api-id", Name=API_NAME, ProtocolType="HTTP", DisableExecuteApiEndpoint=True),
            get_routes=ok(Items=[]),
            get_stage=ok(
                StageName="$default", AutoDeploy=True,
                DefaultRouteSettings={"DetailedMetricsEnabled": False, "ThrottlingBurstLimit": 1, "ThrottlingRateLimit": 1},
            ),
        ),
        "lambda": Client(
            get_function_configuration=[ok_request("request-a",
                FunctionName=FUNCTION_NAME,
                FunctionArn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION_NAME}",
                Runtime="python3.13", Handler="index.handler",
                Role=f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}",
                MemorySize=256, Timeout=20, Architectures=["arm64"],
                State="Active", LastUpdateStatus="Successful",
            ), ok_request("request-b",
                FunctionName=FUNCTION_NAME,
                FunctionArn=f"arn:aws:lambda:{REGION}:{ACCOUNT}:function:{FUNCTION_NAME}",
                Runtime="python3.13", Handler="index.handler",
                Role=f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}",
                MemorySize=256, Timeout=20, Architectures=["arm64"],
                State="Active", LastUpdateStatus="Successful",
            )],
            get_function_concurrency=ok(ReservedConcurrentExecutions=0),
        ),
        "logs": Client(describe_log_groups=ok(logGroups=[{"logGroupName": LOG_GROUP_NAME, "retentionInDays": 7}])),
        "iam": Client(
            get_role=ok(Role={"RoleName": ROLE_NAME, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{ROLE_NAME}", "AssumeRolePolicyDocument": deepcopy(role_props["AssumeRolePolicyDocument"])}),
            list_attached_role_policies=ok(AttachedPolicies=[], IsTruncated=False),
            list_role_policies=ok(PolicyNames=[POLICY_NAME], IsTruncated=False),
            get_role_policy=ok(RoleName=ROLE_NAME, PolicyName=POLICY_NAME, PolicyDocument=json.dumps(actual_policy_doc, separators=(",", ":"))),
        ),
    }
    coordinator.clients["iam"].meta.region_name = "us-east-1"
    coordinator.clients["iam"].meta.endpoint_url = "https://iam.amazonaws.com"
    result = coordinator.run_step("readback")
    assert result == {"step": "readback", "ok": True, "category": "readback_verified", "calls": 15}
    assert journal.state["readback_verified"] is True
    assert "123456789012" not in json.dumps(result)


def test_expired_window_and_journal_binding_fail_closed_before_write():
    clients = preflight_clients()
    assert make_coordinator(clients, Journal(), now=1800.0).run_step("preflight")["category"] == "window_expired"
    assert sum(len(client.calls) for client in clients.values()) == 0
    journal = Journal()
    coordinator = make_coordinator(preflight_clients(), journal)
    assert coordinator.run_step("preflight")["ok"]
    journal.state["source_sha"] = "c" * 40
    coordinator.clients["cloudformation"] = Client(create_stack=ok(StackId=STACK_ID))
    assert coordinator.run_step("create")["category"] == "binding_invalid"
    assert not coordinator.clients["cloudformation"].calls


def test_preflight_rejects_missing_http_metadata_and_pagination_instead_of_proving_absence():
    clients = preflight_clients()
    clients["cloudformation"] = Client(describe_stacks={})
    result = make_coordinator(clients, Journal()).run_step("preflight")
    assert result["category"] == "aws_response_invalid"

    clients = preflight_clients()
    clients["apigatewayv2"] = Client(get_apis=ok(Items=[], NextToken="next-page"))
    journal = Journal()
    result = make_coordinator(clients, journal).run_step("preflight")
    assert result["ok"] is False
    assert journal.state is None


def test_preflight_does_not_skip_required_absence_checks_when_clients_are_missing():
    clients = {"cloudformation": preflight_clients()["cloudformation"]}
    with pytest.raises(RetainedDevBootstrapError) as exc:
        make_coordinator(clients, Journal())
    assert exc.value.category == "clients_invalid"


def test_authority_expiring_between_intent_and_create_never_calls_create_stack():
    class Clock:
        def __init__(self):
            self.value = 1000.0

        def __call__(self):
            return self.value

    clock = Clock()
    clients = preflight_clients()
    journal = Journal()
    coordinator = RetainedDevBootstrapCoordinator(
        clients, journal, account_id=ACCOUNT, source_sha=SOURCE, run_id=RUN_ID,
        expected_caller_arn=CALLER_ARN,
        authorized_from_epoch=900, authorized_until_epoch=1800, wall_clock=clock,
    )
    assert coordinator.run_step("preflight")["ok"]
    clock.value = 1800.0
    create = Client(create_stack=ok(StackId=STACK_ID))
    coordinator.clients["cloudformation"] = create
    assert coordinator.run_step("create")["category"] == "window_expired"
    assert create.calls == []
