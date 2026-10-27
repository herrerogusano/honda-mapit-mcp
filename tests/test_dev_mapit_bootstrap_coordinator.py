from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import copy
import json
import threading
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from scripts.build_aws_dev_mapit_binding_bootstrap import (
    CONFIG_PARAMETER, OPERATOR_BOUNDARY_NAME, OPERATOR_ROLE_NAME,
    RUNTIME_ROLE_NAME, STACK_NAME,
)
from scripts.dev_mapit_bootstrap_contract import build_plan, make_authority
from scripts.dev_mapit_bootstrap_coordinator import (
    MapitBootstrapCoordinator, MapitBootstrapCoordinatorError,
)

ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-mapit-operator"
KEY_ARN = f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/11111111-1111-1111-1111-111111111111"
FRESH = tuple(f"tenant-{x:064x}" for x in (201, 202))
HISTORICAL = tuple(f"tenant-{x:064x}" for x in (101, 102))
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/11111111-1111-1111-1111-111111111111"


def _authority():
    return make_authority(
        account_id=ACCOUNT, operator_user_arn=CALLER, source_sha="a" * 40,
        run_id=33, expected_caller_arn=CALLER,
        authorized_from_epoch=1_800_000_000, authorized_until_epoch=1_800_000_600,
        ci_evidence_sha256="b" * 64, runtime_evidence_sha256="c" * 64,
        ssm_key_arn=KEY_ARN, tenant_keys=FRESH, excluded_tenant_keys=HISTORICAL,
    )


class Clock:
    def __init__(self):
        self.wall = 1_800_000_010.0
        self.mono = 100.0

    def time(self):
        return self.wall

    def monotonic(self):
        self.mono += 0.001
        return self.mono


class Journal:
    def __init__(self):
        self.state = None
        self.lock = threading.RLock()

    @contextmanager
    def locked(self):
        with self.lock:
            yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)


class Missing(Exception):
    def __init__(self, code, status, message=""):
        self.response = {"Error": {"Code": code, "Message": message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}


def _meta(name, region, endpoint):
    cfg = SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2.0,
                          read_timeout=2.0, signature_version="v4", proxies={})
    service = SimpleNamespace(service_name=name)
    return SimpleNamespace(service_model=service, region_name=region,
                           endpoint_url=endpoint, config=cfg)


class Client:
    def __init__(self, name, region, endpoint):
        self.meta = _meta(name, region, endpoint)
        self._endpoint = SimpleNamespace(http_session=SimpleNamespace(_verify=True))


class Sts(Client):
    def __init__(self):
        super().__init__("sts", "eu-west-1", "https://sts.eu-west-1.amazonaws.com")

    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": CALLER, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Kms(Client):
    def __init__(self):
        super().__init__("kms", "eu-west-1", "https://kms.eu-west-1.amazonaws.com")

    def describe_key(self, *, KeyId):
        assert KeyId == "alias/aws/ssm"
        return {"KeyMetadata": {"Arn": KEY_ARN, "AWSAccountId": ACCOUNT, "KeyManager": "AWS",
                                "Enabled": True, "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT"},
                "ResponseMetadata": {"HTTPStatusCode": 200}}


class CloudFormation(Client):
    def __init__(self, plan, *, duplicate_completion=False, fail_create=False,
                 events_next_token=False, resources_next_token=False):
        super().__init__("cloudformation", "eu-west-1", "https://cloudformation.eu-west-1.amazonaws.com")
        self.plan = plan
        self.stack = False
        self.token = None
        self.duplicate_completion = duplicate_completion
        self.fail_create = fail_create
        self.events_next_token = events_next_token
        self.resources_next_token = resources_next_token
        self.event_reads = 0
        self.create_calls = []

    def describe_stacks(self, *, StackName):
        if not self.stack:
            raise Missing("ValidationError", 400, f"Stack with id {STACK_NAME} does not exist")
        return {"Stacks": [{
            "StackId": STACK_ID, "StackName": STACK_NAME, "StackStatus": "CREATE_COMPLETE",
            "EnableTerminationProtection": True, "RoleARN": None,
            "Tags": [{"Key": k, "Value": v} for k, v in {
                "Project": "honda-mapit-mcp", "Environment": "dev",
                "Purpose": "mapit-enrolled-identity-bindings", "OperatorRunId": "33",
            }.items()],
        }], "ResponseMetadata": {"HTTPStatusCode": 200}}

    def create_stack(self, **kwargs):
        self.create_calls.append(kwargs)
        if self.fail_create:
            raise RuntimeError("secret-canary-create-failure")
        self.stack = True
        self.token = kwargs["ClientRequestToken"]
        return {"StackId": STACK_ID, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_template(self, *, StackName, TemplateStage):
        return {"TemplateBody": self.plan.template, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def describe_stack_events(self, *, StackName):
        self.event_reads += 1
        in_progress = {
            "ClientRequestToken": self.token, "StackId": STACK_ID, "StackName": STACK_NAME,
            "LogicalResourceId": STACK_NAME, "PhysicalResourceId": STACK_ID,
            "ResourceType": "AWS::CloudFormation::Stack", "ResourceStatus": "CREATE_IN_PROGRESS",
            "Timestamp": datetime.fromtimestamp(1_800_000_011, tz=timezone.utc),
        }
        child = dict(in_progress, LogicalResourceId="MapitIdentityBindings",
                     PhysicalResourceId=STACK_NAME, ResourceType="AWS::DynamoDB::Table",
                     ResourceStatus="CREATE_COMPLETE")
        done = dict(in_progress, ResourceStatus="CREATE_COMPLETE")
        events = [in_progress, child, done]
        if self.duplicate_completion:
            events.append(dict(done))
        result = {"StackEvents": events, "ResponseMetadata": {"HTTPStatusCode": 200}}
        if self.events_next_token:
            result["NextToken"] = "opaque-first-page-cursor"
        return result

    def describe_stack_resources(self, *, StackName):
        physical = {
            "MapitIdentityBindings": STACK_NAME,
            "IdentityEnrollerBoundary": f"arn:aws:iam::{ACCOUNT}:policy/{OPERATOR_BOUNDARY_NAME}",
            "IdentityEnrollerRole": OPERATOR_ROLE_NAME,
            "RuntimeIdentityBindingPolicy": "generated-runtime-policy-physical-id",
        }
        rows = [{"LogicalResourceId": name, "ResourceType": kind,
                 "ResourceStatus": "CREATE_COMPLETE", "StackId": STACK_ID,
                 "StackName": STACK_NAME, "PhysicalResourceId": physical[name]}
                for name, kind in {
                    "MapitIdentityBindings": "AWS::DynamoDB::Table",
                    "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
                    "IdentityEnrollerRole": "AWS::IAM::Role",
                    "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy",
                }.items()]
        result = {"StackResources": rows, "ResponseMetadata": {"HTTPStatusCode": 200}}
        if self.resources_next_token:
            result["NextToken"] = "opaque-resource-cursor"
        return result


class DynamoDB(Client):
    def __init__(self, plan, *, propagated_cfn_tags=False):
        super().__init__("dynamodb", "eu-west-1", "https://dynamodb.eu-west-1.amazonaws.com")
        self.created = False
        self.props = plan.template["Resources"]["MapitIdentityBindings"]["Properties"]
        self.propagated_cfn_tags = propagated_cfn_tags
        self.extra_tags = {}

    def describe_table(self, *, TableName):
        if not self.created:
            raise Missing("ResourceNotFoundException", 400)
        return {"Table": {
            "TableName": STACK_NAME,
            "TableArn": f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/{STACK_NAME}",
            "TableStatus": "ACTIVE", "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "OnDemandThroughput": self.props["OnDemandThroughput"],
            "KeySchema": self.props["KeySchema"], "AttributeDefinitions": self.props["AttributeDefinitions"],
            "DeletionProtectionEnabled": True, "SSEDescription": None,
            "TableId": "22222222-2222-2222-2222-222222222222",
            "CreationDateTime": datetime.fromtimestamp(1_800_000_011.123456, tz=timezone.utc),
            "GlobalSecondaryIndexes": [], "LocalSecondaryIndexes": [],
        }, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_tags_of_resource(self, *, ResourceArn):
        tags = {
            "Project": "honda-mapit-mcp", "Environment": "dev",
            "Purpose": "mapit-enrolled-identity-bindings",
            "OperatorRunId": "33",
        }
        if self.propagated_cfn_tags:
            tags.update({
                "aws:cloudformation:stack-id": STACK_ID,
                "aws:cloudformation:stack-name": STACK_NAME,
                "aws:cloudformation:logical-id": "MapitIdentityBindings",
            })
        tags.update(self.extra_tags)
        return {"Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_item(self, **kwargs):
        assert kwargs["ConsistentRead"] is True
        assert kwargs["Key"] == {"key": {"S": "identity-bindings-v1"}}
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}


class IAM(Client):
    def __init__(self, plan):
        super().__init__("iam", "us-east-1", "https://iam.amazonaws.com")
        self.created = False
        self.encoded_trust = False
        self.resources = plan.template["Resources"]

    def get_role(self, *, RoleName):
        if not self.created:
            raise Missing("NoSuchEntity", 404)
        props = self.resources["IdentityEnrollerRole"]["Properties"]
        trust = props["AssumeRolePolicyDocument"]
        if self.encoded_trust:
            trust = quote(json.dumps(trust, separators=(",", ":")), safe="")
        return {"Role": {"RoleName": OPERATOR_ROLE_NAME,
                          "Arn": f"arn:aws:iam::{ACCOUNT}:role/{OPERATOR_ROLE_NAME}",
                          "Path": "/", "MaxSessionDuration": 3600,
                          "PermissionsBoundary": {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/{OPERATOR_BOUNDARY_NAME}",
                                                  "PermissionsBoundaryType": "Policy"},
                          "AssumeRolePolicyDocument": trust},
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_role_policy(self, *, RoleName, PolicyName):
        if not self.created:
            raise Missing("NoSuchEntity", 404)
        if RoleName == OPERATOR_ROLE_NAME:
            doc = self.resources["IdentityEnrollerRole"]["Properties"]["Policies"][0]["PolicyDocument"]
        else:
            runtime = self.resources["RuntimeIdentityBindingPolicy"]["Properties"]
            assert PolicyName == runtime["PolicyName"]
            doc = runtime["PolicyDocument"]
        return {"PolicyDocument": doc, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_policy(self, *, PolicyArn):
        if not self.created:
            raise Missing("NoSuchEntity", 404)
        return {"Policy": {"Arn": PolicyArn, "PolicyName": OPERATOR_BOUNDARY_NAME,
                            "Path": "/", "DefaultVersionId": "v1"},
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_policy_version(self, *, PolicyArn, VersionId):
        doc = self.resources["IdentityEnrollerBoundary"]["Properties"]["PolicyDocument"]
        return {"PolicyVersion": {"Document": doc, "IsDefaultVersion": True},
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_role_policies(self, *, RoleName):
        return {"PolicyNames": [OPERATOR_ROLE_NAME + "-policy"], "IsTruncated": False,
                "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_attached_role_policies(self, *, RoleName):
        return {"AttachedPolicies": [], "IsTruncated": False,
                "ResponseMetadata": {"HTTPStatusCode": 200}}


class SSM(Client):
    def __init__(self):
        super().__init__("ssm", "eu-west-1", "https://ssm.eu-west-1.amazonaws.com")

    def get_parameter(self, **kwargs):
        raise Missing("ParameterNotFound", 400)


def _clients(plan, *, duplicate_completion=False, fail_create=False,
             events_next_token=False, resources_next_token=False):
    cfn = CloudFormation(plan, duplicate_completion=duplicate_completion, fail_create=fail_create,
                         events_next_token=events_next_token,
                         resources_next_token=resources_next_token)
    ddb = DynamoDB(plan)
    iam = IAM(plan)
    clients = {
        "sts": Sts(), "cloudformation": cfn, "iam": iam, "dynamodb": ddb,
        "ssm": SSM(), "cognito": Client("cognito-idp", "eu-west-1", "https://cognito-idp.eu-west-1.amazonaws.com"),
        "apigatewayv2": Client("apigatewayv2", "eu-west-1", "https://apigateway.eu-west-1.amazonaws.com"),
        "lambda": Client("lambda", "eu-west-1", "https://lambda.eu-west-1.amazonaws.com"),
        "kms": Kms(),
    }
    return clients, cfn, ddb, iam


def _callbacks(auth):
    def source(a):
        return {"verified": True, "calls": 2, "account_id": a.account_id,
                "source_sha": a.source_sha, "run_id": a.run_id, "caller_arn": a.expected_caller_arn,
                "branch": "develop", "evidence_sha256": a.ci_evidence_sha256}

    def protections(a):
        return {"verified": True, "calls": 3, "account_id": a.account_id,
                "source_sha": a.source_sha, "run_id": a.run_id, "caller_arn": a.expected_caller_arn,
                "environment": "dev", "protections_verified": True,
                "evidence_sha256": a.ci_evidence_sha256}

    def runtime(clients, a, expected_template, *, phase):
        return {"verified": True, "calls": 10, "phase": phase,
                "account_id": a.account_id, "source_sha": a.source_sha,
                "run_id": a.run_id, "caller_arn": a.expected_caller_arn,
                "evidence_sha256": a.runtime_evidence_sha256,
                "resource_count": 19, "api_closed": True, "reserve_zero": True,
                "mapit_policy_attached": phase == "readback"}

    return source, protections, runtime


def _coordinator(*, duplicate_completion=False, fail_create=False, source_mutation=None,
                 events_next_token=False, resources_next_token=False):
    auth = _authority()
    plan = build_plan(auth)
    clients, cfn, ddb, iam = _clients(plan, duplicate_completion=duplicate_completion,
                                      fail_create=fail_create,
                                      events_next_token=events_next_token,
                                      resources_next_token=resources_next_token)
    source, protections, runtime = _callbacks(auth)
    if source_mutation:
        original = source
        source = lambda a: source_mutation(original(a))
    journal = Journal()
    clock = Clock()
    coordinator = MapitBootstrapCoordinator(
        clients, journal, authority=auth, fresh_source=source,
        fresh_protections=protections, closed_runtime_verifier=runtime,
        wall_clock=clock.time, monotonic=clock.monotonic,
    )
    return coordinator, journal, cfn, ddb, iam


def test_injected_coordinator_preflight_create_and_exact_readback():
    coordinator, journal, cfn, ddb, iam = _coordinator()
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert journal.state["kind"] == "dev-mapit-identity-binding-bootstrap"
    assert journal.state["namespace"] == "mapit"
    assert "tenant_keys" not in journal.state
    result = coordinator.run_step("create")
    assert result["category"] == "create_acknowledged"
    assert len(cfn.create_calls) == 1
    request = cfn.create_calls[0]
    assert request["StackName"] == STACK_NAME
    assert request["EnableTerminationProtection"] is True
    assert request["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert request["TemplateBody"] == build_plan(_authority()).template_json
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["readback"] is True
    assert cfn.create_calls[0]["ClientRequestToken"] == journal.state["intent"]["client_request_token"]


def test_create_unknown_outcome_is_consumed_and_never_replayed():
    coordinator, journal, cfn, _, _ = _coordinator(fail_create=True)
    assert coordinator.run_step("preflight")["ok"] is True
    result = coordinator.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert "secret-canary" not in repr(result)
    assert journal.state["intent"] is not None
    again = coordinator.run_step("create")
    assert again["category"] == "create_intent_present"
    assert len(cfn.create_calls) == 1


def test_create_conflict_and_bad_fresh_source_stop_before_intent_or_write():
    coordinator, journal, cfn, _, _ = _coordinator(source_mutation=lambda e: {**e, "source_sha": "f" * 40})
    result = coordinator.run_step("preflight")
    assert result["category"] == "source_unverified"
    assert journal.state is None
    assert cfn.create_calls == []


def test_duplicate_root_create_complete_events_fail_exact_readback():
    coordinator, journal, cfn, ddb, iam = _coordinator(duplicate_completion=True)
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["ok"] is True
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "stack_readback_mismatch"
    assert journal.state["readback"] is False


def test_event_first_page_cursor_is_ignored_without_pagination():
    coordinator, journal, cfn, ddb, iam = _coordinator(events_next_token=True)
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["readback_receipt"]["table_created_at_utc"] == "2027-01-15T08:00:11.123456+00:00"
    assert cfn.event_reads == 1


def test_encoded_assume_role_trust_document_is_normalized_before_comparison():
    coordinator, journal, _, ddb, iam = _coordinator()
    iam.encoded_trust = True
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["readback"] is True


def test_partial_stack_resource_inventory_with_next_token_fails_closed():
    coordinator, journal, _, ddb, iam = _coordinator(resources_next_token=True)
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "aws_response_invalid"
    assert journal.state["readback"] is False


def test_exact_cloudformation_propagated_table_tags_are_accepted():
    coordinator, journal, _, ddb, _ = _coordinator()
    ddb.propagated_cfn_tags = True
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    ddb.created = True
    coordinator.clients["iam"].created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["readback"] is True


def test_unrecognized_cloudformation_tag_is_rejected():
    coordinator, journal, _, ddb, iam = _coordinator()
    ddb.propagated_cfn_tags = True
    ddb.extra_tags["aws:cloudformation:unexpected"] = "not-allowed"
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "stack_readback_mismatch"
    assert journal.state["readback"] is False


def test_maximum_valid_evidence_call_counts_fit_each_bounded_step():
    coordinator, journal, _, ddb, iam = _coordinator()
    original_source, original_protections, original_runtime = _callbacks(_authority())

    def counted(callback, count):
        def call(*args, **kwargs):
            return {**callback(*args, **kwargs), "calls": count}
        return call

    coordinator.fresh_source = counted(original_source, 8)
    coordinator.fresh_protections = counted(original_protections, 8)
    coordinator.closed_runtime_verifier = counted(original_runtime, 64)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    ddb.created = iam.created = True
    result = coordinator.run_step("readback")
    assert result["category"] == "readback_verified"
    assert result["calls"] <= 128
    assert journal.state["readback"] is True


def test_injected_client_profile_rejects_retry_or_tls_relaxation():
    auth = _authority()
    plan = build_plan(auth)
    clients, _, _, _ = _clients(plan)
    clients["ssm"].meta.config.retries["total_max_attempts"] = 2
    source, protection, runtime = _callbacks(auth)
    with pytest.raises(MapitBootstrapCoordinatorError, match="clients_invalid"):
        MapitBootstrapCoordinator(clients, Journal(), authority=auth, fresh_source=source,
                                  fresh_protections=protection, closed_runtime_verifier=runtime)


def test_runtime_callback_requires_exact_context_and_closed_state():
    auth = _authority()
    bad = lambda clients, a, template, *, phase: {
        **_callbacks(a)[2](clients, a, template, phase=phase),
        "api_closed": False,
    }
    plan = build_plan(auth)
    clients, _, _, _ = _clients(plan)
    source, protection, _ = _callbacks(auth)
    coordinator = MapitBootstrapCoordinator(
        clients, Journal(), authority=auth, fresh_source=source,
        fresh_protections=protection, closed_runtime_verifier=bad,
        wall_clock=lambda: 1_800_000_010, monotonic=lambda: 10.0,
    )
    assert coordinator.run_step("preflight")["category"] == "runtime_unverified"


def test_botocore_stubbed_preflight_and_single_create_request():
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config
    from botocore.stub import Stubber

    auth = _authority()
    plan = build_plan(auth)
    endpoints = {
        "sts": ("eu-west-1", "https://sts.eu-west-1.amazonaws.com"),
        "cloudformation": ("eu-west-1", "https://cloudformation.eu-west-1.amazonaws.com"),
        "iam": ("us-east-1", "https://iam.amazonaws.com"),
        "dynamodb": ("eu-west-1", "https://dynamodb.eu-west-1.amazonaws.com"),
        "ssm": ("eu-west-1", "https://ssm.eu-west-1.amazonaws.com"),
        "cognito-idp": ("eu-west-1", "https://cognito-idp.eu-west-1.amazonaws.com"),
        "apigatewayv2": ("eu-west-1", "https://apigateway.eu-west-1.amazonaws.com"),
        "lambda": ("eu-west-1", "https://lambda.eu-west-1.amazonaws.com"),
        "kms": ("eu-west-1", "https://kms.eu-west-1.amazonaws.com"),
    }
    clients = {}
    stubbers = {}
    raw_clients = {}
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=2,
                    read_timeout=2, proxies={}, signature_version="v4")
    for name, (region, endpoint) in endpoints.items():
        clients_key = "cognito" if name == "cognito-idp" else name
        client = boto3.client(name, region_name=region, endpoint_url=endpoint,
                              aws_access_key_id="offline-access",
                              aws_secret_access_key="offline-secret",
                              aws_session_token="offline-session", config=config)
        raw_clients[clients_key] = client
        stubbers[clients_key] = Stubber(client)

        class MetadataAdapter:
            def __init__(self, client):
                self._client = client
                self.meta = client.meta
                self._endpoint = client._endpoint
                self._test_call_names = []
                self._test_error_type = None
                self._test_last_params = None

            def __getattr__(self, name):
                method = getattr(self._client, name)
                if not callable(method):
                    return method
                def call(*args, **kwargs):
                    self._test_call_names.append(name)
                    self._test_last_params = kwargs
                    try:
                        result = method(*args, **kwargs)
                    except Exception as exc:
                        self._test_error_type = type(exc).__name__
                        raise
                    if isinstance(result, dict):
                        result.setdefault("ResponseMetadata", {"HTTPStatusCode": 200})
                    return result
                return call

    clients.update({name: MetadataAdapter(client) for name, client in raw_clients.items()})

    def add_step_expectations():
        stubbers["sts"].add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": CALLER}, {})
        stubbers["kms"].add_response("describe_key", {"KeyMetadata": {
            "KeyId": "11111111-1111-1111-1111-111111111111",
            "Arn": KEY_ARN, "AWSAccountId": ACCOUNT, "KeyManager": "AWS",
            "Enabled": True, "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT",
        }}, {"KeyId": "alias/aws/ssm"})
        stubbers["cloudformation"].add_client_error(
            "describe_stacks", service_error_code="ValidationError",
            service_message=f"Stack with id {STACK_NAME} does not exist",
            http_status_code=400, expected_params={"StackName": STACK_NAME})
        stubbers["dynamodb"].add_client_error(
            "describe_table", service_error_code="ResourceNotFoundException",
            http_status_code=400, expected_params={"TableName": STACK_NAME})
        stubbers["iam"].add_client_error(
            "get_role", service_error_code="NoSuchEntity", http_status_code=404,
            expected_params={"RoleName": OPERATOR_ROLE_NAME})
        boundary_arn = f"arn:aws:iam::{ACCOUNT}:policy/{OPERATOR_BOUNDARY_NAME}"
        stubbers["iam"].add_client_error(
            "get_policy", service_error_code="NoSuchEntity", http_status_code=404,
            expected_params={"PolicyArn": boundary_arn})
        stubbers["iam"].add_client_error(
            "get_role_policy", service_error_code="NoSuchEntity", http_status_code=404,
            expected_params={"RoleName": RUNTIME_ROLE_NAME,
                             "PolicyName": "honda-mapit-mcp-dev-mapit-identity-bindings-runtime-read"})
        for path in (CONFIG_PARAMETER,) + tuple(
                f"/honda-mapit-mcp/dev/tenants/{key}/mapit-refresh-token" for key in FRESH):
            stubbers["ssm"].add_client_error(
                "get_parameter", service_error_code="ParameterNotFound", http_status_code=400,
                expected_params={"Name": path, "WithDecryption": False})

    add_step_expectations()
    journal = Journal()
    source, protections, runtime = _callbacks(auth)
    clock = Clock()
    for name, client in clients.items():
        svc, region, endpoint = MapitBootstrapCoordinator._ENDPOINTS[name]
        assert (client.meta.service_model.service_name, client.meta.region_name,
                client.meta.endpoint_url) == (svc, region, endpoint), name
        assert client.meta.config.retries.get("total_max_attempts") == 1, name
        assert type(client.meta.config.retries.get("total_max_attempts")) is int, name
        assert isinstance(client.meta.config.signature_version, str)
        assert client.meta.config.signature_version == "v4", name
        assert client.meta.config.proxies == {}, name
        assert type(client.meta.config.proxies) is dict, name
        assert client._endpoint.http_session._verify is True, name
        assert all(type(v) in (int, float) and not isinstance(v, bool) and v <= 3
                   for v in (client.meta.config.connect_timeout, client.meta.config.read_timeout)), name
        assert 0 < client.meta.config.connect_timeout <= 3, (name, client.meta.config.connect_timeout)
        assert 0 < client.meta.config.read_timeout <= 3, (name, client.meta.config.read_timeout)
        assert all(__import__("math").isfinite(v) for v in (client.meta.config.connect_timeout,
                                                            client.meta.config.read_timeout)), name
    assert set(clients) == MapitBootstrapCoordinator._CLIENTS
    coordinator = MapitBootstrapCoordinator(
        clients, journal, authority=auth, fresh_source=source,
        fresh_protections=protections, closed_runtime_verifier=runtime,
        wall_clock=clock.time, monotonic=clock.monotonic,
    )
    for stubber in stubbers.values():
        stubber.activate()
    try:
        preflight_result = coordinator.run_step("preflight")
        assert preflight_result["category"] == "preflight_verified", preflight_result
        add_step_expectations()
        stubbers["sts"].add_response("get_caller_identity", {"Account": ACCOUNT, "Arn": CALLER}, {})
        token = coordinator._create_token()
        stubbers["cloudformation"].add_response("create_stack", {"StackId": STACK_ID}, {
            "StackName": STACK_NAME, "TemplateBody": plan.template_json,
            "Capabilities": ["CAPABILITY_NAMED_IAM"], "ClientRequestToken": token,
            "EnableTerminationProtection": True,
            "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"},
                     {"Key": "Environment", "Value": "dev"},
                     {"Key": "Purpose", "Value": "mapit-enrolled-identity-bindings"},
                     {"Key": "OperatorRunId", "Value": "33"}],
        })
        create_result = coordinator.run_step("create")
        mismatch_keys = (
            sorted(k for k, v in stubbers["cloudformation"]._queue[0]["expected_params"].items()
                   if clients["cloudformation"]._test_last_params.get(k) != v)
            if stubbers["cloudformation"]._queue else [])
        assert create_result["category"] == "create_acknowledged", (
            create_result["category"], clients["cloudformation"]._test_error_type,
            mismatch_keys, [x["operation_name"] for x in stubbers["cloudformation"]._queue])
        for stubber in stubbers.values():
            stubber.assert_no_pending_responses()
    finally:
        for stubber in stubbers.values():
            stubber.deactivate()
