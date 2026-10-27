from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from scripts import run_dev_identity_binding_storage_probe as probe
from scripts.run_dev_identity_binding_storage_probe import StorageProbeError


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"


def _client_meta(service: str):
    region = "us-east-1" if service == "iam" else "eu-west-1"
    endpoint = "https://iam.amazonaws.com" if service == "iam" else f"https://{service}.{region}.amazonaws.com"
    if service == "cognito-idp":
        endpoint = f"https://cognito-idp.{region}.amazonaws.com"
    if service == "apigatewayv2":
        endpoint = f"https://apigateway.{region}.amazonaws.com"
    return SimpleNamespace(
        service_model=SimpleNamespace(service_name=service),
        region_name=region,
        endpoint_url=endpoint,
        config=SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3),
    )


class _FakeClient:
    def __init__(self, service: str, **methods):
        self.meta = _client_meta(service)
        self.__dict__.update(methods)


def test_explicit_assumed_identity_call_is_window_guarded_before_dispatch():
    now = [100.0]
    mono = [10.0]
    explicit_identity_calls = []
    credentials = {
        "AccessKeyId": "SYNTHETICACCESSKEY",
        "SecretAccessKey": "synthetic-secret",
        "SessionToken": "synthetic-session",
        "Expiration": datetime.fromtimestamp(1000, timezone.utc),
    }

    base_sts = _FakeClient(
        "sts",
        get_caller_identity=lambda: {
            "ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT, "Arn": CALLER,
        },
        assume_role=lambda **kwargs: {
            "ResponseMetadata": {"HTTPStatusCode": 200}, "Credentials": credentials,
        },
    )
    calls = [0]
    base = probe._window_bound_clients(
        {"sts": base_sts}, {"start": 100, "end": 150},
        lambda: now[0], calls=calls, monotonic=lambda: mono[0], mono_start=mono[0],
    )

    def explicit_factory(_creds):
        # Model slow client construction crossing the exclusive cutoff.
        now[0] = 150.0
        return {
            "sts": _FakeClient("sts", get_caller_identity=lambda: explicit_identity_calls.append(True) or {
                "ResponseMetadata": {"HTTPStatusCode": 200}, "Account": ACCOUNT,
                "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/{probe.OPERATOR_ROLE_NAME}/storage-probe-7",
            }),
            "dynamodb": _FakeClient("dynamodb"),
            "ssm": _FakeClient("ssm"),
        }

    with pytest.raises(StorageProbeError) as exc:
        probe._assume_clients(
            base,
            {"expected_caller_arn": CALLER, "run_id": 7, "start": 100, "end": 150},
            {"account_id": ACCOUNT, "operator_user_arn": CALLER},
            explicit_factory,
            lambda: now[0], calls, lambda: mono[0], mono[0],
        )
    assert exc.value.category == "window_expired"
    assert explicit_identity_calls == []
    # Base identity and AssumeRole are counted; the expired explicit identity
    # must neither dispatch nor consume another call.
    assert calls == [2]


def test_real_probe_steps_compose_accepted_bootstrap_key_publication_and_ab_isolation(monkeypatch):
    import copy
    import json
    import time

    from scripts.build_aws_dev_identity_binding_bootstrap import (
        CONFIG_PARAMETER, OPERATOR_BOUNDARY_NAME, OPERATOR_ROLE_NAME, RUNTIME_ROLE_NAME, STACK_NAME,
    )
    from scripts.run_aws_retained_dev_bootstrap import validate_authorization
    from scripts.run_dev_identity_binding_storage_probe import _MemoryJournal
    from tests.test_aws_dev_identity_binding_bootstrap import _AwsError, _bootstrap_fixture
    from tests.test_run_dev_identity_binding_storage_probe import _ClientMeta
    from tests.test_aws_identity_binding import _DynamoDocument

    bootstrap, _unused_journal, evidence = _bootstrap_fixture()
    binding = copy.deepcopy(bootstrap.binding)
    binding.update({"github_owner_id": 111, "github_repository_id": 222})
    account = binding["account_id"]
    now = [time.time()]
    mono = [100.0]
    auth_start = int(now[0]) - 100
    auth = validate_authorization({
        "account": account, "source_sha": "e" * 40, "run_id": 7001,
        "expected_caller_arn": binding["operator_user_arn"],
        "start": auth_start, "end": auth_start + 3600, "ci_run_id": 9001,
    })
    stack_id = f"arn:aws:cloudformation:eu-west-1:{account}:stack/{STACK_NAME}/12345678-1234-1234-1234-123456789abc"
    bootstrap_receipt = bootstrap._base_state(
        last_epoch=1_700_001_100, preflight=True,
        intent={"token": bootstrap._create_token(), "stack_name": STACK_NAME},
        acknowledged=True, stack_id=stack_id, readback=True,
        receipt={"stack_id": stack_id, "template_sha256": bootstrap.template_sha256},
    )
    template = copy.deepcopy(bootstrap.template)
    boundary_arn = f"arn:aws:iam::{account}:policy/{OPERATOR_BOUNDARY_NAME}"
    table_arn = f"arn:aws:dynamodb:eu-west-1:{account}:table/honda-mapit-mcp-dev-identity-bindings"
    table = {
        "TableName": "honda-mapit-mcp-dev-identity-bindings", "TableArn": table_arn,
        "TableStatus": "ACTIVE", "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
        "OnDemandThroughput": {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100},
        "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}],
        "DeletionProtectionEnabled": True, "SSEDescription": {"Status": "ENABLED"},
        "GlobalSecondaryIndexes": [], "LocalSecondaryIndexes": [],
    }
    ddb = _DynamoDocument()
    ddb_aux_calls = []
    ddb.describe_table = lambda **_: (ddb_aux_calls.append("describe_table") or {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Table": table})
    ddb.list_tags_of_resource = lambda **_: (ddb_aux_calls.append("list_tags_of_resource") or {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Tags": [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "mapit-identity-bindings"},
    ]})
    class StatefulSSM:
        def __init__(self):
            self.meta = _ClientMeta("ssm")
            self.values = {}
            self.calls = []

        def get_parameter(self, *, Name, WithDecryption):
            self.calls.append(("get", Name, WithDecryption))
            path, separator, selector = Name.rpartition(":")
            if selector != "1":
                path, selector = Name, ""
            if path not in self.values:
                raise _AwsError("ParameterNotFound", 400)
            item = {"Name": path,
                    "ARN": f"arn:aws:ssm:eu-west-1:{account}:parameter{path}",
                    "Type": "SecureString", "Value": self.values[path],
                    "Version": 1, "DataType": "text"}
            if selector == "1":
                item["Selector"] = ":1"
            return ok(Parameter=item)

        def put_parameter(self, **request):
            self.calls.append(("put", request.get("Name"), request.get("Overwrite")))
            assert request.get("Overwrite") is False
            assert request.get("Type") == "SecureString"
            assert request.get("Tier") == "Standard"
            assert request.get("KeyId") == "alias/aws/ssm"
            assert request.get("DataType") == "text"
            assert request["Name"] not in self.values
            self.values[request["Name"]] = request["Value"]
            return ok(Version=1, Tier="Standard")

    ssm = StatefulSSM()
    request_calls = []
    assumed_identity_calls = []

    def ok(**fields):
        return {**fields, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def base_dispatch(service, method, kwargs):
        request_calls.append((service, method))
        if service == "sts" and method == "get_caller_identity":
            return ok(Account=account, Arn=binding["operator_user_arn"], UserId="AIDEXAMPLE")
        if service == "sts" and method == "assume_role":
            return ok(Credentials={
                "AccessKeyId": "SYNTHETICACCESSKEY", "SecretAccessKey": "synthetic-secret",
                "SessionToken": "synthetic-session",
                "Expiration": datetime.fromtimestamp(now[0] + 1200, timezone.utc),
            })
        if service == "cloudformation" and method == "describe_stacks":
            return ok(Stacks=[{
                "StackId": stack_id, "StackName": STACK_NAME, "StackStatus": "CREATE_COMPLETE",
                "EnableTerminationProtection": True, "RoleARN": None,
                "Tags": [
                    {"Key": "Project", "Value": "honda-mapit-mcp"},
                    {"Key": "Environment", "Value": "dev"},
                    {"Key": "Purpose", "Value": "mapit-identity-bindings"},
                    {"Key": "OperatorRunId", "Value": str(bootstrap.run_id)},
                ],
            }])
        if service == "cloudformation" and method == "get_template":
            return ok(TemplateBody=json.dumps(template))
        if service == "cloudformation" and method == "describe_stack_events":
            return ok(StackEvents=[{"StackId": stack_id, "StackName": STACK_NAME,
                                    "ClientRequestToken": bootstrap_receipt["intent"]["token"]}])
        if service == "cloudformation" and method == "describe_stack_resources":
            rows = []
            physical = {
                "MapitIdentityBindings": "honda-mapit-mcp-dev-identity-bindings",
                "IdentityEnrollerBoundary": boundary_arn,
                "IdentityEnrollerRole": OPERATOR_ROLE_NAME,
                "RuntimeIdentityBindingPolicy": f"{RUNTIME_ROLE_NAME}:honda-mapit-mcp-dev-identity-bindings-runtime-read",
            }
            for logical, resource in template["Resources"].items():
                rows.append({"StackId": stack_id, "StackName": STACK_NAME,
                    "LogicalResourceId": logical, "ResourceType": resource["Type"],
                    "ResourceStatus": "CREATE_COMPLETE", "PhysicalResourceId": physical[logical]})
            return ok(StackResources=rows)
        if service == "dynamodb" and method == "describe_table":
            return ok(Table=table)
        if service == "dynamodb" and method == "list_tags_of_resource":
            return ddb.list_tags_of_resource(**kwargs)
        if service == "dynamodb" and method in {"get_item", "put_item"}:
            return getattr(ddb, method)(**kwargs)
        if service == "iam" and method == "get_role":
            name = kwargs["RoleName"]
            if name != OPERATOR_ROLE_NAME:
                raise _AwsError("NoSuchEntity", 404)
            props = template["Resources"]["IdentityEnrollerRole"]["Properties"]
            return ok(Role={"RoleName": name, "Arn": f"arn:aws:iam::{account}:role/{name}",
                "Path": "/", "MaxSessionDuration": 3600,
                "PermissionsBoundary": {"PermissionsBoundaryArn": boundary_arn, "PermissionsBoundaryType": "Policy"},
                "AssumeRolePolicyDocument": props["AssumeRolePolicyDocument"]})
        if service == "iam" and method == "get_role_policy":
            if kwargs["RoleName"] == OPERATOR_ROLE_NAME:
                props = template["Resources"]["IdentityEnrollerRole"]["Properties"]
                return ok(PolicyDocument=props["Policies"][0]["PolicyDocument"])
            if kwargs["RoleName"] == RUNTIME_ROLE_NAME:
                if kwargs["PolicyName"] != "honda-mapit-mcp-dev-identity-bindings-runtime-read":
                    raise _AwsError("NoSuchEntity", 404)
                props = template["Resources"]["RuntimeIdentityBindingPolicy"]["Properties"]
                return ok(PolicyDocument=props["PolicyDocument"])
        if service == "iam" and method == "get_policy":
            return ok(Policy={"Arn": boundary_arn, "PolicyName": OPERATOR_BOUNDARY_NAME,
                              "Path": "/", "DefaultVersionId": "v1"})
        if service == "iam" and method == "get_policy_version":
            props = template["Resources"]["IdentityEnrollerBoundary"]["Properties"]
            return ok(PolicyVersion={"Document": props["PolicyDocument"]})
        if service == "iam" and method == "list_role_policies":
            return ok(PolicyNames=sorted({
                "honda-mapit-mcp-dev-retained-owned-log-writes",
                "honda-mapit-mcp-dev-retained-tenant-read",
                "honda-mapit-mcp-dev-identity-bindings-runtime-read",
            }), IsTruncated=False)
        if service == "kms" and method == "describe_key":
            return ok(KeyMetadata={"Arn": binding["ssm_key_arn"], "AWSAccountId": account,
                "KeyManager": "AWS", "Enabled": True, "KeyState": "Enabled", "KeyUsage": "ENCRYPT_DECRYPT"})
        if service == "ssm" and method in {"get_parameter", "put_parameter"}:
            return getattr(ssm, method)(**kwargs)
        raise AssertionError((service, method, kwargs))

    # Reuse the factory-derived SDK-shaped service clients for read-only app,
    # IAM and CloudFormation checks; substitute stateful DDB/SSM fakes.
    base_clients = dict(bootstrap.clients)
    base_clients["dynamodb"] = ddb
    base_clients["ssm"] = ssm
    for service, client in list(base_clients.items()):
        if service == "dynamodb" or service == "ssm":
            continue
        if service == "apigatewayv2":
            client.meta.endpoint_url = "https://apigateway.eu-west-1.amazonaws.com"
        client._dispatch = lambda method, kwargs, service=service: base_dispatch(service, method, kwargs)
    # The coordinator's verifier is the one explicitly allowed simulated
    # receipt; all stack/table/IAM/key/parameter checks still run through code.
    monkeypatch.setattr(probe, "verify_accepted_runtime", lambda *_: copy.deepcopy(evidence))

    def explicit_factory(_credentials):
        assumed_sts = _FakeClient("sts", get_caller_identity=lambda: (assumed_identity_calls.append(True) or ok(
            Account=account, Arn=f"arn:aws:sts::{account}:assumed-role/{OPERATOR_ROLE_NAME}/storage-probe-7001")))
        return {"sts": assumed_sts, "dynamodb": ddb, "ssm": ssm}

    probe_journal, key_journal = _MemoryJournal(), _MemoryJournal()
    steps = []
    for step in ("preflight", "exercise", "readback"):
        result = probe.run_storage_probe_step(
            auth, binding, bootstrap_receipt, probe_journal, key_journal, step,
            source_ci_validator=lambda _: None, protection_validator=lambda _: None,
            client_factory=lambda: base_clients, explicit_client_factory=explicit_factory,
            wall_clock=lambda: now[0], monotonic=lambda: mono[0],
        )
        steps.append(result)
    assert [result["category"] for result in steps] == [
        "preflight_verified", "storage_exercise_verified", "readback_verified",
    ], steps
    assert steps[0]["ok"] is steps[1]["ok"] is steps[2]["ok"] is True
    assert probe_journal.value["phase"] == "readback_verified"
    assert key_journal.value["phase"] == "accepted"
    assert ddb.item is not None
    assert len(ddb.put_calls) == 7
    assert len([name for name, value, overwrite in ssm.calls if name == "put" and overwrite is False]) == 3
    total_requests = len(request_calls) + len(ddb_aux_calls) + len(ddb.get_calls) + len(ddb.put_calls) + len(ssm.calls) + len(assumed_identity_calls)
    assert 0 < total_requests <= probe._PROBE_CALL_LIMIT
    assert probe._PROBE_CALL_LIMIT == 160 and probe._PROBE_STEP_SECONDS == 90.0
