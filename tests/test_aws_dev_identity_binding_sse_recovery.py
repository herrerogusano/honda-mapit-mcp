from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

import pytest

from scripts.aws_dev_identity_binding_sse_recovery import (
    SseRecoveryError,
    _canonical,
    _state_digest,
    _templates,
    validate_recovery_lineage,
)
from scripts.build_aws_dev_identity_binding_bootstrap import build_dev_identity_binding_bootstrap
from scripts.build_aws_dev_identity_binding_bootstrap import STACK_NAME
from scripts.run_aws_dev_identity_binding_bootstrap import _BINDING_FIELDS, _COORDINATOR_FIELDS
from scripts.run_dev_identity_binding_storage_probe import _STATE_FIELDS


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/11111111-2222-4333-8444-555555555555"


def _lineage():
    binding = {
        "account_id": ACCOUNT,
        "operator_user_arn": CALLER,
        "tenant_keys": ("tenant-" + "a" * 64, "tenant-" + "b" * 64),
        "ssm_key_arn": f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "accepted_runtime_journal_path": "C:/private/accepted-runtime",
        "app_stack_arn": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "app_run_id": 123,
        "api_id": "abcdefghij",
        "user_pool_id": "eu-west-1_Abcdefghi",
        "client_id": "Abcdefghijklmnopqrstuvwxyz",
        "template_sha256": "1" * 64,
        "code_sha256": "2" * 64,
        "handler_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        "handler_trust_sha256": "3" * 64,
        "handler_policies_sha256": "4" * 64,
        "github_owner_id": 111,
        "github_repository_id": 222,
    }
    old_template = build_dev_identity_binding_bootstrap(
        account_id=ACCOUNT, operator_user_arn=CALLER,
        tenant_keys=binding["tenant_keys"], ssm_key_arn=binding["ssm_key_arn"],
    )
    old_sha = hashlib.sha256(_canonical(old_template)).hexdigest()
    coordinator_binding = {key: binding[key] for key in _COORDINATOR_FIELDS if key != "tenant_keys"}
    source, run_id, start, end = "a" * 40, 991, 1_800_000_000, 1_800_003_600
    token = "dev-identity-bindings-" + hashlib.sha256(f"{ACCOUNT}:{source}:{run_id}".encode("ascii")).hexdigest()
    bootstrap = {
        "schema": 1,
        "kind": "dev-identity-binding-bootstrap",
        "account": ACCOUNT,
        "source_sha": source,
        "run_id": run_id,
        "template_sha256": old_sha,
        "binding_sha256": _state_digest(coordinator_binding),
        "expected_caller_arn": CALLER,
        "authorized_from_epoch": start,
        "authorized_until_epoch": end,
        "last_observed_epoch": start + 10,
        "preflight": True,
        "intent": {"token": token, "stack_name": STACK_NAME},
        "acknowledged": True,
        "acknowledged_stack_id": STACK_ID,
        "readback": True,
        "readback_receipt": {"stack_id": STACK_ID, "template_sha256": old_sha},
    }
    probe = {
        "schema": 1,
        "operation": "dev_identity_binding_storage_probe",
        "account": ACCOUNT,
        "source": source,
        "run_id": 992,
        "caller": CALLER,
        "start": start + 100,
        "end": start + 400,
        "bootstrap_sha256": old_sha,
        "tenant_keys_sha256": hashlib.sha256(_canonical(list(binding["tenant_keys"]))).hexdigest(),
        "bootstrap_stack_id": STACK_ID,
        "phase": "intent_saved",
        "intent": "storage_exercise",
        "flags": {"preflight": True, "intent_saved": True},
    }
    key_state = {
        "schema": 1,
        "operation": "dev_identity_binding_key_publication",
        "account": ACCOUNT,
        "source": source,
        "run_id": 992,
        "bootstrap_sha256": old_sha,
        "parameter_path": "/honda-mapit-mcp/dev/identity-binding-config",
        "start": probe["start"],
        "end": probe["end"],
        "phase": "accepted",
    }
    recovery = {
        "table_id": "12345678-1234-4234-8234-123456789abc",
        "table_creation_time": datetime.fromtimestamp(start + 5, timezone.utc).isoformat(),
        "bootstrap_state_sha256": _state_digest(bootstrap),
        "probe_state_sha256": _state_digest(probe),
        "key_state_sha256": _state_digest(key_state),
        "sse_key_arn": f"arn:aws:kms:eu-west-1:{ACCOUNT}:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        "runtime_policy_physical_id": "honda-mapit-mcp-dev-runtime-identity-binding-policy-physical",
    }
    return binding, bootstrap, probe, key_state, recovery


def test_lineage_accepts_readonly_historical_receipts_and_exact_table_metadata():
    binding, bootstrap, probe, keys, recovery = _lineage()
    result = validate_recovery_lineage(binding, bootstrap, probe, keys, recovery)
    assert result["stack_id"] == STACK_ID
    assert result["table_arn"].endswith("/honda-mapit-mcp-dev-identity-bindings")
    assert result["sse_key_arn"] == recovery["sse_key_arn"]
    old, new, _, _, old_sha, new_sha = _templates(binding)
    assert old_sha == bootstrap["template_sha256"]
    assert old_sha != new_sha
    assert old["Resources"]["MapitIdentityBindings"]["Properties"]["SSESpecification"] == {"SSEEnabled": True}
    assert new["Resources"]["MapitIdentityBindings"]["Properties"]["SSESpecification"] == {"SSEEnabled": False}
    old_resources = {k: v for k, v in old["Resources"].items() if k != "MapitIdentityBindings"}
    new_resources = {k: v for k, v in new["Resources"].items() if k != "MapitIdentityBindings"}
    assert old_resources == new_resources


@pytest.mark.parametrize("modified", [
    datetime.fromtimestamp(2010000000, timezone.utc),
    datetime(2030, 1, 1),
    None,
])
def test_config_parameter_must_be_original_accepted_version_one(modified):
    from scripts.aws_dev_identity_binding_sse_recovery import DevIdentityBindingSseRecoveryCoordinator

    binding, bootstrap, probe, keys, recovery = _lineage()
    coordinator = object.__new__(DevIdentityBindingSseRecoveryCoordinator)
    coordinator.binding = binding
    coordinator.accepted_key_state = keys
    coordinator._call = lambda *_args, **_kwargs: {
        "Parameter": {
            "Name": "/honda-mapit-mcp/dev/identity-binding-config",
            "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/identity-binding-config",
            "Type": "SecureString", "Version": 1, "DataType": "text",
            "LastModifiedDate": modified,
        }
    }
    if modified == datetime.fromtimestamp(2010000000, timezone.utc):
        # A date from before the accepted key-publication window is not proof of
        # the original version-1 key material.
        with pytest.raises(SseRecoveryError, match="preflight_conflict"):
            coordinator._verify_parameters(require_tenant_absent=False)
    else:
        with pytest.raises(SseRecoveryError, match="preflight_conflict"):
            coordinator._verify_parameters(require_tenant_absent=False)


def test_config_parameter_accepts_original_version_one_modification_time():
    from scripts.aws_dev_identity_binding_sse_recovery import DevIdentityBindingSseRecoveryCoordinator

    binding, _, _, keys, _ = _lineage()
    coordinator = object.__new__(DevIdentityBindingSseRecoveryCoordinator)
    coordinator.binding = binding
    coordinator.accepted_key_state = keys
    coordinator._call = lambda *_args, **_kwargs: {
        "Parameter": {
            "Name": "/honda-mapit-mcp/dev/identity-binding-config",
            "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/identity-binding-config",
            "Type": "SecureString", "Version": 1, "DataType": "text",
            "LastModifiedDate": datetime.fromtimestamp(keys["start"] + 1, timezone.utc),
        }
    }
    coordinator._verify_parameters(require_tenant_absent=False)


@pytest.mark.parametrize("field,value", [
    ("Version", 2),
    ("LastModifiedDate", datetime(2030, 1, 1, tzinfo=timezone.utc)),
    ("LastModifiedDate", None),
    ("Selector", ":1"),
])
def test_latest_tenant_parameter_must_be_version_one_created_in_fresh_window(field, value):
    from scripts.aws_dev_identity_binding_sse_recovery import DevIdentityBindingSseRecoveryCoordinator

    coordinator = object.__new__(DevIdentityBindingSseRecoveryCoordinator)
    coordinator.binding = {"account_id": ACCOUNT}
    coordinator.auth = {"start": 1_800_000_000, "end": 1_800_003_600}
    parameter = {
        "Name": "/honda-mapit-mcp/dev/tenants/tenant-a/mapit-refresh-token",
        "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/tenants/tenant-a/mapit-refresh-token",
        "Type": "SecureString", "Version": 1, "DataType": "text",
        "LastModifiedDate": datetime.fromtimestamp(1_800_000_100, timezone.utc),
    }
    parameter[field] = value
    coordinator._call = lambda *_args, **_kwargs: {
        "ResponseMetadata": {"HTTPStatusCode": 200}, "Parameter": parameter,
    }
    with pytest.raises(ValueError):
        coordinator._verify_current_tenant_parameter(object(), "tenant-a")


def test_latest_tenant_parameter_accepts_unqualified_current_version_one():
    from scripts.aws_dev_identity_binding_sse_recovery import DevIdentityBindingSseRecoveryCoordinator

    coordinator = object.__new__(DevIdentityBindingSseRecoveryCoordinator)
    coordinator.binding = {"account_id": ACCOUNT}
    coordinator.auth = {"start": 1_800_000_000, "end": 1_800_003_600}
    coordinator._call = lambda *_args, **_kwargs: {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "Parameter": {
            "Name": "/honda-mapit-mcp/dev/tenants/tenant-a/mapit-refresh-token",
            "ARN": f"arn:aws:ssm:eu-west-1:{ACCOUNT}:parameter/honda-mapit-mcp/dev/tenants/tenant-a/mapit-refresh-token",
            "Type": "SecureString", "Version": 1, "DataType": "text",
            "LastModifiedDate": datetime.fromtimestamp(1_800_000_100, timezone.utc),
        },
    }
    coordinator._verify_current_tenant_parameter(object(), "tenant-a")


def test_cli_maps_hyphenated_options_to_runner_signature(monkeypatch, capsys):
    import scripts.run_aws_dev_identity_binding_sse_recovery as runner

    seen = {}
    monkeypatch.setattr(runner, "run_authorized_step", lambda **kwargs: seen.update(kwargs) or {
        "step": "preflight", "ok": True, "category": "preflight_verified", "calls": 0, "flags": {},
    })
    assert runner.main([
        "--authorization", "auth.json", "--binding", "binding.json",
        "--historical-directory", "history", "--recovery-binding", "recovery.json",
        "--state-dir", "update", "--probe-state-dir", "probe", "--step", "preflight",
    ]) == 0
    assert set(seen) == {
        "authorization_path", "binding_path", "historical_directory", "recovery_binding_path",
        "state_dir", "probe_state_dir", "step",
    }
    assert seen["authorization_path"].name == "auth.json"
    assert seen["recovery_binding_path"].name == "recovery.json"
    assert '"ok":true' in capsys.readouterr().out


@pytest.mark.parametrize("pace", [0.2, 0.3])
def test_paced_synthetic_exercise_uses_fresh_reader_leases(pace):
    from mapit.aws_binding_keys import generate_binding_keys
    from scripts.aws_dev_identity_binding_sse_recovery import DevIdentityBindingSseRecoveryCoordinator
    from test_run_dev_identity_binding_storage_probe import _DynamoDocument, _SSM, _STS

    class Clock:
        value = 10.0

    clock = Clock()

    class Paced:
        def __init__(self, client):
            self._client = client

        def __getattr__(self, name):
            value = getattr(self._client, name)
            if name == "meta" or not callable(value):
                return value

            def call(*args, **kwargs):
                clock.value += pace
                return value(*args, **kwargs)

            return call

    binding, *_ = _lineage()
    coordinator = object.__new__(DevIdentityBindingSseRecoveryCoordinator)
    coordinator.binding = binding
    coordinator.monotonic = lambda: clock.value
    coordinator.wall_clock = lambda: 1_800_000_100 + clock.value - 10
    clients = {
        "sts": Paced(_STS()),
        "dynamodb": Paced(_DynamoDocument()),
        "ssm": Paced(_SSM()),
    }
    outcome = coordinator._exercise_fresh_readers(clients, generate_binding_keys())
    assert outcome == {
        "tenant_a_enrolled": True,
        "tenant_b_enrolled": True,
        "tenant_results_isolated": True,
        "tenant_a_revoked": True,
        "tenant_b_remained_active": True,
    }


@pytest.mark.parametrize("pace", [0.2, 0.3])
def test_full_coordinator_keeps_update_receipt_and_proof_journals_separate(monkeypatch, pace):
    from copy import deepcopy
    from contextlib import nullcontext
    from types import SimpleNamespace

    from mapit.aws_binding_keys import generate_binding_keys
    from scripts import aws_dev_identity_binding_sse_recovery as module
    from scripts.run_aws_retained_dev_bootstrap import validate_authorization
    from test_run_dev_identity_binding_storage_probe import _DynamoDocument, _SSM, _STS

    binding, bootstrap, probe, keys, recovery = _lineage()
    start = 1_800_000_000
    auth = validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER,
        "source_sha": "f" * 40, "ci_run_id": 555,
        "run_id": 987654, "start": start, "end": start + 3600,
    })
    clock = {"mono": 10.0}

    class ClientMeta:
        def __init__(self, service, region, endpoint):
            self.service_model = SimpleNamespace(service_name=service)
            self.region_name = region
            self.endpoint_url = endpoint
            self.config = SimpleNamespace(
                retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3,
            )

    class PaceClient:
        def __init__(self, client, service, region, endpoint):
            self._client = client
            self.meta = ClientMeta(service, region, endpoint)

        def __getattr__(self, name):
            value = getattr(self._client, name, None)
            if not callable(value):
                return value

            def call(*args, **kwargs):
                clock["mono"] += pace
                return value(*args, **kwargs)

            return call

    class Cfn:
        calls = []

        def update_stack(self, **request):
            self.calls.append(request)
            return {"ResponseMetadata": {"HTTPStatusCode": 200}, "StackId": STACK_ID}

    class Journal:
        def __init__(self):
            self.value = None

        def load(self):
            return deepcopy(self.value)

        def save(self, value):
            self.value = deepcopy(value)

        def locked(self):
            return nullcontext()

    class SSMWithModificationDate(_SSM):
        def get_parameter(self, *, Name, WithDecryption):
            response = super().get_parameter(Name=Name, WithDecryption=WithDecryption)
            response["Parameter"]["LastModifiedDate"] = datetime.fromtimestamp(start + 200, timezone.utc)
            return response

    raw = {
        "sts": _STS(), "dynamodb": _DynamoDocument(), "ssm": SSMWithModificationDate(), "cloudformation": Cfn(),
    }
    clients = {}
    for name, (service, region, endpoint) in module._SERVICE_META.items():
        client = raw.get(name, object())
        clients[name] = PaceClient(client, service, region, endpoint)
    update_journal, proof_journal = Journal(), Journal()
    material = generate_binding_keys()

    monkeypatch.setattr(module.DevIdentityBindingSseRecoveryCoordinator, "_prepare", lambda self: None)
    monkeypatch.setattr(module.DevIdentityBindingSseRecoveryCoordinator, "_source", lambda self: None)
    monkeypatch.setattr(module.DevIdentityBindingSseRecoveryCoordinator, "_verify_operator_identity", lambda self: None)
    monkeypatch.setattr(module.DevIdentityBindingSseRecoveryCoordinator, "_verify_stack", lambda self, **_: None)
    monkeypatch.setattr(module.DevIdentityBindingSseRecoveryCoordinator, "_verify_parameters", lambda self, **_: None)
    monkeypatch.setattr(
        module.DevIdentityBindingSseRecoveryCoordinator, "_assumed",
        lambda self: ({}, {key: self._active_clients[key] for key in ("sts", "dynamodb", "ssm")}),
    )
    monkeypatch.setattr(module, "_load_keys", lambda *_args, **_kwargs: material)

    coordinator = module.DevIdentityBindingSseRecoveryCoordinator(
        clients, update_journal, probe_journal=proof_journal,
        authorization=auth, binding=binding, recovery_binding=recovery,
        accepted_bootstrap_state=bootstrap, accepted_probe_state=probe,
        accepted_key_state=keys, accepted_runtime_verifier=lambda *_: {},
        explicit_client_factory=lambda _: {}, source_ci_validator=lambda _: None,
        protection_validator=lambda _: None,
        wall_clock=lambda: start + clock["mono"] - 10,
        monotonic=lambda: clock["mono"],
    )
    assert coordinator.run_step("preflight")["ok"] is True
    assert coordinator.run_step("update")["category"] == "update_acknowledged"
    assert coordinator.run_step("readback")["category"] == "sse_recovery_accepted"
    accepted_update = deepcopy(update_journal.value)
    assert coordinator.run_step("exercise")["category"] == "storage_exercise_verified"
    assert proof_journal.value["phase"] == "storage_exercise_verified"
    assert proof_journal.value["update_token"] == accepted_update["intent"]["token"]
    assert update_journal.value == accepted_update
    assert coordinator.run_step("verify")["category"] == "readback_verified"
    assert update_journal.value == accepted_update


@pytest.mark.parametrize("extra_tag", [False, True])
def test_schema_shaped_nine_client_stack_table_and_parameter_readback(monkeypatch, extra_tag):
    """Exercise real recovery comparators against fixed AWS-shaped responses."""
    from copy import deepcopy
    from contextlib import nullcontext
    from types import SimpleNamespace

    from scripts import aws_dev_identity_binding_sse_recovery as module
    from scripts.run_aws_retained_dev_bootstrap import validate_authorization
    from scripts.run_dev_identity_binding_storage_probe import _SYNTHETIC_CONFIG
    from mapit.aws_binding_keys import encode_binding_keys, generate_binding_keys
    from test_run_dev_identity_binding_storage_probe import _DynamoDocument, _SSM

    binding, bootstrap, probe, keys, recovery = _lineage()
    old_template, target_template, _, _, _, _ = _templates(binding)
    start = 1_800_000_000
    auth = validate_authorization({
        "account": ACCOUNT, "expected_caller_arn": CALLER,
        "source_sha": "f" * 40, "ci_run_id": 555,
        "run_id": 987654, "start": start, "end": start + 3600,
    })
    now = [start + 10]
    mono = [1.0]
    material = generate_binding_keys()

    class Client:
        def __init__(self, name, service, region, endpoint, dispatch, *, assumed=False):
            self.meta = SimpleNamespace(
                service_model=SimpleNamespace(service_name=service), region_name=region,
                endpoint_url=endpoint,
                config=SimpleNamespace(retries={"total_max_attempts": 1}, connect_timeout=2, read_timeout=3),
            )
            self.name, self.dispatch, self.assumed = name, dispatch, assumed

        def __getattr__(self, method):
            def call(**kwargs):
                mono[0] += 0.01
                label = ("assumed:" if self.assumed else "") + self.name
                return self.dispatch(label, method, kwargs)
            return call

    class AwsError(Exception):
        def __init__(self, code, status):
            self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}

    class Journal:
        def __init__(self): self.value = None
        def load(self): return deepcopy(self.value)
        def save(self, value): self.value = deepcopy(value)
        def locked(self): return nullcontext()

    ddb_doc = _DynamoDocument()
    ssm_doc = _SSM()
    config_path = "/honda-mapit-mcp/dev/identity-binding-config"
    ssm_doc.values[config_path] = encode_binding_keys(
        material, account_id=ACCOUNT, config=_SYNTHETIC_CONFIG,
    )
    ssm_get_parameter = ssm_doc.get_parameter

    def get_parameter(*, Name, WithDecryption):
        if Name.rstrip(":1") not in ssm_doc.values:
            raise AwsError("ParameterNotFound", 400)
        response = ssm_get_parameter(Name=Name, WithDecryption=WithDecryption)
        response["Parameter"]["LastModifiedDate"] = datetime.fromtimestamp(
            keys["start"] + 1 if "identity-binding-config" in Name else start + 100,
            timezone.utc,
        )
        return response

    ssm_doc.get_parameter = get_parameter

    runtime_template = old_template
    updated = [False]
    current_token = [None]
    stack_id = STACK_ID
    table_arn = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/honda-mapit-mcp-dev-identity-bindings"
    table_time = datetime.fromisoformat(recovery["table_creation_time"])
    table_tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "mapit-identity-bindings"},
        {"Key": "OperatorRunId", "Value": str(bootstrap["run_id"])},
    ]
    if extra_tag:
        table_tags.append({"Key": "UnownedTag", "Value": "must-reject"})
    observed_calls = []

    def reply(**values):
        return {**values, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def dispatch(service, method, request):
        observed_calls.append((service, method))
        if service == "assumed:sts" and method == "get_caller_identity":
            return reply(Account=ACCOUNT,
                         Arn=f"arn:aws:sts::{ACCOUNT}:assumed-role/{module.OPERATOR_ROLE_NAME}/storage-probe-987654",
                         UserId="AIDEXAMPLE:storage-probe-987654")
        if service == "sts" and method == "get_caller_identity":
            return reply(Account=ACCOUNT, Arn=CALLER, UserId="AIDEXAMPLE")
        if service == "sts" and method == "assume_role":
            assert request["RoleArn"] == f"arn:aws:iam::{ACCOUNT}:role/{module.OPERATOR_ROLE_NAME}"
            return reply(Credentials={
                "AccessKeyId": "SYNTHETICKEY", "SecretAccessKey": "synthetic-secret",
                "SessionToken": "synthetic-session",
                "Expiration": datetime.fromtimestamp(start + 1800, timezone.utc),
            })
        if service == "cloudformation":
            if method == "describe_stacks":
                return reply(Stacks=[{
                    "StackName": module.STACK_NAME, "StackId": stack_id,
                    "StackStatus": "UPDATE_COMPLETE" if updated[0] else "CREATE_COMPLETE",
                    "EnableTerminationProtection": True, "RoleARN": None,
                    "Tags": [dict(tag) for tag in table_tags],
                }])
            if method == "get_template":
                return reply(TemplateBody=deepcopy(target_template if updated[0] else runtime_template))
            if method == "describe_stack_resources":
                status = "UPDATE_COMPLETE" if updated[0] else "CREATE_COMPLETE"
                return reply(StackResources=[
                    {"LogicalResourceId": "MapitIdentityBindings", "ResourceType": "AWS::DynamoDB::Table",
                     "PhysicalResourceId": "honda-mapit-mcp-dev-identity-bindings", "StackId": stack_id,
                     "StackName": module.STACK_NAME, "ResourceStatus": status},
                    {"LogicalResourceId": "IdentityEnrollerBoundary", "ResourceType": "AWS::IAM::ManagedPolicy",
                     "PhysicalResourceId": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-identity-enroller-boundary",
                     "StackId": stack_id, "StackName": module.STACK_NAME, "ResourceStatus": status},
                    {"LogicalResourceId": "IdentityEnrollerRole", "ResourceType": "AWS::IAM::Role",
                     "PhysicalResourceId": "honda-mapit-mcp-dev-identity-enroller", "StackId": stack_id,
                     "StackName": module.STACK_NAME, "ResourceStatus": status},
                    {"LogicalResourceId": "RuntimeIdentityBindingPolicy", "ResourceType": "AWS::IAM::Policy",
                     "PhysicalResourceId": recovery["runtime_policy_physical_id"],
                     "StackId": stack_id, "StackName": module.STACK_NAME, "ResourceStatus": status},
                ])
            if method == "describe_stack_events":
                return reply(StackEvents=[{
                    "ClientRequestToken": current_token[0], "StackId": stack_id,
                    "StackName": module.STACK_NAME, "LogicalResourceId": module.STACK_NAME,
                    "PhysicalResourceId": stack_id, "ResourceType": "AWS::CloudFormation::Stack",
                    "ResourceStatus": "UPDATE_COMPLETE",
                    "Timestamp": datetime.fromtimestamp(start + 20, timezone.utc),
                }], NextToken="not-followed")
            if method == "update_stack":
                assert request["StackName"] == module.STACK_NAME
                current_token[0] = request["ClientRequestToken"]
                updated[0] = True
                return reply(StackId=stack_id)
        if service.endswith("dynamodb"):
            if method == "describe_table":
                table = {
                    "TableName": "honda-mapit-mcp-dev-identity-bindings", "TableArn": table_arn,
                    "TableId": recovery["table_id"], "TableStatus": "ACTIVE",
                    "CreationDateTime": table_time, "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
                    "OnDemandThroughput": {"MaxReadRequestUnits": 100, "MaxWriteRequestUnits": 100},
                    "KeySchema": [{"AttributeName": "key", "KeyType": "HASH"}],
                    "AttributeDefinitions": [{"AttributeName": "key", "AttributeType": "S"}],
                    "DeletionProtectionEnabled": True, "GlobalSecondaryIndexes": [],
                    "LocalSecondaryIndexes": [],
                }
                if not updated[0]:
                    table["SSEDescription"] = {"Status": "ENABLED", "SSEType": "KMS",
                                                "KMSMasterKeyArn": recovery["sse_key_arn"]}
                else:
                    table["SSEDescription"] = None
                return reply(Table=table)
            if method == "list_tags_of_resource":
                assert request == {"ResourceArn": table_arn}
                return reply(Tags=[dict(tag) for tag in table_tags])
            if method == "get_item":
                assert request["ConsistentRead"] is True
                return ddb_doc.get_item(**request)
            if method == "put_item":
                return ddb_doc.put_item(**request)
        if service.endswith("ssm"):
            if method == "get_parameter":
                return ssm_doc.get_parameter(**request)
            if method == "put_parameter":
                return ssm_doc.put_parameter(**request)
        raise AssertionError((service, method, request))

    clients = {
        key: Client(key, *meta, dispatch) for key, meta in module._SERVICE_META.items()
    }
    update_journal, proof_journal = Journal(), Journal()
    # The app stack/runtime is already independently verified and deliberately
    # not part of this table-only transition. Exercise the recovery stack/table/
    # parameter comparators themselves without replacing their readbacks.
    monkeypatch.setattr(module.DevIdentityBindingSseRecoveryCoordinator, "_verify_current_app", lambda *_: None)
    coordinator = module.DevIdentityBindingSseRecoveryCoordinator(
        clients, update_journal, probe_journal=proof_journal,
        authorization=auth, binding=binding, recovery_binding=recovery,
        accepted_bootstrap_state=bootstrap, accepted_probe_state=probe,
        accepted_key_state=keys, accepted_runtime_verifier=lambda *_: {},
        explicit_client_factory=lambda _: {
            key: Client(key, *meta, dispatch, assumed=True)
            for key, meta in module._SERVICE_META.items()
            if key in {"sts", "dynamodb", "ssm"}
        }, source_ci_validator=lambda _: None,
        protection_validator=lambda _: None,
        wall_clock=lambda: now[0] + (mono[0] - 1.0), monotonic=lambda: mono[0],
    )
    preflight = coordinator.run_step("preflight")
    if extra_tag:
        assert preflight["category"] == "preflight_conflict", preflight
        assert update_journal.value is None
        assert not updated[0]
        return
    assert preflight["category"] == "preflight_verified", (preflight, observed_calls)
    update = coordinator.run_step("update")
    assert update["category"] == "update_acknowledged", update
    readback = coordinator.run_step("readback")
    assert readback["category"] == "sse_recovery_accepted", readback
    assert update_journal.value["phase"] == "sse_recovery_accepted"
    assert update_journal.value["flags"]["sse_recovery_accepted"] is True
    accepted_update = deepcopy(update_journal.value)
    exercised = coordinator.run_step("exercise")
    assert exercised["category"] == "storage_exercise_verified", exercised
    assert proof_journal.value["update_token"] == accepted_update["intent"]["token"]
    assert update_journal.value == accepted_update
    verified = coordinator.run_step("verify")
    assert verified["category"] == "readback_verified", verified
    assert update_journal.value == accepted_update


@pytest.mark.parametrize("mutate", [
    lambda b, p, k, r: r.__setitem__("table_id", "11111111-1111-1111-1111-11111111111x"),
    lambda b, p, k, r: r.__setitem__("table_creation_time", "2026-10-07T00:00:00+01:00"),
    lambda b, p, k, r: p["flags"].__setitem__("preflight", 1),
    lambda b, p, k, r: k.__setitem__("run_id", True),
    lambda b, p, k, r: b.__setitem__("account", "999999999999"),
    lambda b, p, k, r: r.__setitem__("sse_key_arn", "arn:aws:kms:us-east-1:999999999999:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"),
])
def test_lineage_rejects_malformed_or_cross_bound_historical_receipts(mutate):
    binding, bootstrap, probe, keys, recovery = _lineage()
    mutate(bootstrap, probe, keys, recovery)
    recovery["bootstrap_state_sha256"] = _state_digest(bootstrap)
    recovery["probe_state_sha256"] = _state_digest(probe)
    recovery["key_state_sha256"] = _state_digest(keys)
    with pytest.raises(SseRecoveryError, match="lineage_invalid"):
        validate_recovery_lineage(binding, bootstrap, probe, keys, recovery)
