import contextlib
import copy
import uuid

from mapit.aws_prod_geography_upgrade import (
    AUTHORIZATION_CUTOFF_EPOCH,
    ProdGeographyUpgrade,
    ProdGeographyUpgradeError,
    _only_two_template_changes,
)
from mapit.aws_prod_runtime import CognitoProdPolicy
from scripts.build_aws_prod_controls import fixed_prod_controls_template


ACCOUNT = "123456789012"
API = "a1b2c3d4e5"
FUNCTION = "honda-mapit-mcp-prod-handler"
MACHINE = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-prod-shutdown"
STACK_UUID = "11111111-2222-4333-8444-555555555555"
RUN_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
POOL = "eu-west-1_A1b2C3d4E"
OWNER = "18d8ce2b-8f10-4d72-b80f-ea635b4c6189"
BUCKET = "honda-mapit-mcp-prod-artifacts"


class Journal:
    def __init__(self):
        self.value = None

    def load(self):
        return copy.deepcopy(self.value)

    def save(self, value):
        self.value = copy.deepcopy(value)

    @contextlib.contextmanager
    def locked(self):
        yield


class Stub:
    pass


def make_core():
    policy = CognitoProdPolicy(user_pool_id=POOL, api_id=API,
                               client_id="SyntheticProdClient012345", owner_subject=OWNER)
    journal = Journal()
    clients = {name: Stub() for name in (
        "sts", "cloudformation", "apigatewayv2", "lambda", "stepfunctions",
        "cloudwatch", "events",
    )}
    core = ProdGeographyUpgrade(
        clients, journal, policy=policy, account_id=ACCOUNT,
        stack_arn=f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-prod/{STACK_UUID}",
        prod_run_id=RUN_ID, api_id=API, function_name=FUNCTION,
        shutdown_state_machine_arn=MACHINE, bucket=BUCKET,
        old_zip_sha256="1" * 64, old_manifest_sha256="2" * 64,
        new_zip_sha256="3" * 64, new_manifest_sha256="4" * 64,
        authorized_until_epoch=AUTHORIZATION_CUTOFF_EPOCH,
    )
    return core, journal


def test_template_candidate_changes_only_zip_key_and_manifest_digest():
    core, _ = make_core()
    assert _only_two_template_changes(core.old_template, core.new_template)
    altered = copy.deepcopy(core.new_template)
    altered["Resources"]["McpHandler"]["Properties"]["Timeout"] += 1
    assert not _only_two_template_changes(core.old_template, altered)


def test_constructor_binds_fixed_account_stack_function_machine_and_cutoff():
    core, _ = make_core()
    assert core.STEPS == ("preflight", "close", "check-close", "request-update", "check-update", "open")
    assert core.shutdown_arn == MACHINE


def test_constructor_rejects_wrong_machine_arn_without_client_calls():
    policy = CognitoProdPolicy(user_pool_id=POOL, api_id=API,
                               client_id="SyntheticProdClient012345", owner_subject=OWNER)
    try:
        ProdGeographyUpgrade(
            {name: Stub() for name in ("sts", "cloudformation", "apigatewayv2", "lambda", "stepfunctions", "cloudwatch", "events")},
            Journal(), policy=policy, account_id=ACCOUNT,
            stack_arn=f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-prod/{STACK_UUID}",
            prod_run_id=RUN_ID, api_id=API, function_name=FUNCTION,
            shutdown_state_machine_arn=MACHINE.replace("stateMachine:", "stateMachine/"),
            bucket=BUCKET, old_zip_sha256="1" * 64, old_manifest_sha256="2" * 64,
            new_zip_sha256="3" * 64, new_manifest_sha256="4" * 64,
            authorized_until_epoch=AUTHORIZATION_CUTOFF_EPOCH,
        )
    except ProdGeographyUpgradeError as exc:
        assert exc.category == "inputs_invalid"
    else:
        raise AssertionError("invalid machine ARN accepted")


def test_api_readback_requires_exact_template_name_and_endpoint_state():
    core, _ = make_core()
    core._step_started = core.monotonic()
    core._call = lambda *args, **kwargs: {
        "ApiId": API, "Name": "honda-mapit-mcp-prod-api",
        "DisableExecuteApiEndpoint": True,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    core._api(closed=True)
    core._call = lambda *args, **kwargs: {
        "ApiId": API, "Name": "honda-mapit-mcp-prod",
        "DisableExecuteApiEndpoint": True,
        "ResponseMetadata": {"HTTPStatusCode": 200},
    }
    try:
        core._api(closed=True)
    except ProdGeographyUpgradeError as exc:
        assert exc.category == "api_state_mismatch"
    else:
        raise AssertionError("incorrect API name accepted")


def test_tripwire_binds_exact_standard_shutdown_definition():
    core, _ = make_core()
    core._step_started = core.monotonic()
    resources = fixed_prod_controls_template(API)["Resources"]
    alarm = resources["RequestTripwireAlarm"]["Properties"]
    pattern = {
        "source": ["aws.cloudwatch"], "detail-type": ["CloudWatch Alarm State Change"],
        "account": [ACCOUNT], "region": ["eu-west-1"],
        "resources": [f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-prod-request-tripwire"],
        "detail": {"alarmName": ["honda-mapit-mcp-prod-request-tripwire"], "state": {"value": ["ALARM"]}},
    }
    target = {
        "Id": "StartFixedProdShutdownWorkflow", "Arn": MACHINE,
        "RoleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-request-tripwire",
        "Input": "{}", "RetryPolicy": {"MaximumRetryAttempts": 0, "MaximumEventAgeInSeconds": 60},
    }
    expected_definition = resources["ShutdownStateMachine"]["Properties"]["DefinitionString"]
    machine = {"stateMachineArn": MACHINE, "name": "honda-mapit-mcp-prod-shutdown",
               "roleArn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-shutdown-workflow",
               "status": "ACTIVE", "type": "STANDARD", "definition": expected_definition}

    def configure(machine_result):
        def call(service, method, **kwargs):
            metadata = {"ResponseMetadata": {"HTTPStatusCode": 200}}
            if method == "describe_alarms":
                actual = dict(alarm)
                actual.update(ActionsEnabled=True, AlarmActions=[], OKActions=[], InsufficientDataActions=[])
                return {"MetricAlarms": [actual], **metadata}
            if method == "describe_rule":
                return {"Name": "honda-mapit-mcp-prod-request-tripwire-alarm-rule",
                        "Arn": f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/honda-mapit-mcp-prod-request-tripwire-alarm-rule",
                        "State": "ENABLED", "EventPattern": pattern, **metadata}
            if method == "list_targets_by_rule":
                return {"Targets": [target], **metadata}
            if method == "describe_state_machine":
                return {**machine_result, **metadata}
            raise AssertionError(method)
        core._call = call

    configure(machine)
    assert core._tripwire()["rule"]["State"] == "ENABLED"
    tampered = dict(machine)
    tampered["definition"] = expected_definition.replace("updateApi", "deleteApi", 1)
    configure(tampered)
    try:
        core._tripwire()
    except ProdGeographyUpgradeError as exc:
        assert exc.category == "shutdown_machine_mismatch"
    else:
        raise AssertionError("altered shutdown workflow accepted")


def test_open_reconciles_ambiguous_reserve_and_api_ack_without_replaying_writes():
    core, journal = make_core()
    core._step_started = core.monotonic()
    state = core._save_new_state()
    state.update(preflight_verified=True, close_verified=True, update_verified=True,
                 tripwire_fingerprint="fingerprint", concurrency_restore_intent=True,
                 api_open_intent=True)
    journal.save(state)
    core._guard = lambda **kwargs: 1_791_042_000
    core._function = lambda **kwargs: None
    core._capacity = lambda: None
    core._api = lambda **kwargs: None
    core._tripwire = lambda **kwargs: {"safe": True}
    import hashlib
    import json
    journal.value["tripwire_fingerprint"] = hashlib.sha256(
        json.dumps({"safe": True}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    calls = []

    def call(service, method, **kwargs):
        calls.append((service, method, kwargs))
        if method == "get_api":
            return {"ApiId": API, "DisableExecuteApiEndpoint": False,
                    "ResponseMetadata": {"HTTPStatusCode": 200}}
        raise AssertionError("an ambiguous write must not be replayed")

    core._call = call
    result = core._step_open()
    assert result["category"] == "production_open_verified"
    assert result["verified"] is True
    assert [entry[1] for entry in calls] == ["get_api"]
    assert journal.value["concurrency_restore_acknowledged"] is True
    assert journal.value["production_open_verified"] is True


def test_open_persists_intent_before_each_enable_write(monkeypatch):
    core, journal = make_core()
    core._step_started = core.monotonic()
    state = core._save_new_state()
    state.update(preflight_verified=True, close_verified=True, update_verified=True)
    import hashlib
    import json
    tripwire = {"safe": True}
    state["tripwire_fingerprint"] = hashlib.sha256(
        json.dumps(tripwire, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()
    journal.save(state)
    core._guard = lambda **kwargs: 1_791_042_000
    core._function = lambda **kwargs: None
    core._capacity = lambda: None
    core._api = lambda **kwargs: None
    core._tripwire = lambda **kwargs: tripwire
    events = []

    def call(service, method, **kwargs):
        events.append(method)
        current = journal.load()
        if method == "delete_function_concurrency":
            assert current.get("concurrency_restore_intent") is True
            return {"ResponseMetadata": {"HTTPStatusCode": 204}}
        if method == "update_api":
            assert current.get("api_open_intent") is True
            return {"ApiId": API, "ResponseMetadata": {"HTTPStatusCode": 201}}
        if method == "get_api":
            return {"ApiId": API, "DisableExecuteApiEndpoint": False,
                    "ResponseMetadata": {"HTTPStatusCode": 200}}
        raise AssertionError(method)

    core._call = call
    result = core._step_open()
    assert result["verified"] is True
    assert events == ["delete_function_concurrency", "update_api", "get_api"]
