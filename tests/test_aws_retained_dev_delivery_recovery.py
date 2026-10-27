from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
import hashlib
import io
import json
import zipfile

import pytest

from scripts.aws_retained_dev_delivery_recovery import RetainedDevRecoveryCoordinator
from scripts.aws_retained_dev_recovery_artifact import RetainedDevRecoveryArtifactReceipt
from scripts.aws_retained_dev_prior_code import HANDLER_CODE, PriorCodeSnapshot
from scripts.build_aws_retained_dev import build_retained_dev_template
from scripts.build_aws_retained_dev_archive import _make_receipt
from scripts.build_aws_retained_dev_recovery import build_initial_recovery_template, materialize_recovery_template
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest, build_retained_dev_runtime_template, retained_dev_artifact_bucket


ACCOUNT = "123456789012"
API = "a1b2c3d4e5"
STACK_NAME = "honda-mapit-mcp-dev-retained"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/11111111-2222-4333-8444-555555555555"
SOURCE = "a" * 40
CURRENT_ZIP = "b" * 64
JWKS = "e" * 64
RUN = "12345678-1234-4234-8234-123456789abc"
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-dev-executor"
CFN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
HANDLER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"


def _ok(**value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Journal:
    def __init__(self): self.state = None; self.saves = []
    @contextmanager
    def locked(self): yield
    def load(self): return copy.deepcopy(self.state)
    def compare_and_set(self, expected, value):
        current = self.state.get("revision") if isinstance(self.state, dict) else None
        if current != expected: return False
        self.state = copy.deepcopy(value); self.saves.append(copy.deepcopy(value)); return True


def _snapshot():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        # A restarted coordinator reconstructs the same accepted artifact.
        # ZipFile's implicit current DOS timestamp otherwise changes the ZIP
        # digest across a two-second boundary and correctly invalidates its
        # journal binding, making this recovery test time-dependent.
        info = zipfile.ZipInfo("index.py", date_time=(2030, 1, 1, 0, 0, 0))
        archive.writestr(info, HANDLER_CODE)
    body = stream.getvalue(); template = json.dumps(build_retained_dev_template(), sort_keys=True, separators=(",", ":")).encode()
    return PriorCodeSnapshot(body, template, hashlib.sha256(body).hexdigest(), hashlib.sha256(template).hexdigest(), 1_893_456_100)


class Sts:
    def get_caller_identity(self, **kwargs): return _ok(Account=ACCOUNT, Arn=CALLER)


class CloudFormation:
    def __init__(self, current, recovery):
        self.current, self.recovery = current, recovery; self.updated = False; self.calls = []; self.ambiguous = False; self.wrong_event = False; self.omit_role = False
    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs)); row = {"StackId": STACK, "StackName": STACK_NAME, "StackStatus": "UPDATE_COMPLETE" if self.updated else "CREATE_COMPLETE", "RoleARN": CFN_ROLE}
        if self.omit_role: row.pop("RoleARN")
        return _ok(Stacks=[row])
    def get_template(self, **kwargs): self.calls.append(("get_template", kwargs)); return _ok(TemplateBody=self.recovery if self.updated else self.current)
    def describe_stack_resources(self, **kwargs):
        self.calls.append(("describe_stack_resources", kwargs)); physical = {"McpApi": API, "McpApiStage": "$default", "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role", "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler", "McpHandler": "honda-mapit-mcp-dev-retained-handler"}
        return _ok(StackResources=[{"LogicalResourceId": key, "ResourceType": value, "PhysicalResourceId": physical[key], "ResourceStatus": "UPDATE_COMPLETE" if self.updated else "CREATE_COMPLETE", "StackId": STACK, "StackName": STACK_NAME} for key, value in {"McpApi":"AWS::ApiGatewayV2::Api","McpApiStage":"AWS::ApiGatewayV2::Stage","McpHandlerRole":"AWS::IAM::Role","McpHandlerLogGroup":"AWS::Logs::LogGroup","McpHandler":"AWS::Lambda::Function"}.items()])
    def update_stack(self, **kwargs):
        self.calls.append(("update_stack", kwargs)); self.updated = True
        if self.ambiguous: raise RuntimeError("ambiguous")
        return _ok(StackId=STACK)
    def describe_stack_events(self, **kwargs):
        self.calls.append(("describe_stack_events", kwargs)); token = "other" if self.wrong_event else RUN
        return _ok(StackEvents=[{"StackId": STACK, "StackName": STACK_NAME, "ClientRequestToken": token, "ResourceStatus": "UPDATE_COMPLETE", "ResourceType": "AWS::CloudFormation::Stack", "LogicalResourceId": STACK_NAME, "PhysicalResourceId": STACK}])


class Api:
    def get_api(self, **kwargs): return _ok(ApiId=API, ProtocolType="HTTP", DisableExecuteApiEndpoint=True)
    def get_routes(self, **kwargs): return _ok(Items=[])


class S3:
    def __init__(self, body): self.body = body; self.calls = []
    def head_object(self, **kwargs):
        self.calls.append(kwargs); return _ok(ContentLength=len(self.body), ChecksumSHA256=base64.b64encode(hashlib.sha256(self.body).digest()).decode(), ServerSideEncryption="AES256", ContentType="application/zip")


class Lambda:
    def __init__(self, cfn, snapshot): self.cfn, self.snapshot = cfn, snapshot; self.calls = []
    def get_function_configuration(self, **kwargs):
        self.calls.append(("get_function_configuration", kwargs))
        if self.cfn.updated: return _ok(FunctionName="honda-mapit-mcp-dev-retained-handler", Role=HANDLER_ROLE, Runtime="python3.13", Handler="index.handler", Architectures=["arm64"], MemorySize=256, Timeout=20, State="Active", LastUpdateStatus="Successful")
        return _ok(FunctionName="honda-mapit-mcp-dev-retained-handler", Role=HANDLER_ROLE, Runtime="python3.13", Handler="mapit.aws_dev_entrypoint.handler", Architectures=["arm64"], MemorySize=256, Timeout=20, State="Active", LastUpdateStatus="Successful", Environment={"Variables":{"MAPIT_MCP_ENV":"dev","MAPIT_COGNITO_USER_POOL_ID":"eu-west-1_SYNTHETICDEV","MAPIT_API_ID":API,"MAPIT_COGNITO_CLIENT_ID":"SyntheticRetainedDevClient","MAPIT_OWNER_SUBJECT":"00000000-0000-4000-8000-000000000001","MAPIT_COGNITO_JWKS_SHA256":JWKS,"MAPIT_DEV_EXECUTION_START_EPOCH":"1893456000","MAPIT_DEV_EXECUTION_END_EPOCH":"1893456300"}})
    def get_function_concurrency(self, **kwargs): self.calls.append(("get_function_concurrency", kwargs)); return _ok(ReservedConcurrentExecutions=0)
    def list_tags(self, **kwargs): self.calls.append(("list_tags", kwargs)); return _ok(Tags={"Project":"honda-mapit-mcp","Environment":"dev","Purpose":"retained-dev"})
    def get_function(self, **kwargs):
        self.calls.append(("get_function", kwargs)); digest = self.snapshot.zip_sha256 if self.cfn.updated else CURRENT_ZIP
        return _ok(Configuration={"CodeSha256": base64.b64encode(bytes.fromhex(digest)).decode()})


def _coordinator(journal=None, *, ambiguous=False, wrong_event=False, omit_role=False, wall=lambda: 1_893_456_100):
    snapshot = _snapshot(); recovery = build_initial_recovery_template(ACCOUNT, snapshot); recovery_body = materialize_recovery_template(recovery)
    current = build_retained_dev_runtime_template(ACCOUNT, API, CURRENT_ZIP, JWKS)
    receipt = _make_receipt(source_sha=SOURCE, api_id=API, jwks_sha256=JWKS, execution_start_epoch=1_893_456_000, execution_end_epoch=1_893_456_300, zip_sha256=CURRENT_ZIP, manifest_sha256=hashlib.sha256(json.dumps(build_retained_dev_manifest(SOURCE, API, JWKS), sort_keys=True, separators=(",", ":")).encode()).hexdigest(), source_allowlist_sha256="f"*64, source_proof_sha256="e"*64, wheel_lock_sha256="d"*64, wheel_proof_sha256="c"*64, archive_entries=1, wheel_count=0, source_modules=0, public_key_count=1)
    artifact = RetainedDevRecoveryArtifactReceipt(retained_dev_artifact_bucket(ACCOUNT), recovery.key, snapshot.zip_sha256, snapshot.template_sha256, len(snapshot.archive_bytes))
    cfn = CloudFormation(current, recovery_body); cfn.ambiguous = ambiguous; cfn.wrong_event = wrong_event; cfn.omit_role = omit_role
    clients = {"sts": Sts(), "cloudformation": cfn, "lambda": Lambda(cfn, snapshot), "apigatewayv2": Api(), "s3": S3(snapshot.archive_bytes)}
    coordinator = RetainedDevRecoveryCoordinator(clients, journal or Journal(), account_id=ACCOUNT, stack_arn=STACK, api_id=API, run_id=RUN, source_sha=SOURCE, current_build_receipt=receipt, recovery_template=recovery, recovery_artifact=artifact, expected_caller_arn=CALLER, authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000, wall_clock=wall, monotonic=lambda: 1.0)
    return coordinator, cfn, clients, snapshot


def test_restart_fixture_snapshot_is_deterministic_across_reconstruction(monkeypatch):
    monkeypatch.setattr(zipfile.time, "localtime", lambda *_: (2030, 1, 1, 0, 0, 0, 1, 1, -1))
    first = _snapshot()
    monkeypatch.setattr(zipfile.time, "localtime", lambda *_: (2030, 1, 1, 0, 0, 2, 1, 1, -1))
    second = _snapshot()
    assert first.zip_sha256 == second.zip_sha256
    assert first.archive_bytes == second.archive_bytes


def test_closed_recovery_updates_template_once_and_reads_exact_closed_state():
    journal = Journal(); coordinator, cfn, clients, _ = _coordinator(journal)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_acknowledged"
    assert coordinator.run_step("check-update")["category"] == "readback_verified"
    update = next(kwargs for name, kwargs in cfn.calls if name == "update_stack")
    assert update["RoleARN"] == CFN_ROLE and update["Capabilities"] == ["CAPABILITY_NAMED_IAM"] and update["ClientRequestToken"] == RUN
    assert not hasattr(clients["lambda"], "update_function_code")
    assert any(name == "get_function_concurrency" for name, _ in clients["lambda"].calls)


def test_ambiguous_recovery_never_replays_and_matching_event_reconciles_without_ack():
    journal = Journal(); coordinator, cfn, _, _ = _coordinator(journal, ambiguous=True)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    assert coordinator.run_step("request-update")["category"] == "update_intent_present"
    assert coordinator.run_step("check-update")["category"] == "update_reconciled_without_ack"
    assert sum(name == "update_stack" for name, _ in cfn.calls) == 1


def test_wrong_event_token_does_not_verify_rollback():
    journal = Journal(); coordinator, _, _, _ = _coordinator(journal, ambiguous=True, wrong_event=True)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    assert coordinator.run_step("check-update")["category"] == "update_outcome_unknown"
    assert journal.state["update_verified"] is False


def test_missing_persistent_cfn_role_fails_closed_before_update():
    coordinator, _, _, _ = _coordinator(omit_role=True)
    assert coordinator.run_step("preflight")["category"] == "preflight_mismatch"


def test_restart_reconciles_the_existing_intent_without_replaying_update():
    journal = Journal(); first, cfn, clients, snapshot = _coordinator(journal, ambiguous=True)
    assert first.run_step("preflight")["category"] == "preflight_verified"
    assert first.run_step("request-update")["category"] == "update_outcome_unknown"
    second, _, _, _ = _coordinator(journal)
    # Preserve the provider state and client objects across the simulated
    # process restart; only the coordinator instance is recreated.
    second.clients = clients
    assert second.run_step("check-update")["category"] == "update_reconciled_without_ack"
    assert sum(name == "update_stack" for name, _ in cfn.calls) == 1


def test_restart_with_older_wall_clock_is_fenced_before_business_write():
    journal = Journal(); first, cfn, _, _ = _coordinator(journal)
    assert first.run_step("preflight")["category"] == "preflight_verified"
    older, _, _, _ = _coordinator(journal, wall=lambda: 1_893_456_099)
    assert older.run_step("request-update")["category"] == "window_expired"
    assert not any(name == "update_stack" for name, _ in cfn.calls)


def test_restart_with_advanced_wall_clock_accepts_persisted_preflight():
    clock = {"value": 1_893_456_100}
    journal = Journal()
    first, _, _, _ = _coordinator(journal, wall=lambda: clock["value"])
    assert first.run_step("preflight")["category"] == "preflight_verified"
    clock["value"] += 10
    resumed, cfn, _, _ = _coordinator(journal, wall=lambda: clock["value"])
    assert resumed.run_step("request-update")["category"] == "update_acknowledged"
    assert sum(name == "update_stack" for name, _ in cfn.calls) == 1


def test_clock_expiry_after_update_call_is_outcome_unknown():
    clock = {"value": 1_893_456_100}
    coordinator, cfn, _, _ = _coordinator(wall=lambda: clock["value"])
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    original = cfn.update_stack
    def late_update(**kwargs):
        reply = original(**kwargs)
        clock["value"] = 1_893_458_000
        return reply
    cfn.update_stack = late_update
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    assert coordinator.run_step("request-update")["category"] == "window_expired"


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema", 2),
        ("kind", "retained-dev-other-kind"),
        ("account_id", "999999999999"),
        ("stack_arn", STACK.replace(ACCOUNT, "999999999999")),
        ("api_id", "f" * 10),
        ("current_zip_sha256", "f" * 64),
        ("current_template_sha256", "f" * 64),
        ("prior_zip_sha256", "f" * 64),
        ("prior_template_sha256", "f" * 64),
        ("prior_artifact_key", "runtime/" + "f" * 64 + ".zip"),
        ("status", "verified"),
        ("revision", 10_000),
        ("last_observed_epoch", 1_893_454_999),
    ],
)
def test_recovery_core_rejects_mutated_persisted_binding_and_state(field, value):
    """The coordinator must validate the persisted envelope independently of a journal adapter."""
    journal = Journal()
    coordinator, cfn, _, _ = _coordinator(journal)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    journal.state[field] = value

    result = coordinator.run_step("request-update")
    assert result["category"] == "journal_invalid"
    assert not any(name == "update_stack" for name, _ in cfn.calls)
