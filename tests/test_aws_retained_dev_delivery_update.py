from __future__ import annotations

import base64
import copy
import hashlib
import json
from contextlib import contextmanager
import io
import zipfile

import pytest

from scripts.aws_retained_dev_delivery_update import RetainedDevUpdateCoordinator, RetainedDevUpdateError
from scripts.aws_retained_dev_delivery_artifact import RetainedDevArtifactReceipt
from scripts.build_aws_retained_dev_archive import _make_receipt
from scripts.aws_retained_dev_prior_code import PriorCodeSnapshot
from scripts.build_aws_retained_dev import HANDLER_CODE, build_retained_dev_template
from scripts.build_aws_retained_dev_runtime import build_retained_dev_manifest, build_retained_dev_runtime_template, retained_dev_artifact_bucket


ACCOUNT = "123456789012"
STACK_NAME = "honda-mapit-mcp-dev-retained"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/11111111-2222-4333-8444-555555555555"
API = "a1b2c3d4e5"
SOURCE = "a" * 40
OLD_ZIP = "b" * 64
NEW_ZIP = "c" * 64
MANIFEST = "d" * 64
JWKS = "e" * 64
RUN = "12345678-1234-4234-8234-123456789abc"
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-dev-executor"
CFN_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
HANDLER_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"


def _ok(**value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Journal:
    def __init__(self):
        self.state = None
        self.saves = []

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def compare_and_set(self, expected, value):
        current = self.state.get("revision") if isinstance(self.state, dict) else None
        if current != expected:
            return False
        self.state = copy.deepcopy(value)
        self.saves.append(copy.deepcopy(value))
        return True


class CloudFormation:
    def __init__(self, prior):
        self.prior = prior
        self.updated = False
        self.calls = []
        self.fail_update = False
        self.omit_update_event = False

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        return _ok(Stacks=[{
            "StackId": STACK, "StackName": STACK_NAME,
            "StackStatus": "UPDATE_COMPLETE" if self.updated else "CREATE_COMPLETE",
            "RoleARN": CFN_ROLE,
        }])

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        return _ok(TemplateBody=build_retained_dev_runtime_template(ACCOUNT, API, NEW_ZIP if self.updated else OLD_ZIP, JWKS)) if self.updated else _ok(TemplateBody=self.prior)

    def describe_stack_resources(self, **kwargs):
        self.calls.append(("describe_stack_resources", kwargs))
        physical = {
            "McpApi": API, "McpApiStage": "$default", "McpHandlerRole": "honda-mapit-mcp-dev-retained-handler-role",
            "McpHandlerLogGroup": "/aws/lambda/honda-mapit-mcp-dev-retained-handler", "McpHandler": "honda-mapit-mcp-dev-retained-handler",
        }
        kinds = {
            "McpApi": "AWS::ApiGatewayV2::Api", "McpApiStage": "AWS::ApiGatewayV2::Stage", "McpHandlerRole": "AWS::IAM::Role",
            "McpHandlerLogGroup": "AWS::Logs::LogGroup", "McpHandler": "AWS::Lambda::Function",
        }
        return _ok(StackResources=[{
            "LogicalResourceId": logical, "ResourceType": kind, "PhysicalResourceId": physical[logical],
            "ResourceStatus": "UPDATE_COMPLETE" if self.updated else "CREATE_COMPLETE", "StackId": STACK, "StackName": STACK_NAME,
        } for logical, kind in kinds.items()])

    def update_stack(self, **kwargs):
        self.calls.append(("update_stack", kwargs))
        if self.fail_update:
            raise RuntimeError("ambiguous-private")
        self.updated = True
        return _ok(StackId=STACK)

    def describe_stack_events(self, **kwargs):
        self.calls.append(("describe_stack_events", kwargs))
        if not self.updated or self.omit_update_event:
            return _ok(StackEvents=[])
        return _ok(StackEvents=[{
            "StackId": STACK, "StackName": STACK_NAME,
            "ClientRequestToken": RUN, "ResourceStatus": "UPDATE_COMPLETE",
            "ResourceType": "AWS::CloudFormation::Stack", "LogicalResourceId": STACK_NAME, "PhysicalResourceId": STACK,
        }])


class Sts:
    def get_caller_identity(self, **kwargs):
        return _ok(Account=ACCOUNT, Arn=CALLER)


class S3:
    def head_object(self, **kwargs):
        digest = OLD_ZIP if kwargs["Key"] == f"runtime/{OLD_ZIP}.zip" else NEW_ZIP
        return _ok(ContentLength=1, ChecksumSHA256=base64.b64encode(bytes.fromhex(digest)).decode("ascii"), ServerSideEncryption="AES256", ContentType="application/zip")


class Api:
    def get_api(self, **kwargs):
        return _ok(ApiId=API, Name="honda-mapit-mcp-dev-retained-api", ProtocolType="HTTP", DisableExecuteApiEndpoint=True)

    def get_routes(self, **kwargs):
        return _ok(Items=[])


class Lambda:
    def __init__(self, cfn):
        self.cfn = cfn
        self.calls = []

    def get_function_configuration(self, **kwargs):
        self.calls.append(("get_function_configuration", kwargs))
        return _ok(
            FunctionName="honda-mapit-mcp-dev-retained-handler", Role=HANDLER_ROLE,
            Runtime="python3.13", Handler="mapit.aws_dev_entrypoint.handler",
            Architectures=["arm64"], MemorySize=256, Timeout=20, State="Active",
            LastUpdateStatus="Successful",
            Environment={"Variables": {
                "MAPIT_MCP_ENV": "dev", "MAPIT_COGNITO_USER_POOL_ID": "eu-west-1_SYNTHETICDEV",
                "MAPIT_API_ID": API, "MAPIT_COGNITO_CLIENT_ID": "SyntheticRetainedDevClient",
                "MAPIT_OWNER_SUBJECT": "00000000-0000-4000-8000-000000000001",
                "MAPIT_COGNITO_JWKS_SHA256": JWKS,
                "MAPIT_DEV_EXECUTION_START_EPOCH": "1893456000", "MAPIT_DEV_EXECUTION_END_EPOCH": "1893456300",
            }},
        )

    def get_function_concurrency(self, **kwargs):
        self.calls.append(("get_function_concurrency", kwargs))
        return _ok(ReservedConcurrentExecutions=0)

    def list_tags(self, **kwargs):
        self.calls.append(("list_tags", kwargs))
        return _ok(Tags={
            "Project": "honda-mapit-mcp",
            "Environment": "dev",
            "Purpose": "retained-dev",
        })

    def get_function(self, **kwargs):
        self.calls.append(("get_function", kwargs))
        digest = NEW_ZIP if self.cfn.updated else OLD_ZIP
        return _ok(Configuration={"CodeSha256": base64.b64encode(bytes.fromhex(digest)).decode("ascii")})


def _prior():
    return build_retained_dev_runtime_template(ACCOUNT, API, OLD_ZIP, JWKS)


def _coordinator(journal=None, *, fail_update=False, prior=None, wall=lambda: 1_893_456_100, mono=lambda: 1.0):
    prior = prior or _prior()
    cfn = CloudFormation(prior); cfn.fail_update = fail_update
    receipt = _make_receipt(
        source_sha=SOURCE, api_id=API, jwks_sha256=JWKS,
        execution_start_epoch=1_893_456_000, execution_end_epoch=1_893_456_300,
        zip_sha256=NEW_ZIP,
        manifest_sha256=hashlib.sha256(json.dumps(build_retained_dev_manifest(SOURCE, API, JWKS), sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        source_allowlist_sha256="f" * 64, source_proof_sha256="e" * 64,
        wheel_lock_sha256="d" * 64, wheel_proof_sha256="c" * 64,
        archive_entries=1, wheel_count=0, source_modules=0, public_key_count=1,
    )
    old_receipt = RetainedDevArtifactReceipt(f"runtime/{OLD_ZIP}.zip", OLD_ZIP, MANIFEST, 1, "AES256")
    candidate_receipt = RetainedDevArtifactReceipt(f"runtime/{NEW_ZIP}.zip", NEW_ZIP, receipt.manifest_sha256, 1, "AES256")
    clients = {"sts": Sts(), "cloudformation": cfn, "lambda": Lambda(cfn), "apigatewayv2": Api(), "s3": S3()}
    c = RetainedDevUpdateCoordinator(
        clients, journal or Journal(), account_id=ACCOUNT, stack_arn=STACK, api_id=API, source_sha=SOURCE, run_id=RUN,
        prior_template_body=prior, prior_template_sha256=hashlib.sha256(json.dumps(prior, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        prior_zip_sha256=OLD_ZIP, build_receipt=receipt,
        prior_artifact_receipt=old_receipt, candidate_artifact_receipt=candidate_receipt,
        execution_start_epoch=1_893_456_000, execution_end_epoch=1_893_456_300,
        expected_caller_arn=CALLER, authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000,
        wall_clock=wall, monotonic=mono,
    )
    return c, cfn


def test_closed_update_sequence_uses_exact_role_capability_and_readback():
    journal = Journal(); c, cfn = _coordinator(journal)
    assert c.run_step("preflight")["category"] == "preflight_verified"
    assert c.run_step("request-update")["category"] == "update_acknowledged"
    result = c.run_step("check-update")
    assert result["category"] == "readback_verified" and result["verified"] is True
    update = next(kwargs for name, kwargs in cfn.calls if name == "update_stack")
    assert update["RoleARN"] == CFN_ROLE
    assert update["Capabilities"] == ["CAPABILITY_NAMED_IAM"]
    assert update["ClientRequestToken"] == RUN
    assert [row["revision"] for row in journal.saves] == [1, 2, 3, 4]


def test_ambiguous_update_is_reconciled_without_replay():
    journal = Journal(); c, cfn = _coordinator(journal, fail_update=True)
    assert c.run_step("preflight")["category"] == "preflight_verified"
    assert c.run_step("request-update")["category"] == "update_outcome_unknown"
    assert c.run_step("request-update")["category"] == "update_intent_present"
    assert sum(name == "update_stack" for name, _ in cfn.calls) == 1


def test_ambiguous_write_event_does_not_invent_http_ack():
    class EventualCloudFormation(CloudFormation):
        def update_stack(self, **kwargs):
            self.calls.append(("update_stack", kwargs))
            self.updated = True
            raise RuntimeError("ambiguous-private")

    journal = Journal(); c, cfn = _coordinator(journal)
    cfn.__class__ = EventualCloudFormation
    assert c.run_step("preflight")["category"] == "preflight_verified"
    assert c.run_step("request-update")["category"] == "update_outcome_unknown"
    result = c.run_step("check-update")
    assert result["category"] == "update_reconciled_without_ack"
    assert journal.state["update_acknowledged"] is False
    assert journal.state["update_event_observed"] is True
    assert journal.state["update_verified"] is False


def test_complete_stack_without_matching_request_event_is_not_verified():
    journal = Journal(); c, cfn = _coordinator(journal)
    assert c.run_step("preflight")["category"] == "preflight_verified"
    assert c.run_step("request-update")["category"] == "update_acknowledged"
    cfn.omit_update_event = True
    result = c.run_step("check-update")
    assert result["category"] == "update_outcome_unknown"
    assert journal.state["update_acknowledged"] is True
    assert journal.state["update_verified"] is False


def test_initial_inline_scaffold_is_rejected_without_recovery_snapshot():
    prior = _prior()
    prior["Resources"]["McpHandler"]["Properties"]["Code"] = {"ZipFile": "inline-503"}
    with pytest.raises(RetainedDevUpdateError, match="prior_recovery_unavailable"):
        _coordinator(prior=prior)


def test_exact_initial_snapshot_can_authorize_inline_prior_recovery():
    prior = build_retained_dev_template()
    template_bytes = json.dumps(prior, sort_keys=True, separators=(",", ":")).encode()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("index.py", HANDLER_CODE)
    archive_bytes = archive.getvalue()
    snapshot = PriorCodeSnapshot(
        archive_bytes=archive_bytes, template_bytes=template_bytes,
        zip_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        template_sha256=hashlib.sha256(template_bytes).hexdigest(), observed_epoch=1_893_456_100,
    )
    assert RetainedDevUpdateCoordinator._accepted_prior_template(
        prior, snapshot.zip_sha256, ACCOUNT, snapshot,
    )


def test_route_or_current_code_mismatch_fails_closed():
    class BadApi(Api):
        def get_routes(self, **kwargs):
            return _ok(Items=[{"RouteKey": "ANY /"}])
    prior = _prior(); journal = Journal(); c, _ = _coordinator(journal, prior=prior)
    c.clients["apigatewayv2"] = BadApi()
    assert c.run_step("preflight")["category"] == "preflight_mismatch"


def test_persisted_wall_clock_rejects_rollback_on_new_coordinator():
    journal = Journal(); c, _ = _coordinator(journal, wall=lambda: 1_893_456_100)
    assert c.run_step("preflight")["category"] == "preflight_verified"
    older, _ = _coordinator(journal, wall=lambda: 1_893_456_099)
    assert older.run_step("request-update")["category"] == "window_expired"
