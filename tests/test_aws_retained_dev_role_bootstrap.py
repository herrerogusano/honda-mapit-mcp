from __future__ import annotations

from contextlib import contextmanager
import hashlib
import copy

from scripts.aws_retained_dev_role_bootstrap import RetainedDevRoleBootstrapCoordinator, _document
from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles

ACCOUNT = "123456789012"
SOURCE = "a" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-artifact-operator"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
APP_STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-cd-delivery/22222222-3333-4444-8555-666666666666"
ARTIFACT = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/11111111-2222-4333-8444-555555555555"
BUCKET = f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
HANDLER = f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler"
EXECUTION = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role"
API = "arn:aws:apigateway:eu-west-1::/apis/abcdefghij"
SHUTDOWN = f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown"


def _ok(**value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


class Err(Exception):
    def __init__(self, code, status, message):
        self.response = {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPStatusCode": status}}


class Journal:
    def __init__(self): self.state = None
    @contextmanager
    def locked(self): yield
    def load(self): return copy.deepcopy(self.state)
    def save(self, value): self.state = copy.deepcopy(value)


class Sts:
    def get_caller_identity(self): return _ok(Account=ACCOUNT, Arn=CALLER)


class Iam:
    def __init__(self): self.calls = []
    def _absent(self, **kwargs): self.calls.append(kwargs); raise Err("NoSuchEntity", 404, "missing")
    get_role = _absent
    get_policy = _absent
    def get_open_id_connect_provider(self, **kwargs): self.calls.append(kwargs); return _ok(Url="token.actions.githubusercontent.com", ClientIDList=["sts.amazonaws.com"])


class Cfn:
    def describe_stacks(self, **kwargs): raise Err("ValidationError", 400, "Stack with id honda-mapit-mcp-dev-retained-cd-delivery does not exist")


def _bindings():
    subject = "repo:herrerogusano/honda-mapit-mcp:environment:dev"
    return {"account": ACCOUNT, "provider_arn": PROVIDER, "owner_id": "123", "repository_id": "456", "observed_dev_subject_format": "legacy_environment", "observed_dev_subject_sha256": hashlib.sha256(subject.encode()).hexdigest(), "stack_arn": APP_STACK, "artifact_stack_arn": ARTIFACT, "handler_arn": HANDLER, "api_arn": API, "shutdown_state_machine_arn": SHUTDOWN, "artifact_bucket_arn": BUCKET, "execution_role_arn": EXECUTION}


def _coordinator(journal=None, *, mono=lambda: 1.0):
    return RetainedDevRoleBootstrapCoordinator({"sts": Sts(), "cloudformation": Cfn(), "iam": Iam()}, journal or Journal(), bindings=_bindings(), expected_caller_arn=CALLER, source_sha=SOURCE, run_id=2026100601, authorized_from_epoch=1_900_000_000, authorized_until_epoch=1_900_003_000, wall_clock=lambda: 1_900_000_001, monotonic=mono)


def test_preflight_requires_exact_absence_and_oidc_read():
    journal = Journal(); c = _coordinator(journal)
    result = c.run_step("preflight")
    assert result["category"] == "preflight_verified"
    assert journal.state["preflight"] is True


def test_preflight_does_not_accept_successful_stack_absence_shape():
    class Empty(Cfn):
        def describe_stacks(self, **kwargs): return _ok(Stacks=[])
    clients = {"sts": Sts(), "cloudformation": Empty(), "iam": Iam()}
    c = RetainedDevRoleBootstrapCoordinator(clients, Journal(), bindings=_bindings(), expected_caller_arn=CALLER, source_sha=SOURCE, run_id=2026100601, authorized_from_epoch=1_900_000_000, authorized_until_epoch=1_900_003_000, wall_clock=lambda: 1_900_000_001, monotonic=lambda: 1.0)
    assert c.run_step("preflight")["category"] == "named_resource_conflict"


def test_zero_monotonic_still_enforces_step_deadline():
    values = iter([0.0, 30.0]); c = _coordinator(mono=lambda: next(values))
    assert c.run_step("preflight")["category"] == "window_expired"


def test_binding_rejects_wrong_artifact_stack():
    bad = _bindings(); bad["artifact_stack_arn"] = STACK
    try:
        RetainedDevRoleBootstrapCoordinator({"sts": Sts(), "cloudformation": Cfn(), "iam": Iam()}, Journal(), bindings=bad, expected_caller_arn=CALLER, source_sha=SOURCE, run_id=1, authorized_from_epoch=1, authorized_until_epoch=100, wall_clock=lambda: 2, monotonic=lambda: 1)
    except Exception as exc:
        assert getattr(exc, "category", None) == "binding_invalid"


def test_iam_document_decoder_rejects_duplicate_and_oversized_json():
    assert _document('{"Statement":1,"Statement":2}') is None
    assert _document('{"Statement":"' + ('x' * 70000) + '"}') is None


def test_journal_write_crossing_deadline_cannot_report_success():
    values = iter([0.0, 31.0])
    c = _coordinator(mono=lambda: next(values))
    c._started = 0.0; c._last_mono = 0.0; c._last_epoch = 1_900_000_001
    try:
        c._save(preflight=True, intent=None, acknowledged=False, acknowledged_stack_id=None, readback=False)
    except Exception as exc:
        assert getattr(exc, "category", None) == "window_expired"
    else:
        raise AssertionError("slow journal write was accepted")
