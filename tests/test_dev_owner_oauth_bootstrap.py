from __future__ import annotations

import contextlib
import copy
from datetime import datetime, timezone
import json

import pytest

from scripts.dev_owner_oauth_bootstrap import (
    DevOwnerOAuthBootstrapCoordinator,
)
from scripts.build_aws_dev_owner_oauth import STACK_NAME

ACCOUNT = "123456789012"
OPERATOR = f"arn:aws:iam::{ACCOUNT}:user/dev-operator"
POOL = "eu-west-1_abcdefghijk"
API = "abcdefghij"
CALLBACK = "http://127.0.0.1:8787/callback/dev-owner"
SOURCE = "a" * 40
RUN_ID = "123e4567-e89b-42d3-a456-426614174000"
CONTEXT_SHA = "b" * 64
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK_NAME}/123e4567-e89b-42d3-a456-426614174001"
CLIENT_ID = "client12345678901234567890"
CLIENT_READBACK_SHA = "c" * 64


class _AwsError(Exception):
    def __init__(self, code, status, message):
        self.response = {"Error": {"Code": code, "Message": message},
                         "ResponseMetadata": {"HTTPStatusCode": status}}
        super().__init__(message)


class _Journal:
    def __init__(self):
        self.state = None
        self.on_save = None

    @contextlib.contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)
        if self.on_save is not None:
            self.on_save()


class _CloudFormation:
    def __init__(self):
        self.create_calls = []
        self.events_calls = 0
        self.created = False
        self.fail_create = False
        self.duplicate_completion = False
        self.role_arn = None
        self.template = None
        self.epoch = 1_800_000_000

    @staticmethod
    def _ok(**values):
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, **values}

    def describe_stacks(self, **kwargs):
        assert kwargs == {"StackName": STACK_NAME}
        if not self.created:
            raise _AwsError("ValidationError", 400, f"Stack with id {STACK_NAME} does not exist")
        row = {
            "StackId": STACK_ID, "StackName": STACK_NAME,
            "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True,
            "Tags": [
                {"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": "dev"},
                {"Key": "Purpose", "Value": "owner-oauth-client"},
                {"Key": "OperatorRunId", "Value": RUN_ID},
            ],
        }
        if self.role_arn is not None:
            row["RoleARN"] = self.role_arn
        return self._ok(Stacks=[row])

    def create_stack(self, **kwargs):
        self.create_calls.append(copy.deepcopy(kwargs))
        if self.fail_create:
            raise _AwsError("ServiceUnavailable", 503, "untrusted diagnostic text")
        self.created = True
        self.template = kwargs["TemplateBody"]
        return self._ok(StackId=STACK_ID)

    def get_template(self, **kwargs):
        assert kwargs == {"StackName": STACK_ID, "TemplateStage": "Original"}
        return self._ok(TemplateBody=self.template)

    def describe_stack_resources(self, **kwargs):
        assert kwargs == {"StackName": STACK_ID}
        return self._ok(StackResources=[
            {"StackId": STACK_ID, "LogicalResourceId": "McpResourceServer",
             "ResourceType": "AWS::Cognito::UserPoolResourceServer",
             "PhysicalResourceId": f"{POOL}|https://{API}.execute-api.eu-west-1.amazonaws.com/mcp",
             "ResourceStatus": "CREATE_COMPLETE"},
            {"StackId": STACK_ID, "LogicalResourceId": "McpUserPoolClient",
             "ResourceType": "AWS::Cognito::UserPoolClient",
             "PhysicalResourceId": CLIENT_ID, "ResourceStatus": "CREATE_COMPLETE"},
            {"StackId": STACK_ID, "LogicalResourceId": "McpManagedLoginBranding",
             "ResourceType": "AWS::Cognito::ManagedLoginBranding",
             "PhysicalResourceId": f"{POOL}|00000000-0000-4000-8000-000000000001",
             "ResourceStatus": "CREATE_COMPLETE"},
        ])

    def describe_stack_events(self, **kwargs):
        assert kwargs == {"StackName": STACK_ID}
        self.events_calls += 1
        token = self.create_calls[0]["ClientRequestToken"]
        completion = {
            "StackId": STACK_ID, "StackName": STACK_NAME,
            "EventId": "root-create-complete", "LogicalResourceId": STACK_NAME,
            "PhysicalResourceId": STACK_ID, "ResourceType": "AWS::CloudFormation::Stack",
            "ResourceStatus": "CREATE_COMPLETE",
            "Timestamp": datetime.fromtimestamp(self.epoch, timezone.utc),
            "ClientRequestToken": token,
        }
        rows = [
            {**completion, "EventId": "root-create-in-progress",
             "ResourceStatus": "CREATE_IN_PROGRESS",
             "Timestamp": datetime.fromtimestamp(self.epoch - 1, timezone.utc)},
            {**completion, "EventId": "client-create-complete",
             "LogicalResourceId": "McpUserPoolClient",
             "PhysicalResourceId": CLIENT_ID,
             "ResourceType": "AWS::Cognito::UserPoolClient"},
            completion,
        ]
        if self.duplicate_completion:
            rows.append({**completion, "EventId": "duplicate-root-create-complete"})
        return self._ok(StackEvents=rows, NextToken="never-follow-this")


class _Cognito:
    def __init__(self):
        self.calls = []
        self.exists = False

    def describe_resource_server(self, **kwargs):
        self.calls.append(kwargs)
        if not self.exists:
            raise _AwsError("ResourceNotFoundException", 400, "no resource server")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "ResourceServer": {}}


class _Clock:
    def __init__(self, epoch=1_800_000_000, mono=0.0):
        self.epoch = epoch
        self.mono = mono

    def wall(self):
        return self.epoch

    def monotonic(self):
        return self.mono


def _coordinator(*, journal=None, cfn=None, cognito=None, clock=None,
                 source_checker=None, context_reader=None, readback_validator=None,
                 context_sha=CONTEXT_SHA, start=1_799_999_900, end=1_800_000_500):
    journal = journal or _Journal()
    cfn = cfn or _CloudFormation()
    cognito = cognito or _Cognito()
    clock = clock or _Clock()
    contexts = []

    def context(exclude_client_id):
        contexts.append(exclude_client_id)
        return {"verified": True, "account_id": ACCOUNT, "owner_pool_id": POOL,
                "api_id": API, "context_sha256": context_sha}

    def validator(stack_id, template, run_id, start_epoch, end_epoch, resource_ids):
        if readback_validator is not None:
            return readback_validator(stack_id, template, run_id, start_epoch, end_epoch, resource_ids)
        assert stack_id == STACK_ID and run_id == RUN_ID
        assert template["Resources"].keys() == {"McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding"}
        assert start_epoch == start and end_epoch == end
        return {"verified": True, "client_id": resource_ids["McpUserPoolClient"],
                "readback_sha256": CLIENT_READBACK_SHA}

    core = DevOwnerOAuthBootstrapCoordinator(
        {"cloudformation": cfn, "cognito": cognito}, journal,
        account_id=ACCOUNT, operator_user_arn=OPERATOR, owner_pool_id=POOL,
        api_id=API, callback_url=CALLBACK, source_sha=SOURCE, run_id=RUN_ID,
        authorized_from_epoch=start, authorized_until_epoch=end,
        expected_context_sha256=context_sha,
        context_reader=context_reader or context,
        source_checker=source_checker or (lambda: True),
        readback_validator=validator,
        wall_clock=clock.wall, monotonic=clock.monotonic,
    )
    return core, journal, cfn, cognito, clock, contexts


def test_preflight_create_and_readback_are_bound_to_one_exact_three_resource_stack():
    core, journal, cfn, cognito, _, contexts = _coordinator()
    preflight = core.run_step("preflight")
    assert preflight["ok"] is True and preflight["category"] == "preflight_verified"
    assert journal.state["phase"] == "preflight"
    assert cfn.create_calls == []
    assert cognito.calls == [{"UserPoolId": POOL,
                              "Identifier": f"https://{API}.execute-api.eu-west-1.amazonaws.com/mcp"}]

    created = core.run_step("create")
    assert created["ok"] is True and created["category"] == "create_acknowledged"
    request = cfn.create_calls[0]
    assert request["StackName"] == STACK_NAME
    assert request["EnableTerminationProtection"] is True
    assert request["Tags"][-1] == {"Key": "OperatorRunId", "Value": RUN_ID}
    assert "Capabilities" not in request
    submitted = json.loads(request["TemplateBody"])
    assert set(submitted["Resources"]) == {
        "McpResourceServer", "McpUserPoolClient", "McpManagedLoginBranding",
    }
    assert all(resource["Type"] != "AWS::Cognito::UserPool"
               and resource["Type"] != "AWS::Cognito::UserPoolDomain"
               for resource in submitted["Resources"].values())
    assert journal.state["phase"] == "create_acknowledged"

    readback = core.run_step("readback")
    assert readback["ok"] is True and readback["category"] == "readback_verified"
    assert journal.state["phase"] == "readback_verified"
    assert journal.state["readback"]["client_id"] == CLIENT_ID
    assert contexts[-1] == CLIENT_ID
    assert cfn.events_calls == 1


def test_uncertain_create_is_durably_fenced_and_never_retried():
    cfn = _CloudFormation()
    cfn.fail_create = True
    core, journal, cfn, _, _, _ = _coordinator(cfn=cfn)
    assert core.run_step("preflight")["ok"]
    result = core.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert journal.state["phase"] == "create_intent"
    assert len(cfn.create_calls) == 1
    retry = core.run_step("create")
    assert retry["category"] == "create_intent_present"
    assert len(cfn.create_calls) == 1


def test_same_journal_cannot_be_rebound_to_another_owner_context():
    core, journal, cfn, _, clock, _ = _coordinator()
    assert core.run_step("preflight")["ok"]
    rebound, _, _, _, _, _ = _coordinator(journal=journal, cfn=cfn, clock=clock,
                                          context_sha="d" * 64)
    result = rebound.run_step("create")
    assert result["category"] == "journal_invalid"
    assert cfn.create_calls == []


def test_source_or_owner_context_failure_prevents_preflight_calls():
    core, journal, cfn, cognito, _, _ = _coordinator(source_checker=lambda: False)
    assert core.run_step("preflight")["category"] == "source_unverified"
    assert cfn.create_calls == [] and cognito.calls == [] and journal.state is None

    core, journal, cfn, cognito, _, _ = _coordinator(context_reader=lambda _exclude: {})
    assert core.run_step("preflight")["category"] == "context_unverified"
    assert cfn.create_calls == [] and cognito.calls == [] and journal.state is None


def test_cutoff_after_durable_intent_blocks_create_without_replay():
    core, journal, cfn, _, clock, _ = _coordinator()
    assert core.run_step("preflight")["ok"]
    journal.on_save = lambda: setattr(clock, "epoch", core.end)
    result = core.run_step("create")
    assert result["category"] == "window_expired"
    assert journal.state["phase"] == "create_intent"
    assert cfn.create_calls == []
    assert core.run_step("create")["category"] == "window_expired"


def test_readback_rejects_wrong_physical_client_and_wrong_root_event_window():
    core, _, cfn, _, _, _ = _coordinator(
        readback_validator=lambda *_args: {"verified": True, "client_id": "otherclient123456",
                                           "readback_sha256": CLIENT_READBACK_SHA},
    )
    assert core.run_step("preflight")["ok"] and core.run_step("create")["ok"]
    assert core.run_step("readback")["category"] == "stack_readback_mismatch"

    core, _, cfn, _, _, _ = _coordinator()
    assert core.run_step("preflight")["ok"] and core.run_step("create")["ok"]
    cfn.epoch = 1_800_000_600
    assert core.run_step("readback")["category"] == "stack_readback_mismatch"


def test_readback_rejects_duplicate_root_completion_and_attached_stack_role():
    core, _, cfn, _, _, _ = _coordinator()
    assert core.run_step("preflight")["ok"] and core.run_step("create")["ok"]
    cfn.duplicate_completion = True
    assert core.run_step("readback")["category"] == "stack_readback_mismatch"

    core, _, cfn, _, _, _ = _coordinator()
    assert core.run_step("preflight")["ok"] and core.run_step("create")["ok"]
    cfn.role_arn = f"arn:aws:iam::{ACCOUNT}:role/unexpected"
    assert core.run_step("readback")["category"] == "stack_not_complete"


@pytest.mark.parametrize("changes", [
    {"callback_url": "http://localhost:8785/callback"},
    {"callback_url": "http://localhost:8786/callback"},
    {"authorized_until_epoch": 1_800_000_501},
    {"source_sha": "0" * 40},
    {"run_id": "not-a-uuid"},
])
def test_invalid_authority_or_production_callback_port_rejected(changes):
    args = {"account_id": ACCOUNT, "operator_user_arn": OPERATOR,
            "owner_pool_id": POOL, "api_id": API, "callback_url": CALLBACK,
            "source_sha": SOURCE, "run_id": RUN_ID,
            "authorized_from_epoch": 1_799_999_900,
            "authorized_until_epoch": 1_800_000_500,
            "expected_context_sha256": CONTEXT_SHA,
            "context_reader": lambda _: {}, "source_checker": lambda: True,
            "readback_validator": lambda *_: {}}
    args.update(changes)
    with pytest.raises(ValueError):
        DevOwnerOAuthBootstrapCoordinator({"cloudformation": _CloudFormation(), "cognito": _Cognito()},
                                          _Journal(), **args)
