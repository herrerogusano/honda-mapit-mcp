"""Independent provenance regressions for the hosted rollback gate."""

from __future__ import annotations

from copy import deepcopy

from scripts.dev_multiuser_rollback_recovery import _digest, verify_consumed_rollback
from test_dev_multiuser_rollback_recovery import _user_journals


ACCOUNT = "123456789012"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
AUTH = {
    "account": ACCOUNT,
    "expected_caller_arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic",
    "source_sha": "b" * 40,
    "start": 2000,
}
SETUP = {"Resources": {"McpApi": {"Properties": {"DisableExecuteApiEndpoint": True}}}}
BINDING = {
    "schema": 1, "operation": "dev_multiuser_closed_update", "account": ACCOUNT,
    "caller": AUTH["expected_caller_arn"], "stack": STACK, "role": ROLE,
    "source": "a" * 40, "start": 1000, "end": 1300,
    "token": "dev-multiuser-" + "1" * 32, "prior": _digest(SETUP), "target": "c" * 64,
}


class Journal:
    def __init__(self, value):
        self.value = deepcopy(value)

    def load(self):
        return deepcopy(self.value)


class Cloud:
    def __init__(self):
        self.calls = []

    def describe_stacks(self, **_kwargs):
        self.calls.append("stack")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Stacks": [{
            "StackId": STACK, "StackStatus": "UPDATE_ROLLBACK_COMPLETE",
            "RoleARN": ROLE, "EnableTerminationProtection": True,
        }]}

    def get_template(self, **_kwargs):
        self.calls.append("template")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "TemplateBody": SETUP}

    def describe_stack_events(self, **_kwargs):
        self.calls.append("events")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "StackEvents": [{
            "ClientRequestToken": BINDING["token"], "PhysicalResourceId": STACK,
            "ResourceType": "AWS::CloudFormation::Stack",
            "ResourceStatus": "UPDATE_ROLLBACK_COMPLETE",
        }]}


def test_rollback_rejects_foreign_or_malformed_completed_reset_before_aws_reads():
    # A phase-only marker is not proof that this exact pair reset consumed the
    # source/window/run.  The helper must validate the complete reset envelope
    # before accepting the rollback as a safe prerequisite.
    reset = Journal({
        "phase": "complete", "account_id": ACCOUNT,
        "source_sha256": BINDING["source"], "kind": "foreign-reset",
        "run_id": "different-run", "slots": [],
    })
    cloud = Cloud()
    original, latest = _user_journals()
    result = verify_consumed_rollback(
        cloud, Journal({"binding": deepcopy(BINDING), "phase": "acknowledged"}), reset,
        auth=AUTH, app_stack=STACK, expected_setup=SETUP,
        original_user_journal=original, latest_pair_journal=latest,
        user_pool_id="eu-west-1_A1b2C3d4E",
    )
    assert result is False
    assert cloud.calls == []
