from __future__ import annotations

from contextlib import contextmanager
import copy
from collections import OrderedDict

import pytest

from scripts.dev_multiuser_closed_update import ClosedDevUpdate, ClosedUpdateError
from scripts.build_aws_retained_dev_multiuser import build_retained_dev_multiuser_setup
from scripts.build_aws_retained_dev import build_retained_dev_template


ACCOUNT = "123456789012"
CALLER = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
APP = "honda-mapit-mcp-dev-retained"
ROLES = "honda-mapit-mcp-dev-retained-cd-delivery"
APP_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{APP}/11111111-2222-4333-8444-555555555555"
ROLES_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{ROLES}/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
SERVICE_ROLE = f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update"
TOKEN = "dev-multiuser-" + "a" * 32
SOURCE = "1" * 40


class Journal:
    def __init__(self, value=None):
        self.value = copy.deepcopy(value)
        self.saves = []

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.value)

    def save(self, value):
        self.value = copy.deepcopy(value)
        self.saves.append(copy.deepcopy(value))


class STS:
    def __init__(self, account=ACCOUNT, caller=CALLER):
        self.account, self.caller, self.calls = account, caller, 0

    def get_caller_identity(self):
        self.calls += 1
        return {"Account": self.account, "Arn": self.caller}


class Lambda:
    def __init__(self, reserved=0):
        self.reserved = reserved
        self.calls = 0

    def get_function_concurrency(self, **_kwargs):
        self.calls += 1
        return {"ReservedConcurrentExecutions": self.reserved}


class Api:
    def __init__(self, api_id="api1234567", closed=True):
        self.api_id, self.closed = api_id, closed
        self.calls = 0

    def get_api(self, **kwargs):
        self.calls += 1
        return {"ApiId": kwargs["ApiId"], "DisableExecuteApiEndpoint": self.closed}


class CloudFormation:
    def __init__(self, stack_arn, prior, target, *, status="CREATE_COMPLETE", role=None):
        self.stack_arn, self.prior, self.target = stack_arn, copy.deepcopy(prior), copy.deepcopy(target)
        self.stack_name = stack_arn.split("stack/", 1)[1].split("/", 1)[0]
        self.status, self.role = status, role
        self.current = copy.deepcopy(prior)
        self.events = []
        self.update_calls = []
        self.template_calls = 0

    def describe_stacks(self, **_kwargs):
        return {"Stacks": [{
            "StackId": self.stack_arn, "StackName": self.stack_name,
            "StackStatus": self.status, "RoleARN": self.role,
            "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"},
                     {"Key": "Environment", "Value": "dev"}],
        }]}

    def describe_stack_resources(self, **_kwargs):
        return {"StackResources": [{
            "LogicalResourceId": "McpApi", "ResourceType": "AWS::ApiGatewayV2::Api",
            "PhysicalResourceId": "api1234567",
        }]}

    def get_template(self, **_kwargs):
        self.template_calls += 1
        return {"TemplateBody": copy.deepcopy(self.current)}

    def update_stack(self, **kwargs):
        self.update_calls.append(copy.deepcopy(kwargs))
        return {"StackId": self.stack_arn}

    def describe_stack_events(self, **_kwargs):
        return {"StackEvents": copy.deepcopy(self.events)}


def _closed_template(marker="prior"):
    return {
        "Resources": {
            "McpApi": {"Properties": {"DisableExecuteApiEndpoint": True}},
            "McpHandler": {"Properties": {"ReservedConcurrentExecutions": 0}},
        },
        "Marker": marker,
    }


def _clients(cfn, *, account=ACCOUNT, caller=CALLER, reserved=0, api_closed=True):
    api = Api(closed=api_closed)
    return {
        "sts": STS(account, caller),
        "cloudformation": cfn,
        "lambda": Lambda(reserved),
        "apigatewayv2": api,
    }


def _core(*, current=None, target=None, stack_arn=APP_ARN, role=SERVICE_ROLE,
          clients=None, journal=None, clock=lambda: 1_900_000_001):
    prior = _closed_template("prior") if current is None else current
    target = _closed_template("target") if target is None else target
    cfn = CloudFormation(stack_arn, prior, target, role=None if stack_arn == APP_ARN else None)
    if clients is None:
        clients = _clients(cfn)
    else:
        clients["cloudformation"] = cfn
    return ClosedDevUpdate(
        clients, journal or Journal(), account=ACCOUNT, caller_arn=CALLER,
        stack_arn=stack_arn, prior_template=prior, target_template=target,
        service_role_arn=role if stack_arn == APP_ARN else None,
        source_sha=SOURCE, start=1_900_000_000, end=1_900_000_300,
        token=TOKEN, clock=clock,
    ), cfn, clients


def _complete_readback(cfn):
    cfn.current = copy.deepcopy(cfn.target)
    cfn.status = "UPDATE_COMPLETE"
    cfn.role = SERVICE_ROLE
    cfn.events = [{
        "PhysicalResourceId": cfn.stack_arn,
        "ResourceType": "AWS::CloudFormation::Stack",
        "ResourceStatus": "UPDATE_COMPLETE",
        "ClientRequestToken": TOKEN,
    }]


def test_full_app_update_has_one_write_and_same_token_completion_proof():
    core, cfn, clients = _core()
    assert core.run("preflight") == {"ok": True, "phase": "ready"}
    assert core.run("update") == {"ok": True, "phase": "acknowledged"}
    assert len(cfn.update_calls) == 1
    request = cfn.update_calls[0]
    assert request["ClientRequestToken"] == TOKEN
    assert request["RoleARN"] == SERVICE_ROLE
    assert request["Capabilities"] == ["CAPABILITY_NAMED_IAM"]

    _complete_readback(cfn)
    assert core.run("readback") == {"ok": True, "phase": "accepted"}
    assert clients["sts"].calls == 3


def test_sdk_ordered_template_mapping_is_normalized_without_relaxing_shape():
    core, cfn, _ = _core()
    cfn.current = OrderedDict((key, value) for key, value in cfn.current.items())
    assert core.run("preflight") == {"ok": True, "phase": "ready"}


def test_unknown_update_response_is_permanently_fenced_without_retry():
    journal = Journal()
    core, cfn, _ = _core(journal=journal)
    core.run("preflight")

    original = cfn.update_stack
    def unknown(**kwargs):
        cfn.update_calls.append(copy.deepcopy(kwargs))
        return {"StackId": "wrong-stack"}
    cfn.update_stack = unknown
    with pytest.raises(ClosedUpdateError, match="write_response_unknown"):
        core.run("update")
    assert journal.load()["phase"] == "intent"
    cfn.update_stack = original
    with pytest.raises(ClosedUpdateError, match="write_fenced"):
        core.run("update")
    assert len(cfn.update_calls) == 1

    _complete_readback(cfn)
    assert core.run("readback") == {"ok": True, "phase": "accepted"}


def test_wrong_completion_token_or_foreign_stack_event_is_rejected():
    journal = Journal()
    core, cfn, _ = _core(journal=journal)
    core.run("preflight")
    core.run("update")
    _complete_readback(cfn)
    cfn.events[0]["ClientRequestToken"] = "dev-multiuser-" + "b" * 32
    with pytest.raises(ClosedUpdateError, match="completion_provenance_invalid"):
        core.run("readback")
    cfn.events[0]["ClientRequestToken"] = TOKEN
    cfn.events[0]["PhysicalResourceId"] = ROLES_ARN
    with pytest.raises(ClosedUpdateError, match="completion_provenance_invalid"):
        core.run("readback")


@pytest.mark.parametrize("step", ["preflight", "update"])
def test_prior_drift_never_reaches_update_write(step):
    journal = Journal()
    core, cfn, _ = _core(journal=journal)
    core.run("preflight") if step == "update" else None
    cfn.current["Marker"] = "foreign-drift"
    with pytest.raises(ClosedUpdateError, match="prior_mismatch"):
        core.run(step)
    assert cfn.update_calls == []


def test_window_expiry_and_clock_rollback_fail_closed_before_write():
    journal = Journal()
    values = iter([1_900_000_001, 1_900_000_000])
    core, cfn, clients = _core(journal=journal, clock=lambda: next(values))
    assert core.run("preflight") == {"ok": True, "phase": "ready"}
    with pytest.raises(ClosedUpdateError, match="window_closed"):
        core.run("update")
    assert cfn.update_calls == []
    assert clients["sts"].calls == 1

    core, cfn, clients = _core(journal=Journal(), clock=lambda: 1_900_000_301)
    with pytest.raises(ClosedUpdateError, match="window_closed"):
        core.run("preflight")
    assert cfn.update_calls == [] and clients["sts"].calls == 0


def test_identity_runtime_and_service_role_drift_are_rejected_before_write():
    prior = _closed_template("prior")
    target = _closed_template("target")
    cfn = CloudFormation(APP_ARN, prior, target)
    clients = _clients(cfn, caller="arn:aws:iam::123456789012:user/other")
    core, _, _ = _core(clients=clients)
    with pytest.raises(ClosedUpdateError, match="identity_mismatch"):
        core.run("preflight")
    assert cfn.update_calls == []

    cfn = CloudFormation(APP_ARN, prior, target)
    clients = _clients(cfn, reserved=1)
    core, _, _ = _core(clients=clients)
    with pytest.raises(ClosedUpdateError, match="runtime_not_closed"):
        core.run("preflight")
    assert cfn.update_calls == []


def test_setup_helper_preserves_original_runtime_and_adds_only_setup_resources():
    original = build_retained_dev_template()
    setup = build_retained_dev_multiuser_setup(
        api_id="a1b2c3d4e5", callback_url="http://localhost:39031/callback"
    )
    assert setup["Metadata"]["RuntimeUnchanged"] is True
    assert set(setup["Resources"]) == set(original["Resources"]) | {
        "McpUserPool", "McpUserPoolDomain", "McpResourceServer", "McpUserPoolClient",
        "McpManagedLoginBranding", "McpTenantsTable",
    }
    for name in original["Resources"]:
        assert setup["Resources"][name] == original["Resources"][name]
