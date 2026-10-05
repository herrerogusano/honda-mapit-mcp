from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import hashlib

import pytest

from scripts import run_cd_delivery_bootstrap as bootstrap


ACCOUNT = "123456789012"
OWNER_ID = "1234567"
REPOSITORY_ID = "7654321"
SUBJECT = f"repo:herrerogusano@{OWNER_ID}/honda-mapit-mcp@{REPOSITORY_ID}:environment:prod"
SOURCE = "1" * 40
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{bootstrap.STACK}/11111111-2222-4333-8444-555555555555"


class Journal:
    def __init__(self, state):
        self.state = deepcopy(state)
        self.saves = 0

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return self.state

    def save(self, state):
        self.state = deepcopy(state)
        self.saves += 1


def _inventory():
    return {
        "identity": {
            "provider_arn": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com",
            "owner_id": OWNER_ID,
            "repository_id": REPOSITORY_ID,
            "observed_subjects": {"prod": {
                "format": "immutable_environment",
                "sha256": hashlib.sha256(SUBJECT.encode("ascii")).hexdigest(),
            }},
        },
        "account": ACCOUNT,
        "stack": {"StackId": f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-prod/22222222-3333-4444-8555-666666666666"},
        "manifest": {"api_id": "a1b2c3d4e5"},
        "bucket": "honda-mapit-mcp-prod-runtime-artifacts-a1b2c3d4abcd",
        "execution_role": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-prod-runtime",
    }


def _state():
    return {"kind": "cd_delivery_preparation", "inventory": _inventory()}


class AwsError(Exception):
    def __init__(self, code, message="not found"):
        self.response = {"Error": {"Code": code, "Message": message}}


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"}


class FakeIAM:
    def __init__(self, *, wrong_role_path=False):
        self.wrong_role_path = wrong_role_path

    def get_role(self, RoleName):
        if RoleName in {"honda-mapit-mcp-prod-cd-executor", "honda-mapit-mcp-prod-cfn-update"}:
            if not self.wrong_role_path:
                raise AwsError("NoSuchEntity")
            return {"Role": {"RoleName": RoleName}}
        raise AwsError("NoSuchEntity")

    def get_policy(self, PolicyArn):
        raise AwsError("NoSuchEntity")

    def get_open_id_connect_provider(self, OpenIDConnectProviderArn):
        return {"Url": "token.actions.githubusercontent.com", "ClientIDList": ["sts.amazonaws.com"]}


class FakeCloudFormation:
    def __init__(self, *, create_error=False):
        self.create_error = create_error
        self.create_calls = 0

    def describe_stacks(self, StackName):
        raise AwsError("ValidationError", f"Stack with id {StackName} does not exist")

    def create_stack(self, **kwargs):
        self.create_calls += 1
        if self.create_error:
            raise TimeoutError("synthetic ambiguous create")
        return {"StackId": STACK_ID, "ResponseMetadata": {"HTTPStatusCode": 200}}


def _clients(cf=None, iam=None):
    return {"sts": FakeSTS(), "cloudformation": cf or FakeCloudFormation(), "iam": iam or FakeIAM()}


def test_prepare_persists_one_bounded_binding_after_exact_absence_and_provider_checks():
    journal = Journal(_state())
    result = bootstrap.run("prepare", journal, _clients(), SOURCE, clock=lambda: 1000)
    binding = journal.state["bootstrap"]
    assert result == {"ok": True, "category": "bootstrap_prepared"}
    assert binding["source_sha"] == SOURCE
    assert binding["start"] == 1000 and binding["end"] == 4600
    assert len(binding["run_id"]) == 36
    assert binding["operator_arn"] == f"arn:aws:iam::{ACCOUNT}:user/synthetic"
    with pytest.raises(bootstrap.BootstrapError, match="prepare_consumed"):
        bootstrap.run("prepare", journal, _clients(), SOURCE, clock=lambda: 1001)


def test_ambiguous_create_is_never_replayed():
    journal = Journal(_state())
    clients = _clients()
    bootstrap.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    cf = FakeCloudFormation(create_error=True)
    clients["cloudformation"] = cf
    with pytest.raises(bootstrap.BootstrapError, match="create_outcome_unknown"):
        bootstrap.run("create", journal, clients, SOURCE, clock=lambda: 1001)
    assert journal.state["bootstrap"]["create_intent"] == journal.state["bootstrap"]["run_id"]
    with pytest.raises(bootstrap.BootstrapError, match="create_consumed"):
        bootstrap.run("create", journal, clients, SOURCE, clock=lambda: 1002)
    assert cf.create_calls == 1


def test_create_requires_the_exact_operator_arn_bound_at_prepare():
    journal = Journal(_state())
    clients = _clients()
    bootstrap.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)

    class DifferentCaller(FakeSTS):
        def get_caller_identity(self):
            return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/other-synthetic"}

    clients["sts"] = DifferentCaller()
    cf = FakeCloudFormation()
    clients["cloudformation"] = cf
    with pytest.raises(bootstrap.BootstrapError, match="operator_changed"):
        bootstrap.run("create", journal, clients, SOURCE, clock=lambda: 1001)
    assert cf.create_calls == 0


@pytest.mark.parametrize(("source", "now", "category"), [
    ("2" * 40, 1001, "binding_changed"),
    (SOURCE, 4600, "window_expired"),
])
def test_create_rejects_changed_source_or_expired_window_before_write(source, now, category):
    journal = Journal(_state())
    clients = _clients()
    bootstrap.run("prepare", journal, clients, SOURCE, clock=lambda: 1000)
    cf = FakeCloudFormation()
    clients["cloudformation"] = cf
    with pytest.raises(bootstrap.BootstrapError, match=category):
        bootstrap.run("create", journal, clients, source, clock=lambda: now)
    assert cf.create_calls == 0


def test_verify_rejects_mismatched_iam_role_readback():
    template = bootstrap.template_from_inventory(_inventory())
    boundary_names = {
        key: resource["Properties"]["ManagedPolicyName"]
        for key, resource in template["Resources"].items()
        if resource["Type"] == "AWS::IAM::ManagedPolicy"
    }
    roles = [
        (key, resource)
        for key, resource in template["Resources"].items()
        if resource["Type"] == "AWS::IAM::Role"
    ]
    rows = []
    for key, resource in template["Resources"].items():
        props = resource["Properties"]
        physical = props["RoleName"] if resource["Type"] == "AWS::IAM::Role" else (
            f"arn:aws:iam::{ACCOUNT}:policy/{props['ManagedPolicyName']}"
        )
        rows.append({"LogicalResourceId": key, "PhysicalResourceId": physical,
                     "ResourceType": resource["Type"], "ResourceStatus": "CREATE_COMPLETE"})
    stack_tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "prod"},
        {"Key": "UniqueCdDeliveryRunId", "Value": "00000000-0000-4000-8000-000000000000"},
    ]

    class VerifyCF(FakeCloudFormation):
        def __init__(self, stack_id=STACK_ID):
            super().__init__()
            self.stack_id = stack_id

        def describe_stacks(self, StackName):
            return {"Stacks": [{"StackName": bootstrap.STACK, "StackId": self.stack_id,
                                "EnableTerminationProtection": True, "Tags": stack_tags,
                                "StackStatus": "CREATE_COMPLETE"}]}

        def get_template(self, **kwargs):
            return {"TemplateBody": template}

        def describe_stack_resources(self, **kwargs):
            return {"StackResources": rows}

    class VerifyIAM(FakeIAM):
        def get_policy(self, PolicyArn):
            name = PolicyArn.rsplit("/", 1)[1]
            return {"Policy": {"Arn": PolicyArn, "AttachmentCount": 0,
                                "PermissionsBoundaryUsageCount": 1, "DefaultVersionId": "v1"}}

        def get_policy_version(self, **kwargs):
            policy_arn = kwargs["PolicyArn"]
            name = policy_arn.rsplit("/", 1)[1]
            logical = next(k for k, v in boundary_names.items() if v == name)
            return {"PolicyVersion": {"Document": template["Resources"][logical]["Properties"]["PolicyDocument"]}}

        def get_role(self, RoleName):
            logical, resource = next((k, v) for k, v in roles if v["Properties"]["RoleName"] == RoleName)
            props = resource["Properties"]
            boundary_name = boundary_names[props["PermissionsBoundary"]["Fn::GetAtt"][0]]
            return {"Role": {
                "Arn": f"arn:aws:iam::{ACCOUNT}:role/{RoleName}", "Path": "/wrong/",
                "MaxSessionDuration": 3600,
                "PermissionsBoundary": {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/{boundary_name}"},
                "AssumeRolePolicyDocument": props["AssumeRolePolicyDocument"],
                "Tags": props["Tags"],
            }}

    state = _state()
    state["bootstrap"] = {
        "source_sha": SOURCE, "template_sha256": hashlib.sha256(bootstrap.canonical(template)).hexdigest(),
        "operator_arn": "arn:aws:iam::123456789012:user/synthetic",
        "run_id": stack_tags[-1]["Value"], "start": 1000, "end": 4600,
        "last_observed_epoch": 1000,
        "create_intent": stack_tags[-1]["Value"], "stack_arn": STACK_ID,
    }
    bad_journal = Journal(state)
    with pytest.raises(bootstrap.BootstrapError, match="stack_unverified"):
        bootstrap.run(
            "verify", Journal(state),
            _clients(cf=VerifyCF(stack_id=STACK_ID.replace("11111111", "aaaaaaaa")), iam=VerifyIAM()),
            SOURCE, clock=lambda: 1001,
        )
    with pytest.raises(bootstrap.BootstrapError, match="role_mismatch"):
        bootstrap.run("verify", bad_journal, _clients(cf=VerifyCF(), iam=VerifyIAM()), SOURCE, clock=lambda: 1001)
