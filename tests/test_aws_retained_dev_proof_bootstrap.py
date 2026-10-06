from __future__ import annotations

import copy
import hashlib
import json
from contextlib import contextmanager

from scripts.aws_retained_dev_proof_bootstrap import RetainedDevProofBootstrapCoordinator
from scripts.build_cd_identity_bootstrap import AUDIENCE, ISSUER_HOST, OWNER, REPOSITORY
from scripts.build_cd_retained_dev_proof_role import build_cd_retained_dev_proof_role


ACCOUNT = "123456789012"
PROVIDER = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
APP = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained/11111111-2222-4333-8444-555555555555"
ARTIFACT = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/11111111-2222-4333-8444-555555555555"
CONTROLS = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-controls/11111111-2222-4333-8444-555555555555"
RUN = "12345678-1234-4234-8234-123456789abc"
SOURCE = "a" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-dev-executor"
STACK = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-readonly-proof/11111111-2222-4333-8444-555555555555"


def _ok(**value):
    return {**value, "ResponseMetadata": {"HTTPStatusCode": 200}}


class AwsError(Exception):
    def __init__(self, code, status, message=""):
        self.response = {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPStatusCode": status}}


class Journal:
    def __init__(self):
        self.state = None

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
        return True


def _bindings():
    values = {
        "account_id": ACCOUNT, "provider_arn": PROVIDER, "owner_id": "123456789",
        "repository_id": "987654321", "app_stack_arn": APP, "artifact_stack_arn": ARTIFACT,
        "controls_stack_arn": CONTROLS, "artifact_bucket_arn": f"arn:aws:s3:::honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1",
        "api_arn": f"arn:aws:apigateway:eu-west-1::/apis/a1b2c3d4e5",
        "handler_arn": f"arn:aws:lambda:eu-west-1:{ACCOUNT}:function:honda-mapit-mcp-dev-retained-handler",
        "cfn_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-cfn-update",
        "execution_role_arn": f"arn:aws:iam::{ACCOUNT}:role/honda-mapit-mcp-dev-retained-handler-role",
        "cfn_boundary_arn": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-cfn-update-boundary",
        "executor_boundary_arn": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-cd-executor-boundary",
        "shutdown_state_machine_arn": f"arn:aws:states:eu-west-1:{ACCOUNT}:stateMachine:honda-mapit-mcp-dev-retained-shutdown",
        "tripwire_alarm_arn": f"arn:aws:cloudwatch:eu-west-1:{ACCOUNT}:alarm:honda-mapit-mcp-dev-retained-request-tripwire",
        "tripwire_rule_arn": f"arn:aws:events:eu-west-1:{ACCOUNT}:rule/honda-mapit-mcp-dev-retained-request-tripwire-alarm-rule",
    }
    subject = f"repo:{OWNER}@{values['owner_id']}/{REPOSITORY}@{values['repository_id']}:environment:dev"
    values["observed_dev_subject_sha256"] = hashlib.sha256(subject.encode()).hexdigest()
    return values


class CloudFormation:
    def __init__(self, template, *, run_id=RUN, stack=STACK):
        self.template = template; self.created = False; self.calls = []; self.fail_create = False; self.run_id = run_id; self.stack = stack

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        if not self.created:
            raise AwsError("ValidationError", 400, "Stack with id honda-mapit-mcp-dev-retained-readonly-proof does not exist")
        return _ok(Stacks=[{"StackId": self.stack, "StackName": "honda-mapit-mcp-dev-retained-readonly-proof", "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True, "Tags": [{"Key": k, "Value": v} for k, v in (("Project", "honda-mapit-mcp"), ("Environment", "dev"), ("Purpose", "CDReadOnlyProof"), ("OperatorRunId", self.run_id))]}])

    def create_stack(self, **kwargs):
        self.calls.append(("create_stack", kwargs))
        if self.fail_create:
            raise RuntimeError("ambiguous")
        self.created = True
        return _ok(StackId=self.stack)

    def get_template(self, **kwargs):
        return _ok(TemplateBody=self.template)

    def describe_stack_resources(self, **kwargs):
        return _ok(StackResources=[
            {"LogicalResourceId": "RetainedDevReadOnlyProofBoundary", "PhysicalResourceId": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-readonly-proof-boundary", "ResourceType": "AWS::IAM::ManagedPolicy", "ResourceStatus": "CREATE_COMPLETE", "StackId": self.stack, "StackName": "honda-mapit-mcp-dev-retained-readonly-proof"},
            {"LogicalResourceId": "RetainedDevReadOnlyProofRole", "PhysicalResourceId": "honda-mapit-mcp-dev-retained-readonly-proof", "ResourceType": "AWS::IAM::Role", "ResourceStatus": "CREATE_COMPLETE", "StackId": self.stack, "StackName": "honda-mapit-mcp-dev-retained-readonly-proof"},
        ])

    def describe_stack_events(self, **kwargs):
        return _ok(StackEvents=[{"ClientRequestToken": self.run_id, "StackId": self.stack}])


class Sts:
    def get_caller_identity(self, **kwargs):
        return _ok(Account=ACCOUNT, Arn=CALLER)


class Iam:
    def __init__(self, template, cfn):
        self.template = template; self.cfn = cfn

    def get_open_id_connect_provider(self, **kwargs): return _ok(Url=ISSUER_HOST, ClientIDList=[AUDIENCE])
    def get_role(self, **kwargs):
        if not self.cfn.created or kwargs.get("RoleName") != "honda-mapit-mcp-dev-retained-readonly-proof": raise AwsError("NoSuchEntity", 404)
        props = self.template["Resources"]["RetainedDevReadOnlyProofRole"]["Properties"]
        tags = [{"Key": k, "Value": v} for k, v in {**{x["Key"]: x["Value"] for x in props["Tags"]}, "OperatorRunId": self.cfn.run_id, "aws:cloudformation:stack-id": self.cfn.stack, "aws:cloudformation:stack-name": "honda-mapit-mcp-dev-retained-readonly-proof", "aws:cloudformation:logical-id": "RetainedDevReadOnlyProofRole"}.items()]
        return _ok(Role={"RoleName": props["RoleName"], "Path": "/", "Arn": f"arn:aws:iam::{ACCOUNT}:role/{props['RoleName']}", "MaxSessionDuration": 3600, "AssumeRolePolicyDocument": props["AssumeRolePolicyDocument"], "PermissionsBoundary": {"PermissionsBoundaryArn": f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-readonly-proof-boundary", "PermissionsBoundaryType": "Policy"}, "Tags": tags})
    def get_policy(self, **kwargs):
        if not self.cfn.created or kwargs.get("PolicyArn") != f"arn:aws:iam::{ACCOUNT}:policy/honda-mapit-mcp-dev-retained-readonly-proof-boundary": raise AwsError("NoSuchEntity", 404)
        props = self.template["Resources"]["RetainedDevReadOnlyProofBoundary"]["Properties"]
        return _ok(Policy={"PolicyName": props["ManagedPolicyName"], "Path": "/", "Arn": kwargs["PolicyArn"], "IsAttachable": True, "AttachmentCount": 0, "PermissionsBoundaryUsageCount": 1, "DefaultVersionId": "v1"})
    def list_role_policies(self, **kwargs): return _ok(PolicyNames=["honda-mapit-mcp-dev-retained-readonly-proof-policy"], IsTruncated=False)
    def get_role_policy(self, **kwargs): return _ok(RoleName=kwargs["RoleName"], PolicyName=kwargs["PolicyName"], PolicyDocument=self.template["Resources"]["RetainedDevReadOnlyProofRole"]["Properties"]["Policies"][0]["PolicyDocument"])
    def list_attached_role_policies(self, **kwargs): return _ok(AttachedPolicies=[], IsTruncated=False)
    def get_policy_version(self, **kwargs): return _ok(PolicyVersion={"VersionId": "v1", "IsDefaultVersion": True, "Document": self.template["Resources"]["RetainedDevReadOnlyProofBoundary"]["Properties"]["PolicyDocument"]})


def _coordinator(journal=None, *, fail_create=False):
    bindings = _bindings(); template = build_cd_retained_dev_proof_role(**bindings); cfn = CloudFormation(template); cfn.fail_create = fail_create
    clients = {"sts": Sts(), "cloudformation": cfn, "iam": Iam(template, cfn)}
    coordinator = RetainedDevProofBootstrapCoordinator(clients, journal or Journal(), bindings=bindings, expected_caller_arn=CALLER, source_sha=SOURCE, run_id=RUN, authorized_from_epoch=1_893_455_000, authorized_until_epoch=1_893_458_000, wall_clock=lambda: 1_893_456_100, monotonic=lambda: 1.0)
    return coordinator, cfn


def test_closed_create_and_exact_readback():
    journal = Journal(); coordinator, cfn = _coordinator(journal)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("create")["category"] == "create_acknowledged"
    assert coordinator.run_step("readback")["category"] == "readback_verified"
    create = next(kwargs for name, kwargs in cfn.calls if name == "create_stack")
    assert create["Capabilities"] == ["CAPABILITY_NAMED_IAM"] and create["EnableTerminationProtection"] is True


def test_unknown_create_is_fenced_without_replay():
    journal = Journal(); coordinator, cfn = _coordinator(journal, fail_create=True)
    assert coordinator.run_step("preflight")["ok"]
    assert coordinator.run_step("create")["category"] == "create_outcome_unknown"
    assert coordinator.run_step("create")["category"] == "create_intent_present"
    assert sum(name == "create_stack" for name, _ in cfn.calls) == 1
    cfn.fail_create = False; cfn.created = True
    assert coordinator.run_step("readback")["category"] == "readback_verified"
    assert journal.state["acknowledged"] is False
    assert journal.state["readback_receipt"]["acknowledged"] is False


def test_provider_or_absence_mismatch_fails_closed():
    coordinator, _ = _coordinator()
    coordinator.clients["iam"].get_open_id_connect_provider = lambda **kwargs: _ok(Url=ISSUER_HOST, ClientIDList=["wrong"])
    assert coordinator.run_step("preflight")["category"] == "provider_mismatch"
