from __future__ import annotations

from contextlib import contextmanager
import copy
import hashlib
from pathlib import Path

import pytest

from scripts.aws_retained_dev_artifact_bootstrap import RetainedDevArtifactCoordinator
from scripts.build_aws_retained_dev_support import build_retained_dev_artifacts


ACCOUNT = "123456789012"
SOURCE = "a" * 40
CALLER = f"arn:aws:iam::{ACCOUNT}:role/retained-artifact-operator"
BUCKET = f"honda-mapit-mcp-dev-retained-{ACCOUNT}-eu-west-1"
STACK_ID = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/honda-mapit-mcp-dev-retained-runtime-artifacts/11111111-2222-4333-8444-555555555555"


def _ok(**body):
    return {**body, "ResponseMetadata": {"HTTPStatusCode": 200}}


class AwsError(Exception):
    def __init__(self, code, status, message):
        self.response = {"Error": {"Code": code, "Message": message}, "ResponseMetadata": {"HTTPStatusCode": status}}


class Journal:
    def __init__(self):
        self.state = None
        self.saved = []

    @contextmanager
    def locked(self):
        yield

    def load(self):
        return copy.deepcopy(self.state)

    def save(self, state):
        self.state = copy.deepcopy(state)
        self.saved.append(copy.deepcopy(state))


class Sts:
    def __init__(self):
        self.calls = 0

    def get_caller_identity(self):
        self.calls += 1
        return _ok(Account=ACCOUNT, Arn=CALLER)


class CloudFormation:
    def __init__(self):
        self.calls = []
        self.created = False

    def describe_stacks(self, **kwargs):
        self.calls.append(("describe_stacks", kwargs))
        if not self.created:
            raise AwsError("ValidationError", 400, "Stack with id honda-mapit-mcp-dev-retained-runtime-artifacts does not exist")
        return _ok(Stacks=[{
            "StackId": STACK_ID, "StackName": "honda-mapit-mcp-dev-retained-runtime-artifacts", "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True,
            "Tags": [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-artifacts"}, {"Key": "OperatorRunId", "Value": "2026100601"}],
            "Outputs": [{"OutputKey": "RuntimeArtifactBucketName", "OutputValue": BUCKET}],
        }])

    def create_stack(self, **kwargs):
        self.calls.append(("create_stack", kwargs))
        self.created = True
        return _ok(StackId=STACK_ID)

    def get_template(self, **kwargs):
        self.calls.append(("get_template", kwargs))
        return _ok(TemplateBody=build_retained_dev_artifacts())

    def describe_stack_events(self, **kwargs):
        self.calls.append(("describe_stack_events", kwargs))
        from scripts.aws_retained_dev_artifact_bootstrap import _create_token
        return _ok(StackEvents=[{"StackId": STACK_ID, "ClientRequestToken": _create_token(ACCOUNT, SOURCE, 2026100601)}])

    def describe_stack_resources(self, **kwargs):
        self.calls.append(("describe_stack_resources", kwargs))
        return _ok(StackResources=[
            {"LogicalResourceId": "RuntimeArtifactBucket", "ResourceType": "AWS::S3::Bucket", "PhysicalResourceId": BUCKET, "ResourceStatus": "CREATE_COMPLETE", "StackId": STACK_ID, "StackName": "honda-mapit-mcp-dev-retained-runtime-artifacts"},
            {"LogicalResourceId": "RuntimeArtifactBucketPolicy", "ResourceType": "AWS::S3::BucketPolicy", "PhysicalResourceId": BUCKET, "ResourceStatus": "CREATE_COMPLETE", "StackId": STACK_ID, "StackName": "honda-mapit-mcp-dev-retained-runtime-artifacts"},
        ])


class S3:
    def __init__(self):
        self.calls = []

    def head_bucket(self, **kwargs):
        self.calls.append(("head_bucket", kwargs))
        raise AwsError("404", 404, "not found")

    def get_public_access_block(self, **kwargs):
        self.calls.append(("get_public_access_block", kwargs))
        return _ok(PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})

    def get_bucket_encryption(self, **kwargs):
        self.calls.append(("get_bucket_encryption", kwargs))
        return _ok(ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})

    def get_bucket_ownership_controls(self, **kwargs):
        self.calls.append(("get_bucket_ownership_controls", kwargs))
        return _ok(OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]})

    def get_bucket_versioning(self, **kwargs):
        self.calls.append(("get_bucket_versioning", kwargs))
        return _ok()

    def get_bucket_location(self, **kwargs):
        self.calls.append(("get_bucket_location", kwargs))
        return _ok(LocationConstraint="eu-west-1")

    def get_bucket_policy_status(self, **kwargs):
        self.calls.append(("get_bucket_policy_status", kwargs))
        return _ok(PolicyStatus={"IsPublic": False})

    def get_bucket_tagging(self, **kwargs):
        self.calls.append(("get_bucket_tagging", kwargs))
        return _ok(TagSet=[{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "dev"}, {"Key": "Purpose", "Value": "retained-dev-artifacts"}, {"Key": "OperatorRunId", "Value": "2026100601"}, {"Key": "aws:cloudformation:stack-id", "Value": STACK_ID}, {"Key": "aws:cloudformation:stack-name", "Value": "honda-mapit-mcp-dev-retained-runtime-artifacts"}, {"Key": "aws:cloudformation:logical-id", "Value": "RuntimeArtifactBucket"}])

    def get_bucket_lifecycle_configuration(self, **kwargs):
        self.calls.append(("get_bucket_lifecycle_configuration", kwargs))
        return _ok(Rules=[{"ID": "DevTerminalJournalRetention", "Status": "Enabled", "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}}, "Expiration": {"Days": 30}}])

    def get_bucket_policy(self, **kwargs):
        self.calls.append(("get_bucket_policy", kwargs))
        return _ok(Policy='{"Version":"2012-10-17","Statement":[{"Sid":"DenyInsecureTransportForThisBucketOnly","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":["arn:aws:s3:::' + BUCKET + '","arn:aws:s3:::' + BUCKET + '/*"],"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}')


def _coordinator(journal=None, *, clients=None, wall=lambda: 1_900_000_000, mono=lambda: 1.0):
    return RetainedDevArtifactCoordinator(
        clients or {"sts": Sts(), "cloudformation": CloudFormation(), "s3": S3()}, journal or Journal(),
        account_id=ACCOUNT, source_sha=SOURCE, run_id=2026100601, expected_caller_arn=CALLER,
        authorized_from_epoch=1_899_999_000, authorized_until_epoch=1_900_002_000,
        wall_clock=wall, monotonic=mono,
    )


def _seed_preflight(coordinator, journal):
    journal.state = {"schema": 1, "kind": "retained-dev-artifact", "account": ACCOUNT,
                     "source_sha": SOURCE, "run_id": 2026100601, "template_sha256": coordinator.template_sha256,
                     "expected_caller_arn": CALLER, "authorized_from_epoch": 1_899_999_000,
                     "authorized_until_epoch": 1_900_002_000, "last_observed_epoch": 1_900_000_000,
                     "preflight": True, "intent": None, "acknowledged": False, "acknowledged_stack_id": None,
                     "readback": False, "readback_receipt": None}


def test_preflight_is_strict_absence_and_persists_no_write_intent():
    journal = Journal()
    c = _coordinator(journal)
    result = c.run_step("preflight")
    assert result == {"step": "preflight", "ok": True, "category": "preflight_verified", "calls": 2}
    assert journal.state["preflight"] is True and journal.state["intent"] is None


def test_create_saves_intent_before_one_stack_write_and_never_replays():
    journal = Journal()
    cfn = CloudFormation()
    clients = {"sts": Sts(), "cloudformation": cfn, "s3": S3()}
    c = _coordinator(journal, clients=clients)
    _seed_preflight(c, journal)
    result = c.run_step("create")
    assert result["category"] == "create_acknowledged"
    assert [name for name, _ in cfn.calls].count("create_stack") == 1
    assert journal.state["acknowledged"] is True
    assert c.run_step("create")["category"] == "create_intent_present"
    assert [name for name, _ in cfn.calls].count("create_stack") == 1


def test_readback_verifies_exact_cfn_and_s3_metadata():
    journal = Journal()
    cfn = CloudFormation()
    clients = {"sts": Sts(), "cloudformation": cfn, "s3": S3()}
    c = _coordinator(journal, clients=clients)
    _seed_preflight(c, journal)
    c.run_step("create")
    result = c.run_step("readback")
    assert result["category"] == "readback_verified"
    assert result["calls"] == 14
    assert journal.state["acknowledged_stack_id"] == STACK_ID
    assert journal.state["readback_receipt"]["stack_id"] == STACK_ID
    assert all(kwargs.get("ExpectedBucketOwner") == ACCOUNT for name, kwargs in clients["s3"].calls if name != "head_bucket" or True)


def test_successful_empty_absence_response_is_not_accepted():
    class EmptyCfn(CloudFormation):
        def describe_stacks(self, **kwargs):
            return _ok(Stacks=[])
    c = _coordinator(clients={"sts": Sts(), "cloudformation": EmptyCfn(), "s3": S3()})
    result = c.run_step("preflight")
    assert result["category"] == "named_resource_conflict"


def test_preflight_does_not_use_head_bucket_as_absence_proof():
    clients = {"sts": Sts(), "cloudformation": CloudFormation(), "s3": S3()}
    c = _coordinator(clients=clients)
    assert c.run_step("preflight")["ok"]
    assert clients["s3"].calls == []


def test_create_ambiguous_failure_keeps_intent_and_second_create_does_not_write():
    journal = Journal()
    cfn = CloudFormation()
    original = cfn.create_stack
    def ambiguous(**kwargs):
        raise AwsError("InternalError", 500, "ambiguous")
    cfn.create_stack = ambiguous
    c = _coordinator(journal, clients={"sts": Sts(), "cloudformation": cfn, "s3": S3()})
    _seed_preflight(c, journal)
    result = c.run_step("create")
    assert result["category"] == "create_outcome_unknown"
    assert journal.state["intent"] is not None and journal.state["acknowledged"] is False
    cfn.create_stack = original
    assert c.run_step("create")["category"] == "create_intent_present"


def test_unknown_create_can_reconcile_without_inventing_acknowledgement():
    journal = Journal()
    cfn = CloudFormation()
    def ambiguous_but_created(**kwargs):
        cfn.calls.append(("create_stack", kwargs))
        cfn.created = True
        raise AwsError("InternalError", 500, "ambiguous")
    cfn.create_stack = ambiguous_but_created
    c = _coordinator(journal, clients={"sts": Sts(), "cloudformation": cfn, "s3": S3()})
    _seed_preflight(c, journal)
    assert c.run_step("create")["category"] == "create_outcome_unknown"
    result = c.run_step("readback")
    assert result["category"] == "readback_verified"
    assert journal.state["acknowledged"] is False
    assert journal.state["acknowledged_stack_id"] is None
    assert journal.state["readback_receipt"]["stack_id"] == STACK_ID


def test_nonmonotonic_clock_and_budget_fail_closed():
    values = iter([1_900_000_000, 1_899_999_999])
    c = _coordinator(wall=lambda: next(values))
    assert c.run_step("preflight")["category"] in {"window_invalid", "preflight_conflict"}


def test_response_without_http_200_is_rejected():
    class BadSts(Sts):
        def get_caller_identity(self):
            return {"Account": ACCOUNT, "Arn": CALLER, "ResponseMetadata": {"HTTPStatusCode": 201}}
    c = _coordinator(clients={"sts": BadSts(), "cloudformation": CloudFormation(), "s3": S3()})
    assert c.run_step("preflight")["category"] == "aws_response_invalid"


def test_zero_monotonic_does_not_disable_deadline():
    clock = iter([0.0, 30.0])
    c = _coordinator(mono=lambda: next(clock))
    assert c.run_step("preflight")["category"] == "window_expired"


def test_pagination_is_rejected_in_any_read_response():
    class PaginatedSts(Sts):
        def get_caller_identity(self):
            return _ok(Account=ACCOUNT, Arn=CALLER, NextToken="opaque")
    c = _coordinator(clients={"sts": PaginatedSts(), "cloudformation": CloudFormation(), "s3": S3()})
    assert c.run_step("preflight")["category"] == "aws_response_invalid"
