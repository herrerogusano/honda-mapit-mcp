"""Injected offline coverage for the exact-stack artifact retention operator."""

from __future__ import annotations

from copy import deepcopy
from contextlib import contextmanager
import hashlib
import json

import pytest

from scripts.build_aws_prod_artifacts import fixed_prod_artifact_template
from scripts.run_cd_artifact_retention import BootstrapError, STACK, run
from test_cd_delivery_bootstrap import ACCOUNT, Journal, _state
from scripts.run_cd_delivery_bootstrap import canonical


BUCKET = "honda-mapit-mcp-prod-runtime-artifacts-a1b2c3d4abcd"
STACK_ARN = f"arn:aws:cloudformation:eu-west-1:{ACCOUNT}:stack/{STACK}/11111111-2222-4333-8444-555555555555"


class AwsError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}
        super().__init__("SYNTHETIC_AWS_ERROR")


class FakeSTS:
    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"}


class FakeCF:
    def __init__(self, *, old_template=None):
        self.template = deepcopy(old_template or fixed_prod_artifact_template())
        self.status = "UPDATE_COMPLETE"
        self.updates = []

    def _stack(self):
        return {"StackName": STACK, "StackId": STACK_ARN, "Tags": [
            {"Key": "Project", "Value": "honda-mapit-mcp"},
        ], "StackStatus": self.status}

    def describe_stacks(self, **kwargs):
        assert kwargs == {"StackName": STACK}
        return {"Stacks": [self._stack()]}

    def get_template(self, **kwargs):
        assert kwargs == {"StackName": STACK_ARN, "TemplateStage": "Original"}
        return {"TemplateBody": deepcopy(self.template)}

    def describe_stack_resources(self, **kwargs):
        assert kwargs == {"StackName": STACK_ARN}
        return {"StackResources": [
            {"LogicalResourceId": "RuntimeArtifactBucket", "ResourceType": "AWS::S3::Bucket",
             "PhysicalResourceId": BUCKET},
            {"LogicalResourceId": "RuntimeArtifactBucketPolicy", "ResourceType": "AWS::S3::BucketPolicy",
             "PhysicalResourceId": BUCKET},
        ]}

    def update_stack(self, **kwargs):
        self.updates.append(deepcopy(kwargs))
        self.template = json.loads(kwargs["TemplateBody"])
        self.status = "UPDATE_COMPLETE"
        return {"StackId": STACK_ARN, "ResponseMetadata": {"HTTPStatusCode": 200}}


class FakeS3:
    def __init__(self, *, lifecycle_error="NoSuchLifecycleConfiguration", lifecycle=None):
        self.lifecycle_error = lifecycle_error
        self.lifecycle = lifecycle

    def get_bucket_versioning(self, **kwargs):
        assert kwargs == {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}
        return {}

    def get_public_access_block(self, **kwargs):
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True,
        }}

    def get_bucket_ownership_controls(self, **kwargs):
        return {"OwnershipControls": {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}}

    def get_bucket_encryption(self, **kwargs):
        return {"ServerSideEncryptionConfiguration": {"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}},
        ]}}

    def get_bucket_policy(self, **kwargs):
        assert kwargs == {"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}
        return {"Policy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyInsecureTransportForThisBucketOnly",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{BUCKET}", f"arn:aws:s3:::{BUCKET}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }],
        })}

    def get_bucket_lifecycle_configuration(self, **kwargs):
        if self.lifecycle is None:
            raise AwsError(self.lifecycle_error)
        return deepcopy(self.lifecycle)


def clients(cf=None, s3=None):
    return {"sts": FakeSTS(), "cloudformation": cf or FakeCF(), "s3": s3 or FakeS3()}


def preparation_state():
    state = _state()
    state["inventory"]["bucket"] = BUCKET
    return state


def terminal_rule():
    return {"Rules": [{
        "ID": "CdDeliveryJournalRetention",
        "Status": "Enabled",
        "Expiration": {"Days": 30},
        "Filter": {"And": {"Prefix": "journals/", "Tags": [
            {"Key": "cd-terminal", "Value": "true"},
        ]}},
    }]}


def test_retention_template_preserves_legacy_and_expires_only_terminal_journals():
    legacy = fixed_prod_artifact_template()
    retained = fixed_prod_artifact_template(journal_retention_days=30)
    bucket = next(r for r in retained["Resources"].values() if r["Type"] == "AWS::S3::Bucket")
    rule = bucket["Properties"]["LifecycleConfiguration"]["Rules"][0]
    assert rule == {
        "Id": "CdDeliveryJournalRetention", "Status": "Enabled",
        "Prefix": "journals/", "TagFilters": [{"Key": "cd-terminal", "Value": "true"}],
        "ExpirationInDays": 30,
    }
    assert "LifecycleConfiguration" not in next(r for r in legacy["Resources"].values()
                                                   if r["Type"] == "AWS::S3::Bucket")["Properties"]
    assert next(r for r in retained["Resources"].values()
                if r["Type"] == "AWS::S3::Bucket")["Properties"].get("VersioningConfiguration") is None


def test_prepare_request_verify_mutate_only_exact_lifecycle_and_keep_journal_binding():
    journal = Journal(preparation_state())
    cf, s3 = FakeCF(), FakeS3()
    remote = clients(cf, s3)
    prepared = run("prepare", journal, remote, clock=lambda: 1_800_000_000.25)
    binding = journal.load()["retention"]
    assert prepared["category"] == "retention_prepared"
    assert binding["end"] - binding["start"] == 3600
    assert not cf.updates

    pending = run("request", journal, remote, clock=lambda: 1_800_000_010.0)
    assert pending["category"] == "retention_update_pending"
    assert len(cf.updates) == 1
    update = cf.updates[0]
    assert set(update) == {"StackName", "TemplateBody", "ClientRequestToken"}
    assert update["StackName"] == STACK_ARN and update["ClientRequestToken"] == binding["token"]
    requested = json.loads(update["TemplateBody"])
    assert requested == fixed_prod_artifact_template(journal_retention_days=30)
    assert requested["Resources"] == fixed_prod_artifact_template(journal_retention_days=30)["Resources"]

    s3.lifecycle = terminal_rule()
    result = run("verify", journal, remote, clock=lambda: 1_800_000_020.0)
    assert result == {"ok": True, "category": "retention_verified", "days": 30, "runtime_expiry": False}
    assert journal.load()["retention"]["verified"] is True
    with pytest.raises(BootstrapError, match="update_consumed"):
        run("request", journal, remote, clock=lambda: 1_800_000_030.0)
    assert len(cf.updates) == 1


def test_prepare_rejects_existing_or_unverified_lifecycle_before_journaling():
    for code in ("AccessDenied", "InternalError"):
        journal = Journal(preparation_state())
        cf = FakeCF()
        remote = clients(cf, FakeS3(lifecycle_error=code))
        with pytest.raises(BootstrapError, match="existing_lifecycle_unverified"):
            run("prepare", journal, remote, clock=lambda: 1_800_000_000)
        assert "retention" not in journal.load()
        assert not cf.updates

    existing = Journal(preparation_state())
    with pytest.raises(BootstrapError, match="existing_lifecycle_conflict"):
        run("prepare", existing, clients(s3=FakeS3(lifecycle=terminal_rule())), clock=lambda: 1_800_000_000)
    assert "retention" not in existing.load()


@pytest.mark.parametrize("bad_rule", [
    {"Rules": [{"ID": "CdDeliveryJournalRetention", "Status": "Enabled", "Expiration": {"Days": 30},
                "Filter": {"Prefix": "journals/"}}]},
    {"Rules": [{"ID": "CdDeliveryJournalRetention", "Status": "Enabled", "Expiration": {"Days": 30},
                "Filter": {"And": {"Prefix": "runtime/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}}}]},
    {"Rules": [{"ID": "CdDeliveryJournalRetention", "Status": "Enabled", "Expiration": {"Days": 30},
                "Filter": {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "false"}]}}}]},
])
def test_verify_refuses_broad_or_nonterminal_retention_rule(bad_rule):
    journal = Journal(preparation_state())
    cf = FakeCF()
    remote = clients(cf, FakeS3(lifecycle=bad_rule))
    # Establish exactly the state that a completed update would leave.
    desired = fixed_prod_artifact_template(journal_retention_days=30)
    cf.template = deepcopy(desired)
    journal.state["retention"] = {
        "stack_arn": STACK_ARN,
        "template_sha256": hashlib.sha256(canonical(desired)).hexdigest(),
        "operator_arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator",
        "last_observed_epoch": 1_800_000_000,
        "start": 1_800_000_000,
        "end": 1_800_003_600,
        "token": "11111111-2222-4333-8444-555555555555",
        "update_intent": "11111111-2222-4333-8444-555555555555",
    }
    with pytest.raises(BootstrapError, match="retention_rule_mismatch"):
        run("verify", journal, remote, clock=lambda: 1_800_000_100)
    assert "verified" not in journal.load()["retention"]


def test_prepare_caps_window_at_one_hour_from_a_single_clock_sample():
    journal = Journal(preparation_state())
    clock_values = iter((1_800_000_000.99, 1_800_000_001.01))
    run("prepare", journal, clients(), clock=lambda: next(clock_values))
    binding = journal.load()["retention"]
    assert binding["end"] - binding["start"] == 3600
