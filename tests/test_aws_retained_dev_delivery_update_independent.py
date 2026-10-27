"""Independent adversarial review of the retained-dev update coordinator.

These tests deliberately use the existing SDK-shaped doubles, but do not share
the happy-path assertions from the implementation test module as acceptance
proof.  They cover the write fence, factory binding, event-token scope and the
two distinct Lambda concurrency/readback operations.
"""

from __future__ import annotations

import copy
import base64
import hashlib
import io
import json
import zipfile

import pytest

from scripts.aws_retained_dev_delivery_update import RetainedDevCreationTagBinding, RetainedDevUpdateError, _lambda_tags_equal
from scripts.aws_retained_dev_prior_code import PriorCodeSnapshot
from scripts.build_aws_retained_dev import HANDLER_CODE
from tests import test_aws_retained_dev_delivery_update as base


def test_configuration_and_concurrency_are_separate_sdk_reads():
    journal = base.Journal()
    coordinator, _ = base._coordinator(journal)

    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    lambda_client = coordinator.clients["lambda"]
    names = [name for name, _ in lambda_client.calls]
    assert names.count("get_function_configuration") == 1
    assert names.count("get_function_concurrency") == 1
    configuration = next(
        kwargs for name, kwargs in lambda_client.calls
        if name == "get_function_configuration"
    )
    assert "ReservedConcurrentExecutions" not in configuration


def test_s3_prior_requires_the_exact_closed_factory_and_role_arn():
    prior = copy.deepcopy(base._prior())
    prior["Description"] = "untrusted-but-otherwise-closed-template"
    with pytest.raises(RetainedDevUpdateError, match="prior_recovery_unavailable"):
        base._coordinator(prior=prior)

    journal = base.Journal()
    coordinator, cfn = base._coordinator(journal)

    class MissingRoleCloudFormation(base.CloudFormation):
        def describe_stacks(self, **kwargs):
            response = super().describe_stacks(**kwargs)
            response["Stacks"][0].pop("RoleARN")
            return response

    replacement = MissingRoleCloudFormation(cfn.prior)
    coordinator.clients["cloudformation"] = replacement
    assert coordinator.run_step("preflight")["category"] == "preflight_mismatch"


def test_initial_inline_snapshot_allows_missing_cloudformation_role_arn():
    """An exact sealed inline snapshot is the only RoleARN-none exception."""
    coordinator, cfn = base._coordinator()
    inline = base.build_retained_dev_template()
    template_bytes = json.dumps(inline, sort_keys=True, separators=(",", ":")).encode()
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as output:
        output.writestr("index.py", HANDLER_CODE)
    archive_bytes = archive.getvalue()
    snapshot = PriorCodeSnapshot(
        archive_bytes=archive_bytes,
        template_bytes=template_bytes,
        zip_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        template_sha256=hashlib.sha256(template_bytes).hexdigest(),
        observed_epoch=1_893_456_100,
    )

    class MissingRoleCloudFormation(base.CloudFormation):
        def describe_stacks(self, **kwargs):
            response = super().describe_stacks(**kwargs)
            response["Stacks"][0].pop("RoleARN")
            return response

    cfn.__class__ = MissingRoleCloudFormation
    cfn.prior = inline
    coordinator.prior_template = inline
    coordinator.prior_template_sha256 = snapshot.template_sha256
    coordinator.prior_zip_sha256 = snapshot.zip_sha256
    coordinator.prior_artifact_receipt = None
    coordinator.prior_code_snapshot = snapshot

    class InlineLambda:
        def get_function_configuration(self, **kwargs):
            return base._ok(
                    FunctionName=base.HANDLER_ROLE.rsplit("/", 1)[-1].replace("-role", ""),
                Role=base.HANDLER_ROLE,
                Runtime="python3.13", Handler="index.handler", Architectures=["arm64"],
                MemorySize=256, Timeout=20, State="Active", LastUpdateStatus="Successful",
            )

        def get_function_concurrency(self, **kwargs):
            return base._ok(ReservedConcurrentExecutions=0)

        def list_tags(self, **kwargs):
            return base._ok(Tags={
                "Project": "honda-mapit-mcp",
                "Environment": "dev",
                "Purpose": "retained-dev",
            })
        def get_function(self, **kwargs):
            return base._ok(Configuration={
                "CodeSha256": base64.b64encode(archive_bytes[:0] + bytes.fromhex(snapshot.zip_sha256)).decode("ascii"),
            })

    coordinator.clients["lambda"] = InlineLambda()
    # Keep the independent fixture intentionally explicit: inline snapshots
    # have no Environment section and use index.handler.
    assert inline["Resources"]["McpHandler"]["Properties"].get("Environment") is None
    assert coordinator._read_closed_current(
        expected_template=coordinator.prior_template,
        expected_code_sha=snapshot.zip_sha256,
    ) == base.STACK


def test_lambda_list_tags_uses_real_sdk_map_and_only_owned_cfn_extras():
    expected = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev"},
    ]
    stack = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/00000000-0000-4000-8000-000000000001"
    assert _lambda_tags_equal({"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev"}, expected, stack_arn=stack)
    assert _lambda_tags_equal({"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "aws:cloudformation:stack-id": stack, "aws:cloudformation:stack-name": "honda-mapit-mcp-dev-retained", "aws:cloudformation:logical-id": "McpHandler"}, expected, stack_arn=stack)
    assert not _lambda_tags_equal([{"Key": "Project", "Value": "honda-mapit-mcp"}], expected, stack_arn=stack)
    assert not _lambda_tags_equal({"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "aws:cloudformation:stack-id": "foreign"}, expected, stack_arn=stack)
    assert not _lambda_tags_equal({"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "RunId": "unexpected"}, expected, stack_arn=stack)


def test_creation_run_binding_allows_only_fresh_exact_operator_tag():
    expected = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "retained-dev"},
    ]
    stack = "arn:aws:cloudformation:eu-west-1:123456789012:stack/honda-mapit-mcp-dev-retained/00000000-0000-4000-8000-000000000001"
    binding = RetainedDevCreationTagBinding.from_stack_tags(
        stack_arn=stack,
        stack_name="honda-mapit-mcp-dev-retained",
        tags=[*expected, {"Key": "OperatorRunId", "Value": "314159"}],
    )
    actual = {"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": "314159"}
    assert _lambda_tags_equal(actual, expected, stack_arn=stack, creation_tag_binding=binding)
    assert not _lambda_tags_equal({**actual, "OperatorRunId": "271828"}, expected, stack_arn=stack, creation_tag_binding=binding)
    assert not _lambda_tags_equal({"Project": "honda-mapit-mcp", "Environment": "dev", "Purpose": "retained-dev", "OperatorRunId": "314159", "RunId": "foreign"}, expected, stack_arn=stack, creation_tag_binding=binding)
    with pytest.raises(RetainedDevUpdateError, match="creation_tag_binding_invalid"):
        RetainedDevCreationTagBinding.from_stack_tags(stack_arn=stack, stack_name="honda-mapit-mcp-dev-retained", tags=[*expected, {"Key": "OperatorRunId", "Value": "0314159"}])


def test_caller_is_rechecked_after_intent_and_before_update_stack():
    class CallerChangesAfterPreflight(base.Sts):
        def __init__(self):
            self.calls = 0

        def get_caller_identity(self, **kwargs):
            self.calls += 1
            if self.calls <= 2:
                return super().get_caller_identity(**kwargs)
            return base._ok(Account=base.ACCOUNT, Arn="arn:aws:iam::999999999999:role/other")

    journal = base.Journal()
    coordinator, cfn = base._coordinator(journal)
    sts = CallerChangesAfterPreflight()
    coordinator.clients["sts"] = sts

    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    result = coordinator.run_step("request-update")
    assert result["category"] == "caller_mismatch"
    assert not any(name == "update_stack" for name, _ in cfn.calls)
    assert journal.state["update_intent"] is not None


def test_artifact_readback_requires_checksum_encryption_and_owner_binding():
    class RecordingS3(base.S3):
        def __init__(self):
            self.calls = []

        def head_object(self, **kwargs):
            self.calls.append(kwargs)
            return super().head_object(**kwargs)

    journal = base.Journal()
    coordinator, _ = base._coordinator(journal)
    s3 = RecordingS3()
    coordinator.clients["s3"] = s3
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert s3.calls
    request = s3.calls[0]
    assert request["Bucket"] == "honda-mapit-mcp-dev-retained-123456789012-eu-west-1"
    assert request["ExpectedBucketOwner"] == base.ACCOUNT
    assert request["ChecksumMode"] == "ENABLED"

    class BadChecksumS3(base.S3):
        def head_object(self, **kwargs):
            reply = super().head_object(**kwargs)
            reply["ChecksumSHA256"] = "not-the-receipt"
            return reply

    coordinator, _ = base._coordinator(base.Journal())
    coordinator.clients["s3"] = BadChecksumS3()
    assert coordinator.run_step("preflight")["category"] == "artifact_readback_mismatch"


def test_wrong_event_token_cannot_reconcile_an_ambiguous_write():
    class EventWithWrongToken(base.CloudFormation):
        def update_stack(self, **kwargs):
            self.calls.append(("update_stack", kwargs))
            self.updated = True
            raise RuntimeError("ambiguous-private")

        def describe_stack_events(self, **kwargs):
            self.calls.append(("describe_stack_events", kwargs))
            return base._ok(StackEvents=[{
                "StackId": base.STACK,
                "StackName": base.STACK_NAME,
                "ClientRequestToken": "different-run-token",
                "ResourceType": "AWS::CloudFormation::Stack", "LogicalResourceId": base.STACK_NAME, "PhysicalResourceId": base.STACK,
                "ResourceStatus": "UPDATE_COMPLETE",
            }])

    journal = base.Journal()
    coordinator, cfn = base._coordinator(journal)
    cfn.__class__ = EventWithWrongToken

    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    result = coordinator.run_step("check-update")
    assert result["category"] == "update_outcome_unknown"
    assert journal.state["update_event_observed"] is False
    assert journal.state["update_verified"] is False


def test_malformed_update_ack_stack_id_is_unknown_and_not_replayed():
    class WrongStackAck(base.CloudFormation):
        def update_stack(self, **kwargs):
            self.calls.append(("update_stack", kwargs))
            self.updated = True
            return base._ok(StackId="arn:aws:cloudformation:eu-west-1:123456789012:stack/other/00000000-0000-4000-8000-000000000000")

    journal = base.Journal()
    coordinator, cfn = base._coordinator(journal)
    cfn.__class__ = WrongStackAck

    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    assert coordinator.run_step("request-update")["category"] == "update_outcome_unknown"
    assert coordinator.run_step("request-update")["category"] == "update_intent_present"
    assert sum(name == "update_stack" for name, _ in cfn.calls) == 1


def test_event_observed_without_stack_binding_is_rejected():
    journal = base.Journal()
    coordinator, _ = base._coordinator(journal)
    assert coordinator.run_step("preflight")["category"] == "preflight_verified"
    journal.state["update_intent"] = {"client_request_token": base.RUN}
    journal.state["update_event_observed"] = True
    journal.state["stack_id"] = None
    result = coordinator.run_step("check-update")
    assert result["category"] == "journal_invalid"
