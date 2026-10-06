"""Optional SDK metadata is not a substitute for exact resource checks."""

import pytest

from test_aws_retained_dev_artifact_bootstrap import (
    CloudFormation, Journal, S3, Sts, _coordinator, _seed_preflight,
)


@pytest.mark.parametrize("metadata,accepted", [
    ({"StackResourceDriftStatus": "NOT_CHECKED"}, True),
    (None, False),
    ({}, False),
    ({"StackResourceDriftStatus": "MODIFIED"}, False),
    ({"StackResourceDriftStatus": "DELETED"}, False),
    ({"StackResourceDriftStatus": "IN_SYNC"}, False),
    ({"StackResourceDriftStatus": "NOT_CHECKED", "unexpected": True}, False),
    ({"StackResourceDriftStatus": "NOT_CHECKED", "LastCheckTimestamp": 1}, False),
])
def test_exact_unchecked_metadata_only(metadata, accepted):
    class WithMetadata(CloudFormation):
        def describe_stack_resources(self, **kwargs):
            response = super().describe_stack_resources(**kwargs)
            for resource in response["StackResources"]:
                resource["DriftInformation"] = metadata
            return response

    journal = Journal()
    cfn = WithMetadata()
    coordinator = _coordinator(journal, clients={"sts": Sts(), "cloudformation": cfn, "s3": S3()})
    _seed_preflight(coordinator, journal)
    assert coordinator.run_step("create")["ok"] is True
    assert coordinator.run_step("readback")["ok"] is accepted
    assert sum(name == "create_stack" for name, _ in cfn.calls) == 1


@pytest.mark.parametrize("configuration,accepted", [
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}, True),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": False}]}, True),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": False, "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}}]}, True),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BlockedEncryptionTypes": {"EncryptionType": []}}]}, False),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BlockedEncryptionTypes": {"EncryptionType": ["NONE"]}}]}, False),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"], "extra": True}}]}, False),
    ([{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}], False),
    ({"Rules": []}, False),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}, False),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256", "KMSMasterKeyID": "unexpected"}}]}, False),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": True}]}, False),
    ({"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}], "extra": True}, False),
])
def test_sdk_encryption_envelope_exact(configuration, accepted):
    from test_aws_retained_dev_artifact_bootstrap import _ok

    class Encryption(S3):
        def get_bucket_encryption(self, **kwargs):
            return _ok(ServerSideEncryptionConfiguration=configuration)

    journal = Journal()
    coordinator = _coordinator(journal, clients={"sts": Sts(), "cloudformation": CloudFormation(), "s3": Encryption()})
    _seed_preflight(coordinator, journal)
    assert coordinator.run_step("create")["ok"] is True
    assert coordinator.run_step("readback")["ok"] is accepted
