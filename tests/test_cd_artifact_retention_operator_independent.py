"""Independent synthetic checks for the retention operator's S3 policy gate."""

from __future__ import annotations

import json

import pytest

from scripts.run_cd_artifact_retention import BootstrapError, storage_readback
from test_cd_artifact_retention_operator import ACCOUNT, BUCKET, FakeS3


def tls_only_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "DenyInsecureTransportForThisBucketOnly",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }],
    }


class PolicyS3(FakeS3):
    def __init__(self, policy: dict):
        super().__init__()
        self.policy = policy
        self.policy_calls = []

    def get_bucket_policy(self, **kwargs):
        self.policy_calls.append(kwargs)
        return {"Policy": json.dumps(self.policy)}


def test_storage_readback_requires_exact_tls_only_bucket_policy():
    good = PolicyS3(tls_only_policy(BUCKET))
    storage_readback(good, BUCKET, ACCOUNT)
    assert good.policy_calls == [{"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}]

    drifted = tls_only_policy(BUCKET)
    drifted["Statement"].append({
        "Sid": "UnexpectedCrossAccountRead",
        "Effect": "Allow",
        "Principal": {"AWS": "arn:aws:iam::210987654321:root"},
        "Action": "s3:GetObject",
        "Resource": [f"arn:aws:s3:::{BUCKET}/*"],
    })
    bad = PolicyS3(drifted)
    with pytest.raises(BootstrapError, match="bucket_policy_unverified"):
        storage_readback(bad, BUCKET, ACCOUNT)
    assert bad.policy_calls == [{"Bucket": BUCKET, "ExpectedBucketOwner": ACCOUNT}]
