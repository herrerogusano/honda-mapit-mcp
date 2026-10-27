"""SDK-shaped retained artifact responses for the complete readback fixture."""
from __future__ import annotations

import base64
import copy
import json


class ArtifactResponses:
    def __init__(self, authority, sizes):
        self.account = authority["account_id"]
        self.bucket = authority["artifact_bucket"]
        self.sizes = dict(sizes)
        self.name = "honda-mapit-mcp-dev-retained-runtime-artifacts"
        self.stack = (f"arn:aws:cloudformation:eu-west-1:{self.account}:stack/"
                      f"{self.name}/22222222-3333-4333-8444-555555555555")
        self.calls = []

    def dispatch(self, service, method, kwargs):
        """Return None only when this is not an artifact fixture operation."""
        if service == "cloudformation":
            if kwargs.get("StackName") not in (self.name, self.stack):
                return None
            if method == "describe_stacks":
                body = {"Stacks": [{"StackId": self.stack, "StackName": self.name,
                    "StackStatus": "CREATE_COMPLETE", "EnableTerminationProtection": True}]}
            elif method == "describe_stack_resources":
                body = {"StackResources": [{"LogicalResourceId": name,
                    "PhysicalResourceId": self.bucket, "ResourceType": kind,
                    "ResourceStatus": "CREATE_COMPLETE", "StackId": self.stack,
                    "StackName": self.name} for name, kind in (
                        ("RuntimeArtifactBucket", "AWS::S3::Bucket"),
                        ("RuntimeArtifactBucketPolicy", "AWS::S3::BucketPolicy"))]}
            else:
                raise AssertionError((service, method))
        elif service == "s3":
            expected = {"Bucket": self.bucket, "ExpectedBucketOwner": self.account}
            if method == "head_object":
                key = kwargs.get("Key", "")
                assert key.startswith("runtime/") and key.endswith(".zip")
                digest = key[8:-4]
                assert kwargs == {**expected, "Key": key, "ChecksumMode": "ENABLED"}
                body = {"ContentLength": self.sizes[digest], "ContentType": "application/zip",
                    "ChecksumSHA256": base64.b64encode(bytes.fromhex(digest)).decode("ascii"),
                    "ServerSideEncryption": "AES256"}
            else:
                assert kwargs == expected
                responses = {
                    "get_public_access_block": {"PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True, "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
                    "get_bucket_encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}},
                    "get_bucket_ownership_controls": {"OwnershipControls": {"Rules": [
                        {"ObjectOwnership": "BucketOwnerEnforced"}]}},
                    "get_bucket_versioning": {},
                    "get_bucket_location": {"LocationConstraint": "eu-west-1"},
                    "get_bucket_policy_status": {"PolicyStatus": {"IsPublic": False}},
                    "get_bucket_policy": {"Policy": json.dumps({"Version": "2012-10-17",
                        "Statement": [{"Sid": "DenyInsecureTransportForThisBucketOnly",
                            "Effect": "Deny", "Principal": "*", "Action": "s3:*",
                            "Resource": [f"arn:aws:s3:::{self.bucket}", f"arn:aws:s3:::{self.bucket}/*"],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})},
                    "get_bucket_tagging": {"TagSet": [{"Key": key, "Value": value}
                        for key, value in {"Project": "honda-mapit-mcp", "Environment": "dev",
                            "Purpose": "retained-dev-artifacts", "OperatorRunId": "123"}.items()]},
                    "get_bucket_lifecycle_configuration": {"Rules": [{
                        "ID": "DevTerminalJournalRetention", "Status": "Enabled",
                        "Filter": {"And": {"Prefix": "journals/", "Tags": [
                            {"Key": "cd-terminal", "Value": "true"}]}},
                        "Expiration": {"Days": 30}}]},
                }
                body = responses[method]
        else:
            return None
        self.calls.append((service, method, copy.deepcopy(kwargs)))
        return {**copy.deepcopy(body), "ResponseMetadata": {"HTTPStatusCode": 200}}
