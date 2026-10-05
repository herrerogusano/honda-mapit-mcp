from __future__ import annotations

import copy

import pytest

from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template
from scripts.build_aws_dev_runtime_template import (
    RuntimeTemplateError,
    fixed_runtime_bucket_template,
    fixed_runtime_candidate_template,
)

BUCKET = "honda-mapit-mcp-dev-runtime-artifacts-abc123xyz789"
SHA = "a" * 64


def test_bucket_template_is_dev_private_encrypted_temporary_and_conditioned():
    template = fixed_runtime_bucket_template()
    resources = template["Resources"]
    bucket = resources["RuntimeArtifactBucket"]
    props = bucket["Properties"]
    assert set(resources) == {"RuntimeArtifactBucket", "RuntimeArtifactBucketPolicy"}
    assert template["Conditions"]["SupportedDeployment"]["Fn::And"] == [
        {"Fn::Equals": [{"Ref": "AWS::Region"}, "eu-west-1"]},
        {"Fn::Equals": [{"Ref": "AWS::StackName"}, "honda-mapit-mcp-dev-runtime-artifacts"]},
    ]
    assert bucket["Condition"] == "SupportedDeployment"
    assert bucket["DeletionPolicy"] == bucket["UpdateReplacePolicy"] == "Delete"
    assert "BucketName" not in props
    assert "VersioningConfiguration" not in props
    assert "AccessControl" not in props
    assert "WebsiteConfiguration" not in props
    assert props["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }
    assert props["OwnershipControls"] == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}
    assert props["BucketEncryption"] == {
        "ServerSideEncryptionConfiguration": [{
            "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
        }]
    }
    assert template["Outputs"]["RuntimeArtifactBucketName"] == {
        "Condition": "SupportedDeployment", "Value": {"Ref": "RuntimeArtifactBucket"}
    }

    policy_resource = resources["RuntimeArtifactBucketPolicy"]
    assert policy_resource["Condition"] == "SupportedDeployment"
    assert policy_resource["DeletionPolicy"] == policy_resource["UpdateReplacePolicy"] == "Delete"
    policy = policy_resource["Properties"]["PolicyDocument"]["Statement"]
    assert len(policy) == 1
    assert policy[0]["Effect"] == "Deny"
    assert policy[0]["Principal"] == "*"
    assert policy[0]["Action"] == "s3:*"
    assert policy[0]["Condition"] == {"Bool": {"aws:SecureTransport": "false"}}
    assert policy[0]["Resource"] == [
        {"Fn::GetAtt": ["RuntimeArtifactBucket", "Arn"]},
        {"Fn::Sub": "${RuntimeArtifactBucket.Arn}/*"},
    ]


@pytest.mark.parametrize("bucket", [
    "", "AUpperCaseBucket", "ab", "-prefixbucket", "suffixbucket-", "dot..dot",
    "192.168.0.1", "a" * 64, "a_b_c",
    "xn--reserved-bucket", "sthree-reserved-bucket", "amzn-s3-demo-reserved-bucket",
    "valid-name-s3alias", "valid-name-ext-s3alias", "valid-name--ol-s3", "valid-name.mrap",
    "valid-name--x-s3", "valid-name--table-s3",
])
def test_runtime_candidate_rejects_invalid_bucket_names(bucket):
    with pytest.raises(RuntimeTemplateError, match="runtime_bucket_name_invalid"):
        fixed_runtime_candidate_template(bucket, SHA)


@pytest.mark.parametrize("digest", ["", "A" * 64, "a" * 63, "g" * 64, "a" * 65])
def test_runtime_candidate_rejects_invalid_artifact_hash(digest):
    with pytest.raises(RuntimeTemplateError, match="runtime_artifact_hash_invalid"):
        fixed_runtime_candidate_template(BUCKET, digest)


def test_runtime_candidate_changes_only_function_handler_code_and_metadata():
    base = fixed_bootstrap_template()
    base_before = copy.deepcopy(base)
    candidate = fixed_runtime_candidate_template(BUCKET, SHA)
    assert base == base_before
    assert candidate["Metadata"]["Readiness"] == "RUNTIME_CANDIDATE_NOT_DEPLOY_READY"
    assert candidate["Metadata"]["RuntimeActivation"] is False
    assert candidate["Metadata"]["MissingPrerequisites"]
    assert set(candidate) == set(base)
    for key in set(base) - {"Resources", "Metadata"}:
        assert candidate[key] == base[key]
    for resource_name, base_resource in base["Resources"].items():
        actual = candidate["Resources"][resource_name]
        if resource_name == "McpHandler":
            expected = copy.deepcopy(base_resource)
            expected["Properties"]["Handler"] = "mapit.aws_dev_entrypoint.handler"
            expected["Properties"]["Code"] = {
                "S3Bucket": BUCKET,
                "S3Key": f"runtime/{SHA}.zip",
            }
            assert actual == expected
        else:
            assert actual == base_resource
    assert candidate["Resources"]["McpApi"]["Properties"]["DisableExecuteApiEndpoint"] is True
    assert candidate["Resources"]["McpHandler"]["Properties"]["ReservedConcurrentExecutions"] == 0
    assert candidate["Resources"]["McpHandlerRole"] == base["Resources"]["McpHandlerRole"]
    assert set(candidate["Resources"]["McpHandler"]["Properties"]["Code"]) == {"S3Bucket", "S3Key"}


def test_runtime_template_factory_returns_independent_copy():
    first = fixed_runtime_candidate_template(BUCKET, SHA)
    first["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"] = "changed"
    second = fixed_runtime_candidate_template(BUCKET, SHA)
    assert second["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"] == f"runtime/{SHA}.zip"
