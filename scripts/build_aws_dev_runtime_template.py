"""Build disabled AWS dev runtime-artifact templates offline.

These factories do not create a bucket, upload an artifact, or deploy a stack.
The generated bucket has a CloudFormation-assigned name; the candidate runtime
template consumes only a separately validated bucket name and ZIP SHA-256.
"""

from __future__ import annotations

import re
from typing import Any

from scripts.build_aws_dev_bootstrap import fixed_bootstrap_template

_REGION = "eu-west-1"
_STACK_NAME = "honda-mapit-mcp-dev-runtime-artifacts"
_BUCKET_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{1,61}[a-z0-9])$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_HANDLER = "mapit.aws_dev_entrypoint.handler"


class RuntimeTemplateError(ValueError):
    """Closed local validation error without echoing the supplied input."""


def _deployment_condition() -> dict[str, Any]:
    return {
        "Fn::And": [
            {"Fn::Equals": [{"Ref": "AWS::Region"}, _REGION]},
            {"Fn::Equals": [{"Ref": "AWS::StackName"}, _STACK_NAME]},
        ]
    }


def fixed_runtime_bucket_template() -> dict[str, Any]:
    """Return a fresh temporary private artifact-bucket stack template."""
    tags = [
        {"Key": "Project", "Value": "honda-mapit-mcp"},
        {"Key": "Environment", "Value": "dev"},
        {"Key": "Purpose", "Value": "temporary-runtime-artifact"},
    ]
    bucket_arn = {"Fn::GetAtt": ["RuntimeArtifactBucket", "Arn"]}
    object_arn = {"Fn::Sub": "${RuntimeArtifactBucket.Arn}/*"}
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Review-only temporary private dev runtime-artifact bucket; not deployment-ready.",
        "Metadata": {
            "Readiness": "TEMPORARY_ARTIFACT_BUCKET_NOT_DEPLOY_READY",
            "Region": _REGION,
            "NoUploadOrDeployment": True,
            "NoAutomaticCleanupClaim": True,
            "MissingPrerequisites": [
                "approved runtime candidate and artifact hash",
                "operator verifies the bucket is empty before stack deletion",
                "bounded upload, exact object readback, and explicit cleanup procedure",
            ],
        },
        "Conditions": {"SupportedDeployment": _deployment_condition()},
        "Resources": {
            "RuntimeArtifactBucket": {
                "Type": "AWS::S3::Bucket",
                "Condition": "SupportedDeployment",
                "DeletionPolicy": "Delete",
                "UpdateReplacePolicy": "Delete",
                "Properties": {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    },
                    "OwnershipControls": {
                        "Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}],
                    },
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{
                            "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                        }],
                    },
                    "Tags": tags,
                },
            },
            "RuntimeArtifactBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Condition": "SupportedDeployment",
                "DeletionPolicy": "Delete",
                "UpdateReplacePolicy": "Delete",
                "Properties": {
                    "Bucket": {"Ref": "RuntimeArtifactBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "DenyInsecureTransportForThisBucketOnly",
                            "Effect": "Deny",
                            "Principal": "*",
                            "Action": "s3:*",
                            "Resource": [bucket_arn, object_arn],
                            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                        }],
                    },
                },
            },
        },
        "Outputs": {
            "RuntimeArtifactBucketName": {
                "Condition": "SupportedDeployment",
                "Value": {"Ref": "RuntimeArtifactBucket"},
            },
        },
    }


def _validate_bucket_name(bucket_name: str) -> str:
    if type(bucket_name) is not str or len(bucket_name) < 3 or len(bucket_name) > 63:
        raise RuntimeTemplateError("runtime_bucket_name_invalid")
    if not _BUCKET_NAME.fullmatch(bucket_name) or ".." in bucket_name:
        raise RuntimeTemplateError("runtime_bucket_name_invalid")
    if bucket_name.startswith(("xn--", "sthree-", "amzn-s3-demo-")) or bucket_name.endswith(
        ("-s3alias", "-ext-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")
    ):
        raise RuntimeTemplateError("runtime_bucket_name_invalid")
    labels = bucket_name.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        raise RuntimeTemplateError("runtime_bucket_name_invalid")
    if re.fullmatch(r"[0-9]+(?:\.[0-9]+){3}", bucket_name):
        raise RuntimeTemplateError("runtime_bucket_name_invalid")
    return bucket_name


def fixed_runtime_candidate_template(bucket_name: str, zip_sha256: str) -> dict[str, Any]:
    """Return a closed runtime candidate using one content-addressed S3 key.

    Only the fixed Lambda handler, S3 code location, and readiness metadata
    differ from the fixed six-resource bootstrap scaffold. The function remains
    reserved at zero and the API endpoint remains disabled.
    """
    bucket_name = _validate_bucket_name(bucket_name)
    if type(zip_sha256) is not str or not _SHA256.fullmatch(zip_sha256):
        raise RuntimeTemplateError("runtime_artifact_hash_invalid")

    template = fixed_bootstrap_template()
    resources = template.get("Resources")
    if not isinstance(resources, dict):
        raise RuntimeTemplateError("bootstrap_scaffold_invalid")
    function = resources.get("McpHandler")
    if not isinstance(function, dict) or not isinstance(function.get("Properties"), dict):
        raise RuntimeTemplateError("bootstrap_scaffold_invalid")
    properties = function["Properties"]
    if properties.get("ReservedConcurrentExecutions") != 0:
        raise RuntimeTemplateError("bootstrap_scaffold_not_closed")
    api = resources.get("McpApi")
    if not isinstance(api, dict) or not isinstance(api.get("Properties"), dict) or api["Properties"].get("DisableExecuteApiEndpoint") is not True:
        raise RuntimeTemplateError("bootstrap_scaffold_not_closed")

    properties["Handler"] = _HANDLER
    properties["Code"] = {"S3Bucket": bucket_name, "S3Key": f"runtime/{zip_sha256}.zip"}
    metadata = template.get("Metadata")
    if not isinstance(metadata, dict):
        raise RuntimeTemplateError("bootstrap_scaffold_invalid")
    metadata.update({
        "Readiness": "RUNTIME_CANDIDATE_NOT_DEPLOY_READY",
        "RuntimeImplementation": True,
        "RuntimeActivation": False,
        "ArtifactReference": "content-addressed S3 object; no version ID is pinned",
        "MissingPrerequisites": [
            "real owner, callback, Cognito client, and public-key binding",
            "runtime template and exact object readback reviewed before deployment",
            "operator confirms the temporary bucket is empty before deletion",
            "closed shutdown and cleanup acceptance before any activation",
        ],
    })
    return template


__all__ = [
    "RuntimeTemplateError",
    "fixed_runtime_bucket_template",
    "fixed_runtime_candidate_template",
]
