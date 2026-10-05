"""Bounded exact-stack lifecycle update; never expires runtime ZIPs."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT, ROOT / "src"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from scripts.build_aws_prod_artifacts import fixed_prod_artifact_template
from scripts.run_cd_delivery_bootstrap import BootstrapError, canonical, epoch, guard, require
from scripts.run_aws_closed_rehearsal import FileJournal

STACK = "honda-mapit-mcp-prod-runtime-artifacts"


def owned_stack(cf, account):
    rows = cf.describe_stacks(StackName=STACK)["Stacks"]
    require(len(rows) == 1, "artifact_stack_unverified")
    s = rows[0]
    require(s["StackName"] == STACK and s["StackId"].startswith(f"arn:aws:cloudformation:eu-west-1:{account}:stack/{STACK}/") and
            not s.get("RoleARN"), "artifact_stack_unverified")
    require({t["Key"]: t["Value"] for t in s.get("Tags", [])}.get("Project") == "honda-mapit-mcp", "artifact_stack_unverified")
    return s


def template_read(cf, stack):
    value = cf.get_template(StackName=stack, TemplateStage="Original")["TemplateBody"]
    return json.loads(value) if isinstance(value, str) else value


def storage_readback(s3, bucket, account):
    args = {"Bucket": bucket, "ExpectedBucketOwner": account}
    require(not s3.get_bucket_versioning(**args).get("Status"), "bucket_versioning_unverified")
    block = s3.get_public_access_block(**args)["PublicAccessBlockConfiguration"]
    require(block == {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}, "bucket_privacy_unverified")
    ownership = s3.get_bucket_ownership_controls(**args)["OwnershipControls"]
    require(ownership == {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]}, "bucket_ownership_unverified")
    rules = s3.get_bucket_encryption(**args)["ServerSideEncryptionConfiguration"]["Rules"]
    require(len(rules) == 1 and rules[0]["ApplyServerSideEncryptionByDefault"] == {"SSEAlgorithm": "AES256"}, "bucket_encryption_unverified")
    policy = json.loads(s3.get_bucket_policy(**args)["Policy"])
    expected = {"Version": "2012-10-17", "Statement": [{
        "Sid": "DenyInsecureTransportForThisBucketOnly", "Effect": "Deny",
        "Principal": "*", "Action": "s3:*", "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
    }]}
    require(canonical(policy) == canonical(expected), "bucket_policy_unverified")


def run(step, journal, clients, *, clock=time.time):
    require(step in {"prepare", "request", "verify"}, "step_invalid")
    with journal.locked():
        state = journal.load()
        require(state and state.get("kind") == "cd_delivery_preparation", "journal_invalid")
        inventory = state["inventory"]
        account, bucket = inventory["account"], inventory["bucket"]
        caller = clients["sts"].get_caller_identity()
        require(caller.get("Account") == account and ":root" not in caller.get("Arn", ""), "identity_unverified")
        cf, s3 = clients["cloudformation"], clients["s3"]
        stack = owned_stack(cf, account)
        desired = fixed_prod_artifact_template(journal_retention_days=30)
        desired_sha = hashlib.sha256(canonical(desired)).hexdigest()
        if step == "prepare":
            require("retention" not in state, "prepare_consumed")
            require(stack["StackStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}, "stack_not_complete")
            require(canonical(template_read(cf, stack["StackId"])) == canonical(fixed_prod_artifact_template()), "artifact_template_mismatch")
            rows = cf.describe_stack_resources(StackName=stack["StackId"])["StackResources"]
            require(len(rows) == 2 and sum(x["ResourceType"] == "AWS::S3::Bucket" and x["LogicalResourceId"] == "RuntimeArtifactBucket" and x["PhysicalResourceId"] == bucket for x in rows) == 1, "bucket_binding_unverified")
            storage_readback(s3, bucket, account)
            try:
                s3.get_bucket_lifecycle_configuration(Bucket=bucket, ExpectedBucketOwner=account)
            except Exception as exc:
                require(getattr(exc, "response", {}).get("Error", {}).get("Code") == "NoSuchLifecycleConfiguration", "existing_lifecycle_unverified")
            else:
                raise BootstrapError("existing_lifecycle_conflict")
            now = epoch(clock)
            state["retention"] = {"stack_arn": stack["StackId"], "template_sha256": desired_sha,
                                  "operator_arn": caller["Arn"], "last_observed_epoch": now,
                                  "start": now, "end": now + 3600, "token": str(uuid.uuid4())}
            journal.save(state)
            return {"ok": True, "category": "retention_prepared"}
        binding = state.get("retention", {})
        require(binding.get("stack_arn") == stack["StackId"] and binding.get("template_sha256") == desired_sha, "retention_binding_changed")
        require(caller.get("Arn") == binding.get("operator_arn"), "operator_changed")
        guard(binding, clock)
        if step == "request":
            require("update_intent" not in binding, "update_consumed")
            require(stack["StackStatus"] in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} and canonical(template_read(cf, stack["StackId"])) == canonical(fixed_prod_artifact_template()), "artifact_template_mismatch")
            guard(binding, clock)
            binding["update_intent"] = binding["token"]
            journal.save(state)
            try:
                reply = cf.update_stack(StackName=stack["StackId"], TemplateBody=canonical(desired).decode("ascii"), ClientRequestToken=binding["token"])
                require(reply.get("StackId") == stack["StackId"] and reply.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200, "update_ack_invalid")
            except Exception:
                raise BootstrapError("retention_update_outcome_unknown") from None
            binding["update_acknowledged"] = True
            guard(binding, clock)
            journal.save(state)
            return {"ok": True, "category": "retention_update_pending"}
        require(binding.get("update_intent") == binding["token"], "update_required")
        if stack["StackStatus"] == "UPDATE_IN_PROGRESS":
            return {"ok": True, "category": "retention_update_pending"}
        require(stack["StackStatus"] == "UPDATE_COMPLETE" and canonical(template_read(cf, stack["StackId"])) == canonical(desired), "retention_update_unverified")
        rules = s3.get_bucket_lifecycle_configuration(Bucket=bucket, ExpectedBucketOwner=account)["Rules"]
        require(len(rules) == 1 and rules[0].get("ID") == "CdDeliveryJournalRetention" and rules[0].get("Status") == "Enabled" and
                rules[0].get("Expiration") == {"Days": 30} and
                rules[0].get("Filter") == {"And": {"Prefix": "journals/", "Tags": [{"Key": "cd-terminal", "Value": "true"}]}} and
                set(rules[0]) <= {"ID", "Status", "Expiration", "Prefix", "Filter"}, "retention_rule_mismatch")
        storage_readback(s3, bucket, account)
        binding["verified"] = True
        guard(binding, clock)
        journal.save(state)
        return {"ok": True, "category": "retention_verified", "days": 30, "runtime_expiry": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=("prepare", "request", "verify"))
    parser.add_argument("--state-directory", required=True)
    args = parser.parse_args()
    try:
        import boto3
        from botocore.config import Config
        config = Config(region_name="eu-west-1", connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1})
        session = boto3.Session(region_name="eu-west-1")
        clients = {x: session.client(x, config=config) for x in ("sts", "cloudformation", "s3")}
        result = run(args.step, FileJournal(Path(args.state_directory)), clients)
    except BootstrapError as exc:
        result = {"ok": False, "category": str(exc)}
    except Exception:
        result = {"ok": False, "category": "retention_failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
