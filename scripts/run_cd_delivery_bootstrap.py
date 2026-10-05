"""One-attempt, private-journal bootstrap of the two production CD roles.

No application update, identity reset, provider change or package publication.
The operator supplies an ACL-protected inventory receipt outside the checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for directory in (ROOT, ROOT / "src"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

from scripts.build_cd_delivery_roles import build_cd_delivery_roles
from scripts.run_aws_closed_rehearsal import FileJournal

STACK = "honda-mapit-mcp-cd-delivery"
REGION = "eu-west-1"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


class BootstrapError(ValueError):
    pass


def require(value, category):
    if not value:
        raise BootstrapError(category)


def epoch(clock):
    value = clock()
    require(type(value) in (int, float) and math.isfinite(value) and value > 0, "clock_invalid")
    return int(value)


def guard(binding, clock):
    now = epoch(clock)
    require(type(binding.get("start")) is int and type(binding.get("end")) is int and
            type(binding.get("last_observed_epoch")) is int and
            binding["end"] - binding["start"] == 3600 and
            binding["start"] <= binding["last_observed_epoch"] <= now < binding["end"], "window_expired")
    binding["last_observed_epoch"] = now


def template_from_inventory(inventory, *, lambda_environment_key_arn=None):
    identity = inventory["identity"]
    account = inventory["account"]
    subject = identity["observed_subjects"]["prod"]
    return build_cd_delivery_roles(
        account_id=account, provider_arn=identity["provider_arn"],
        owner_id=identity["owner_id"], repository_id=identity["repository_id"],
        observed_prod_subject_format=subject["format"],
        observed_prod_subject_sha256=subject["sha256"],
        stack_arn=inventory["stack"]["StackId"],
        handler_arn=f"arn:aws:lambda:{REGION}:{account}:function:honda-mapit-mcp-prod-handler",
        api_arn=f"arn:aws:apigateway:{REGION}::/apis/{inventory['manifest']['api_id']}",
        shutdown_state_machine_arn=f"arn:aws:states:{REGION}:{account}:stateMachine:honda-mapit-mcp-prod-shutdown",
        artifact_bucket_arn=f"arn:aws:s3:::{inventory['bucket']}",
        execution_role_arn=inventory["execution_role"],
        tripwire_alarm_arn=f"arn:aws:cloudwatch:{REGION}:{account}:alarm:honda-mapit-mcp-prod-request-tripwire",
        tripwire_rule_arn=f"arn:aws:events:{REGION}:{account}:rule/honda-mapit-mcp-prod-request-tripwire-alarm-rule",
        allow_execution_role_passrole=True,
        lambda_environment_key_arn=lambda_environment_key_arn,
    )


def absent(call, code):
    try:
        call()
    except Exception as exc:
        reply = getattr(exc, "response", {})
        error = reply.get("Error", {})
        if error.get("Code") == code:
            if code != "ValidationError" or "does not exist" in str(error.get("Message", "")).lower():
                return
        raise BootstrapError("absence_unverified") from None
    raise BootstrapError("name_conflict")


def run(step, journal, clients, source_sha, *, clock=time.time):
    require(step in {"prepare", "create", "verify"}, "step_invalid")
    require(re.fullmatch(r"[0-9a-f]{40}", source_sha or "") and source_sha != "0" * 40, "source_invalid")
    with journal.locked():
        state = journal.load()
        require(state and state.get("kind") == "cd_delivery_preparation", "journal_invalid")
        inventory = state["inventory"]
        account = inventory["account"]
        template = template_from_inventory(inventory)
        digest = hashlib.sha256(canonical(template)).hexdigest()
        identity = clients["sts"].get_caller_identity()
        require(identity.get("Account") == account and ":root" not in identity.get("Arn", ""), "identity_unverified")
        cf, iam = clients["cloudformation"], clients["iam"]
        if step == "prepare":
            require("bootstrap" not in state, "prepare_consumed")
            absent(lambda: cf.describe_stacks(StackName=STACK), "ValidationError")
            for resource in template["Resources"].values():
                properties = resource["Properties"]
                if resource["Type"] == "AWS::IAM::Role":
                    absent(lambda p=properties: iam.get_role(RoleName=p["RoleName"]), "NoSuchEntity")
                else:
                    arn = f"arn:aws:iam::{account}:policy/{properties['ManagedPolicyName']}"
                    absent(lambda a=arn: iam.get_policy(PolicyArn=a), "NoSuchEntity")
            provider = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=inventory["identity"]["provider_arn"])
            require(provider.get("Url") == "token.actions.githubusercontent.com" and provider.get("ClientIDList") == ["sts.amazonaws.com"], "provider_unverified")
            now = epoch(clock)
            state["bootstrap"] = {"source_sha": source_sha, "template_sha256": digest,
                                  "operator_arn": identity["Arn"],
                                  "run_id": str(uuid.uuid4()), "start": now, "end": now + 3600,
                                  "last_observed_epoch": now}
            journal.save(state)
            return {"ok": True, "category": "bootstrap_prepared"}
        binding = state.get("bootstrap", {})
        require(binding.get("source_sha") == source_sha and binding.get("template_sha256") == digest, "binding_changed")
        require(identity.get("Arn") == binding.get("operator_arn"), "operator_changed")
        guard(binding, clock)
        tags = [{"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": "prod"},
                {"Key": "UniqueCdDeliveryRunId", "Value": binding["run_id"]}]
        if step == "create":
            require("create_intent" not in binding, "create_consumed")
            absent(lambda: cf.describe_stacks(StackName=STACK), "ValidationError")
            guard(binding, clock)
            binding["create_intent"] = binding["run_id"]
            journal.save(state)
            try:
                reply = cf.create_stack(StackName=STACK, TemplateBody=canonical(template).decode("ascii"),
                                        Capabilities=["CAPABILITY_NAMED_IAM"], Tags=tags,
                                        ClientRequestToken=binding["run_id"], EnableTerminationProtection=True)
                stack_arn = reply.get("StackId")
                require(reply.get("ResponseMetadata", {}).get("HTTPStatusCode") == 200 and
                        re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK}/[0-9a-f-]{{36}}", stack_arn or ""), "create_ack_invalid")
            except Exception:
                raise BootstrapError("create_outcome_unknown") from None
            binding["stack_arn"] = stack_arn
            guard(binding, clock)
            journal.save(state)
            return {"ok": True, "category": "bootstrap_create_pending"}
        require(binding.get("create_intent") == binding["run_id"], "create_required")
        stacks = cf.describe_stacks(StackName=binding.get("stack_arn", STACK))["Stacks"]
        require(len(stacks) == 1, "stack_unverified")
        stack = stacks[0]
        require(re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK}/[0-9a-f-]{{36}}", stack.get("StackId", "")) and
                (binding.get("stack_arn") is None or stack.get("StackId") == binding["stack_arn"]) and
                stack.get("StackName") == STACK and stack.get("EnableTerminationProtection") is True and
                sorted(stack.get("Tags", []), key=lambda x: x["Key"]) == sorted(tags, key=lambda x: x["Key"]), "stack_unverified")
        if stack.get("StackStatus") == "CREATE_IN_PROGRESS":
            return {"ok": True, "category": "bootstrap_create_pending"}
        require(stack.get("StackStatus") == "CREATE_COMPLETE", "stack_not_complete")
        actual = cf.get_template(StackName=stack["StackId"], TemplateStage="Original")["TemplateBody"]
        if isinstance(actual, str):
            actual = json.loads(actual)
        require(canonical(actual) == canonical(template), "template_mismatch")
        rows = cf.describe_stack_resources(StackName=stack["StackId"])["StackResources"]
        require(len(rows) == 4 and {x["LogicalResourceId"] for x in rows} == set(template["Resources"]), "resources_mismatch")
        for row in rows:
            resource = template["Resources"][row["LogicalResourceId"]]
            p = resource["Properties"]
            require(row["ResourceType"] == resource["Type"] and row["ResourceStatus"] == "CREATE_COMPLETE", "resources_mismatch")
            if resource["Type"] == "AWS::IAM::ManagedPolicy":
                arn = f"arn:aws:iam::{account}:policy/{p['ManagedPolicyName']}"
                require(row["PhysicalResourceId"] == arn, "boundary_mismatch")
                policy = iam.get_policy(PolicyArn=arn)["Policy"]
                require(policy["Arn"] == arn and policy["AttachmentCount"] == 0 and policy.get("PermissionsBoundaryUsageCount") == 1, "boundary_mismatch")
                document = iam.get_policy_version(PolicyArn=arn, VersionId=policy["DefaultVersionId"])["PolicyVersion"]["Document"]
                require(canonical(document) == canonical(p["PolicyDocument"]), "boundary_mismatch")
            else:
                name = p["RoleName"]
                require(row["PhysicalResourceId"] == name, "role_mismatch")
                role = iam.get_role(RoleName=name)["Role"]
                boundary_id = p["PermissionsBoundary"]["Fn::GetAtt"][0]
                boundary_name = template["Resources"][boundary_id]["Properties"]["ManagedPolicyName"]
                role_tags = role.get("Tags", [])
                tagmap = {t["Key"]: t["Value"] for t in role_tags}
                require(role["Arn"] == f"arn:aws:iam::{account}:role/{name}" and role["Path"] == "/" and
                        role["MaxSessionDuration"] == 3600 and role["PermissionsBoundary"]["PermissionsBoundaryArn"] == f"arn:aws:iam::{account}:policy/{boundary_name}" and
                        canonical(role["AssumeRolePolicyDocument"]) == canonical(p["AssumeRolePolicyDocument"]) and
                        len(tagmap) == len(role_tags) and all(tagmap.get(t["Key"]) == t["Value"] for t in p["Tags"]) and
                        tagmap.get("UniqueCdDeliveryRunId", binding["run_id"]) == binding["run_id"], "role_mismatch")
                names = iam.list_role_policies(RoleName=name)
                attachments = iam.list_attached_role_policies(RoleName=name)
                require(names.get("IsTruncated") is False and names.get("PolicyNames") == [p["Policies"][0]["PolicyName"]] and
                        attachments.get("IsTruncated") is False and attachments.get("AttachedPolicies") == [], "role_mismatch")
                document = iam.get_role_policy(RoleName=name, PolicyName=p["Policies"][0]["PolicyName"])["PolicyDocument"]
                require(canonical(document) == canonical(p["Policies"][0]["PolicyDocument"]), "role_mismatch")
        binding["stack_arn"] = stack["StackId"]
        binding["verified"] = True
        guard(binding, clock)
        journal.save(state)
        return {"ok": True, "category": "bootstrap_verified", "roles": 2, "boundaries": 2}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=("prepare", "create", "verify"))
    parser.add_argument("--state-directory", required=True)
    args = parser.parse_args()
    try:
        import boto3
        from botocore.config import Config
        config = Config(region_name=REGION, connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1})
        session = boto3.Session(region_name=REGION)
        clients = {name: session.client(name, config=config) for name in ("sts", "iam", "cloudformation")}
        source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
        result = run(args.step, FileJournal(Path(args.state_directory)), clients, source)
    except BootstrapError as exc:
        result = {"ok": False, "category": str(exc)}
    except Exception:
        result = {"ok": False, "category": "bootstrap_failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
