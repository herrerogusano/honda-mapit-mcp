"""Fresh one-attempt update of the existing four-resource CD IAM stack only.

The private journal retains both templates. Clients are injected into run();
the CLI constructs bounded owner clients, never assumes a delivery role.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
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

from scripts import run_cd_delivery_bootstrap as bootstrap
from scripts.run_aws_closed_rehearsal import FileJournal

REGION, STACK = bootstrap.REGION, bootstrap.STACK


class KeyUpdateError(ValueError):
    """Only fixed categories leave the operator."""


def require(condition, category):
    if not condition:
        raise KeyUpdateError(category)


def digest(value):
    return hashlib.sha256(bootstrap.canonical(value)).hexdigest()


def _receipt(state):
    account = state["inventory"]["account"]
    receipt = state.get("lambda_environment_key", {})
    evidence = state.get("lambda_environment_key_context_evidence", {})
    arn = receipt.get("arn")
    require(type(arn) is str and re.fullmatch(
        rf"arn:aws:kms:{REGION}:{account}:key/[0-9a-f]{{8}}-(?:[0-9a-f]{{4}}-){{3}}[0-9a-f]{{12}}", arn), "key_receipt_invalid")
    require(receipt.get("aws_managed") is True and receipt.get("enabled") is True
            and receipt.get("multi_region") is False, "key_receipt_invalid")
    context = {"aws:lambda:FunctionArn": f"arn:aws:lambda:{REGION}:{account}:function:honda-mapit-mcp-prod-handler"}
    contexts = evidence.get("contexts")
    require(type(contexts) is list and len(contexts) == 3 and all(x == context for x in contexts)
            and evidence.get("readback_exact_key") is True and evidence.get("function_context_exact") is True,
            "key_context_invalid")
    return arn, digest({"key": receipt, "evidence": evidence})


def _new_template(inventory, key_arn):
    return bootstrap.template_from_inventory(inventory, lambda_environment_key_arn=key_arn)


def _guard(binding, clock):
    try:
        bootstrap.guard(binding, clock)
    except bootstrap.BootstrapError:
        raise KeyUpdateError("window_expired") from None


def _read(clients, binding, clock, service, method, **kwargs):
    _guard(binding, clock)
    try:
        result = getattr(clients[service], method)(**kwargs)
    except Exception:
        raise KeyUpdateError("read_failed") from None
    _guard(binding, clock)
    require(type(result) is dict and type(result.get("ResponseMetadata", {}).get("HTTPStatusCode")) is int
            and result["ResponseMetadata"]["HTTPStatusCode"] == 200, "read_response_invalid")
    return result


def _key(clients, binding, clock, account, key_arn):
    metadata = _read(clients, binding, clock, "kms", "describe_key", KeyId="alias/aws/lambda").get("KeyMetadata", {})
    require(metadata.get("Arn") == key_arn and metadata.get("AWSAccountId") == account
            and metadata.get("KeyManager") == "AWS" and metadata.get("KeyState") == "Enabled"
            and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT" and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
            and metadata.get("MultiRegion") is False, "key_changed")


def _stack(clients, binding, clock, template, original, account, *, pending=False):
    read = lambda service, method, **kw: _read(clients, binding, clock, service, method, **kw)
    arn = original["stack_arn"]
    rows = read("cloudformation", "describe_stacks", StackName=arn).get("Stacks")
    require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict, "stack_unverified")
    stack = rows[0]
    tags = [{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": "prod"},
            {"Key": "UniqueCdDeliveryRunId", "Value": original["run_id"]}]
    require(re.fullmatch(rf"arn:aws:cloudformation:{REGION}:{account}:stack/{STACK}/[0-9a-f]{{8}}-(?:[0-9a-f]{{4}}-){{3}}[0-9a-f]{{12}}", arn)
            and stack.get("StackId") == arn and stack.get("StackName") == STACK
            and stack.get("EnableTerminationProtection") is True and stack.get("RoleARN") in (None, "")
            and sorted(stack.get("Tags", []), key=lambda x: x["Key"]) == sorted(tags, key=lambda x: x["Key"]), "stack_unverified")
    if pending and stack.get("StackStatus") == "UPDATE_IN_PROGRESS":
        return False
    require(stack.get("StackStatus") in ({"UPDATE_COMPLETE"} if pending else {"CREATE_COMPLETE", "UPDATE_COMPLETE"}), "stack_not_complete")
    actual = read("cloudformation", "get_template", StackName=arn, TemplateStage="Original").get("TemplateBody")
    if type(actual) is str:
        actual = json.loads(actual)
    require(bootstrap.canonical(actual) == bootstrap.canonical(template), "template_mismatch")
    resources = read("cloudformation", "describe_stack_resources", StackName=arn).get("StackResources")
    require(type(resources) is list and len(resources) == 4
            and {x["LogicalResourceId"] for x in resources} == set(template["Resources"]), "resources_mismatch")
    for row in resources:
        resource = template["Resources"][row["LogicalResourceId"]]
        p = resource["Properties"]
        require(row.get("ResourceType") == resource["Type"]
                and row.get("ResourceStatus") in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}, "resources_mismatch")
        if resource["Type"] == "AWS::IAM::ManagedPolicy":
            policy_arn = f"arn:aws:iam::{account}:policy/{p['ManagedPolicyName']}"
            require(row.get("PhysicalResourceId") == policy_arn, "boundary_mismatch")
            policy = read("iam", "get_policy", PolicyArn=policy_arn).get("Policy", {})
            version = policy.get("DefaultVersionId")
            require(policy.get("Arn") == policy_arn and policy.get("AttachmentCount") == 0
                    and policy.get("PermissionsBoundaryUsageCount") == 1
                    and type(version) is str and re.fullmatch(r"v[1-9][0-9]*", version), "boundary_mismatch")
            document = read("iam", "get_policy_version", PolicyArn=policy_arn, VersionId=version).get("PolicyVersion", {})
            require(document.get("IsDefaultVersion") is True and document.get("VersionId") == version
                    and bootstrap.canonical(document.get("Document")) == bootstrap.canonical(p["PolicyDocument"]), "boundary_mismatch")
        else:
            name = p["RoleName"]
            require(row.get("PhysicalResourceId") == name, "role_mismatch")
            role = read("iam", "get_role", RoleName=name).get("Role", {})
            boundary_name = template["Resources"][p["PermissionsBoundary"]["Fn::GetAtt"][0]]["Properties"]["ManagedPolicyName"]
            role_tags = role.get("Tags", [])
            tagmap = {t["Key"]: t["Value"] for t in role_tags}
            require(role.get("Arn") == f"arn:aws:iam::{account}:role/{name}" and role.get("Path") == "/"
                    and role.get("MaxSessionDuration") == 3600
                    and role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") == f"arn:aws:iam::{account}:policy/{boundary_name}"
                    and role.get("PermissionsBoundary", {}).get("PermissionsBoundaryType") in {"Policy", "PermissionsBoundaryPolicy"}
                    and bootstrap.canonical(role.get("AssumeRolePolicyDocument")) == bootstrap.canonical(p["AssumeRolePolicyDocument"])
                    and len(tagmap) == len(role_tags) and all(tagmap.get(t["Key"]) == t["Value"] for t in p["Tags"])
                    and tagmap.get("UniqueCdDeliveryRunId", original["run_id"]) == original["run_id"], "role_mismatch")
            names = read("iam", "list_role_policies", RoleName=name)
            attached = read("iam", "list_attached_role_policies", RoleName=name)
            require(names.get("IsTruncated") is False and names.get("PolicyNames") == [p["Policies"][0]["PolicyName"]]
                    and attached.get("IsTruncated") is False and attached.get("AttachedPolicies") == [], "role_mismatch")
            document = read("iam", "get_role_policy", RoleName=name, PolicyName=p["Policies"][0]["PolicyName"])
            require(bootstrap.canonical(document.get("PolicyDocument")) == bootstrap.canonical(p["Policies"][0]["PolicyDocument"]), "role_mismatch")
    return True


def run(step, journal, clients, source_sha, *, clock=time.time):
    require(step in {"prepare", "update", "verify"}, "step_invalid")
    require(type(source_sha) is str and re.fullmatch(r"[0-9a-f]{40}", source_sha) and source_sha != "0" * 40, "source_invalid")
    with journal.locked():
        state = journal.load()
        require(type(state) is dict and state.get("kind") == "cd_delivery_preparation", "journal_invalid")
        original = state.get("bootstrap", {})
        require(original.get("verified") is True and original.get("create_intent") == original.get("run_id"), "bootstrap_unverified")
        inventory, account = state["inventory"], state["inventory"]["account"]
        key_arn, evidence_sha = _receipt(state)
        old, new = bootstrap.template_from_inventory(inventory), _new_template(inventory, key_arn)
        require(original.get("template_sha256") == digest(old) and set(old["Resources"]) == set(new["Resources"])
                and len(old["Resources"]) == 4 and old != new, "template_binding_invalid")
        if step == "prepare":
            require("environment_key_update" not in state, "prepare_consumed")
            now = bootstrap.epoch(clock)
            binding = {"source_sha": source_sha, "old_template_sha256": digest(old), "new_template_sha256": digest(new),
                       "evidence_sha256": evidence_sha, "key_arn": key_arn, "stack_arn": original["stack_arn"],
                       "bootstrap_run_id": original["run_id"], "run_id": str(uuid.uuid4()),
                       "start": now, "end": now + 3600, "last_observed_epoch": now,
                       "recovery_template": copy.deepcopy(old), "proposed_template": copy.deepcopy(new)}
        else:
            binding = state.get("environment_key_update", {})
            require(binding.get("source_sha") == source_sha and binding.get("old_template_sha256") == digest(old)
                    and binding.get("new_template_sha256") == digest(new) and binding.get("evidence_sha256") == evidence_sha
                    and binding.get("key_arn") == key_arn and binding.get("stack_arn") == original["stack_arn"]
                    and binding.get("bootstrap_run_id") == original["run_id"]
                    and binding.get("recovery_template") == old and binding.get("proposed_template") == new
                    and type(binding.get("run_id")) is str and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", binding["run_id"]), "binding_changed")
        read = lambda service, method, **kw: _read(clients, binding, clock, service, method, **kw)
        identity = read("sts", "get_caller_identity")
        operator = identity.get("Arn")
        require(identity.get("Account") == account and type(operator) is str
                and re.fullmatch(rf"arn:aws:(?:iam|sts)::{account}:(?:user|assumed-role)/[A-Za-z0-9+=,.@_/-]+", operator), "identity_unverified")
        if step == "prepare":
            binding["operator_arn"] = operator
        else:
            require(binding.get("operator_arn") == operator, "operator_changed")
        _key(clients, binding, clock, account, key_arn)
        provider = read("iam", "get_open_id_connect_provider", OpenIDConnectProviderArn=inventory["identity"]["provider_arn"])
        require(provider.get("Url") == "token.actions.githubusercontent.com"
                and provider.get("ClientIDList") == ["sts.amazonaws.com"], "provider_unverified")
        if step == "verify":
            require(binding.get("update_intent") == binding["run_id"], "update_required")
            if not _stack(clients, binding, clock, new, original, account, pending=True):
                _guard(binding, clock)
                journal.save(state)
                return {"ok": True, "category": "key_update_pending"}
            binding["verified"] = True
            _guard(binding, clock)
            journal.save(state)
            return {"ok": True, "category": "key_update_verified", "roles": 2, "boundaries": 2}
        if step == "update":
            require("update_intent" not in binding, "update_consumed")
        _stack(clients, binding, clock, old, original, account)
        _guard(binding, clock)
        if step == "prepare":
            state["environment_key_update"] = binding
            journal.save(state)
            return {"ok": True, "category": "key_update_prepared"}
        binding["update_intent"] = binding["run_id"]
        journal.save(state)
        _guard(binding, clock)
        try:
            reply = clients["cloudformation"].update_stack(
                StackName=original["stack_arn"], TemplateBody=bootstrap.canonical(new).decode("ascii"),
                Capabilities=["CAPABILITY_NAMED_IAM"], ClientRequestToken=binding["run_id"])
            require(type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is int
                    and reply["ResponseMetadata"]["HTTPStatusCode"] == 200
                    and reply.get("StackId") == original["stack_arn"], "update_ack_invalid")
        except Exception:
            raise KeyUpdateError("update_outcome_unknown") from None
        _guard(binding, clock)
        binding["update_acknowledged"] = True
        journal.save(state)
        return {"ok": True, "category": "key_update_pending"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("step", choices=("prepare", "update", "verify"))
    parser.add_argument("--state-directory", required=True)
    args = parser.parse_args()
    try:
        import boto3
        from botocore.config import Config
        session = boto3.Session(region_name=REGION)
        clients = {}
        for name in ("sts", "kms", "iam", "cloudformation"):
            region = "us-east-1" if name == "iam" else REGION
            endpoint = "https://iam.amazonaws.com" if name == "iam" else f"https://{name}.{REGION}.amazonaws.com"
            clients[name] = session.client(name, endpoint_url=endpoint, config=Config(
                region_name=region, connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1}, proxies={}))
        source = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True).stdout.strip()
        result = run(args.step, FileJournal(Path(args.state_directory)), clients, source)
    except KeyUpdateError as exc:
        result = {"ok": False, "category": str(exc)}
    except Exception:
        result = {"ok": False, "category": "key_update_failed"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
