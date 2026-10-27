"""Fresh metadata-only bootstrap authority; historical journals are read-only."""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
for item in (str(ROOT), str(ROOT / "src")):
    if item not in sys.path:
        sys.path.insert(0, item)

from scripts.dev_multiuser_closed_update import _digest
from scripts.dev_identity_binding_runtime_evidence import verify_accepted_runtime
from scripts.prepare_dev_multiuser_private import _create_private_directory
from scripts.run_dev_multiuser_runtime_update import CasFileJournal as FileJournal
from scripts.run_aws_retained_dev_bootstrap import (validate_private_location,
    validate_source_and_ci, write_private_authorization, _bounded_command, _reject_duplicates,
    validate_authorization)
from scripts.github_cd_protections import REPOSITORY


def prepare(*, parent, accepted_runtime_directory, source_sha, ci_run_id,
            client_factory=None, source_ci_validator=validate_source_and_ci,
            acl_checker=None, clock=time.time, runtime_verifier=verify_accepted_runtime,
            repository_reader=None, monotonic=time.monotonic):
    if client_factory is None:
        from scripts.run_aws_dev_identity_binding_bootstrap import _build_clients
        client_factory = _build_clients
    historical = validate_private_location(Path(accepted_runtime_directory), acl_checker=acl_checker)
    parent = validate_private_location(Path(parent), acl_checker=acl_checker)
    journal = FileJournal(historical).load()
    prior = journal["binding"]
    if journal.get("phase") != "accepted" or prior.get("operation") != "dev_multiuser_closed_update":
        raise ValueError("private_preparation_failed")
    clients = client_factory()
    begun = monotonic()
    if type(begun) not in (int, float) or not math.isfinite(begun):
        raise ValueError("private_preparation_failed")
    last = begun
    calls = 0
    def fresh():
        nonlocal last
        now = monotonic()
        if (type(now) not in (int, float) or not math.isfinite(now) or now < last
                or now - begun >= 180):
            raise ValueError("private_preparation_failed")
        last = now
    def read(service, operation, **kwargs):
        nonlocal calls
        fresh()
        if calls >= 12:
            raise ValueError("private_preparation_failed")
        calls += 1
        reply = getattr(clients[service], operation)(**kwargs)
        fresh()
        if (type(reply) is not dict or type(reply.get("ResponseMetadata", {}).get("HTTPStatusCode")) is not int
                or reply["ResponseMetadata"]["HTTPStatusCode"] != 200
                or any(reply.get(k) not in (None, "") for k in ("NextToken", "NextMarker", "Marker"))
                or "IsTruncated" in reply and (type(reply["IsTruncated"]) is not bool or reply["IsTruncated"])):
            raise ValueError("private_preparation_failed")
        return reply
    identity = read("sts", "get_caller_identity")
    account, caller = identity.get("Account"), identity.get("Arn")
    if (account != prior["account"] or caller != prior["caller"]
            or not caller.startswith(f"arn:aws:iam::{account}:user/")):
        raise ValueError("private_preparation_failed")
    now = clock()
    if type(now) not in (int, float) or not math.isfinite(now) or now <= 0:
        raise ValueError("private_preparation_failed")
    start = int(now)
    auth = {"account": account, "expected_caller_arn": caller, "source_sha": source_sha,
            "ci_run_id": ci_run_id, "run_id": int.from_bytes(secrets.token_bytes(6), "big"),
            "start": start, "end": start + 3600}
    validate_authorization(auth)
    source_ci_validator(auth)
    if repository_reader is None:
        def repository_reader():
            code, text = _bounded_command(["gh", "api", f"repos/{REPOSITORY}"])
            if code != 0:
                raise ValueError
            return json.loads(text, object_pairs_hook=_reject_duplicates)
    repo = repository_reader()
    if (repo.get("full_name") != REPOSITORY or type(repo.get("id")) is not int or repo["id"] <= 0
            or type(repo.get("owner", {}).get("id")) is not int or repo["owner"]["id"] <= 0
            or repo["owner"].get("login") != REPOSITORY.split("/")[0]):
        raise ValueError("private_preparation_failed")
    body = read("cloudformation", "get_template", StackName=prior["stack"], TemplateStage="Original")["TemplateBody"]
    template = json.loads(body) if type(body) is str else json.loads(json.dumps(body))
    if _digest(template) != prior["target"] or len(template["Resources"]) != 19:
        raise ValueError("private_preparation_failed")
    stack_reply = read("cloudformation", "describe_stacks", StackName=prior["stack"])
    stacks = stack_reply["Stacks"]
    if len(stacks) != 1 or stacks[0]["StackId"] != prior["stack"]:
        raise ValueError("private_preparation_failed")
    tags = {row["Key"]: row["Value"] for row in stacks[0]["Tags"]}
    resource_reply = read("cloudformation", "list_stack_resources", StackName=prior["stack"])
    if resource_reply.get("NextToken") not in (None, ""):
        raise ValueError("private_preparation_failed")
    rows = resource_reply["StackResourceSummaries"]
    resources = {row["LogicalResourceId"]: row["PhysicalResourceId"] for row in rows}
    if len(rows) != 19 or len(resources) != 19:
        raise ValueError("private_preparation_failed")
    role_name = "honda-mapit-mcp-dev-retained-handler-role"
    role = read("iam", "get_role", RoleName=role_name)["Role"]
    names_reply = read("iam", "list_role_policies", RoleName=role_name)
    if names_reply.get("IsTruncated") not in (None, False):
        raise ValueError("private_preparation_failed")
    names = names_reply["PolicyNames"]
    if set(names) != {"honda-mapit-mcp-dev-retained-owned-log-writes", "honda-mapit-mcp-dev-retained-tenant-read"}:
        raise ValueError("private_preparation_failed")
    policies = {name: read("iam", "get_role_policy", RoleName=role_name, PolicyName=name)["PolicyDocument"]
                for name in names}
    ssm_key = read("kms", "describe_key", KeyId="alias/aws/ssm")["KeyMetadata"]
    if (ssm_key.get("AWSAccountId") != account or ssm_key.get("KeyManager") != "AWS"
            or ssm_key.get("Enabled") is not True or ssm_key.get("KeyState") != "Enabled"
            or ssm_key.get("KeyUsage") != "ENCRYPT_DECRYPT"
            or type(ssm_key.get("Arn")) is not str
            or re.fullmatch(rf"arn:aws:kms:eu-west-1:{account}:key/[0-9a-f]{{8}}-(?:[0-9a-f]{{4}}-){{3}}[0-9a-f]{{12}}", ssm_key["Arn"]) is None):
        raise ValueError("private_preparation_failed")
    binding = {"account_id": account, "operator_user_arn": caller,
        "ssm_key_arn": ssm_key["Arn"],
        "github_owner_id": repo["owner"]["id"], "github_repository_id": repo["id"],
        "tenant_keys": ["tenant-" + secrets.token_hex(32) for _ in range(2)],
        "accepted_runtime_journal_path": str(historical), "app_stack_arn": prior["stack"],
        "app_run_id": int(tags["OperatorRunId"]), "api_id": resources["McpApi"],
        "user_pool_id": resources["McpUserPool"], "client_id": resources["McpUserPoolClient"],
        "template_sha256": prior["target"],
        "code_sha256": template["Resources"]["McpHandler"]["Properties"]["Code"]["S3Key"].split("/")[-1][:-4],
        "handler_role_arn": role["Arn"], "handler_trust_sha256": _digest(role["AssumeRolePolicyDocument"]),
        "handler_policies_sha256": _digest(policies)}
    if runtime_verifier(clients, binding).get("verified") is not True:
        raise ValueError("private_preparation_failed")
    fresh()
    now = clock()
    if type(now) not in (int, float) or not math.isfinite(now) or not start <= now < auth["end"]:
        raise ValueError("private_preparation_failed")
    target = parent / ("ib-" + secrets.token_hex(8))
    _create_private_directory(target, acl_checker)
    _create_private_directory(target / "bootstrap", acl_checker)
    payload = json.dumps(binding, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(payload) > 32 * 1024:
        raise ValueError("private_preparation_failed")
    with (target / "bindings.json").open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    validate_private_location(target / "bindings.json", acl_checker=acl_checker)
    fresh()
    now = clock()
    if type(now) not in (int, float) or not math.isfinite(now) or not start <= now < auth["end"]:
        raise ValueError("private_preparation_failed")
    write_private_authorization(target / "authorization.json", auth, acl_checker=acl_checker)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--accepted-runtime-directory", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", type=int, required=True)
    args = parser.parse_args()
    try:
        target = prepare(**vars(args))
        print(json.dumps({"ok": True, "private_directory": str(target)}))
        return 0
    except Exception:
        print('{"ok":false,"category":"private_preparation_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
