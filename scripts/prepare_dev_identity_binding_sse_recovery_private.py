"""Prepare fresh private metadata for the owner-approved table-only DEV recovery.

This never updates AWS, publishes keys, or rewrites historical journals. The
three SDK operations are pinned caller, table and stack-resource metadata reads.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
for entry in (str(ROOT), str(ROOT / "src")):
    if entry not in sys.path:
        sys.path.insert(0, entry)

from scripts.prepare_dev_multiuser_private import _create_private_directory
from scripts.run_aws_closed_rehearsal import FileJournal
from scripts.run_aws_dev_identity_binding_bootstrap import (
    _build_clients, load_binding, validate_github_protections,
)
from scripts.run_aws_retained_dev_bootstrap import (
    validate_authorization, validate_private_location, validate_source_and_ci,
    write_private_authorization,
)
from scripts.run_dev_identity_binding_storage_probe import _verify_client_set
from scripts.build_aws_dev_identity_binding_bootstrap import STACK_NAME


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   allow_nan=False).encode("ascii")).hexdigest()


def prepare(*, parent, historical_directory, source_sha, ci_run_id,
            client_factory=_build_clients, source_ci_validator=validate_source_and_ci,
            protection_validator=validate_github_protections, acl_checker=None,
            client_validator=_verify_client_set, lineage_validator=None,
            clock=time.time, monotonic=time.monotonic):
    if lineage_validator is None:
        from scripts.aws_dev_identity_binding_sse_recovery import validate_recovery_lineage
        lineage_validator = validate_recovery_lineage
    parent = validate_private_location(Path(parent), acl_checker=acl_checker)
    history = validate_private_location(Path(historical_directory), acl_checker=acl_checker)
    binding = load_binding(history / "bindings.json", acl_checker=acl_checker)
    states = []
    for name in ("bootstrap", "probe", "keys"):
        journal = FileJournal(validate_private_location(history / name, acl_checker=acl_checker))
        validate_private_location(journal.path, acl_checker=acl_checker)
        states.append(journal.load())
    if any(type(state) is not dict for state in states):
        raise ValueError("historical_receipts_required")
    now = clock()
    if type(now) not in (int, float) or not math.isfinite(now) or now <= 0:
        raise ValueError("private_preparation_failed")
    auth = validate_authorization({
        "account": binding["account_id"],
        "expected_caller_arn": binding["operator_user_arn"],
        "source_sha": source_sha, "ci_run_id": ci_run_id,
        "run_id": secrets.randbelow(10**15) + 1,
        "start": int(now), "end": int(now) + 3600,
    })
    if source_ci_validator(auth) is False:
        raise ValueError("source_ci_failed")
    if protection_validator(binding) is False:
        raise ValueError("protection_failed")
    started = monotonic()
    last_mono = started
    last_wall = float(auth["start"])
    if type(started) not in (int, float) or not math.isfinite(started):
        raise ValueError("private_preparation_failed")

    def fresh():
        nonlocal last_mono, last_wall
        current, wall = monotonic(), clock()
        if (type(current) not in (int, float) or not math.isfinite(current)
                or current < last_mono or current - started >= 14
                or type(wall) not in (int, float) or not math.isfinite(wall)
                or wall < last_wall or not auth["start"] <= wall < auth["end"]):
            raise ValueError("private_preparation_failed")
        last_mono, last_wall = current, wall

    fresh()
    clients = client_factory()
    if client_validator(clients) is False:
        raise ValueError("private_preparation_failed")
    fresh()
    who = clients["sts"].get_caller_identity()
    fresh()
    if (who.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200
            or who.get("Account") != binding["account_id"]
            or who.get("Arn") != binding["operator_user_arn"]):
        raise ValueError("private_preparation_failed")
    response = clients["dynamodb"].describe_table(
        TableName="honda-mapit-mcp-dev-identity-bindings")
    fresh()
    table = response.get("Table", {})
    creation = table.get("CreationDateTime")
    sse = table.get("SSEDescription")
    if (response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200
            or table.get("TableArn") != f"arn:aws:dynamodb:eu-west-1:{binding['account_id']}:table/honda-mapit-mcp-dev-identity-bindings"
            or table.get("TableStatus") != "ACTIVE"
            or type(table.get("TableId")) is not str
            or re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", table["TableId"]) is None
            or not isinstance(creation, datetime) or creation.tzinfo is None
            or creation.utcoffset() is None
            or type(sse) is not dict or sse.get("Status") != "ENABLED"
            or sse.get("SSEType") != "KMS"
            or type(sse.get("KMSMasterKeyArn")) is not str
            or re.fullmatch(rf"arn:aws:kms:eu-west-1:{binding['account_id']}:key/[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}", sse["KMSMasterKeyArn"]) is None):
        raise ValueError("private_preparation_failed")
    expected_stack = states[0].get("acknowledged_stack_id")
    if (type(expected_stack) is not str or re.fullmatch(
            rf"arn:aws:cloudformation:eu-west-1:{binding['account_id']}:stack/{STACK_NAME}/[0-9a-f]{{8}}(?:-[0-9a-f]{{4}}){{3}}-[0-9a-f]{{12}}", expected_stack) is None):
        raise ValueError("private_preparation_failed")
    response = clients["cloudformation"].describe_stack_resources(StackName=expected_stack)
    fresh()
    resources = response.get("StackResources")
    expected_types = {"MapitIdentityBindings": "AWS::DynamoDB::Table",
                      "IdentityEnrollerBoundary": "AWS::IAM::ManagedPolicy",
                      "IdentityEnrollerRole": "AWS::IAM::Role",
                      "RuntimeIdentityBindingPolicy": "AWS::IAM::Policy"}
    if (response.get("ResponseMetadata", {}).get("HTTPStatusCode") != 200
            or type(resources) is not list or len(resources) != 4
            or any(type(row) is not dict or row.get("StackId") != expected_stack
                   or row.get("StackName") != STACK_NAME or row.get("ResourceStatus") != "CREATE_COMPLETE"
                   or row.get("ResourceType") != expected_types.get(row.get("LogicalResourceId")) for row in resources)
            or {row["LogicalResourceId"] for row in resources} != set(expected_types)):
        raise ValueError("private_preparation_failed")
    policy_id = next(row.get("PhysicalResourceId") for row in resources
                     if row["LogicalResourceId"] == "RuntimeIdentityBindingPolicy")
    if type(policy_id) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:_./-]{0,1023}", policy_id) is None:
        raise ValueError("private_preparation_failed")
    recovery_binding = {
        "table_id": table.get("TableId"),
        "table_creation_time": creation.astimezone(timezone.utc).isoformat(),
        "sse_key_arn": sse["KMSMasterKeyArn"],
        "runtime_policy_physical_id": policy_id,
        "bootstrap_state_sha256": _digest(states[0]),
        "probe_state_sha256": _digest(states[1]),
        "key_state_sha256": _digest(states[2]),
    }
    if lineage_validator(binding, *states, recovery_binding) is False:
        raise ValueError("historical_receipts_required")
    fresh()
    target = parent / ("sse-" + secrets.token_hex(6))
    _create_private_directory(target, acl_checker)
    for name in ("update", "probe"):
        _create_private_directory(target / name, acl_checker)
    payload = json.dumps(recovery_binding, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("ascii")
    with (target / "recovery-binding.json").open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    validate_private_location(target / "recovery-binding.json", acl_checker=acl_checker)
    fresh()
    # Authority is published last; a partially prepared root is never usable.
    write_private_authorization(target / "authorization.json", auth, acl_checker=acl_checker)
    return target


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", required=True, type=Path)
    parser.add_argument("--historical-directory", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--ci-run-id", required=True, type=int)
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
