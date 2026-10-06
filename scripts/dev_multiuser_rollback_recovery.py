"""Read-only exact provenance check before a fresh closed DEV recovery."""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping

from scripts.dev_multiuser_confirmed_pair_recovery import _latest_pair
from scripts.dev_multiuser_confirmed_reset_recovery import _reset_context
from scripts.dev_multiuser_user_recovery import _validate_original


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=True, allow_nan=False).encode()).hexdigest()


def _ok(value):
    return isinstance(value, Mapping) and type(value.get("ResponseMetadata", {}).get("HTTPStatusCode")) is int and value["ResponseMetadata"]["HTTPStatusCode"] == 200


def verify_consumed_rollback(
    client, journal, latest_reset, *, auth, app_stack, expected_setup,
    original_user_journal, latest_pair_journal, user_pool_id,
):
    """Three bounded reads; no mutation, journal changes, or prior-write replay."""
    try:
        state, reset = journal.load(), latest_reset.load()
        if type(state) is not dict or set(state) != {"binding", "phase"} or state["phase"] != "acknowledged":
            return False
        b = state["binding"]
        fields = {"schema", "operation", "account", "caller", "stack", "role", "source", "start", "end", "token", "prior", "target"}
        role = f"arn:aws:iam::{auth['account']}:role/honda-mapit-mcp-dev-retained-cfn-update"
        if (type(b) is not dict or set(b) != fields or type(b["schema"]) is not int or b["schema"] != 1
            or b["operation"] != "dev_multiuser_closed_update" or b["account"] != auth["account"]
            or b["caller"] != auth["expected_caller_arn"] or b["stack"] != app_stack or b["role"] != role
            or type(b["source"]) is not str or re.fullmatch(r"[0-9a-f]{40}", b["source"]) is None
            or b["source"] == auth["source_sha"] or type(b["token"]) is not str
            or re.fullmatch(r"dev-multiuser-[0-9a-f]{32}", b["token"]) is None
            or any(type(b[k]) is not int for k in ("start", "end")) or not 0 < b["end"] - b["start"] <= 3600
            or b["start"] >= auth["start"] or b["prior"] != _digest(expected_setup)
            or type(b["target"]) is not str or re.fullmatch(r"[0-9a-f]{64}", b["target"]) is None
            or b["target"] == b["prior"] or type(user_pool_id) is not str):
            return False
        original = _validate_original(original_user_journal.load(), account=auth["account"], pool=user_pool_id)
        latest = _latest_pair(
            latest_pair_journal.load(), account=auth["account"], pool=user_pool_id, original=original,
        )
        reset = _reset_context(reset)
        if (
            reset["phase"] != "complete"
            or reset["account_id"] != auth["account"]
            or reset["user_pool_id"] != user_pool_id
            or reset["run_id"] != original["run_id"]
            or reset["source_sha256"] != b["source"]
            or not (b["start"] <= reset["authorized_from_epoch"] < reset["authorized_until_epoch"] <= b["end"])
            or reset["authorized_from_epoch"] != latest["authorized_from_epoch"]
            or reset["authorized_until_epoch"] != latest["authorized_until_epoch"]
            or latest["authorized_until_epoch"] > auth["start"]
            or reset["original_creation_sha256"] != _digest(original)
            or reset["original_start_epoch"] != original["authorized_from_epoch"]
            or reset["original_end_epoch"] != original["authorized_until_epoch"]
            or reset["confirmed_a_subject_sha256"] != latest["slots"][0]["user_sub_sha256"]
        ):
            return False
        value = client.describe_stacks(StackName=app_stack)
        rows = value.get("Stacks")
        if (not _ok(value) or not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping)
            or rows[0].get("StackId") != app_stack or rows[0].get("StackStatus") != "UPDATE_ROLLBACK_COMPLETE"
            or rows[0].get("RoleARN") != role or rows[0].get("EnableTerminationProtection") is not True):
            return False
        value = client.get_template(StackName=app_stack, TemplateStage="Original")
        body = value.get("TemplateBody")
        if isinstance(body, str):
            def unique(pairs):
                result = {}
                for k, v in pairs:
                    if k in result:
                        raise ValueError
                    result[k] = v
                return result
            if len(body.encode()) > 65536:
                return False
            body = json.loads(body, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not _ok(value) or not isinstance(body, Mapping) or _digest(body) != b["prior"]:
            return False
        value = client.describe_stack_events(StackName=app_stack)
        if not _ok(value) or value.get("NextToken") or not isinstance(value.get("StackEvents"), list) or len(value["StackEvents"]) > 1000:
            return False
        matches = [e for e in value["StackEvents"] if isinstance(e, Mapping) and e.get("ClientRequestToken") == b["token"]
                   and e.get("PhysicalResourceId") == app_stack and e.get("ResourceType") == "AWS::CloudFormation::Stack"
                   and e.get("ResourceStatus") == "UPDATE_ROLLBACK_COMPLETE"]
        return len(matches) == 1
    except Exception:
        return False
