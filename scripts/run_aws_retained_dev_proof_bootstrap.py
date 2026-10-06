"""Private runner for the retained-dev proof-role bootstrap.

The default path is intentionally private and bounded.  It constructs direct
TLS boto3 clients only when explicitly invoked; importing this module does not
construct clients or read credentials.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_retained_dev_proof_bootstrap import RetainedDevProofBootstrapCoordinator, RetainedDevProofBootstrapError
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_retained_dev_bootstrap import load_authorization, validate_private_location, validate_source_and_ci

REGION = "eu-west-1"
_PROXY_KEYS = frozenset({"http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle", "aws_endpoint_url", "aws_endpoint_url_s3", "aws_endpoint_url_sts"})
_BINDING_FIELDS = frozenset({"account_id", "provider_arn", "owner_id", "repository_id", "observed_dev_subject_sha256", "app_stack_arn", "artifact_stack_arn", "controls_stack_arn", "artifact_bucket_arn", "api_arn", "handler_arn", "cfn_role_arn", "execution_role_arn", "cfn_boundary_arn", "executor_boundary_arn", "shutdown_state_machine_arn", "tripwire_alarm_arn", "tripwire_rule_arn"})
_RUN_NAMESPACE = uuid.UUID("4fbe2f5e-3cf9-4ca2-9aa0-6d7345c0a2c6")
_STATE_FIELDS = frozenset({
    "schema", "kind", "revision", "binding_sha256", "source_sha", "run_id",
    "template_sha256", "expected_caller_arn", "authorized_from_epoch",
    "authorized_until_epoch", "last_observed_epoch", "preflight", "intent",
    "acknowledged", "acknowledged_stack_id", "readback", "readback_receipt",
})
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_CALLER = re.compile(r"arn:aws:(?:iam|sts)::([0-9]{12}):(?:user|role)/[^\s:/]+(?:$|/[^\s:/]+$)|arn:aws:sts::([0-9]{12}):assumed-role/[^\s:/]+/[^\s:/]+\Z")
_STACK = re.compile(r"arn:aws:cloudformation:eu-west-1:([0-9]{12}):stack/[^/]+/[0-9a-f-]{36}\Z")


class FileCasJournal:
    """CAS adapter over the ACL-checked/fsynced FileJournal."""

    def __init__(self, journal: Any):
        self.journal = journal

    @contextmanager
    def locked(self):
        with self.journal.locked():
            yield

    def load(self):
        current = self.journal.load()
        if current is not None and not _valid_state(current):
            raise RehearsalError("state_file_invalid")
        return current

    def compare_and_set(self, expected_revision, value):
        current = self.journal.load()
        if current is not None and not _valid_state(current):
            raise RehearsalError("state_file_invalid")
        current_revision = current.get("revision") if isinstance(current, Mapping) else None
        if current_revision != expected_revision:
            return False
        if not _valid_state(value) or value["revision"] != (1 if expected_revision is None else expected_revision + 1):
            return False
        if isinstance(current, Mapping):
            immutable = ("binding_sha256", "source_sha", "run_id", "template_sha256", "expected_caller_arn", "authorized_from_epoch", "authorized_until_epoch")
            if any(value.get(key) != current.get(key) for key in immutable):
                return False
        self.journal.save(dict(value))
        return True


def _valid_state(value: Any) -> bool:
    """Validate the proof journal envelope before any CAS write.

    The coordinator repeats these checks, but the file adapter must not allow
    an old owner/window or a malformed revision to be replaced before the
    coordinator gets a chance to inspect it.
    """
    if not isinstance(value, Mapping) or set(value) != _STATE_FIELDS:
        return False
    if value.get("schema") != 1 or value.get("kind") != "retained-dev-proof-role":
        return False
    if type(value.get("revision")) is not int or value["revision"] < 1:
        return False
    if type(value.get("source_sha")) is not str or _SHA1.fullmatch(value["source_sha"]) is None:
        return False
    if type(value.get("run_id")) is not str or _UUID.fullmatch(value["run_id"]) is None:
        return False
    if any(type(value.get(key)) is not str or _SHA256.fullmatch(value[key]) is None for key in ("binding_sha256", "template_sha256")):
        return False
    caller = value.get("expected_caller_arn")
    match = _CALLER.fullmatch(caller) if type(caller) is str else None
    if match is None:
        return False
    caller_account = next((group for group in match.groups() if group is not None), None)
    if caller_account is None or _ACCOUNT.fullmatch(caller_account) is None:
        return False
    start, end, observed = (value.get(key) for key in ("authorized_from_epoch", "authorized_until_epoch", "last_observed_epoch"))
    if any(type(item) is not int or isinstance(item, bool) for item in (start, end, observed)):
        return False
    if start <= 0 or end <= start or end - start > 3600 or observed < start or observed >= end:
        return False
    if any(type(value.get(key)) is not bool for key in ("preflight", "acknowledged", "readback")):
        return False
    intent = value.get("intent")
    if intent is not None and (not isinstance(intent, Mapping) or set(intent) != {"client_request_token"} or intent.get("client_request_token") != value["run_id"]):
        return False
    stack_id = value.get("acknowledged_stack_id")
    if stack_id is not None:
        stack_match = _STACK.fullmatch(stack_id) if type(stack_id) is str else None
        if stack_match is None or stack_match.group(1) != caller_account:
            return False
    receipt = value.get("readback_receipt")
    if receipt is not None and (
        not isinstance(receipt, Mapping)
        or set(receipt) != {"stack_id", "template_sha256", "client_request_token", "acknowledged"}
        or receipt.get("stack_id") != stack_id
        or receipt.get("template_sha256") != value["template_sha256"]
        or receipt.get("client_request_token") != value["run_id"]
        or type(receipt.get("acknowledged")) is not bool
    ):
        return False
    if value["readback"] and receipt is None:
        return False
    if (intent is not None and value["preflight"] is not True
            or stack_id is not None and intent is None
            or receipt is not None and (value["readback"] is not True
                                       or receipt["acknowledged"] != value["acknowledged"])
            or value["readback"] and intent is None):
        return False
    if value["acknowledged"] and (intent is None or stack_id is None):
        return False
    return True


def _journal_factory(path: Path) -> FileCasJournal:
    return FileCasJournal(FileJournal(path))


def _operation_uuid(source_sha: Any, auth_run_id: Any) -> str:
    if type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or type(auth_run_id) is not int or isinstance(auth_run_id, bool) or auth_run_id <= 0:
        raise RuntimeError("authorization_invalid")
    return str(uuid.uuid5(_RUN_NAMESPACE, f"{source_sha}:{auth_run_id}"))


def _build_clients() -> dict[str, Any]:
    if any(key.casefold() in _PROXY_KEYS for key in os.environ):
        raise RuntimeError("proxy_or_custom_endpoint_rejected")
    try:
        import logging
        import boto3
        from botocore.config import Config
        logging.getLogger("botocore").setLevel(logging.CRITICAL)
        regional = Config(region_name=REGION, connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4")
        global_iam = Config(region_name="us-east-1", connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4")
        session = boto3.Session(region_name=REGION)
        return {
            "sts": session.client("sts", region_name=REGION, endpoint_url="https://sts.eu-west-1.amazonaws.com", config=regional, verify=True),
            "cloudformation": session.client("cloudformation", region_name=REGION, endpoint_url="https://cloudformation.eu-west-1.amazonaws.com", config=regional, verify=True),
            "iam": session.client("iam", region_name="us-east-1", endpoint_url="https://iam.amazonaws.com", config=global_iam, verify=True),
        }
    except Exception:
        raise RuntimeError("client_construction_failed") from None


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _load_bindings(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > 8192:
            raise ValueError
        with path.open("rb") as stream:
            raw = stream.read(8193)
        if not 0 < len(raw) <= 8192:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique)
        if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
            raise ValueError
        return value
    except Exception:
        raise RuntimeError("bindings_file_invalid") from None


def run_authorized_step(authorization_path: Path, bindings_path: Path, state_dir: Path, step: str, *, acl_checker: Callable[[Path], bool] | None = None, source_ci_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci, client_factory: Callable[[], Mapping[str, Any]] = _build_clients, journal_factory: Callable[[Path], Any] = _journal_factory) -> dict[str, Any]:
    try:
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        binding_path = validate_private_location(Path(bindings_path), acl_checker=acl_checker)
        private_state = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        auth = load_authorization(auth_path); bindings = _load_bindings(binding_path)
        if auth.get("account") != bindings.get("account_id"):
            raise RuntimeError("binding_mismatch")
        source_ci_validator(auth)
        clients = client_factory(); journal = journal_factory(private_state)
        coordinator = RetainedDevProofBootstrapCoordinator(
            clients, journal, bindings=bindings, expected_caller_arn=auth["expected_caller_arn"],
            source_sha=auth["source_sha"], run_id=_operation_uuid(auth["source_sha"], auth["run_id"]),
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
        )
        return coordinator.run_step(step)
    except (RuntimeError, RetainedDevProofBootstrapError, RehearsalError) as exc:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": getattr(exc, "category", str(exc) if str(exc) in {"binding_mismatch", "bindings_file_invalid", "client_construction_failed", "proxy_or_custom_endpoint_rejected"} else "runner_failed"), "calls": 0}
    except Exception:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": "runner_failed", "calls": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--bindings", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--step", required=True, choices=("preflight", "create", "readback"))
    args = parser.parse_args(argv)
    result = run_authorized_step(args.authorization, args.bindings, args.state_dir, args.step)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
