"""Private runner for the retained-dev IAM role bootstrap (offline by default)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_retained_dev_role_bootstrap import RetainedDevRoleBootstrapCoordinator, RetainedDevRoleBootstrapError
from scripts.build_cd_retained_dev_roles import build_cd_retained_dev_roles
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_retained_dev_bootstrap import REGION, RetainedDevRunnerError, load_authorization, validate_private_location, validate_source_and_ci

_PROXY_KEYS = frozenset({"http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle", "aws_endpoint_url", "aws_endpoint_url_s3", "aws_endpoint_url_sts"})


def _build_clients() -> dict[str, Any]:
    if any(key.casefold() in _PROXY_KEYS for key in os.environ):
        raise RetainedDevRunnerError("proxy_or_custom_endpoint_rejected")
    try:
        import logging
        import boto3
        from botocore.config import Config
        logging.getLogger("botocore").setLevel(logging.CRITICAL)
        config = Config(region_name=REGION, connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4")
        iam_config = Config(region_name="us-east-1", connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4")
        session = boto3.Session(region_name=REGION)
        endpoints = {"sts": "https://sts.eu-west-1.amazonaws.com", "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com", "iam": "https://iam.amazonaws.com"}
        return {name: session.client(name, region_name=REGION if name != "iam" else "us-east-1", endpoint_url=endpoint, config=config if name != "iam" else iam_config, verify=True) for name, endpoint in endpoints.items()}
    except Exception:
        raise RetainedDevRunnerError("client_construction_failed") from None


_BINDING_FIELDS = ("account_id", "provider_arn", "owner_id", "repository_id", "observed_dev_subject_format", "observed_dev_subject_sha256", "stack_arn", "artifact_stack_arn", "handler_arn", "api_arn", "shutdown_state_machine_arn", "artifact_bucket_arn", "execution_role_arn")


def _load_bindings(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= 0 or size > 8192:
            raise ValueError
        raw = path.read_bytes()
        if len(raw) != size or len(raw) > 8192:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=lambda pairs: _unique(pairs))
        if not isinstance(value, dict) or set(value) != set(_BINDING_FIELDS):
            raise ValueError
        return value
    except Exception:
        raise RetainedDevRunnerError("bindings_file_invalid") from None


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def run_authorized_step(authorization_path: Path, bindings_path: Path, state_dir: Path, step: str, *, acl_checker: Callable[[Path], bool] | None = None, source_ci_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci, client_factory: Callable[[], Mapping[str, Any]] = _build_clients, journal_factory: Callable[[Path], Any] = FileJournal) -> dict[str, Any]:
    try:
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        binding_path = validate_private_location(Path(bindings_path), acl_checker=acl_checker)
        private_state = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        auth = load_authorization(auth_path); bindings = _load_bindings(binding_path)
        if auth.get("account") != bindings.get("account_id"):
            raise RetainedDevRunnerError("binding_mismatch")
        source_ci_validator(auth)
        clients = client_factory(); journal = journal_factory(private_state)
        factory_bindings = dict(bindings); factory_bindings["account"] = factory_bindings.pop("account_id")
        coordinator = RetainedDevRoleBootstrapCoordinator(clients, journal, bindings=factory_bindings, expected_caller_arn=auth["expected_caller_arn"], source_sha=auth["source_sha"], run_id=auth["run_id"], authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"])
        return coordinator.run_step(step)
    except (RetainedDevRunnerError, RetainedDevRoleBootstrapError, RehearsalError) as exc:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": getattr(exc, "category", "runner_failed"), "calls": 0}
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
