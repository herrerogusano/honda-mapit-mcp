"""Private single-step runner for retained-dev controls bootstrap.

The authorization envelope is the existing seven-field private CD envelope.
The API binding is a separate private readback artifact and is never printed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_retained_dev_controls_bootstrap import RetainedDevControlsCoordinator, RetainedDevControlsError
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_retained_dev_bootstrap import (
    REGION, RetainedDevRunnerError, load_authorization, validate_private_location, validate_source_and_ci,
)

MAX_BINDING_BYTES = 8192
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_APP_STACK = re.compile(
    rf"arn:aws:cloudformation:{REGION}:([0-9]{{12}}):stack/honda-mapit-mcp-dev-retained/"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
_PROXY_KEYS = frozenset({
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle", "aws_endpoint_url",
    "aws_endpoint_url_s3", "aws_endpoint_url_sts",
})


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def load_api_binding(path: Path) -> dict[str, str]:
    """Load the exact private output shape of retained-dev binding discovery."""
    try:
        target = Path(path)
        if target.stat().st_size <= 0 or target.stat().st_size > MAX_BINDING_BYTES:
            raise ValueError
        raw = target.read_bytes()
        if len(raw) != target.stat().st_size or len(raw) > MAX_BINDING_BYTES:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs)
        if not isinstance(value, dict) or set(value) != {"account", "stack_id", "api_id"}:
            raise ValueError
        account, stack_id, api_id = value["account"], value["stack_id"], value["api_id"]
        if type(account) is not str or _ACCOUNT.fullmatch(account) is None or account == "000000000000":
            raise ValueError
        if type(stack_id) is not str or _APP_STACK.fullmatch(stack_id) is None or stack_id.split(":")[4] != account:
            raise ValueError
        if type(api_id) is not str or _API.fullmatch(api_id) is None:
            raise ValueError
        return {"account": account, "stack_id": stack_id, "api_id": api_id}
    except Exception:
        raise RetainedDevRunnerError("api_binding_invalid") from None


def _build_clients() -> dict[str, Any]:
    if any(key.casefold() in _PROXY_KEYS for key in os.environ):
        raise RetainedDevRunnerError("proxy_or_custom_endpoint_rejected")
    try:
        import boto3
        from botocore.config import Config

        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("boto3").setLevel(logging.ERROR)
        config = Config(region_name=REGION, connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4")
        iam_config = Config(region_name="us-east-1", connect_timeout=2, read_timeout=3, retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4")
        session = boto3.Session(region_name=REGION)
        endpoints = {
            "sts": "https://sts.eu-west-1.amazonaws.com",
            "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com",
            "iam": "https://iam.amazonaws.com",
            "sfn": "https://states.eu-west-1.amazonaws.com",
            "events": "https://events.eu-west-1.amazonaws.com",
            "cloudwatch": "https://monitoring.eu-west-1.amazonaws.com",
            "apigatewayv2": "https://apigateway.eu-west-1.amazonaws.com",
            "lambda": "https://lambda.eu-west-1.amazonaws.com",
        }
        services = {"sfn": "stepfunctions"}
        return {
            name: session.client(services.get(name, name), region_name=("us-east-1" if name == "iam" else REGION), endpoint_url=endpoint, config=(iam_config if name == "iam" else config), verify=True)
            for name, endpoint in endpoints.items()
        }
    except RetainedDevRunnerError:
        raise
    except Exception:
        raise RetainedDevRunnerError("client_construction_failed") from None


def run_authorized_step(
    authorization_path: Path,
    binding_path: Path,
    state_dir: Path,
    step: str,
    *,
    acl_checker: Callable[[Path], bool] | None = None,
    source_ci_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci,
    client_factory: Callable[[], Mapping[str, Any]] = _build_clients,
    journal_factory: Callable[[Path], Any] = FileJournal,
) -> dict[str, Any]:
    try:
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        binding_path = validate_private_location(Path(binding_path), acl_checker=acl_checker)
        state_dir = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        auth = load_authorization(auth_path)
        binding = load_api_binding(binding_path)
        if binding["account"] != auth["account"]:
            raise RetainedDevRunnerError("binding_mismatch")
        source_ci_validator(auth)
        coordinator = RetainedDevControlsCoordinator(
            client_factory(), journal_factory(state_dir), account_id=auth["account"], api_id=binding["api_id"], app_stack_id=binding["stack_id"],
            source_sha=auth["source_sha"], run_id=auth["run_id"], expected_caller_arn=auth["expected_caller_arn"],
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
        )
        return coordinator.run_step(step)
    except (RetainedDevRunnerError, RetainedDevControlsError, RehearsalError) as exc:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": getattr(exc, "category", "runner_failed"), "calls": 0}
    except Exception:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": "runner_failed", "calls": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--api-binding", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--step", required=True, choices=("preflight", "create", "readback"))
    args = parser.parse_args(argv)
    result = run_authorized_step(args.authorization, args.api_binding, args.state_dir, args.step)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
