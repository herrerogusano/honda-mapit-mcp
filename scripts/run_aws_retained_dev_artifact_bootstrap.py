"""Private single-step runner for the retained-dev artifact bootstrap."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

# Keep direct ``python scripts/run_...py`` invocation independent of cwd.
_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_retained_dev_artifact_bootstrap import RetainedDevArtifactCoordinator, RetainedDevArtifactError
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_retained_dev_bootstrap import (
    REGION, RetainedDevRunnerError, load_authorization, validate_private_location, validate_source_and_ci,
)

_PROXY_KEYS = frozenset({
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle", "aws_endpoint_url",
    "aws_endpoint_url_s3", "aws_endpoint_url_sts",
})


def _build_clients() -> dict[str, Any]:
    if any(key.casefold() in _PROXY_KEYS for key in os.environ):
        raise RetainedDevRunnerError("proxy_or_custom_endpoint_rejected")
    try:
        # SDK INFO diagnostics may expose local credential-provider paths.
        # This operator emits only its fixed categorical projection.
        logging.getLogger("botocore").setLevel(logging.ERROR)
        logging.getLogger("boto3").setLevel(logging.ERROR)
        import boto3
        from botocore.config import Config
        config = Config(region_name=REGION, connect_timeout=2, read_timeout=3,
                        retries={"total_max_attempts": 1, "mode": "standard"},
                        proxies={}, signature_version="v4")
        session = boto3.Session(region_name=REGION)
        endpoints = {
            "sts": "https://sts.eu-west-1.amazonaws.com",
            "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com",
            "s3": "https://s3.eu-west-1.amazonaws.com",
        }
        return {
            name: session.client(name, region_name=REGION, endpoint_url=endpoint, config=config, verify=True)
            for name, endpoint in endpoints.items()
        }
    except RetainedDevRunnerError:
        raise
    except Exception:
        raise RetainedDevRunnerError("client_construction_failed") from None


def run_authorized_step(
    authorization_path: Path,
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
        private_state = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        auth = load_authorization(auth_path)
        source_ci_validator(auth)
        clients = client_factory()
        journal = journal_factory(private_state)
        coordinator = RetainedDevArtifactCoordinator(
            clients, journal, account_id=auth["account"], source_sha=auth["source_sha"], run_id=auth["run_id"],
            expected_caller_arn=auth["expected_caller_arn"], authorized_from_epoch=auth["start"],
            authorized_until_epoch=auth["end"],
        )
        return coordinator.run_step(step)
    except (RetainedDevRunnerError, RetainedDevArtifactError, RehearsalError) as exc:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False,
                "category": getattr(exc, "category", "runner_failed"), "calls": 0}
    except Exception:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False,
                "category": "runner_failed", "calls": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--step", required=True, choices=("preflight", "create", "readback"))
    args = parser.parse_args(argv)
    result = run_authorized_step(args.authorization, args.state_dir, args.step)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
