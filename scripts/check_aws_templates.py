"""Static checks of fixed, synthetic CloudFormation drafts; no account operations."""

from __future__ import annotations

import json
import os
import re
import socket
from contextlib import contextmanager
from importlib.metadata import version
from pathlib import Path
from typing import Callable

MAX_TEMPLATE_BYTES = 128 * 1024
CFN_LINT_VERSION = "1.57.1"
_RULE_ID = re.compile(r"[EWI][0-9]{4}\Z")


@contextmanager
def deny_python_network():
    """Deny Python socket/DNS APIs during lint, not a native-code/OS sandbox."""
    names = (
        "socket", "SocketType", "socketpair", "create_connection", "getaddrinfo",
        "gethostbyname", "gethostbyname_ex", "gethostbyaddr",
    )
    originals = {name: getattr(socket, name) for name in names if hasattr(socket, name)}

    def denied(*_args, **_kwargs):
        raise RuntimeError("static_lint_network_denied")

    blocked_socket = type("BlockedSocket", (socket.socket,), {"__new__": denied})
    try:
        for name in originals:
            setattr(socket, name, blocked_socket if name in {"socket", "SocketType"} else denied)
        yield
    finally:
        for name, original in originals.items():
            setattr(socket, name, original)


def fixed_documents() -> dict[str, str]:
    from mapit.aws_dev_cleanup_schedule import build_dev_cleanup_schedule
    from mapit.aws_dev_control_bundle import build_dev_control_bundle
    from mapit.aws_dev_shutdown import AwsDevShutdownPolicy
    from mapit.aws_dev_shutdown_control import build_dev_shutdown_control

    root = Path(__file__).resolve().parents[1]
    documents = {}
    for label, filename in (
        ("application_draft", "template.json"),
        ("shutdown_lambda_draft", "dev-shutdown.template.json"),
    ):
        source = root / "infra" / "aws" / filename
        if source.is_symlink() or not source.is_file() or source.stat().st_size > MAX_TEMPLATE_BYTES:
            raise ValueError("fixed_template_invalid")
        with source.open("rb") as stream:
            raw = stream.read(MAX_TEMPLATE_BYTES + 1)
        if len(raw) > MAX_TEMPLATE_BYTES:
            raise ValueError("fixed_template_invalid")
        documents[label] = raw.decode("utf-8", errors="strict")
    documents["shutdown_control_draft"] = json.dumps(build_dev_shutdown_control(
        AwsDevShutdownPolicy("a1b2c3d4e5"), "2030-01-01T00:00:00",
    ))
    documents["cleanup_schedule_draft"] = json.dumps(build_dev_cleanup_schedule("2030-01-01T00:00:00"))
    documents["combined_control_draft"] = json.dumps(build_dev_control_bundle(
        AwsDevShutdownPolicy("a1b2c3d4e5"),
        resource_started_epoch=1893456000,
        now_epoch=1893456060,
        activation_start_epoch=1893456240,
    ))
    return documents


def check_documents(documents: dict[str, str], lint: Callable) -> dict:
    results = []
    for label, document in documents.items():
        matches = lint(document, regions=["eu-west-1"], config={
            "regions": ["eu-west-1"], "config_file": os.devnull,
            "ignore_checks": [], "append_rules": [], "custom_rules": None,
            "ignore_bad_template": False,
        })
        rule_ids = [match.rule.id for match in matches]
        if any(not isinstance(rule, str) or not _RULE_ID.fullmatch(rule) for rule in rule_ids):
            raise ValueError("static_lint_result_invalid")
        failing = any(rule.startswith(("E", "W")) for rule in rule_ids)
        results.append({"component": label, "valid": not failing,
                        "finding_count": len(rule_ids), "rule_ids": sorted(set(rule_ids))})
    return {"success": all(item["valid"] for item in results), "components": results,
            "account_operations": False, "deployment": False}


def main() -> int:
    try:
        with deny_python_network():
            if version("cfn-lint") != CFN_LINT_VERSION:
                raise ValueError("static_lint_version_invalid")
            from cfnlint.api import lint

            result = check_documents(fixed_documents(), lint)
    except Exception:
        print(json.dumps({"success": False, "category": "static_template_check_failed",
                          "account_operations": False, "deployment": False}))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
