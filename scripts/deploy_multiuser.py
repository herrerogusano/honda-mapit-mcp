"""Operator CLI: build, upload and change-set deploy of the multiuser stacks.

``python -m scripts.deploy_multiuser --env dev --private-config PATH`` verifies
the caller identity, ensures the artifacts stack, builds the shared ZIP,
uploads it under ``runtime/<sha256>.zip`` if absent and creates a change set
for the main stack, printing a compact summary. Only ``--execute`` executes
change sets. A dry run deletes nothing; it leaves the change set for review.

The private config is a JSON object with ``domain_prefix``,
``codex_callback_url``, ``codex_callback_port``, ``mapit_config`` (object),
``privacy_contact``, optional ``geography`` (bool) and, for prod,
``budget_email``. ``MapitConfigJson``, the privacy contact and the budget
email are never printed.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from mapit.multiuser_common import REGION, artifacts_stack_name, stack_name, validate_environment
from scripts.build_multiuser_stack import (
    CODEX_CALLBACK_PATTERN, build_artifacts_template, build_multiuser_template,
)

MAX_CONFIG_BYTES = 16 * 1024
POLL_SECONDS = 5.0
MAX_WAIT_SECONDS = 45 * 60
# Exactly the fields both Lambdas parse from MAPIT_CONFIG_JSON (no frontend_url).
_MAPIT_KEYS = frozenset({
    "region", "user_pool_id", "user_pool_client_id", "identity_pool_id",
    "core_api_url", "geo_api_url", "discovery_enabled", "http_timeout",
})
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class DeployError(RuntimeError):
    """Operator-facing failure; messages never include private values."""


@dataclass(frozen=True)
class PrivateConfig:
    domain_prefix: str
    codex_callback_url: str
    codex_callback_port: int
    mapit_config_json: str
    privacy_contact: str
    geography: bool
    budget_email: str | None

    def __repr__(self) -> str:  # never leak private values
        return "PrivateConfig(<redacted>)"


def load_private_config(path: Path, env: str) -> PrivateConfig:
    env = validate_environment(env)
    try:
        raw = Path(path).read_bytes()
    except OSError:
        raise DeployError("private config unreadable") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise DeployError("private config too large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise DeployError("private config is not valid JSON") from None
    required = {"domain_prefix", "codex_callback_url", "codex_callback_port", "mapit_config", "privacy_contact"}
    allowed = required | {"geography", "budget_email"}
    if env == "prod":
        required = required | {"budget_email"}
    if not isinstance(value, dict) or not required <= set(value) or not set(value) <= allowed:
        raise DeployError("private config fields invalid")
    domain = value["domain_prefix"]
    if type(domain) is not str or not _DOMAIN.fullmatch(domain) or any(word in domain for word in ("aws", "amazon", "cognito")):
        raise DeployError("domain_prefix invalid")
    callback = value["codex_callback_url"]
    port = value["codex_callback_port"]
    if type(callback) is not str or not re.fullmatch(CODEX_CALLBACK_PATTERN, callback):
        raise DeployError("codex_callback_url invalid")
    if type(port) is not int or not 1024 <= port <= 65535 or urlsplit(callback).port != port:
        raise DeployError("codex_callback_port invalid or different from the callback URL port")
    mapit = value["mapit_config"]
    if not isinstance(mapit, dict) or set(mapit) != _MAPIT_KEYS:
        raise DeployError("mapit_config must contain exactly: " + ", ".join(sorted(_MAPIT_KEYS)))
    timeout = mapit["http_timeout"]
    if (
        any(type(mapit[name]) is not str for name in _MAPIT_KEYS - {"discovery_enabled", "http_timeout"})
        or mapit["discovery_enabled"] is not False
        or isinstance(timeout, bool) or type(timeout) not in (int, float)
        or not math.isfinite(timeout) or not 0 < timeout <= 2
    ):
        raise DeployError("mapit_config invalid (discovery_enabled must be false, http_timeout in (0, 2])")
    from mapit.cloud_transport import validate_cloud_config
    from mapit.config import MapitConfig

    try:
        validate_cloud_config(MapitConfig(**mapit))
    except Exception:
        raise DeployError("mapit_config rejected by the runtime validator") from None
    mapit_json = json.dumps(mapit, sort_keys=True, separators=(",", ":"))
    if len(mapit_json) > 2048:
        raise DeployError("mapit_config too large")
    contact = value["privacy_contact"]
    if type(contact) is not str or not 3 <= len(contact) <= 254:
        raise DeployError("privacy_contact invalid")
    geography = value.get("geography", False)
    if type(geography) is not bool:
        raise DeployError("geography invalid")
    budget = value.get("budget_email")
    if env == "prod" and (type(budget) is not str or not _EMAIL.fullmatch(budget)):
        raise DeployError("budget_email invalid")
    if env == "dev":
        budget = None
    return PrivateConfig(domain, callback, port, mapit_json, contact, geography, budget)


def mask_account(account: str) -> str:
    return "*" * 8 + account[-4:] if len(account) >= 4 else "****"


def _code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Code", ""))
    return ""


def _message(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        return str(response.get("Error", {}).get("Message", ""))
    return ""


@dataclass
class Clients:
    sts: Any
    cloudformation: Any
    s3: Any


class Deployer:
    def __init__(self, env: str, clients: Clients, *, out: Callable[[str], None] = print,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic,
                 change_set_suffix: Callable[[], str] | None = None) -> None:
        self.env = validate_environment(env)
        self.clients = clients
        self.out = out
        self.sleep = sleep
        self.clock = clock
        self._suffix = change_set_suffix or (lambda: time.strftime("%Y%m%d%H%M%S", time.gmtime()))

    # -- identity -----------------------------------------------------------
    def verify_identity(self) -> str:
        identity = self.clients.sts.get_caller_identity()
        account = identity.get("Account", "")
        if not re.fullmatch(r"[0-9]{12}", str(account)):
            raise DeployError("caller identity invalid")
        if str(identity.get("Arn", "")).endswith(":root"):
            raise DeployError("refusing to deploy with root credentials")
        self.out(f"AWS account {mask_account(account)} region {REGION}")
        return account

    # -- stacks -------------------------------------------------------------
    def stack_status(self, name: str) -> str | None:
        try:
            stacks = self.clients.cloudformation.describe_stacks(StackName=name)["Stacks"]
        except Exception as error:  # botocore ClientError
            if _code(error) == "ValidationError" and "does not exist" in _message(error):
                return None
            raise
        return stacks[0]["StackStatus"] if stacks else None

    def stack_outputs(self, name: str) -> dict[str, str]:
        stacks = self.clients.cloudformation.describe_stacks(StackName=name)["Stacks"]
        return {item["OutputKey"]: item["OutputValue"] for item in stacks[0].get("Outputs", [])}

    def _wait(self, check: Callable[[], str | None]) -> str:
        deadline = self.clock() + MAX_WAIT_SECONDS
        while True:
            result = check()
            if result is not None:
                return result
            if self.clock() > deadline:
                raise DeployError("timed out waiting for CloudFormation")
            self.sleep(POLL_SECONDS)

    def create_change_set(self, name: str, template: dict[str, Any],
                          parameters: list[dict[str, str]]) -> tuple[str, list[dict[str, Any]]] | None:
        """Return (change set name, changes), or None when there is nothing to change."""
        status = self.stack_status(name)
        if status is not None and status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
            raise DeployError(f"stack {name} is busy ({status})")
        if status == "ROLLBACK_COMPLETE":
            raise DeployError(f"stack {name} is ROLLBACK_COMPLETE; delete it manually after review")
        change_type = "CREATE" if status in (None, "REVIEW_IN_PROGRESS") else "UPDATE"
        change_set = f"deploy-{self._suffix()}"
        cfn = self.clients.cloudformation
        cfn.create_change_set(
            StackName=name, ChangeSetName=change_set, ChangeSetType=change_type,
            TemplateBody=json.dumps(template, separators=(",", ":")),
            Parameters=parameters, Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            Tags=[{"Key": "Project", "Value": "honda-mapit-mcp"}, {"Key": "Environment", "Value": self.env}],
        )

        def check() -> str | None:
            described = cfn.describe_change_set(StackName=name, ChangeSetName=change_set)
            state = described["Status"]
            if state in ("CREATE_COMPLETE", "FAILED"):
                return state if state == "CREATE_COMPLETE" else "FAILED:" + str(described.get("StatusReason", ""))
            return None

        state = self._wait(check)
        if state.startswith("FAILED:"):
            reason = state[len("FAILED:"):]
            if "didn't contain changes" in reason or "No updates are to be performed" in reason:
                self.out(f"{name}: no changes")
                return None
            raise DeployError(f"change set for {name} failed: {reason[:300]}")
        changes: list[dict[str, Any]] = []
        token = None
        while True:
            kwargs = {"StackName": name, "ChangeSetName": change_set}
            if token:
                kwargs["NextToken"] = token
            page = cfn.describe_change_set(**kwargs)
            changes.extend(page.get("Changes", []))
            token = page.get("NextToken")
            if not token:
                break
        self.print_changes(name, change_set, change_type, changes)
        return change_set, changes

    def print_changes(self, name: str, change_set: str, change_type: str, changes: list[dict[str, Any]]) -> None:
        self.out(f"Change set {change_set} ({change_type}) for {name}: {len(changes)} change(s)")
        self.out(f"  {'Action':<8} {'LogicalId':<38} {'Type':<40} Replacement")
        for change in changes:
            item = change.get("ResourceChange", {})
            self.out(f"  {item.get('Action', ''):<8} {item.get('LogicalResourceId', ''):<38} "
                     f"{item.get('ResourceType', ''):<40} {item.get('Replacement', '-') or '-'}")

    def execute_change_set(self, name: str, change_set: str) -> str:
        cfn = self.clients.cloudformation
        cfn.execute_change_set(StackName=name, ChangeSetName=change_set)

        def check() -> str | None:
            status = self.stack_status(name)
            if status is None or status.endswith("_IN_PROGRESS"):
                return None
            return status

        status = self._wait(check)
        if status not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            raise DeployError(f"stack {name} finished as {status}")
        self.out(f"{name}: {status}")
        return status

    # -- artifacts ----------------------------------------------------------
    def upload_if_absent(self, bucket: str, key: str, zip_path: Path) -> bool:
        s3 = self.clients.s3
        try:
            s3.head_object(Bucket=bucket, Key=key)
            self.out(f"Artifact already present: {key}")
            return False
        except Exception as error:
            if _code(error) not in ("404", "NoSuchKey", "NotFound"):
                raise
        with Path(zip_path).open("rb") as stream:
            s3.put_object(Bucket=bucket, Key=key, Body=stream.read(), ContentType="application/zip")
        self.out(f"Uploaded artifact {key}")
        return True


def stack_parameters(env: str, config: PrivateConfig, artifact_key: str) -> list[dict[str, str]]:
    params = {
        "ArtifactKey": artifact_key,
        "DomainPrefix": config.domain_prefix,
        "CodexCallbackUrl": config.codex_callback_url,
        "CodexCallbackPort": str(config.codex_callback_port),
        "MapitConfigJson": config.mapit_config_json,
        "PrivacyContact": config.privacy_contact,
        "Geography": "1" if config.geography else "0",
    }
    if validate_environment(env) == "prod":
        params["BudgetEmail"] = str(config.budget_email)
    return [{"ParameterKey": key, "ParameterValue": value} for key, value in params.items()]


def build_zip(wheel_dir: Path, geography_wheel_dir: Path | None, workdir: Path) -> tuple[Path, str]:
    from scripts.build_multiuser_runtime import build_multiuser_archive

    output = workdir / "multiuser-runtime.zip"
    summary = build_multiuser_archive(wheel_dir, output, geography_wheel_dir=geography_wheel_dir)
    return output, summary.sha256


def run(env: str, config: PrivateConfig, clients: Clients, *, execute: bool,
        build: Callable[[Path], tuple[Path, str]], out: Callable[[str], None] = print,
        sleep: Callable[[float], None] = time.sleep, workdir: Path | None = None,
        change_set_suffix: Callable[[], str] | None = None) -> int:
    deployer = Deployer(env, clients, out=out, sleep=sleep, change_set_suffix=change_set_suffix)
    deployer.verify_identity()

    artifacts = artifacts_stack_name(env)
    result = deployer.create_change_set(artifacts, build_artifacts_template(env), [])
    if result is not None:
        if execute:
            deployer.execute_change_set(artifacts, result[0])
        elif deployer.stack_status(artifacts) in (None, "REVIEW_IN_PROGRESS"):
            out(f"Artifacts stack {artifacts} does not exist yet. Re-run with --execute to create it.")
            return 0
        else:
            out(f"Artifacts stack change set {result[0]} left for review (not executed).")
    bucket = deployer.stack_outputs(artifacts).get("BucketName")
    if not bucket:
        raise DeployError("artifacts stack has no BucketName output")

    with tempfile.TemporaryDirectory(prefix="mapit-multiuser-") as temporary:
        zip_path, sha256 = build(Path(workdir or temporary))
        key = f"runtime/{sha256}.zip"
        out(f"Built runtime ZIP sha256={sha256}")
        deployer.upload_if_absent(bucket, key, zip_path)

    main = stack_name(env)
    template = build_multiuser_template(env)
    result = deployer.create_change_set(main, template, stack_parameters(env, config, key))
    if result is None:
        return 0
    change_set, _ = result
    if not execute:
        out("Dry run: nothing executed or deleted. To apply, re-run with --execute, or:")
        out(f"  aws cloudformation execute-change-set --region {REGION} --stack-name {main} "
            f"--change-set-name {change_set}")
        return 0
    deployer.execute_change_set(main, change_set)
    for key_name, value in sorted(deployer.stack_outputs(main).items()):
        out(f"  {key_name}: {value}")
    return 0


def default_clients() -> Clients:  # pragma: no cover - real AWS only
    import boto3

    session = boto3.session.Session(region_name=REGION)
    return Clients(sts=session.client("sts", region_name=REGION),
                   cloudformation=session.client("cloudformation", region_name=REGION),
                   s3=session.client("s3", region_name=REGION))


def main(argv: list[str] | None = None, *, clients: Clients | None = None,
         build: Callable[[Path], tuple[Path, str]] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--env", required=True, choices=["dev", "prod"])
    parser.add_argument("--private-config", required=True, type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--wheel-dir", type=Path, default=None)
    parser.add_argument("--geography-wheel-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        config = load_private_config(args.private_config, args.env)
        if build is None:
            wheel_dir = args.wheel_dir or (Path(os.environ["HONDA_MAPIT_WHEEL_DIR"])
                                           if os.environ.get("HONDA_MAPIT_WHEEL_DIR") else None)
            if wheel_dir is None:
                raise DeployError("--wheel-dir (or HONDA_MAPIT_WHEEL_DIR) is required")
            if config.geography and args.geography_wheel_dir is None:
                raise DeployError("geography is enabled: --geography-wheel-dir is required")
            geo_dir = args.geography_wheel_dir if config.geography else None
            build = lambda workdir: build_zip(wheel_dir, geo_dir, workdir)  # noqa: E731
        return run(args.env, config, clients or default_clients(), execute=args.execute, build=build)
    except DeployError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["Clients", "DeployError", "Deployer", "PrivateConfig", "load_private_config",
           "main", "mask_account", "run", "stack_parameters"]
