"""Private one-step operator for the dedicated synthetic DEV identity stack.

The fixed factory/coordinator and root-owned accepted-runtime verifier are
used directly. Importing this module performs no filesystem, GitHub or AWS IO.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable, Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_dev_identity_binding_bootstrap import (
    REGION, DevIdentityBindingBootstrapCoordinator, IdentityBindingBootstrapError,
)
from scripts.dev_identity_binding_runtime_evidence import verify_accepted_runtime
from scripts.github_cd_protections import (
    REPOSITORY, validate_admin_bypass_disabled, validate_branch_protection_readback,
    validate_environment_readback,
)
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_retained_dev_bootstrap import (
    RetainedDevRunnerError, _bounded_command, load_authorization,
    validate_private_location, validate_source_and_ci,
)

MAX_BINDING_BYTES = 32 * 1024
_BINDING_FIELDS = frozenset({
    "account_id", "operator_user_arn", "tenant_keys", "accepted_runtime_journal_path",
    "app_stack_arn", "app_run_id", "api_id", "user_pool_id", "client_id",
    "template_sha256", "code_sha256", "handler_role_arn", "handler_trust_sha256",
    "handler_policies_sha256", "github_owner_id", "github_repository_id", "ssm_key_arn",
})
_COORDINATOR_FIELDS = _BINDING_FIELDS - {"github_owner_id", "github_repository_id"}
_STEPS = DevIdentityBindingBootstrapCoordinator.STEPS
_PROXY_ENV = frozenset({
    "http_proxy", "https_proxy", "all_proxy", "no_proxy", "aws_ca_bundle",
    "aws_endpoint_url", "aws_endpoint_url_cloudformation", "aws_endpoint_url_dynamodb",
    "aws_endpoint_url_iam", "aws_endpoint_url_ssm", "aws_endpoint_url_sts",
    "aws_endpoint_url_cognito", "aws_endpoint_url_apigatewayv2", "aws_endpoint_url_lambda",
    "aws_endpoint_url_kms",
})


class IdentityBindingBootstrapRunnerError(ValueError):
    def __init__(self, category: str):
        self.category = category if category in {
            "step_invalid", "authorization_invalid", "binding_invalid",
            "authorization_binding_mismatch", "source_ci_failed", "github_protection_failed",
            "private_location_invalid", "private_acl_invalid", "private_acl_unverified", "client_setup_failed",
            "journal_setup_failed", "runner_internal_error",
        } else "runner_internal_error"
        super().__init__(self.category)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise ValueError("constant")


def load_binding(path: Path, *, acl_checker: Callable[[Path], bool] | None = None) -> dict[str, Any]:
    try:
        resolved = validate_private_location(Path(path), acl_checker=acl_checker)
        size = resolved.stat().st_size
        if size <= 0 or size > MAX_BINDING_BYTES:
            raise IdentityBindingBootstrapRunnerError("binding_invalid")
        payload = resolved.read_bytes()
        if len(payload) > MAX_BINDING_BYTES:
            raise IdentityBindingBootstrapRunnerError("binding_invalid")
        value = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates,
                           parse_constant=_reject_constant)
    except IdentityBindingBootstrapRunnerError:
        raise
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "private_location_invalid"
        raise IdentityBindingBootstrapRunnerError(category) from None
    except Exception:
        raise IdentityBindingBootstrapRunnerError("binding_invalid") from None
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        raise IdentityBindingBootstrapRunnerError("binding_invalid")
    # JSON arrays are normalized only after exact schema/type validation.
    keys = value.get("tenant_keys")
    if type(keys) is not list or len(keys) != 2 or any(type(key) is not str for key in keys):
        raise IdentityBindingBootstrapRunnerError("binding_invalid")
    value["tenant_keys"] = tuple(keys)
    for name in ("github_owner_id", "github_repository_id"):
        if type(value.get(name)) is not int or isinstance(value.get(name), bool) or value[name] <= 0:
            raise IdentityBindingBootstrapRunnerError("binding_invalid")
    return value


def validate_github_protections(binding: Mapping[str, Any], *, command_runner: Callable[..., Any] = subprocess.run) -> None:
    """Freshly bind the fixed repository, develop protection and dev environment."""
    commands = (
        ["gh", "api", f"repos/{REPOSITORY}"],
        ["gh", "api", f"repos/{REPOSITORY}/branches/develop/protection"],
        ["gh", "api", f"repos/{REPOSITORY}/environments/dev"],
        ["gh", "api", f"repos/{REPOSITORY}/environments/dev/deployment-branch-policies?per_page=100"],
    )
    payloads = []
    for command in commands:
        code, output = _bounded_command(command, runner=command_runner)
        if code != 0:
            raise IdentityBindingBootstrapRunnerError("github_protection_failed")
        try:
            payloads.append(json.loads(output, object_pairs_hook=_reject_duplicates,
                                       parse_constant=_reject_constant))
        except Exception:
            raise IdentityBindingBootstrapRunnerError("github_protection_failed") from None
    repository, branch, environment, rules = payloads
    owner = repository.get("owner") if isinstance(repository, Mapping) else None
    if (not isinstance(repository, Mapping) or repository.get("full_name") != REPOSITORY
        or type(repository.get("id")) is not int or repository["id"] != binding["github_repository_id"]
        or not isinstance(owner, Mapping) or owner.get("login") != "herrerogusano"
        or type(owner.get("id")) is not int or owner["id"] != binding["github_owner_id"]
        or not validate_branch_protection_readback("develop", branch)
        or not validate_environment_readback("dev", binding["github_owner_id"], environment, rules)
        or not validate_admin_bypass_disabled(environment.get("can_admins_bypass") if isinstance(environment, Mapping) else None)):
        raise IdentityBindingBootstrapRunnerError("github_protection_failed")


def _build_clients() -> dict[str, Any]:
    if any(name.casefold() in _PROXY_ENV for name in os.environ):
        raise IdentityBindingBootstrapRunnerError("client_setup_failed")
    try:
        import boto3
        from botocore.config import Config
        credentials_logger = logging.getLogger("botocore.credentials")
        previous_log_level = credentials_logger.level
        credentials_logger.setLevel(logging.CRITICAL)
        common = Config(connect_timeout=2, read_timeout=3,
                        retries={"mode": "standard", "total_max_attempts": 1}, proxies={},
                        signature_version="v4")
        iam_config = Config(connect_timeout=2, read_timeout=3,
                            retries={"mode": "standard", "total_max_attempts": 1}, proxies={},
                            signature_version="v4")
        try:
            session = boto3.Session(region_name=REGION)
            return {
                "kms": session.client("kms", region_name=REGION,
                                      endpoint_url=f"https://kms.{REGION}.amazonaws.com", config=common, verify=True),
                "sts": session.client("sts", region_name=REGION,
                                      endpoint_url=f"https://sts.{REGION}.amazonaws.com", config=common, verify=True),
                "cloudformation": session.client("cloudformation", region_name=REGION,
                                      endpoint_url=f"https://cloudformation.{REGION}.amazonaws.com", config=common, verify=True),
                "iam": session.client("iam", region_name="us-east-1", endpoint_url="https://iam.amazonaws.com",
                                      config=iam_config, verify=True),
                "dynamodb": session.client("dynamodb", region_name=REGION,
                                      endpoint_url=f"https://dynamodb.{REGION}.amazonaws.com", config=common, verify=True),
                "ssm": session.client("ssm", region_name=REGION,
                                      endpoint_url=f"https://ssm.{REGION}.amazonaws.com", config=common, verify=True),
                "cognito": session.client("cognito-idp", region_name=REGION,
                                      endpoint_url=f"https://cognito-idp.{REGION}.amazonaws.com", config=common, verify=True),
                "apigatewayv2": session.client("apigatewayv2", region_name=REGION,
                                      endpoint_url=f"https://apigateway.{REGION}.amazonaws.com", config=common, verify=True),
                "lambda": session.client("lambda", region_name=REGION,
                                      endpoint_url=f"https://lambda.{REGION}.amazonaws.com", config=common, verify=True),
            }
        finally:
            credentials_logger.setLevel(previous_log_level)
    except IdentityBindingBootstrapRunnerError:
        raise
    except Exception:
        raise IdentityBindingBootstrapRunnerError("client_setup_failed") from None


def run_authorized_step(
    authorization_path: Path,
    binding_path: Path,
    state_dir: Path,
    step: str,
    *,
    acl_checker: Callable[[Path], bool] | None = None,
    source_ci_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci,
    protection_validator: Callable[[Mapping[str, Any]], None] = validate_github_protections,
    client_factory: Callable[[], Mapping[str, Any]] = _build_clients,
    journal_factory: Callable[[Path], Any] = FileJournal,
) -> dict[str, Any]:
    safe_step = step if type(step) is str and step in _STEPS else "unknown"
    if safe_step == "unknown":
        return {"step": "unknown", "ok": False, "category": "step_invalid", "calls": 0}
    try:
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        auth = load_authorization(auth_path)
        binding = load_binding(Path(binding_path), acl_checker=acl_checker)
        if (auth["account"] != binding["account_id"]
            or auth["expected_caller_arn"] != binding["operator_user_arn"]):
            raise IdentityBindingBootstrapRunnerError("authorization_binding_mismatch")
        try:
            source_ci_validator(auth)
        except Exception:
            raise IdentityBindingBootstrapRunnerError("source_ci_failed") from None
        try:
            protection_validator(binding)
        except Exception:
            raise IdentityBindingBootstrapRunnerError("github_protection_failed") from None
        private_state = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        try:
            clients = client_factory()
        except Exception:
            raise IdentityBindingBootstrapRunnerError("client_setup_failed") from None
        journal = journal_factory(private_state)
        coordinator = DevIdentityBindingBootstrapCoordinator(
            clients, journal, binding={key: binding[key] for key in _COORDINATOR_FIELDS}, source_sha=auth["source_sha"],
            run_id=auth["run_id"], expected_caller_arn=auth["expected_caller_arn"],
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
            accepted_runtime_verifier=verify_accepted_runtime,
        )
        return coordinator.run_step(safe_step)
    except IdentityBindingBootstrapRunnerError as exc:
        return {"step": safe_step, "ok": False, "category": exc.category, "calls": 0}
    except IdentityBindingBootstrapError as exc:
        return {"step": safe_step, "ok": False, "category": exc.category, "calls": 0}
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "authorization_invalid"
        return {"step": safe_step, "ok": False, "category": category, "calls": 0}
    except RehearsalError:
        return {"step": safe_step, "ok": False, "category": "journal_setup_failed", "calls": 0}
    except Exception:
        return {"step": safe_step, "ok": False, "category": "runner_internal_error", "calls": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run one fresh, explicit DEV identity-binding bootstrap step.")
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--binding", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--step", required=True, choices=_STEPS)
    args = parser.parse_args(argv)
    result = run_authorized_step(args.authorization, args.binding, args.state_dir, args.step)
    sys.stdout.write(json.dumps(result, separators=(",", ":")) + "\n")
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
