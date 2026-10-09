"""Private, one-step runner for the isolated DEV owner OAuth stack.

Importing this module performs no filesystem, GitHub, AWS or credential IO.
Authorization preparation and deployment steps are explicit and create-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping
from typing import Any, Callable

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.dev_owner_oauth_bootstrap import (
    DevOwnerOAuthBootstrapCoordinator,
    DevOwnerOAuthBootstrapError,
)
from scripts.dev_owner_oauth_sdk import OwnerOAuthSdkBindings, OwnerOAuthSdkError
from scripts.github_cd_protections import (
    REPOSITORY,
    validate_admin_bypass_disabled,
    validate_branch_protection_readback,
    validate_environment_readback,
)
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError
from scripts.run_aws_dev_identity_binding_bootstrap import _build_clients
from scripts.run_aws_retained_dev_bootstrap import (
    RetainedDevRunnerError,
    _bounded_command,
    load_authorization,
    validate_authorization,
    validate_private_location,
    validate_source_and_ci,
    write_private_authorization,
)

_BINDING_NAME = "owner-oauth-binding.json"
_STATE_DIR_NAME = "state"
_BINDING_FIELDS = frozenset({
    "schema", "kind", "account_id", "operator_user_arn", "owner_pool_id", "api_id",
    "callback_url", "context_sha256", "run_uuid", "github_owner_id",
    "github_repository_id", "authorization_sha256", "state_directory",
})
_ACCOUNT = re.compile(r"[0-9]{12}\Z")
_API = re.compile(r"[a-z0-9]{10}\Z")
_POOL = re.compile(r"eu-west-1_[A-Za-z0-9]{9,45}\Z")
_SHA1 = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
_OWNER_ARN = re.compile(r"arn:aws:iam::([0-9]{12}):user/(?:[A-Za-z0-9+=,.@_-]+/)*[A-Za-z0-9+=,.@_-]+\Z")
_CALLBACK = re.compile(r"http://(?:localhost|127\.0\.0\.1|\[::1\]):([0-9]{1,5})/.+\Z")
_STEPS = ("preflight", "create", "readback")
_CLIENTS = frozenset({
    "kms", "sts", "cloudformation", "iam", "dynamodb", "ssm", "cognito",
    "apigatewayv2", "lambda",
})
class OwnerOAuthRunnerError(ValueError):
    def __init__(self, category: str):
        allowed = {
            "step_invalid", "authorization_invalid", "binding_invalid", "authorization_binding_mismatch",
            "source_ci_failed", "github_protection_failed", "private_location_invalid",
            "private_acl_invalid", "private_acl_unverified", "client_setup_failed",
            "journal_setup_failed", "authority_write_failed", "context_unverified",
            "window_expired", "runner_internal_error",
        }
        self.category = category if type(category) is str and category in allowed else "runner_internal_error"
        super().__init__(self.category)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _binding_path(authorization_path: Path) -> Path:
    return Path(authorization_path).parent / _BINDING_NAME


def _validate_callback(callback_url: Any) -> str:
    if type(callback_url) is not str:
        raise OwnerOAuthRunnerError("binding_invalid")
    try:
        from scripts.build_aws_dev_oauth_template import _validate_callback as syntax_check
        callback = syntax_check(callback_url)
        match = _CALLBACK.fullmatch(callback)
        if match is None:
            raise ValueError
        port = int(match.group(1))
        if not 1024 <= port <= 65535 or port in {8785, 8786}:
            raise ValueError
        return callback
    except Exception:
        raise OwnerOAuthRunnerError("binding_invalid") from None


def _write_private_binding(path: Path, binding: Mapping[str, Any], *,
                           acl_checker: Callable[[Path], bool] | None = None) -> Path:
    try:
        parent = validate_private_location(Path(path).parent, acl_checker=acl_checker)
        target = parent / Path(path).name
        if target.name != _BINDING_NAME or target.exists() or target.is_symlink():
            raise OwnerOAuthRunnerError("binding_invalid")
        payload = _canonical(binding)
        if not payload or len(payload) > 16 * 1024:
            raise OwnerOAuthRunnerError("binding_invalid")
        with target.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return target
    except OwnerOAuthRunnerError:
        raise
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "private_location_invalid"
        raise OwnerOAuthRunnerError(category) from None
    except Exception:
        raise OwnerOAuthRunnerError("authority_write_failed") from None


def _load_binding(path: Path, *, acl_checker: Callable[[Path], bool] | None = None) -> dict[str, Any]:
    try:
        resolved = validate_private_location(Path(path), acl_checker=acl_checker)
        if resolved.name != _BINDING_NAME:
            raise OwnerOAuthRunnerError("binding_invalid")
        size = resolved.stat().st_size
        if size <= 0 or size > 16 * 1024:
            raise OwnerOAuthRunnerError("binding_invalid")
        value = json.loads(resolved.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)
    except OwnerOAuthRunnerError:
        raise
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "private_location_invalid"
        raise OwnerOAuthRunnerError(category) from None
    except Exception:
        raise OwnerOAuthRunnerError("binding_invalid") from None
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
        raise OwnerOAuthRunnerError("binding_invalid")
    if (type(value.get("schema")) is not int or value["schema"] != 1
            or value.get("kind") != "dev-owner-oauth-authority"
            or type(value.get("account_id")) is not str or _ACCOUNT.fullmatch(value["account_id"]) is None
            or type(value.get("operator_user_arn")) is not str
            or _OWNER_ARN.fullmatch(value["operator_user_arn"]) is None
            or _OWNER_ARN.fullmatch(value["operator_user_arn"]).group(1) != value["account_id"]
            or type(value.get("owner_pool_id")) is not str or _POOL.fullmatch(value["owner_pool_id"]) is None
            or type(value.get("api_id")) is not str or _API.fullmatch(value["api_id"]) is None
            or type(value.get("callback_url")) is not str
            or type(value.get("context_sha256")) is not str or _SHA256.fullmatch(value["context_sha256"]) is None
            or type(value.get("run_uuid")) is not str or _UUID.fullmatch(value["run_uuid"]) is None
            or type(value.get("github_owner_id")) is not int or value["github_owner_id"] <= 0
            or type(value.get("github_repository_id")) is not int or value["github_repository_id"] <= 0
            or type(value.get("authorization_sha256")) is not str
            or _SHA256.fullmatch(value["authorization_sha256"]) is None
            or type(value.get("state_directory")) is not str):
        raise OwnerOAuthRunnerError("binding_invalid")
    _validate_callback(value["callback_url"])
    try:
        state_path = validate_private_location(Path(value["state_directory"]), acl_checker=acl_checker)
        if (not state_path.is_dir() or state_path.name != _STATE_DIR_NAME
                or state_path.parent != resolved.parent):
            raise ValueError
    except Exception:
        raise OwnerOAuthRunnerError("binding_invalid") from None
    return value


def _context_matches(context: Any, *, account: str,
                     owner_pool: str | None = None, api_id: str | None = None,
                     context_sha: str | None = None) -> bool:
    if (not isinstance(context, Mapping)
            or set(context) != {"verified", "account_id", "owner_pool_id", "api_id", "context_sha256"}
            or context.get("verified") is not True
            or context.get("account_id") != account):
        return False
    if owner_pool is not None and context.get("owner_pool_id") != owner_pool:
        return False
    if api_id is not None and context.get("api_id") != api_id:
        return False
    if context_sha is not None and context.get("context_sha256") != context_sha:
        return False
    return (type(context.get("owner_pool_id")) is str and _POOL.fullmatch(context["owner_pool_id"]) is not None
            and type(context.get("api_id")) is str and _API.fullmatch(context["api_id"]) is not None
            and type(context.get("context_sha256")) is str and _SHA256.fullmatch(context["context_sha256"]) is not None)


def validate_github_protections(*, expected_owner_id: int | None = None,
                                expected_repository_id: int | None = None,
                                command_runner: Callable[..., Any] = subprocess.run) -> tuple[int, int]:
    """Read fixed-repository metadata and DEV protections; IDs come from GitHub."""
    try:
        from scripts.run_aws_dev_identity_binding_bootstrap import _normalize_deployment_branch_policies
        owner_name = REPOSITORY.split("/", 1)[0]
        commands = (
            f"repos/{REPOSITORY}",
            f"repos/{REPOSITORY}/branches/develop/protection",
            f"repos/{REPOSITORY}/environments/dev",
            f"repos/{REPOSITORY}/environments/dev/deployment-branch-policies?per_page=100",
        )
        values = []
        for endpoint in commands:
            result = _bounded_command(["gh", "api", endpoint], runner=command_runner)
            if result[0] != 0:
                raise ValueError
            values.append(json.loads(result[1], object_pairs_hook=_reject_duplicates))
        repository, branch, environment, raw_rules = values
        owner = repository.get("owner") if isinstance(repository, Mapping) else None
        if (not isinstance(repository, Mapping) or repository.get("full_name") != REPOSITORY
                or type(repository.get("id")) is not int or repository["id"] <= 0
                or not isinstance(owner, Mapping) or owner.get("login") != owner_name
                or type(owner.get("id")) is not int or owner["id"] <= 0
                or not validate_branch_protection_readback("develop", branch)
                or not validate_environment_readback(
                    "dev", owner["id"], environment,
                    _normalize_deployment_branch_policies(raw_rules))
                or not validate_admin_bypass_disabled(environment.get("can_admins_bypass"))):
            raise ValueError
        if (expected_owner_id is not None and owner["id"] != expected_owner_id
                or expected_repository_id is not None and repository["id"] != expected_repository_id):
            raise ValueError
        return owner["id"], repository["id"]
    except Exception:
        raise OwnerOAuthRunnerError("github_protection_failed") from None


def prepare_private_authorization(
    authorization_path: Path,
    state_dir: Path,
    *,
    account_id: str,
    operator_user_arn: str,
    source_sha: str,
    ci_run_id: int,
    callback_url: str,
    acl_checker: Callable[[Path], bool] | None = None,
    source_ci_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci,
    protection_reader: Callable[..., tuple[int, int]] = validate_github_protections,
    client_factory: Callable[[], Mapping[str, Any]] = _build_clients,
    sdk_factory: Callable[..., Any] = OwnerOAuthSdkBindings,
    run_id_factory: Callable[[], tuple[int, str]] | None = None,
    wall_clock: Callable[[], float] | None = None,
) -> dict[str, Any]:
    """Create a new, immutable private authority file pair after read-only gates.

    The callback URL is syntax-checked only. This function does not claim that a
    loopback listener or Codex registration exists.
    """
    sdk = None
    try:
        if (type(account_id) is not str or _ACCOUNT.fullmatch(account_id) is None
                or type(operator_user_arn) is not str or _OWNER_ARN.fullmatch(operator_user_arn) is None
                or _OWNER_ARN.fullmatch(operator_user_arn).group(1) != account_id
                or type(source_sha) is not str or _SHA1.fullmatch(source_sha) is None or source_sha == "0" * 40
                or type(ci_run_id) is not int or isinstance(ci_run_id, bool) or ci_run_id <= 0):
            raise OwnerOAuthRunnerError("authorization_invalid")
        callback = _validate_callback(callback_url)
        target = Path(authorization_path)
        parent = validate_private_location(target.parent, acl_checker=acl_checker)
        target = parent / target.name
        state_target = Path(state_dir)
        if state_target != parent / _STATE_DIR_NAME:
            raise OwnerOAuthRunnerError("authorization_invalid")
        companion = target.parent / _BINDING_NAME
        if (target.exists() or companion.exists() or target.is_symlink() or companion.is_symlink()
                or state_target.exists() or state_target.is_symlink()):
            raise OwnerOAuthRunnerError("authorization_invalid")
        now = wall_clock() if wall_clock is not None else time.time()
        if type(now) not in (int, float) or isinstance(now, bool) or not 0 < now < float("inf"):
            raise OwnerOAuthRunnerError("authorization_invalid")
        start = int(now)
        if run_id_factory is None:
            run_uuid = str(uuid.uuid4())
            run_id = secrets.randbits(62) + 1
        else:
            run_id, run_uuid = run_id_factory()
        auth = validate_authorization({
            "account": account_id, "expected_caller_arn": operator_user_arn,
            "source_sha": source_sha, "run_id": run_id,
            "start": start, "end": start + 600, "ci_run_id": ci_run_id,
        })
        # Bind fixed-repository identity from GitHub metadata, never from CLI IDs.
        github_owner_id, github_repository_id = protection_reader()
        if (type(github_owner_id) is not int or isinstance(github_owner_id, bool) or github_owner_id <= 0
                or type(github_repository_id) is not int or isinstance(github_repository_id, bool) or github_repository_id <= 0):
            raise OwnerOAuthRunnerError("github_protection_failed")
        try:
            source_ci_validator(auth)
        except Exception:
            raise OwnerOAuthRunnerError("source_ci_failed") from None
        clients = client_factory()
        if not isinstance(clients, Mapping) or set(clients) != _CLIENTS:
            raise OwnerOAuthRunnerError("client_setup_failed")
        sdk = sdk_factory(clients, account_id=account_id, operator_user_arn=operator_user_arn,
                          until_epoch=auth["end"])
        context = sdk.capture_context()
        if not _context_matches(context, account=account_id):
            raise OwnerOAuthRunnerError("context_unverified")
        # Recheck source and protections immediately before publishing the
        # private envelope pair; the checks have no cloud mutation authority.
        try:
            source_ci_validator(auth)
        except Exception:
            raise OwnerOAuthRunnerError("source_ci_failed") from None
        try:
            owner_again, repository_again = protection_reader(
                expected_owner_id=github_owner_id, expected_repository_id=github_repository_id,
            )
        except Exception:
            raise OwnerOAuthRunnerError("github_protection_failed") from None
        if owner_again != github_owner_id or repository_again != github_repository_id:
            raise OwnerOAuthRunnerError("github_protection_failed")
        final_now = wall_clock() if wall_clock is not None else time.time()
        if (type(final_now) not in (int, float) or isinstance(final_now, bool)
                or not 0 < final_now < float("inf") or int(final_now) < start
                or int(final_now) >= auth["end"]):
            raise OwnerOAuthRunnerError("window_expired")
        binding = {
            "schema": 1, "kind": "dev-owner-oauth-authority",
            "account_id": account_id, "operator_user_arn": operator_user_arn,
            "owner_pool_id": context["owner_pool_id"], "api_id": context["api_id"],
            "callback_url": callback, "context_sha256": context["context_sha256"],
            "run_uuid": run_uuid, "github_owner_id": github_owner_id,
            "github_repository_id": github_repository_id,
            "authorization_sha256": _sha(auth),
            "state_directory": str((parent / _STATE_DIR_NAME).resolve(strict=False)),
        }
        # The journal directory is a unique child of this private authority
        # root, so an operator cannot replay a consumed create under a new
        # empty journal path.
        from scripts.prepare_dev_multiuser_private import _create_private_directory
        _create_private_directory(state_target, acl_checker=acl_checker)
        # Binding is written first; authorization is the final commit marker.
        _write_private_binding(companion, binding, acl_checker=acl_checker)
        write_private_authorization(target, auth, acl_checker=acl_checker)
        return {"ok": True, "category": "authority_prepared", "step": "prepare", "calls": getattr(sdk, "calls", 0)}
    except OwnerOAuthRunnerError as exc:
        return {"ok": False, "category": exc.category, "step": "prepare", "calls": getattr(sdk, "calls", 0)}
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "authorization_invalid"
        return {"ok": False, "category": category, "step": "prepare", "calls": getattr(sdk, "calls", 0)}
    except Exception:
        return {"ok": False, "category": "runner_internal_error", "step": "prepare", "calls": getattr(sdk, "calls", 0)}


def run_authorized_step(
    authorization_path: Path,
    state_dir: Path,
    step: str,
    *,
    acl_checker: Callable[[Path], bool] | None = None,
    source_ci_validator: Callable[[Mapping[str, Any]], None] = validate_source_and_ci,
    protection_reader: Callable[..., tuple[int, int]] = validate_github_protections,
    client_factory: Callable[[], Mapping[str, Any]] = _build_clients,
    sdk_factory: Callable[..., Any] = OwnerOAuthSdkBindings,
    journal_factory: Callable[[Path], Any] = FileJournal,
) -> dict[str, Any]:
    safe_step = step if type(step) is str and step in _STEPS else "unknown"
    if safe_step == "unknown":
        return {"step": "unknown", "ok": False, "category": "step_invalid", "calls": 0}
    sdk = None
    try:
        auth_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        binding_path = validate_private_location(_binding_path(auth_path), acl_checker=acl_checker)
        state_path = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        binding = _load_binding(binding_path, acl_checker=acl_checker)
        if (state_path != (auth_path.parent / _STATE_DIR_NAME).resolve(strict=True)
                or str(state_path) != binding["state_directory"]):
            raise OwnerOAuthRunnerError("journal_setup_failed")
        auth = load_authorization(auth_path)
        if (binding.get("authorization_sha256") != _sha(auth)
                or binding.get("account_id") != auth["account"]
                or binding.get("operator_user_arn") != auth["expected_caller_arn"]
                or auth["end"] - auth["start"] > 600):
            raise OwnerOAuthRunnerError("authorization_binding_mismatch")
        try:
            source_ci_validator(auth)
        except Exception:
            raise OwnerOAuthRunnerError("source_ci_failed") from None
        try:
            owner_id, repository_id = protection_reader(
                expected_owner_id=binding["github_owner_id"],
                expected_repository_id=binding["github_repository_id"],
            )
        except Exception:
            raise OwnerOAuthRunnerError("github_protection_failed") from None
        if (owner_id != binding["github_owner_id"] or repository_id != binding["github_repository_id"]):
            raise OwnerOAuthRunnerError("github_protection_failed")
        clients = client_factory()
        if not isinstance(clients, Mapping) or set(clients) != _CLIENTS:
            raise OwnerOAuthRunnerError("client_setup_failed")
        sdk = sdk_factory(clients, account_id=auth["account"],
                          operator_user_arn=auth["expected_caller_arn"], until_epoch=auth["end"])

        def source_and_protection() -> bool:
            source_ci_validator(auth)
            actual_owner, actual_repository = protection_reader(
                expected_owner_id=binding["github_owner_id"],
                expected_repository_id=binding["github_repository_id"],
            )
            return actual_owner == binding["github_owner_id"] and actual_repository == binding["github_repository_id"]

        coordinator = DevOwnerOAuthBootstrapCoordinator(
            {"cloudformation": sdk.proxy("cloudformation"), "cognito": sdk.proxy("cognito")},
            journal_factory(state_path), account_id=auth["account"],
            operator_user_arn=auth["expected_caller_arn"], owner_pool_id=binding["owner_pool_id"],
            api_id=binding["api_id"], callback_url=binding["callback_url"],
            source_sha=auth["source_sha"], run_id=binding["run_uuid"],
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
            expected_context_sha256=binding["context_sha256"],
            context_reader=sdk.capture_context,
            source_checker=source_and_protection,
            readback_validator=sdk.validate_candidate,
        )
        result = coordinator.run_step(safe_step)
        # Shared SDKBindings counts all context and coordinator requests.
        if isinstance(result, dict):
            result["calls"] = getattr(sdk, "calls", result.get("calls", 0))
        return result
    except OwnerOAuthRunnerError as exc:
        return {"step": safe_step, "ok": False, "category": exc.category, "calls": getattr(sdk, "calls", 0)}
    except DevOwnerOAuthBootstrapError as exc:
        return {"step": safe_step, "ok": False, "category": exc.category, "calls": getattr(sdk, "calls", 0)}
    except OwnerOAuthSdkError:
        return {"step": safe_step, "ok": False, "category": "context_unverified", "calls": getattr(sdk, "calls", 0)}
    except RetainedDevRunnerError as exc:
        category = getattr(exc, "category", "private_location_invalid")
        if category not in {"private_location_invalid", "private_acl_invalid", "private_acl_unverified"}:
            category = "authorization_invalid"
        return {"step": safe_step, "ok": False, "category": category, "calls": getattr(sdk, "calls", 0)}
    except RehearsalError:
        return {"step": safe_step, "ok": False, "category": "journal_setup_failed", "calls": getattr(sdk, "calls", 0)}
    except Exception:
        return {"step": safe_step, "ok": False, "category": "runner_internal_error", "calls": getattr(sdk, "calls", 0)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare or run one isolated DEV owner OAuth bootstrap step.")
    parser.add_argument("--step", required=True, choices=("prepare", *_STEPS))
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--account-id")
    parser.add_argument("--operator-user-arn")
    parser.add_argument("--source-sha")
    parser.add_argument("--ci-run-id", type=int)
    parser.add_argument("--callback-url")
    args = parser.parse_args(argv)
    if args.step == "prepare":
        if any(value is None for value in (
                args.account_id, args.operator_user_arn, args.source_sha, args.ci_run_id,
                args.callback_url, args.state_dir)):
            result = {"ok": False, "category": "authorization_invalid", "step": "prepare", "calls": 0}
        else:
            result = prepare_private_authorization(
                args.authorization, args.state_dir, account_id=args.account_id,
                operator_user_arn=args.operator_user_arn, source_sha=args.source_sha,
                ci_run_id=args.ci_run_id, callback_url=args.callback_url,
            )
    elif args.state_dir is None:
        result = {"ok": False, "category": "private_location_invalid", "step": args.step, "calls": 0}
    else:
        result = run_authorized_step(args.authorization, args.state_dir, args.step)
    sys.stdout.write(json.dumps({key: result.get(key) for key in ("step", "ok", "category", "calls")},
                                separators=(",", ":")) + "\n")
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
