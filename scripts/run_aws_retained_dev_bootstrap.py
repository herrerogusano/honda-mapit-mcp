"""Private, single-step runner for the retained-dev bootstrap.

The runner is deliberately an authorization and wiring boundary.  It reads a
bounded private authorization file, proves the exact clean ``develop`` commit
and its fresh eight-job CI run, then constructs six single-attempt clients
lazily.  It emits only the coordinator's fixed safe projection.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping

_ROOT = Path(__file__).resolve().parents[1]
for _path in (str(_ROOT), str(_ROOT / "src")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from scripts.aws_retained_dev_bootstrap import (
    REGION,
    RetainedDevBootstrapCoordinator,
    RetainedDevBootstrapError,
)
from scripts.github_cd_protections import REPOSITORY, REQUIRED_CHECKS
from scripts.run_aws_closed_rehearsal import FileJournal, RehearsalError

MAX_AUTH_BYTES = 32 * 1024
MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
CI_JOB_NAMES = frozenset(REQUIRED_CHECKS)
AUTH_FIELDS = frozenset({
    "account", "source_sha", "run_id", "expected_caller_arn", "start", "end", "ci_run_id",
})
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_SOURCE_RE = re.compile(r"^[0-9a-f]{40}$")
_ARN_RE = re.compile(
    r"^arn:aws:(?:iam|sts)::([0-9]{12}):(?:user|role)/[^\s:/]+$|"
    r"^arn:aws:sts::([0-9]{12}):assumed-role/[^\s:/]+/[^\s:/]+$"
)
_PROXY_ENV = frozenset({
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "aws_ca_bundle", "aws_endpoint_url", "aws_endpoint_url_s3", "aws_endpoint_url_sts",
})


class RetainedDevRunnerError(ValueError):
    """Stable category without input, command output, paths, or AWS text."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def load_authorization(path: Path) -> dict[str, Any]:
    """Read one bounded, strict private authorization envelope."""
    try:
        original = Path(path)
        _reject_reparse_ancestors(original)
        if _is_reparse_or_symlink(original):
            raise RetainedDevRunnerError("authorization_file_invalid")
        resolved = original.resolve(strict=True)
        if resolved.stat().st_size <= 0 or resolved.stat().st_size > MAX_AUTH_BYTES:
            raise RetainedDevRunnerError("authorization_file_invalid")
        raw = resolved.read_bytes()
        if len(raw) > MAX_AUTH_BYTES:
            raise RetainedDevRunnerError("authorization_file_invalid")
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicates)
    except RetainedDevRunnerError:
        raise
    except Exception:
        raise RetainedDevRunnerError("authorization_file_invalid") from None
    return validate_authorization(value)


def _is_reparse_or_symlink(path: Path) -> bool:
    """Detect links/reparse points without resolving the path first."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & reparse_flag)


def _reject_reparse_ancestors(path: Path) -> None:
    probe = Path(path).absolute()
    for candidate in (probe, *probe.parents):
        if _is_reparse_or_symlink(candidate):
            raise RetainedDevRunnerError("private_location_invalid")


def write_private_authorization(
    path: Path,
    authorization: Mapping[str, Any],
    *,
    acl_checker: Callable[[Path], bool] | None = None,
) -> Path:
    """Create one canonical authorization envelope without replacing a file.

    The caller supplies already-held, non-secret authorization values.  The
    helper validates the exact envelope and the private parent before opening
    the target with exclusive-create semantics.  It never prints or returns
    the envelope, and a failed write is best-effort cleaned up.
    """
    try:
        normalized = validate_authorization(dict(authorization))
        target = Path(path)
        parent = validate_private_location(target.parent, acl_checker=acl_checker)
        if not parent.is_dir() or not target.name or target.name in {".", ".."}:
            raise RetainedDevRunnerError("authorization_file_invalid")
        target = parent / target.name
        if target.exists() or target.is_symlink():
            raise RetainedDevRunnerError("authorization_file_exists")
        payload = json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        if not payload or len(payload) > MAX_AUTH_BYTES:
            raise RetainedDevRunnerError("authorization_file_invalid")
        created = False
        try:
            with target.open("xb") as stream:
                created = True
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except FileExistsError:
            raise RetainedDevRunnerError("authorization_file_exists") from None
        except Exception:
            if created:
                try:
                    target.unlink()
                except Exception:
                    pass
            raise RetainedDevRunnerError("authorization_file_write_failed") from None
        return target
    except RetainedDevRunnerError:
        raise
    except Exception:
        raise RetainedDevRunnerError("authorization_file_write_failed") from None


def validate_authorization(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != AUTH_FIELDS:
        raise RetainedDevRunnerError("authorization_invalid")
    if type(value["account"]) is not str or _ACCOUNT_RE.fullmatch(value["account"]) is None:
        raise RetainedDevRunnerError("authorization_invalid")
    if type(value["source_sha"]) is not str or _SOURCE_RE.fullmatch(value["source_sha"]) is None or value["source_sha"] == "0" * 40:
        raise RetainedDevRunnerError("authorization_invalid")
    if type(value["run_id"]) is not int or isinstance(value["run_id"], bool) or value["run_id"] <= 0:
        raise RetainedDevRunnerError("authorization_invalid")
    caller = value["expected_caller_arn"]
    if type(caller) is not str:
        raise RetainedDevRunnerError("authorization_invalid")
    match = _ARN_RE.fullmatch(caller)
    if match is None or next(group for group in match.groups() if group is not None) != value["account"]:
        raise RetainedDevRunnerError("authorization_invalid")
    if any(caller.endswith(suffix) for suffix in (":root", "/")):
        raise RetainedDevRunnerError("authorization_invalid")
    for key in ("start", "end", "ci_run_id"):
        if type(value[key]) is not int or isinstance(value[key], bool) or value[key] <= 0:
            raise RetainedDevRunnerError("authorization_invalid")
    if value["end"] <= value["start"] or value["end"] - value["start"] > 3600:
        raise RetainedDevRunnerError("authorization_window_invalid")
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def validate_private_location(path: Path, *, acl_checker: Callable[[Path], bool] | None = None) -> Path:
    try:
        original = Path(path)
        _reject_reparse_ancestors(original)
        resolved = original.resolve(strict=True)
        if any(part.casefold() == "onedrive" or part.casefold().startswith("onedrive - ") for part in resolved.parts):
            raise RetainedDevRunnerError("private_location_invalid")
        if resolved == _ROOT or _ROOT in resolved.parents:
            raise RetainedDevRunnerError("private_location_invalid")
        if acl_checker is not None:
            if acl_checker(resolved) is not True:
                raise RetainedDevRunnerError("private_acl_invalid")
        elif _windows_acl_exact(resolved) is not True:
            raise RetainedDevRunnerError("private_acl_unverified")
        return resolved
    except RetainedDevRunnerError:
        raise
    except Exception:
        raise RetainedDevRunnerError("private_location_invalid") from None


def _windows_acl_exact(path: Path) -> bool:
    if os.name != "nt":
        return True
    script = r'''
$ErrorActionPreference = 'Stop'
$path = $env:MAPIT_ACL_PATH
$acl = Get-Acl -LiteralPath $path
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$owner = ([System.Security.Principal.NTAccount]$acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value
$full = [int][System.Security.AccessControl.FileSystemRights]::FullControl

function Get-RuleState([object]$rules, [bool]$allowInherited) {
    $valid = $true
    $hasCurrent = $false
    $hasSystem = $false
    foreach ($rule in $rules) {
        $sid = [string]$rule.IdentityReference.Value
        if ((-not $allowInherited -and $rule.IsInherited) -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or [int]$rule.FileSystemRights -ne $full) {
            $valid = $false
        }
        if ($sid -eq $current) { $hasCurrent = $true }
        elseif ($sid -eq 'S-1-5-18') { $hasSystem = $true }
        else { $valid = $false }
    }
    [pscustomobject]@{ valid = $valid; has_current = $hasCurrent; has_system = $hasSystem }
}

$isDirectory = [System.IO.Directory]::Exists($path)
$targetState = Get-RuleState $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) (-not $isDirectory)
$parentValid = $true
if (-not $isDirectory) {
    $parentPath = [System.IO.Directory]::GetParent($path).FullName
    $parentAcl = Get-Acl -LiteralPath $parentPath
    $parentOwner = ([System.Security.Principal.NTAccount]$parentAcl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value
    $parentState = Get-RuleState $parentAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) $false
    $parentValid = ($parentOwner -eq $current) -and [bool]$parentAcl.AreAccessRulesProtected -and $parentState.valid -and $parentState.has_current -and $parentState.has_system
}
[pscustomobject]@{
    owner = ($owner -eq $current)
    protected = ($(if ($isDirectory) { [bool]$acl.AreAccessRulesProtected } else { $parentValid }))
    valid = [bool]$targetState.valid -and $parentValid
    has_current = [bool]$targetState.has_current
    has_system = [bool]$targetState.has_system
} | ConvertTo-Json -Compress
'''
    try:
        env = {
            "MAPIT_ACL_PATH": str(path),
            "SystemRoot": os.environ.get("SystemRoot", r"C:\Windows"),
        }
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            env=env, capture_output=True, text=False, shell=False, check=False, timeout=5,
        )
        stdout = result.stdout if isinstance(result.stdout, bytes) else b""
        stderr = result.stderr if isinstance(result.stderr, bytes) else b""
        if result.returncode != 0 or len(stdout) > 8192 or len(stderr) > 8192:
            return False
        value = json.loads(stdout.decode("utf-8", "strict"))
        if (
            type(value) is not dict
            or set(value) != {"owner", "protected", "valid", "has_current", "has_system"}
            or any(type(value[key]) is not bool for key in value)
        ):
            return False
        return value == {"owner": True, "protected": True, "valid": True, "has_current": True, "has_system": True}
    except Exception:
        return False


def _bounded_command(command: list[str], *, runner: Callable[..., Any] = subprocess.run) -> tuple[int, str]:
    try:
        result = runner(command, cwd=_ROOT, shell=False, capture_output=True, text=False, check=False, timeout=20)
        stdout = result.stdout if isinstance(result.stdout, bytes) else b""
        stderr = result.stderr if isinstance(getattr(result, "stderr", None), bytes) else b""
        if len(stdout) > MAX_COMMAND_OUTPUT_BYTES or len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
            raise RetainedDevRunnerError("verification_output_too_large")
        return int(result.returncode), stdout.decode("utf-8", "strict")
    except RetainedDevRunnerError:
        raise
    except Exception:
        raise RetainedDevRunnerError("verification_failed") from None


def validate_source_and_ci(
    authorization: Mapping[str, Any],
    *,
    command_runner: Callable[..., Any] = subprocess.run,
) -> None:
    """Require clean develop HEAD and one exact successful eight-job CI run."""
    source = authorization["source_sha"]
    commands = [
        ["git", "-C", str(_ROOT), "rev-parse", "--verify", "HEAD"],
        ["git", "-C", str(_ROOT), "branch", "--show-current"],
        ["git", "-C", str(_ROOT), "status", "--porcelain=v1"],
    ]
    results = [_bounded_command(command, runner=command_runner) for command in commands]
    if results[0] != (0, source + "\n") or results[1] != (0, "develop\n") or results[2][0] != 0 or results[2][1] != "":
        raise RetainedDevRunnerError("source_verification_failed")
    code, output = _bounded_command(
        ["gh", "run", "view", str(authorization["ci_run_id"]), "--repo", REPOSITORY, "--json", "status,conclusion,headSha,headBranch,event,jobs,workflowName,databaseId,workflowDatabaseId"],
        runner=command_runner,
    )
    if code != 0:
        raise RetainedDevRunnerError("ci_verification_failed")
    try:
        run = json.loads(output, object_pairs_hook=_reject_duplicates)
    except Exception:
        raise RetainedDevRunnerError("ci_verification_failed") from None
    if (
        not isinstance(run, dict)
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("headSha") != source
        or run.get("headBranch") != "develop"
        or run.get("event") != "push"
        or run.get("workflowName") != "CI"
        or run.get("databaseId") != authorization["ci_run_id"]
        or type(run.get("workflowDatabaseId")) is not int
        or isinstance(run.get("workflowDatabaseId"), bool)
        or run.get("workflowDatabaseId") <= 0
        or type(run.get("jobs")) is not list
    ):
        raise RetainedDevRunnerError("ci_verification_failed")
    names: list[str] = []
    for job in run["jobs"]:
        if not isinstance(job, dict) or type(job.get("name")) is not str or job.get("status") != "completed" or job.get("conclusion") != "success":
            raise RetainedDevRunnerError("ci_verification_failed")
        names.append(job["name"])
    if len(names) != len(CI_JOB_NAMES) or set(names) != set(CI_JOB_NAMES):
        raise RetainedDevRunnerError("ci_verification_failed")
    workflow_code, workflow_output = _bounded_command(
        ["gh", "api", f"repos/{REPOSITORY}/actions/workflows/{run['workflowDatabaseId']}"],
        runner=command_runner,
    )
    if workflow_code != 0:
        raise RetainedDevRunnerError("ci_verification_failed")
    try:
        workflow = json.loads(workflow_output, object_pairs_hook=_reject_duplicates)
    except Exception:
        raise RetainedDevRunnerError("ci_verification_failed") from None
    if (
        not isinstance(workflow, dict)
        or workflow.get("id") != run["workflowDatabaseId"]
        or workflow.get("path") != ".github/workflows/ci.yml"
        or workflow.get("name") != "CI"
        or workflow.get("state") != "active"
    ):
        raise RetainedDevRunnerError("ci_verification_failed")


def _build_clients() -> dict[str, Any]:
    """Lazy-create only the six fixed, direct TLS clients."""
    if any(key.casefold() in _PROXY_ENV for key in os.environ):
        raise RetainedDevRunnerError("proxy_or_custom_endpoint_rejected")
    try:
        import boto3
        from botocore.config import Config
        config = Config(
            region_name=REGION, connect_timeout=2, read_timeout=3,
            retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4",
        )
        iam_config = Config(
            region_name="us-east-1", connect_timeout=2, read_timeout=3,
            retries={"total_max_attempts": 1, "mode": "standard"}, proxies={}, signature_version="v4",
        )
        session = boto3.Session(region_name=REGION)
        endpoints = {
            "sts": "https://sts.eu-west-1.amazonaws.com",
            "cloudformation": "https://cloudformation.eu-west-1.amazonaws.com",
            "lambda": "https://lambda.eu-west-1.amazonaws.com",
            "apigatewayv2": "https://apigateway.eu-west-1.amazonaws.com",
            "logs": "https://logs.eu-west-1.amazonaws.com",
            "iam": "https://iam.amazonaws.com",
        }
        clients = {
            name: session.client(name, region_name=("us-east-1" if name == "iam" else REGION), endpoint_url=url, config=(iam_config if name == "iam" else config), verify=True)
            for name, url in endpoints.items()
        }
        return clients
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
        authorization_path = validate_private_location(Path(authorization_path), acl_checker=acl_checker)
        state_dir = validate_private_location(Path(state_dir), acl_checker=acl_checker)
        auth = load_authorization(authorization_path)
        source_ci_validator(auth)
        journal = journal_factory(state_dir)
        coordinator = RetainedDevBootstrapCoordinator(
            client_factory(), journal, account_id=auth["account"], source_sha=auth["source_sha"],
            run_id=auth["run_id"], expected_caller_arn=auth["expected_caller_arn"],
            authorized_from_epoch=auth["start"], authorized_until_epoch=auth["end"],
        )
        return coordinator.run_step(step)
    except (RetainedDevRunnerError, RetainedDevBootstrapError, RehearsalError) as exc:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": getattr(exc, "category", "runner_failed"), "calls": 0}
    except Exception:
        return {"step": step if step in {"preflight", "create", "readback"} else "unknown", "ok": False, "category": "runner_failed", "calls": 0}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--authorization", required=True, type=Path)
    parser.add_argument("--state-dir", required=True, type=Path)
    parser.add_argument("--step", required=True, choices=("preflight", "create", "readback"))
    args = parser.parse_args(argv)
    result = run_authorized_step(args.authorization, args.state_dir, args.step)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
