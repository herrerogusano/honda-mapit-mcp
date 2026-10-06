"""Credential-free source gate for the retained-dev promotion boundary.

The module is deliberately independent from AWS, deployment operators and
workflow writers.  Callers inject bounded local-git and GitHub read
functions; this module validates only a typed, read-only ``develop`` payload
and returns a redacted projection.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Mapping
import math
import re
from typing import Any

from scripts.github_cd_protections import (
    REPOSITORY,
    REQUIRED_CHECKS,
    validate_admin_bypass_disabled,
    validate_branch_protection_readback,
    validate_environment_readback,
)

OWNER = "herrerogusano"
BRANCH = "develop"
ENVIRONMENT = "dev"
WORKFLOW_NAME = "CI"
WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_CALLS = 16
MAX_OUTPUT_BYTES = 256 * 1024
_SHA = re.compile(r"[0-9a-f]{40}\Z")


class SourceGateError(ValueError):
    """Stable category without echoing IDs, paths, payloads or exceptions."""

    _CATEGORIES = frozenset({
        "binding_invalid", "local_checkout_invalid", "local_checkout_dirty",
        "repository_readback_failed", "branch_head_mismatch", "ci_readback_failed",
        "workflow_readback_failed", "ci_jobs_mismatch", "branch_protection_mismatch",
        "environment_protection_mismatch", "administrator_bypass_mismatch",
        "call_budget_exhausted", "read_failed", "source_gate_internal_error",
    })

    def __init__(self, category: str) -> None:
        self.category = category if category in self._CATEGORIES else "source_gate_internal_error"
        super().__init__(self.category)


def _positive_id(value: Any) -> bool:
    return type(value) is int and not isinstance(value, bool) and value > 0


def _sha(value: Any) -> bool:
    return type(value) is str and _SHA.fullmatch(value) is not None and value != "0" * 40


@dataclass(frozen=True)
class SourceGateBinding:
    owner_id: int
    repository_id: int
    source_sha: str
    ci_run_id: int
    owner: str = OWNER
    repository: str = REPOSITORY
    branch: str = BRANCH
    environment: str = ENVIRONMENT
    readonly: bool = True

    @classmethod
    def from_payload(cls, value: Any) -> "SourceGateBinding":
        fields = {"owner_id", "repository_id", "source_sha", "ci_run_id", "owner", "repository", "branch", "environment", "readonly"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise SourceGateError("binding_invalid")
        candidate = cls(**dict(value))
        if (
            not _positive_id(candidate.owner_id) or not _positive_id(candidate.repository_id)
            or not _positive_id(candidate.ci_run_id) or not _sha(candidate.source_sha)
            or candidate.owner != OWNER or candidate.repository != REPOSITORY
            or candidate.branch != BRANCH or candidate.environment != ENVIRONMENT
            or candidate.readonly is not True
        ):
            raise SourceGateError("binding_invalid")
        return candidate


class _Reader:
    def __init__(self, git: Callable[[list[str]], Any], github: Callable[[str], Any]) -> None:
        self.git = git
        self.github = github
        self.calls = 0

    def local(self, command: list[str]) -> tuple[int, str]:
        self.calls += 1
        if self.calls > MAX_CALLS:
            raise SourceGateError("call_budget_exhausted")
        try:
            result = self.git(list(command))
            code = result[0] if isinstance(result, tuple) and len(result) == 2 else getattr(result, "returncode", None)
            output = result[1] if isinstance(result, tuple) and len(result) == 2 else getattr(result, "stdout", None)
            if type(code) is not int or type(output) is not str or len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
                raise SourceGateError("local_checkout_invalid")
            return code, output
        except SourceGateError:
            raise
        except Exception:
            raise SourceGateError("local_checkout_invalid") from None

    def remote(self, endpoint: str) -> Any:
        self.calls += 1
        if self.calls > MAX_CALLS:
            raise SourceGateError("call_budget_exhausted")
        try:
            value = self.github(endpoint)
            if not isinstance(value, (Mapping, list, tuple)):
                raise SourceGateError("read_failed")
            # Providers must enforce their own bounded HTTP body.  Reject a
            # suspiciously deep/large synthetic payload before inspecting it.
            if len(repr(value).encode("utf-8", "ignore")) > MAX_OUTPUT_BYTES:
                raise SourceGateError("read_failed")
            return value
        except SourceGateError:
            raise
        except Exception:
            raise SourceGateError("read_failed") from None


def _strict_jobs(value: Any, source_sha: str) -> bool:
    if not isinstance(value, Mapping) or set(value) != {"total_count", "jobs"}:
        return False
    jobs = value.get("jobs")
    if type(value.get("total_count")) is not int or value["total_count"] != len(REQUIRED_CHECKS):
        return False
    if type(jobs) is not list or len(jobs) != len(REQUIRED_CHECKS):
        return False
    names: list[str] = []
    for job in jobs:
        if not isinstance(job, Mapping):
            return False
        if job.get("name") not in REQUIRED_CHECKS or job.get("status") != "completed" or job.get("conclusion") != "success":
            return False
        if job.get("head_sha") != source_sha:
            return False
        names.append(job["name"])
    return len(set(names)) == len(REQUIRED_CHECKS) and set(names) == set(REQUIRED_CHECKS)


def _local_checkout(reader: _Reader, binding: SourceGateBinding) -> None:
    code, head = reader.local(["git", "rev-parse", "--verify", "HEAD"])
    if code != 0 or head.strip() != binding.source_sha:
        raise SourceGateError("branch_head_mismatch")
    code, branch = reader.local(["git", "branch", "--show-current"])
    if code != 0 or branch.strip() != BRANCH:
        raise SourceGateError("local_checkout_invalid")
    code, status = reader.local(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    if code != 0:
        raise SourceGateError("local_checkout_invalid")
    if status != "":
        raise SourceGateError("local_checkout_dirty")


def validate_source_gate(
    binding_payload: Mapping[str, Any],
    *,
    git_reader: Callable[[list[str]], Any],
    github_reader: Callable[[str], Any],
) -> dict[str, Any]:
    """Run the bounded, read-only source/protection gate."""
    try:
        binding = SourceGateBinding.from_payload(binding_payload)
        reader = _Reader(git_reader, github_reader)
        _local_checkout(reader, binding)

        repository = reader.remote("repository")
        owner = repository.get("owner")
        if (
            repository.get("full_name") != REPOSITORY
            or not _positive_id(repository.get("id"))
            or repository.get("id") != binding.repository_id
            or not isinstance(owner, Mapping)
            or owner.get("login") != OWNER
            or not _positive_id(owner.get("id"))
            or owner.get("id") != binding.owner_id
        ):
            raise SourceGateError("repository_readback_failed")

        ref = reader.remote("ref/heads/develop")
        obj = ref.get("object")
        if ref.get("ref") != "refs/heads/develop" or not isinstance(obj, Mapping) or obj.get("sha") != binding.source_sha:
            raise SourceGateError("branch_head_mismatch")

        run = reader.remote(f"actions/runs/{binding.ci_run_id}")
        if (
            not _positive_id(run.get("id")) or run.get("id") != binding.ci_run_id or run.get("status") != "completed"
            or run.get("conclusion") != "success" or run.get("head_sha") != binding.source_sha
            or run.get("head_branch") != BRANCH or run.get("event") != "push"
            or type(run.get("workflow_id")) is not int or run.get("workflow_id") <= 0
        ):
            raise SourceGateError("ci_readback_failed")

        workflow = reader.remote(f"actions/workflows/{run['workflow_id']}")
        if not _positive_id(workflow.get("id")) or workflow.get("id") != run["workflow_id"] or workflow.get("name") != WORKFLOW_NAME or workflow.get("path") != WORKFLOW_PATH or workflow.get("state") != "active":
            raise SourceGateError("workflow_readback_failed")
        jobs = reader.remote(f"actions/runs/{binding.ci_run_id}/jobs")
        if not _strict_jobs(jobs, binding.source_sha):
            raise SourceGateError("ci_jobs_mismatch")

        branch_protection = reader.remote("branches/develop/protection")
        if not validate_branch_protection_readback(BRANCH, branch_protection):
            raise SourceGateError("branch_protection_mismatch")
        environment = reader.remote("environments/dev")
        branch_rules = reader.remote("environments/dev/deployment-branch-policy")
        if not validate_environment_readback(ENVIRONMENT, binding.owner_id, environment, branch_rules):
            raise SourceGateError("environment_protection_mismatch")
        if not validate_admin_bypass_disabled(environment.get("can_admins_bypass")):
            raise SourceGateError("administrator_bypass_mismatch")
        return {"ok": True, "category": "source_gate_verified", "ci_jobs": len(REQUIRED_CHECKS), "read_only": True}
    except SourceGateError as exc:
        return {"ok": False, "category": exc.category, "read_only": True}
    except Exception:
        return {"ok": False, "category": "source_gate_internal_error", "read_only": True}


__all__ = ["SourceGateBinding", "SourceGateError", "validate_source_gate"]
