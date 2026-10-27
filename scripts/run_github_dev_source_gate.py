"""Read-only entrypoint for an exact retained-dev CI/source check."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import json
import os
from pathlib import Path
import re
from typing import Any

from scripts.github_dev_source_gate import REPOSITORY
from scripts.github_dev_source_transport import run_bound_source_gate


def run(environment: Mapping[str, str], *, root: Path,
        gate: Callable[..., dict[str, Any]] = run_bound_source_gate) -> dict[str, Any]:
    failure = {"ok": False, "category": "runner_context_invalid", "read_only": True}
    try:
        sha = environment.get("GITHUB_SHA")
        if (environment.get("GITHUB_REPOSITORY") != REPOSITORY
                or environment.get("GITHUB_REF") != "refs/heads/develop"
                or type(sha) is not str or re.fullmatch(r"[0-9a-f]{40}", sha) is None
                or sha == "0" * 40 or environment.get("CHECKED_OUT_SHA") != sha):
            return failure
        ids = {}
        for name, variable in (("owner_id", "GITHUB_REPOSITORY_OWNER_ID"),
                               ("repository_id", "GITHUB_REPOSITORY_ID"),
                               ("ci_run_id", "GITHUB_CI_RUN_ID")):
            value = environment.get(variable)
            if type(value) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", value) is None:
                return failure
            ids[name] = int(value)
        token = environment.get("GH_TOKEN")
        if type(token) is not str or not token:
            return failure
        binding = {**ids, "source_sha": sha, "owner": "herrerogusano", "repository": REPOSITORY,
                   "branch": "develop", "environment": "dev", "readonly": True}
        result = gate(binding, token=token, root=root)
        # Never let an injected reader return arbitrary data to Actions logs.
        if not isinstance(result, dict) or result.get("read_only") is not True:
            return failure
        if result.get("ok") is True and result.get("category") == "source_gate_verified" and result.get("ci_jobs") == 8:
            return {"ok": True, "category": "source_gate_verified", "ci_jobs": 8, "read_only": True}
        return {"ok": False, "category": "source_gate_failed", "read_only": True}
    except Exception:
        return failure


def main() -> int:
    result = run(os.environ, root=Path(__file__).resolve().parents[1])
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
