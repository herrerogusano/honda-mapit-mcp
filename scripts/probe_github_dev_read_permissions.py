"""Three bounded read-only GitHub protection reads; no AWS/OIDC/artifacts."""
from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import re
from typing import Any

from scripts.github_cd_protections import (
    REPOSITORY, validate_admin_bypass_disabled,
    validate_branch_protection_readback, validate_environment_readback,
)
from scripts.github_dev_source_transport import SourceReadTransport


def run(environment: Mapping[str, str], *, root: Path, transport_factory=SourceReadTransport) -> dict[str, Any]:
    result = {"read_only": True, "context_verified": False, "branch_readable": False,
              "environment_readable": False, "branch_policy_readable": False,
              "protections_verified": False}
    try:
        owner = environment.get("GITHUB_REPOSITORY_OWNER_ID")
        sha = environment.get("GITHUB_SHA")
        if (environment.get("GITHUB_REPOSITORY") != REPOSITORY
                or environment.get("GITHUB_REF") != "refs/heads/develop"
                or type(owner) is not str or re.fullmatch(r"[1-9][0-9]{0,19}", owner) is None
                or type(sha) is not str or re.fullmatch(r"[0-9a-f]{40}", sha) is None
                or sha == "0" * 40):
            return result
        reader = transport_factory(environment.get("GH_TOKEN"), root)
        result["context_verified"] = True
        values = {}
        for name, endpoint in (
            ("branch", "branches/develop/protection"),
            ("environment", "environments/dev"),
            ("branch_policy", "environments/dev/deployment-branch-policy"),
        ):
            try:
                value = reader.remote(endpoint)
                if isinstance(value, dict):
                    values[name] = value
                    result[name + "_readable"] = True
            except Exception:
                pass
        if len(values) == 3:
            result["protections_verified"] = (
                validate_branch_protection_readback("develop", values["branch"])
                and validate_environment_readback("dev", int(owner), values["environment"], values["branch_policy"])
                and validate_admin_bypass_disabled(values["environment"].get("can_admins_bypass"))
            ) is True
        return result
    except Exception:
        return result


def main() -> int:
    result = run(os.environ, root=Path(__file__).resolve().parents[1])
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0 if result["protections_verified"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
