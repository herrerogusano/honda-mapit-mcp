"""Offline environment diagnostics, not a provider connectivity test."""

from __future__ import annotations

import json
import sys
from importlib import metadata


def _installed(distribution: str) -> bool:
    try:
        metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return False
    return True


def environment_health() -> dict[str, object]:
    """Inspect package metadata only; never load sessions or credential stores."""
    supported_python = (3, 11) <= sys.version_info[:2] <= (3, 13)
    core_available = all(_installed(name) for name in ("mcp", "pydantic"))
    return {
        "success": supported_python and core_available,
        "category": "local_check_passed" if supported_python and core_available else "local_requirements_missing",
        "check_kind": "offline_environment",
        "supported_python": supported_python,
        "core_dependencies_available": core_available,
        "agent_dependency_available": _installed("openai-agents"),
        "realtime_dependency_available": _installed("websockets"),
        "windows_keyring_dependency_available": sys.platform == "win32" and _installed("keyring"),
        "credentials_checked": False,
        "provider_connectivity_checked": False,
    }


def main() -> int:
    try:
        result = environment_health()
    except Exception:
        result = {"success": False, "category": "local_check_failed", "check_kind": "offline_environment"}
    print(json.dumps(result, allow_nan=False))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
