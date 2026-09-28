"""Optional bounded Phase 4 live gate.

This script is intentionally not run by CI. It prints only safe status fields
and never prints the answer, prompt, arguments, results, usage, or credentials.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.agent import READ_ONLY_TOOL_NAMES, run_agent_once  # noqa: E402

_SAFE_CATEGORIES = frozenset(
    {
        "configuration_missing",
        "agent_sdk_missing",
        "invalid_question",
        "invalid_timeout",
        "mcp_start_failed",
        "mcp_close_failed",
        "agent_timeout",
        "agent_cancelled",
        "agent_run_failed",
        "unsupported_tool",
        "no_tool_call",
    }
)


async def perform_agent_phase4_gate() -> dict[str, object]:
    """Run one fixed read-only status question and redact its outcome."""
    outcome = await run_agent_once("What is the current vehicle status?")
    names = list(outcome.used_tool_names)
    category = outcome.category
    success = outcome.success and bool(names) and all(name in READ_ONLY_TOOL_NAMES for name in names)
    if outcome.success and not names:
        category = "no_tool_call"
    elif outcome.success and any(name not in READ_ONLY_TOOL_NAMES for name in names):
        category = "unsupported_tool"
        success = False
    result: dict[str, object] = {"success": bool(success), "used_tool_names": names}
    if category is not None:
        result["category"] = category if category in _SAFE_CATEGORIES else "agent_run_failed"
    return result


def main() -> int:
    if not os.environ.get("OPENAI_API_KEY") or not os.environ.get("MAPIT_AGENT_MODEL"):
        result: dict[str, object] = {"success": False, "used_tool_names": [], "category": "configuration_missing"}
    else:
        try:
            result = asyncio.run(perform_agent_phase4_gate())
        except asyncio.CancelledError:
            result = {"success": False, "used_tool_names": [], "category": "agent_cancelled"}
        except Exception:
            result = {"success": False, "used_tool_names": [], "category": "agent_run_failed"}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
