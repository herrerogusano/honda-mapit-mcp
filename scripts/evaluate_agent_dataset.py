"""Run the deterministic Phase 4 agent-contract evaluator."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.agent_eval import evaluate_dataset  # noqa: E402


def main() -> int:
    result = evaluate_dataset()
    summary = {
        "success": result.success,
        "total_cases": result.total_cases,
        "passed_cases": result.passed_cases,
        "failed_cases": result.failed_cases,
        "class_counts": result.class_counts,
    }
    print(json.dumps(summary, separators=(",", ":")))
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
