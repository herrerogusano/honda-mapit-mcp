"""Explicit local history commands; stateless MCP behavior is unchanged."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .history_runtime import HistoryRuntimeError, forget_history, import_current_month, local_breakdown
from .ledger import LedgerError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Opt-in local distance history (UTC, native MAPIT unit unconfirmed)")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("import-current-month", help="Explicit bounded MAPIT read; save minimal facts locally")
    summary = commands.add_parser("summary", help="Private local aggregates; no MAPIT or authentication calls")
    summary.add_argument("--group-by", choices=("day", "month", "year"), default="month")
    forget = commands.add_parser("forget", help="Delete this app's local history and alias key, not MAPIT credentials")
    forget.add_argument("--confirm", action="store_true", help="Required; deletion cannot be undone by this app")
    args = parser.parse_args(argv)
    try:
        if args.command == "import-current-month":
            result = import_current_month()
        elif args.command == "summary":
            result = {"success": True, "category": "success", **asdict(local_breakdown(args.group_by))}
        else:
            if not args.confirm:
                raise HistoryRuntimeError("confirmation_required")
            forget_history()
            result = {"success": True, "category": "history_deleted"}
    except (HistoryRuntimeError, LedgerError) as exc:
        result = {"success": False, "category": exc.category}
    except Exception:
        result = {"success": False, "category": "history_failed"}
    print(json.dumps(result, ensure_ascii=True, allow_nan=False))
    return 0 if result["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
