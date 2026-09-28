"""Bounded, redacted Phase 3 realtime live gate.

The default path uses the saved-session realtime factory.  Tests may inject a
service builder, but this script never inspects a snapshot or persists a
realtime frame.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from threading import Event
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.realtime import RealtimeError, realtime_service_from_saved_session  # noqa: E402

MAX_WAIT_SECONDS = 10.0
_SAFE_CATEGORIES = frozenset(
    {
        "session_missing",
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
        "account_summary_failed",
        "account_missing",
        "dependency_missing",
        "invalid_url",
        "handshake_failed",
        "receive_failed",
        "stale_connection",
        "reconnect_exhausted",
        "state_timeout",
        "start_failed",
        "stop_failed",
        "shutdown_timeout",
        "service_failed",
        "factory_failed",
    }
)


def _safe_category(value: Any, fallback: str) -> str:
    return value if isinstance(value, str) and value in _SAFE_CATEGORIES else fallback


def perform_realtime_phase3_smoke(
    *,
    service_builder: Callable[..., Any] = realtime_service_from_saved_session,
    max_wait_seconds: float = MAX_WAIT_SECONDS,
) -> dict[str, object]:
    """Run one bounded realtime observation and return only safe status fields."""
    observed = Event()
    service: Any | None = None
    started = False
    observed_valid_state = False
    stopped_cleanly = False
    category: str | None = None

    def on_state(_state: Any) -> None:
        observed.set()

    try:
        service = service_builder(on_state=on_state)
    except RealtimeError as exc:
        category = _safe_category(exc.category, "factory_failed")
    except Exception:
        category = "factory_failed"

    if service is not None:
        try:
            started = service.start() is True
            if not started:
                category = category or "start_failed"
            else:
                wait_seconds = min(MAX_WAIT_SECONDS, max(0.0, float(max_wait_seconds)))
                observed_valid_state = observed.wait(wait_seconds)
                if not observed_valid_state:
                    category = category or "state_timeout"
        except RealtimeError as exc:
            category = _safe_category(exc.category, "service_failed")
        except (TypeError, ValueError, OverflowError):
            category = category or "service_failed"
        except Exception:
            category = category or "service_failed"
        finally:
            try:
                stopped_cleanly = service.stop() is True
            except RealtimeError as exc:
                category = category or _safe_category(exc.category, "stop_failed")
            except Exception:
                category = category or "stop_failed"
            if not stopped_cleanly:
                category = category or "shutdown_timeout"

    result: dict[str, object] = {
        "success": bool(started and observed_valid_state and stopped_cleanly and category is None),
        "started": started,
        "observed_valid_state": observed_valid_state,
        "stopped_cleanly": stopped_cleanly,
    }
    if category is not None:
        result["category"] = _safe_category(category, "service_failed")
    return result


def main() -> int:
    result = perform_realtime_phase3_smoke()
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["success"] is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
