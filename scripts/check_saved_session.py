"""Non-interactive saved-session check with no Core/Geo calls."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.auth import CognitoAuthenticator  # noqa: E402
from mapit.config import RuntimeConfig, fetch_public_runtime_config  # noqa: E402
from mapit.session import RefreshTokenStore, SessionManager, SessionManagerError, WindowsKeyringRefreshTokenStore  # noqa: E402


SAFE_CATEGORIES = frozenset(
    {
        "discovery_failed",
        "authentication_rejected",
        "authentication_failed",
        "credential_store_failed",
        "session_missing",
    }
)


def _default_store() -> RefreshTokenStore | None:
    try:
        return WindowsKeyringRefreshTokenStore()
    except Exception:
        return None


def perform_saved_session_check(
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    discover: Callable[..., RuntimeConfig] = fetch_public_runtime_config,
    authenticator_factory: Callable[..., Any] = CognitoAuthenticator,
) -> dict[str, Any]:
    """Run public discovery plus saved Cognito refresh/Identity Pool exchange."""
    if store is None:
        store = _default_store()
    if store is None:
        return {"success": False, "session_valid": False, "error": "credential_store_failed"}
    manager: Any | None = None
    try:
        manager = manager_factory(
            store=store,
            discover=discover,
            authenticator_factory=authenticator_factory,
        )
        context = manager.login_saved()
        if context is None:
            category = getattr(manager, "last_error_category", None) or "session_missing"
            if not isinstance(category, str) or category not in SAFE_CATEGORIES:
                category = "authentication_failed"
            return {"success": False, "session_valid": False, "error": category}
        return {"success": True, "session_valid": True}
    except SessionManagerError as exc:
        category = exc.category if exc.category in SAFE_CATEGORIES else "authentication_failed"
        return {"success": False, "session_valid": False, "error": category}
    except Exception:
        category = getattr(manager, "last_error_category", None) if manager is not None else None
        if not isinstance(category, str) or category not in SAFE_CATEGORIES:
            category = "authentication_failed"
        return {"success": False, "session_valid": False, "error": category}


def main() -> int:
    result = perform_saved_session_check()
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    raise SystemExit(main())
