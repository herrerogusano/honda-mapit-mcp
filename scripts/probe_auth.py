"""Safe, manual Cognito authentication probe.

The probe deliberately emits only a small JSON summary. It never prints the
account input, identifiers, tokens, credentials, headers, or exception text.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mapit.auth import (  # noqa: E402
    CognitoAuthenticator,
    MapitSession,
    UnsupportedCognitoChallenge,
)
from mapit.config import MapitConfig, fetch_public_runtime_config  # noqa: E402


def _iso(value: datetime) -> str:
    return value.isoformat()


def safe_session_summary(session: MapitSession, *, region: str) -> dict[str, Any]:
    """Return only non-sensitive session facts suitable for stdout."""
    return {
        "success": True,
        "region": region,
        "id_token_expires_at": _iso(session.token_expiration),
        "credentials_expires_at": _iso(session.credentials.expiration),
        "refresh_available": bool(session.refresh_token),
        "temporary_credentials_available": bool(
            session.credentials.access_key_id
            and session.credentials.secret_access_key
            and session.credentials.session_token
        ),
    }


def safe_error_summary(*, region: str, category: str) -> dict[str, Any]:
    """Return a stable categorized error without exception details."""
    return {"success": False, "region": region, "error": category}


def error_category(exc: BaseException, *, stage: str) -> str:
    if isinstance(exc, KeyboardInterrupt):
        return "authentication_interrupted"
    if isinstance(exc, UnsupportedCognitoChallenge):
        return "unsupported_cognito_challenge"
    if stage == "configuration":
        return "configuration_or_credentials_missing"
    if stage == "discovery":
        return "public_discovery_failed"
    if isinstance(exc, TimeoutError):
        return "authentication_timeout"
    if isinstance(exc, OSError):
        return "authentication_network_error"
    return "authentication_failed"


def main() -> int:
    stage = "configuration"
    config: MapitConfig | None = None
    region = "eu-west-1"
    try:
        config = MapitConfig.from_env()
        region = config.region
        stage = "discovery"
        runtime = fetch_public_runtime_config(
            config.frontend_url,
            timeout=config.http_timeout,
        )
        config = config.with_runtime(runtime)
        stage = "authentication"
        session = CognitoAuthenticator(config).authenticate()
    except KeyboardInterrupt as exc:
        print(json.dumps(safe_error_summary(region=region, category=error_category(exc, stage=stage))))
        return 130
    except Exception as exc:
        print(json.dumps(safe_error_summary(region=region, category=error_category(exc, stage=stage))))
        return 1
    print(json.dumps(safe_session_summary(session, region=config.region)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
