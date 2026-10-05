"""Create-only publication of one Standard SecureString through an injected client.

No SDK construction, credential lookup, overwrite, retry or deletion is performed.
The operator must bind the client/account/region and obtain handoff authority.
"""

from __future__ import annotations

import hmac
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable

from .aws_session_reader import AwsSessionReader

_PATH = "/honda-mapit-mcp/prod/mapit-refresh-token"
_ACCOUNT = re.compile(r"^[0-9]{12}$")


@dataclass(frozen=True)
class SessionPublicationResult:
    success: bool
    category: str
    write_acknowledged: bool
    parameter_version: int | None = None


def publish_standard_session(
    client: Any,
    refresh_token: str,
    *,
    account_id: str,
    deadline: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> SessionPublicationResult:
    """One create-only PutParameter, then exact pinned secret readback.

    Failure never implies that no parameter exists: a write may have succeeded
    before a timeout or invalid acknowledgement. Never retry/overwrite blindly.
    Deadlines are cooperative; wire timeouts belong to the injected client.
    """
    def result(category: str, ack: bool = False, version: int | None = None):
        return SessionPublicationResult(False, category, ack, version)

    if (
        type(account_id) is not str or not _ACCOUNT.fullmatch(account_id)
        or account_id == "000000000000" or not callable(monotonic)
        or type(deadline) not in (int, float)
    ):
        return result("invalid_configuration")
    try:
        if not math.isfinite(deadline) or deadline <= 0:
            return result("invalid_configuration")
    except (OverflowError, TypeError):
        return result("invalid_configuration")
    if type(refresh_token) is not str or not refresh_token or len(refresh_token) > 4096:
        return result("value_invalid")
    try:
        secret_bytes = refresh_token.encode("utf-8", errors="strict")
    except UnicodeError:
        return result("value_invalid")
    if len(secret_bytes) > 4096:
        return result("value_invalid")
    last_clock: float | None = None
    effective_deadline: float | None = None

    def guard() -> bool:
        nonlocal last_clock, effective_deadline
        try:
            now = monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
                return False
            if last_clock is not None and now < last_clock:
                return False
            if effective_deadline is None:
                effective_deadline = min(deadline, float(now) + 10.0)
            last_clock = float(now)
            return now < effective_deadline
        except Exception:
            return False

    if not guard():
        return result("deadline_failed")
    try:
        put = getattr(client, "put_parameter")
        get = getattr(client, "get_parameter")
        if not callable(put) or not callable(get):
            return result("invalid_configuration")
    except Exception:
        return result("invalid_configuration")
    if not guard():
        return result("deadline_failed")
    try:
        response = put(
            Name=_PATH,
            Value=refresh_token,
            Type="SecureString",
            KeyId="alias/aws/ssm",
            Overwrite=False,
            Tier="Standard",
            DataType="text",
            Tags=[
                {"Key": "Project", "Value": "honda-mapit-mcp"},
                {"Key": "Environment", "Value": "prod"},
                {"Key": "Purpose", "Value": "owner-session"},
            ],
        )
    except Exception:
        return result("publication_outcome_unknown")
    if not isinstance(response, Mapping):
        return result("publication_outcome_unknown")
    metadata = response.get("ResponseMetadata")
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    version = response.get("Version")
    if type(status) is not int or status != 200:
        return result("publication_outcome_unknown")
    # A successful HTTP acknowledgement is recorded even if other fields fail.
    if type(version) is not int or version != 1 or response.get("Tier") != "Standard":
        return result("publication_ack_invalid", True)
    if not guard():
        return result("deadline_failed", True, version)
    try:
        reader = AwsSessionReader(
            client, account_id=account_id, version=version, tier="Standard", monotonic=monotonic
        )
        readback = reader.read_refresh_token(deadline=effective_deadline)
        if not hmac.compare_digest(secret_bytes, readback.refresh_token.encode("utf-8")):
            return result("publication_readback_failed", True, version)
    except Exception:
        return result("publication_readback_failed", True, version)
    if not guard():
        return result("deadline_failed", True, version)
    return SessionPublicationResult(True, "session_publication_verified", True, version)


__all__ = ["SessionPublicationResult", "publish_standard_session"]
