"""Lazy optional connector for the synchronous websockets 17 API."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlsplit


class WebSocketDependencyError(RuntimeError):
    """The optional realtime dependency is not installed."""


def validate_account_socket_url(url: str) -> str:
    """Accept only the observed account-level MAPIT WebSocket target."""
    if not isinstance(url, str):
        raise ValueError("invalid MAPIT WebSocket URL")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        explicit_port = parsed.port
    except ValueError:
        raise ValueError("invalid MAPIT WebSocket URL") from None
    if (
        parsed.scheme != "wss"
        or hostname is None
        or hostname.lower() != "dsw.prod.mapit.me"
        or parsed.username is not None
        or parsed.password is not None
        or explicit_port is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/accounts/")
    ):
        raise ValueError("invalid MAPIT WebSocket URL")
    segment = parsed.path[len("/accounts/") :]
    if not segment or "/" in segment or ";" in segment:
        raise ValueError("invalid MAPIT WebSocket URL")
    for index, character in enumerate(segment):
        if character == "%" and (
            index + 2 >= len(segment)
            or segment[index + 1] not in "0123456789abcdefABCDEF"
            or segment[index + 2] not in "0123456789abcdefABCDEF"
        ):
            raise ValueError("invalid MAPIT WebSocket URL")
    decoded_segment = unquote(segment)
    if not decoded_segment or decoded_segment in {".", ".."}:
        raise ValueError("invalid MAPIT WebSocket URL")
    return url


def connect_account_socket(
    url: str,
    id_token: str,
    *,
    timeout: float,
    max_size: int,
    max_queue: int,
    ping_interval: float = 20.0,
    ping_timeout: float = 20.0,
) -> Any:
    """Open one sync websocket with the Cognito ID token as sole subprotocol."""
    validate_account_socket_url(url)
    if not isinstance(id_token, str) or not id_token:
        raise ValueError("ID token is required")
    try:
        from websockets.sync.client import connect
    except ImportError:
        raise WebSocketDependencyError("websockets realtime dependency is unavailable") from None
    return connect(
        url,
        subprotocols=[id_token],
        open_timeout=timeout,
        close_timeout=1.0,
        max_size=max_size,
        max_queue=max_queue,
        ping_interval=ping_interval,
        ping_timeout=ping_timeout,
        proxy=None,
    )
