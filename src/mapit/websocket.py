"""Lazy optional connector for the synchronous websockets 17 API."""

from __future__ import annotations

from typing import Any


class WebSocketDependencyError(RuntimeError):
    """The optional realtime dependency is not installed."""


def connect_account_socket(
    url: str,
    id_token: str,
    *,
    timeout: float,
    max_size: int,
    max_queue: int,
) -> Any:
    """Open one sync websocket with the Cognito ID token as sole subprotocol."""
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
    )
