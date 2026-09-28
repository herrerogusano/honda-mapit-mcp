"""Small, read-only MAPIT client foundation."""

from .auth import (
    CognitoAuthenticator,
    CognitoHTTPError,
    MapitSession,
    SessionRefreshError,
    TemporaryCredentials,
    UnsupportedCognitoChallenge,
)
from .agent import AgentAdapterError, AgentAnswer, AgentRunOutcome, run_agent_once
from .client import MapitClient, MapitHTTPError, MapitResponseError, MapitResponseTooLarge, MapitTransportError
from .config import MapitConfig, RuntimeConfig, discover_runtime_config
from .realtime import (
    RealtimeClient,
    RealtimeError,
    RealtimeFactoryError,
    RealtimeAuthenticationError,
    RealtimeService,
    RealtimeState,
    account_socket_url,
    create_realtime_service,
    normalize_realtime_message,
    realtime_service_from_saved_session,
)
from .session import ManagedSession, RefreshTokenStore, SessionManager, SessionManagerError, WindowsKeyringRefreshTokenStore

__all__ = [
    "CognitoAuthenticator",
    "AgentAdapterError",
    "AgentAnswer",
    "AgentRunOutcome",
    "CognitoHTTPError",
    "MapitClient",
    "MapitConfig",
    "MapitHTTPError",
    "MapitTransportError",
    "MapitResponseError",
    "MapitResponseTooLarge",
    "MapitSession",
    "SessionRefreshError",
    "RuntimeConfig",
    "TemporaryCredentials",
    "UnsupportedCognitoChallenge",
    "ManagedSession",
    "RefreshTokenStore",
    "SessionManager",
    "SessionManagerError",
    "WindowsKeyringRefreshTokenStore",
    "discover_runtime_config",
    "run_agent_once",
    "RealtimeClient",
    "RealtimeError",
    "RealtimeFactoryError",
    "RealtimeAuthenticationError",
    "RealtimeService",
    "RealtimeState",
    "account_socket_url",
    "create_realtime_service",
    "normalize_realtime_message",
    "realtime_service_from_saved_session",
]
