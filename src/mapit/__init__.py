"""Small, read-only MAPIT client foundation."""

from .auth import (
    CognitoAuthenticator,
    CognitoHTTPError,
    MapitSession,
    SessionRefreshError,
    TemporaryCredentials,
    UnsupportedCognitoChallenge,
)
from .client import MapitClient, MapitHTTPError
from .config import MapitConfig, RuntimeConfig, discover_runtime_config
from .session import ManagedSession, RefreshTokenStore, SessionManager, WindowsKeyringRefreshTokenStore

__all__ = [
    "CognitoAuthenticator",
    "CognitoHTTPError",
    "MapitClient",
    "MapitConfig",
    "MapitHTTPError",
    "MapitSession",
    "SessionRefreshError",
    "RuntimeConfig",
    "TemporaryCredentials",
    "UnsupportedCognitoChallenge",
    "ManagedSession",
    "RefreshTokenStore",
    "SessionManager",
    "WindowsKeyringRefreshTokenStore",
    "discover_runtime_config",
]
