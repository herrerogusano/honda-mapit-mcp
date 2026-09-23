"""Fail-closed refresh-token storage and reusable session orchestration."""

from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from typing import Any, Callable, Protocol

from .auth import CognitoAuthenticator, CognitoHTTPError, MapitSession
from .config import MapitConfig, RuntimeConfig, fetch_public_runtime_config


class RefreshTokenStoreError(RuntimeError):
    """A refresh-token store is unavailable or not the approved backend."""


class RefreshTokenStore(Protocol):
    def save(self, refresh_token: str) -> None: ...
    def load(self) -> str | None: ...
    def delete(self) -> None: ...


class WindowsKeyringRefreshTokenStore:
    """Use only the native Windows keyring backend; never fall back to files."""

    SERVICE = "mapit-client"
    ACCOUNT = "refresh-token"
    EXPECTED_MODULE = "keyring.backends.Windows"
    EXPECTED_CLASS = "WinVaultKeyring"

    def __init__(self, *, keyring_module: Any | None = None, backend: Any | None = None) -> None:
        self._injected = keyring_module is not None or backend is not None
        if keyring_module is None:
            if sys.platform != "win32":
                raise RefreshTokenStoreError("Windows keyring is unavailable")
            try:
                import keyring as keyring_module  # type: ignore[no-redef]
            except Exception as exc:
                raise RefreshTokenStoreError("keyring dependency is unavailable") from None
        self._keyring = keyring_module
        self._backend = backend if backend is not None else self._get_backend()
        self._assert_native_backend()

    def _get_backend(self) -> Any:
        try:
            return self._keyring.get_keyring()
        except Exception:
            raise RefreshTokenStoreError("keyring backend is unavailable") from None

    def _assert_native_backend(self) -> None:
        backend_type = type(self._backend)
        if backend_type.__module__ != self.EXPECTED_MODULE or backend_type.__name__ != self.EXPECTED_CLASS:
            raise RefreshTokenStoreError("keyring backend is not native Windows Credential Manager")

    def save(self, refresh_token: str) -> None:
        if not isinstance(refresh_token, str) or not refresh_token:
            raise RefreshTokenStoreError("refresh token is empty")
        self._assert_native_backend()
        try:
            self._keyring.set_password(self.SERVICE, self.ACCOUNT, refresh_token)
        except Exception:
            raise RefreshTokenStoreError("keyring save failed") from None

    def load(self) -> str | None:
        self._assert_native_backend()
        try:
            value = self._keyring.get_password(self.SERVICE, self.ACCOUNT)
        except Exception:
            raise RefreshTokenStoreError("keyring load failed") from None
        return value if isinstance(value, str) and value else None

    def delete(self) -> None:
        self._assert_native_backend()
        password_delete_error = None
        try:
            password_delete_error = getattr(getattr(self._keyring, "errors", None), "PasswordDeleteError", None)
            if password_delete_error is None:
                from keyring.errors import PasswordDeleteError
                password_delete_error = PasswordDeleteError
        except Exception:
            password_delete_error = None
        try:
            self._keyring.delete_password(self.SERVICE, self.ACCOUNT)
        except Exception as exc:
            if password_delete_error is not None and isinstance(exc, password_delete_error):
                return
            raise RefreshTokenStoreError("keyring delete failed") from None


@dataclass(frozen=True)
class ManagedSession:
    config: MapitConfig
    session: MapitSession


class SessionManager:
    """Coordinate public discovery, manual login, saved refresh and forgetting."""

    def __init__(
        self,
        *,
        base_config: MapitConfig | None = None,
        store: RefreshTokenStore | None = None,
        discover=fetch_public_runtime_config,
        authenticator_factory=CognitoAuthenticator,
    ) -> None:
        self.base_config = base_config or MapitConfig()
        self.store = store
        self.discover = discover
        self.authenticator_factory = authenticator_factory

    def _discover_config(self, *, email: str | None = None, password: str | None = None) -> MapitConfig:
        config = replace(self.base_config, email=email, password=password)
        runtime: RuntimeConfig = self.discover(config.frontend_url, timeout=config.http_timeout)
        return config.with_runtime(runtime)

    def login_manual(self, email: str, password: str) -> ManagedSession:
        config = self._discover_config(email=email, password=password)
        session = self.authenticator_factory(config).authenticate()
        if self.store is not None and session.refresh_token:
            self.store.save(session.refresh_token)
        self._bind_refresh_persistence(session)
        return ManagedSession(config, session)

    def login_saved(self) -> ManagedSession | None:
        if self.store is None:
            return None
        try:
            refresh_token = self.store.load()
        except Exception:
            return None
        if not refresh_token:
            return None
        try:
            config = self._discover_config()
        except Exception:
            # Discovery is public and transient; never destroy a usable token
            # merely because the frontend or a bundle is unavailable.
            return None
        try:
            session = self.authenticator_factory(config).authenticate_with_refresh_token(refresh_token)
        except Exception as exc:
            if self._is_invalid_saved_token_error(exc):
                self._safe_delete()
            return None
        if session.refresh_token and session.refresh_token != refresh_token:
            try:
                self.store.save(session.refresh_token)
            except Exception:
                return None
        self._bind_refresh_persistence(session)
        return ManagedSession(config, session)

    def forget_saved_session(self) -> bool:
        """Delete the saved token and report whether the operation succeeded."""
        return self._safe_delete()

    @staticmethod
    def _is_invalid_saved_token_error(exc: BaseException) -> bool:
        """Only forget a token when the auth service clearly rejected it."""
        return isinstance(exc, CognitoHTTPError) and 400 <= exc.status < 500

    def _bind_refresh_persistence(self, session: MapitSession) -> None:
        if self.store is None or session._refresh_callback is None:
            return
        callback: Callable[[MapitSession], None] = session._refresh_callback

        def refresh_and_persist(current: MapitSession) -> None:
            previous = current.refresh_token
            callback(current)
            rotated = current.refresh_token
            if rotated and rotated != previous:
                self.store.save(rotated)

        session._refresh_callback = refresh_and_persist

    def _safe_delete(self) -> bool:
        try:
            if self.store is None:
                return True
            self.store.delete()
            return True
        except Exception:
            return False
