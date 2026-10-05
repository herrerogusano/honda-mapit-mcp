"""Lazy, invocation-local production MAPIT services with injected dependencies.

Construction is side-effect free. One call to ``get`` performs at most one
secret read and one Cognito refresh-token authentication; the resulting services
are cached only on this provider instance and must be discarded after the
request. No local session manager, keyring, environment, or AWS SDK is used.
"""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Mapping
from typing import Any

from .auth import CognitoAuthenticator, MapitSession
from .client import MapitClient
from .config import MapitConfig
from .services import MapitServices
from .cloud_transport import CloudTransportError, validate_cloud_config

_IDENTITY_RE = re.compile(r"^eu-west-1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_MAX_TOKEN_BYTES = 8192
_MAX_WINDOW_SECONDS = 14.0


class CloudProviderError(RuntimeError):
    """Closed-category provider failure; never includes input or SDK text."""

    _CATEGORIES = frozenset({
        "configuration_invalid", "deadline_invalid", "deadline_expired", "clock_invalid",
        "clock_rollback", "provider_already_used", "secret_read_failed", "auth_failed",
        "refresh_token_changed", "session_invalid",
    })

    def __init__(self, category: str):
        self.category = category if category in self._CATEGORIES else "auth_failed"
        super().__init__(self.category)


class CloudServicesProvider:
    """Lazily prepare services for one request, then reuse them only locally."""

    def __init__(
        self,
        config: MapitConfig,
        reader: Any,
        auth_transport: Callable[..., Mapping[str, Any]],
        mapit_transport: Callable[..., bytes],
        *,
        deadline: float,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        try:
            self._config = validate_cloud_config(config)
        except CloudTransportError:
            raise CloudProviderError("configuration_invalid") from None
        if not callable(auth_transport) or not callable(mapit_transport) or not callable(monotonic):
            raise CloudProviderError("configuration_invalid")
        try:
            reader_method = getattr(reader, "read_refresh_token", None)
        except Exception:
            reader_method = None
        if not callable(reader_method):
            raise CloudProviderError("configuration_invalid")
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, (int, float))
            or (isinstance(deadline, float) and not math.isfinite(deadline))
            or deadline <= 0
        ):
            raise CloudProviderError("deadline_invalid")
        self._reader = reader
        self._auth_transport = auth_transport
        self._mapit_transport = mapit_transport
        self._deadline = deadline
        self._monotonic = monotonic
        self._last_clock = self._clock()
        if self._deadline <= self._last_clock or self._deadline - self._last_clock > _MAX_WINDOW_SECONDS:
            raise CloudProviderError("deadline_invalid")
        self._attempted = False
        self._services: MapitServices | None = None

    def __repr__(self) -> str:
        state = "ready" if self._services is not None else ("used" if self._attempted else "uninitialized")
        return f"CloudServicesProvider(state={state})"

    def _clock(self) -> float:
        try:
            value = self._monotonic()
        except Exception:
            raise CloudProviderError("clock_invalid") from None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CloudProviderError("clock_invalid")
        try:
            if not math.isfinite(value) or value < 0:
                raise CloudProviderError("clock_invalid")
            return float(value)
        except OverflowError:
            raise CloudProviderError("clock_invalid") from None

    def _check_deadline(self) -> None:
        now = self._clock()
        if now < self._last_clock:
            raise CloudProviderError("clock_rollback")
        self._last_clock = now
        if now >= self._deadline:
            raise CloudProviderError("deadline_expired")

    def get(self) -> MapitServices:
        """Return this request's services, authenticating at most once."""
        self._check_deadline()
        if self._services is not None:
            return self._services
        if self._attempted:
            raise CloudProviderError("provider_already_used")
        self._attempted = True

        try:
            secret_result = self._reader.read_refresh_token(deadline=self._deadline)
        except Exception:
            raise CloudProviderError("secret_read_failed") from None
        self._check_deadline()
        try:
            if getattr(secret_result, "success", None) is not True:
                raise CloudProviderError("secret_read_failed")
            token = getattr(secret_result, "refresh_token", None)
        except CloudProviderError:
            raise
        except Exception:
            raise CloudProviderError("secret_read_failed") from None
        if type(token) is not str or not token:
            raise CloudProviderError("secret_read_failed")
        try:
            if len(token.encode("utf-8", errors="strict")) > _MAX_TOKEN_BYTES:
                raise CloudProviderError("secret_read_failed")
        except UnicodeEncodeError:
            raise CloudProviderError("secret_read_failed") from None

        try:
            # The existing authenticator treats a falsey optional transport
            # as a request to use its network default. This wrapper prevents
            # fallback for any explicitly injected callable.
            def explicit_auth_transport(url: str, headers: Mapping[str, str], payload: Mapping[str, Any]) -> Mapping[str, Any]:
                return self._auth_transport(url, headers, payload)

            authenticator = CognitoAuthenticator(self._config, transport=explicit_auth_transport)
            session = authenticator.authenticate_with_refresh_token(token)
        except Exception:
            raise CloudProviderError("auth_failed") from None
        self._check_deadline()
        if type(session) is not MapitSession:
            raise CloudProviderError("session_invalid")
        if session.refresh_token != token:
            raise CloudProviderError("refresh_token_changed")

        refresh_callback = session._refresh_callback
        if not callable(refresh_callback):
            raise CloudProviderError("session_invalid")

        def guarded_refresh(current: MapitSession) -> None:
            self._check_deadline()
            if current.refresh_token != token:
                raise CloudProviderError("refresh_token_changed")
            try:
                refresh_callback(current)
            except CloudProviderError:
                raise
            except Exception:
                raise CloudProviderError("auth_failed") from None
            self._check_deadline()
            if current.refresh_token != token:
                raise CloudProviderError("refresh_token_changed")

        session._refresh_callback = guarded_refresh
        try:
            # The existing adapters treat a falsey optional transport as a
            # request to use their network default. Wrap injected callables in
            # ordinary truthy functions so that fallback can never occur.
            def explicit_mapit_transport(method: str, url: str, headers: Mapping[str, str]) -> bytes:
                return self._mapit_transport(method, url, headers)

            client = MapitClient(self._config, session, transport=explicit_mapit_transport)
            services = MapitServices(client)
        except Exception:
            raise CloudProviderError("session_invalid") from None
        self._check_deadline()
        self._services = services
        return services


__all__ = ["CloudProviderError", "CloudServicesProvider"]
