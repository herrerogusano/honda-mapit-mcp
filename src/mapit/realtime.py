"""Reusable, memory-only account-level MAPIT realtime state service."""

from __future__ import annotations

import json
import math
import random
import threading
import time
from collections import OrderedDict
from datetime import datetime
from threading import Event, RLock, Thread
from typing import Any, Callable, Mapping
from urllib.parse import quote

from pydantic import BaseModel, ConfigDict

from .client import MapitClient
from .session import (
    RefreshTokenStore,
    SessionManager,
    WindowsKeyringRefreshTokenStore,
)
from .websocket import WebSocketDependencyError, connect_account_socket, validate_account_socket_url

MAX_FRAME_BYTES = 64 * 1024
MAX_QUEUE = 4
RECEIVE_TIMEOUT_SECONDS = 1.0
DEFAULT_STALE_SECONDS = 120.0
MAX_RECONNECTS = 8
MAX_CACHE_ENTRIES = 64


class RealtimeError(RuntimeError):
    """A stable public realtime category without transport details."""

    def __init__(self, category: str) -> None:
        self.category = category
        super().__init__(category)


class RealtimeAuthenticationError(RealtimeError):
    pass


class RealtimeState(BaseModel):
    """Immutable normalized state for one account-level realtime identity."""

    model_config = ConfigDict(frozen=True, extra="forbid", allow_inf_nan=False)

    entity_id: str
    status: str | None = None
    battery: float | None = None
    lat: float | None = None
    lng: float | None = None
    hdop: float | None = None
    last_ts: float | None = None

    @property
    def id(self) -> str:
        return self.entity_id


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            result = float(value)
        except OverflowError:
            return None
        return result if math.isfinite(result) else None
    if isinstance(value, str) and value.strip():
        try:
            result = float(value.strip())
        except (ValueError, OverflowError):
            return None
        return result if math.isfinite(result) else None
    return None


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _payload(message: Any) -> Mapping[str, Any] | None:
    if isinstance(message, Mapping):
        return message
    if not isinstance(message, str):
        return None
    try:
        parsed = json.loads(message)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, Mapping) else None


def normalize_realtime_message(message: Any) -> RealtimeState | None:
    """Normalize one eligible text JSON object and discard unsupported input."""
    payload = _payload(message)
    if payload is None:
        return None
    entity_id = _text(payload.get("id")) or _text(payload.get("deviceId"))
    if entity_id is None:
        return None
    last_ts = _finite_number(payload.get("lastTs"))
    if last_ts is None:
        last_ts = _finite_number(payload.get("lastCoordTs"))
    return RealtimeState(
        entity_id=entity_id,
        status=_text(payload.get("status")),
        battery=_finite_number(payload.get("battery")),
        lat=_finite_number(payload.get("lat")),
        lng=_finite_number(payload.get("lng")),
        hdop=_finite_number(payload.get("hdop")),
        last_ts=last_ts,
    )


def account_socket_url(account_id: str) -> str:
    if not isinstance(account_id, str) or not account_id.strip():
        raise ValueError("invalid MAPIT account ID")
    url = f"wss://dsw.prod.mapit.me/accounts/{quote(account_id, safe='')}"
    return validate_account_socket_url(url)


class RealtimeClient:
    """Own exactly one synchronous account-level WebSocket connection."""

    def __init__(
        self,
        account_id: str,
        *,
        token_provider: Callable[[], str],
        connector: Callable[..., Any] = connect_account_socket,
        handshake_timeout: float = 10.0,
        receive_timeout: float = RECEIVE_TIMEOUT_SECONDS,
        max_size: int = MAX_FRAME_BYTES,
        max_queue: int = MAX_QUEUE,
        ping_interval: float = 20.0,
        ping_timeout: float = 20.0,
    ) -> None:
        self.url = account_socket_url(account_id)
        self._token_provider = token_provider
        self._connector = connector
        self._handshake_timeout = handshake_timeout
        self._receive_timeout = receive_timeout
        self._max_size = max_size
        self._max_queue = max_queue
        self._ping_interval = ping_interval
        self._ping_timeout = ping_timeout
        self._socket: Any | None = None
        self._connection_context: Any | None = None
        self._lock = RLock()
        self._connect_lock = threading.Lock()
        self._connect_cancel: Event | None = None

    @staticmethod
    def _close_candidate(socket: Any | None, context: Any | None) -> None:
        if socket is None and context is None:
            return
        try:
            if context is not None:
                context.__exit__(None, None, None)
            else:
                socket.close()
        except Exception:
            pass

    def connect(self) -> Any:
        # Serialize handshakes, but never hold the state lock while a token
        # provider, connector, or context manager can block.  ``close`` can
        # therefore cancel an in-flight handshake and return independently.
        with self._connect_lock:
            validate_account_socket_url(self.url)
            self.close()
            attempt_cancel = Event()
            with self._lock:
                self._connect_cancel = attempt_cancel
            connection: Any | None = None
            context: Any | None = None
            socket: Any | None = None
            assigned = False
            try:
                if attempt_cancel.is_set():
                    raise RealtimeError("connect_cancelled")
                try:
                    token = self._token_provider()
                except Exception:
                    if attempt_cancel.is_set():
                        raise RealtimeError("connect_cancelled") from None
                    raise RealtimeAuthenticationError("authentication_failed") from None
                if attempt_cancel.is_set():
                    raise RealtimeError("connect_cancelled")
                if not isinstance(token, str) or not token:
                    raise RealtimeAuthenticationError("authentication_failed")
                connection = self._connector(
                    self.url,
                    token,
                    timeout=self._handshake_timeout,
                    max_size=self._max_size,
                    max_queue=self._max_queue,
                    ping_interval=self._ping_interval,
                    ping_timeout=self._ping_timeout,
                )
                context = connection if callable(getattr(connection, "__enter__", None)) else None
                socket = context.__enter__() if context is not None else connection
                if attempt_cancel.is_set():
                    raise RealtimeError("connect_cancelled")
                if socket is None:
                    raise RealtimeError("handshake_failed")
                with self._lock:
                    cancelled = self._connect_cancel is not attempt_cancel or attempt_cancel.is_set()
                    if cancelled:
                        raise RealtimeError("connect_cancelled")
                    self._socket = socket
                    self._connection_context = context
                    assigned = True
                    return socket
            except WebSocketDependencyError:
                raise
            except RealtimeAuthenticationError:
                raise
            except RealtimeError as exc:
                if exc.category in {"connect_cancelled", "handshake_failed"}:
                    raise
                raise RealtimeError("handshake_failed") from None
            except Exception:
                raise RealtimeError("handshake_failed") from None
            finally:
                with self._lock:
                    if self._connect_cancel is attempt_cancel:
                        self._connect_cancel = None
                if not assigned:
                    self._close_candidate(socket, context)

    def receive(self, *, timeout: float | None = None) -> Any:
        with self._lock:
            socket = self._socket
        if socket is None:
            raise RealtimeError("not_connected")
        try:
            return socket.recv(timeout=self._receive_timeout if timeout is None else timeout)
        except TimeoutError:
            raise
        except Exception:
            raise RealtimeError("receive_failed") from None

    def close(self) -> None:
        with self._lock:
            if self._connect_cancel is not None:
                self._connect_cancel.set()
            socket = self._socket
            context = self._connection_context
            self._socket = None
            self._connection_context = None
        self._close_candidate(socket, context)


class RealtimeService:
    """One non-daemon reconnecting worker and a bounded immutable state cache."""

    def __init__(
        self,
        client: RealtimeClient,
        *,
        stale_seconds: float = DEFAULT_STALE_SECONDS,
        max_reconnects: int = MAX_RECONNECTS,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] | None = None,
        join_timeout: float = 2.0,
        on_state: Callable[[RealtimeState], None] | None = None,
        on_lifecycle: Callable[[str], None] | None = None,
    ) -> None:
        if not math.isfinite(stale_seconds) or stale_seconds <= 0:
            raise ValueError("stale_seconds must be positive and finite")
        if not isinstance(max_reconnects, int) or isinstance(max_reconnects, bool) or max_reconnects < 0:
            raise ValueError("max_reconnects must be a non-negative integer")
        self.client = client
        self.stale_seconds = stale_seconds
        self.max_reconnects = max_reconnects
        self._clock = clock
        self._sleep = sleep
        self._jitter = jitter or (lambda: random.random() * 0.399)
        self._join_timeout = join_timeout
        self._on_state = on_state
        self._on_lifecycle = on_lifecycle
        self._lock = RLock()
        self._stop_event = Event()
        self._thread: Thread | None = None
        self._lifecycle = "stopped"
        self._failure_category: str | None = None
        self._cache: OrderedDict[str, tuple[RealtimeState, float]] = OrderedDict()

    @property
    def lifecycle(self) -> str:
        with self._lock:
            return self._lifecycle

    @property
    def failure_category(self) -> str | None:
        with self._lock:
            return self._failure_category

    @property
    def thread(self) -> Thread | None:
        with self._lock:
            return self._thread

    def _set_lifecycle(self, value: str, failure: str | None = None) -> None:
        with self._lock:
            self._lifecycle = value
            self._failure_category = failure
            callback = self._on_lifecycle
        if callback is not None:
            try:
                callback(value)
            except Exception:
                pass

    def start(self) -> bool:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            self._stop_event.clear()
            self._lifecycle = "starting"
            self._failure_category = None
            self._thread = Thread(target=self._run, name="mapit-realtime", daemon=False)
            self._thread.start()
            return True

    def stop(self) -> bool:
        with self._lock:
            thread = self._thread
            if thread is None or not thread.is_alive():
                self._lifecycle = "stopped"
                return True
            self._lifecycle = "stopping"
            self._stop_event.set()
        self.client.close()
        if thread is threading.current_thread():
            # A callback may stop its own worker.  It cannot join itself;
            # _run() will publish the final stopped state on return.
            return True
        thread.join(timeout=self._join_timeout)
        if thread.is_alive():
            self._set_lifecycle("failed", "shutdown_timeout")
            return False
        self._set_lifecycle("stopped")
        return True

    def __enter__(self) -> "RealtimeService":
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        self.stop()
        return False

    def latest(self, entity_id: str) -> RealtimeState | None:
        with self._lock:
            entry = self._cache.get(entity_id)
            return entry[0] if entry is not None else None

    get_state = latest

    def snapshot(self) -> tuple[RealtimeState, ...]:
        with self._lock:
            return tuple(entry[0] for entry in self._cache.values())

    def is_stale(self, entity_id: str, *, now: float | None = None) -> bool:
        with self._lock:
            entry = self._cache.get(entity_id)
        if entry is None:
            return True
        current = self._clock() if now is None else now
        return current - entry[1] > self.stale_seconds

    def _store(self, state: RealtimeState, received_at: float) -> None:
        with self._lock:
            self._cache.pop(state.entity_id, None)
            self._cache[state.entity_id] = (state, received_at)
            while len(self._cache) > MAX_CACHE_ENTRIES:
                self._cache.popitem(last=False)
            callback = self._on_state
        if callback is not None:
            try:
                callback(state)
            except Exception:
                pass

    def _sleep_interruptibly(self, seconds: float) -> bool:
        if self._sleep is not time.sleep:
            self._sleep(seconds)
            return not self._stop_event.is_set()
        deadline = self._clock() + seconds
        while not self._stop_event.is_set():
            remaining = deadline - self._clock()
            if remaining <= 0:
                return True
            self._sleep(min(remaining, 0.25))
        return False

    def _backoff(self, reconnect_number: int) -> float:
        base = (1.0, 2.0, 4.0, 8.0, 16.0, 30.0)[min(max(reconnect_number, 0), 5)]
        try:
            jitter = float(self._jitter())
        except Exception:
            jitter = 0.0
        return base + min(0.399, max(0.0, jitter))

    def _run(self) -> None:
        reconnects = 0
        last_valid: float | None = None
        while not self._stop_event.is_set():
            try:
                self._set_lifecycle("starting")
                self.client.connect()
            except RealtimeAuthenticationError as exc:
                self._set_lifecycle("failed", exc.category)
                return
            except WebSocketDependencyError:
                self._set_lifecycle("failed", "dependency_missing")
                return
            except ValueError:
                self._set_lifecycle("failed", "invalid_url")
                return
            except RealtimeError as exc:
                category = exc.category
                if category in {"authentication_failed", "dependency_missing", "invalid_url"}:
                    self._set_lifecycle("failed", category)
                    return
                if reconnects >= self.max_reconnects:
                    self._set_lifecycle("failed", "reconnect_exhausted")
                    return
                self._set_lifecycle("backoff")
                reconnects += 1
                if not self._sleep_interruptibly(self._backoff(reconnects - 1)):
                    break
                continue
            except Exception:
                if reconnects >= self.max_reconnects:
                    self._set_lifecycle("failed", "reconnect_exhausted")
                    return
                self._set_lifecycle("backoff")
                reconnects += 1
                if not self._sleep_interruptibly(self._backoff(reconnects - 1)):
                    break
                continue

            self._set_lifecycle("connected")
            # Start staleness at connection time.  Invalid frames and receive
            # timeouts do not count as fresh state; a valid frame resets it.
            last_valid = self._clock()
            try:
                while not self._stop_event.is_set():
                    if self._clock() - last_valid > self.stale_seconds:
                        raise RealtimeError("stale_connection")
                    try:
                        raw = self.client.receive(timeout=RECEIVE_TIMEOUT_SECONDS)
                    except TimeoutError:
                        if last_valid is not None and self._clock() - last_valid > self.stale_seconds:
                            raise RealtimeError("stale_connection")
                        continue
                    except RealtimeError:
                        raise
                    except Exception:
                        raise RealtimeError("receive_failed") from None
                    if raw is None:
                        raise RealtimeError("receive_failed")
                    state = normalize_realtime_message(raw)
                    raw = None
                    if self._clock() - last_valid > self.stale_seconds:
                        raise RealtimeError("stale_connection")
                    if state is None:
                        continue
                    received_at = self._clock()
                    self._store(state, received_at)
                    last_valid = received_at
            except RealtimeError:
                pass
            finally:
                self.client.close()

            if self._stop_event.is_set():
                break
            if reconnects >= self.max_reconnects:
                self._set_lifecycle("failed", "reconnect_exhausted")
                return
            self._set_lifecycle("backoff")
            reconnects += 1
            if not self._sleep_interruptibly(self._backoff(reconnects - 1)):
                break
        self._set_lifecycle("stopped")


class RealtimeFactoryError(RealtimeError):
    pass


def realtime_service_from_saved_session(
    *,
    store: RefreshTokenStore | None = None,
    manager_factory: Callable[..., Any] = SessionManager,
    mapit_client_factory: Callable[..., MapitClient] = MapitClient,
    realtime_client_factory: Callable[..., RealtimeClient] = RealtimeClient,
    service_factory: Callable[..., RealtimeService] = RealtimeService,
    **service_kwargs: Any,
) -> RealtimeService:
    """Build realtime safely from the saved session and account summary."""
    if store is None:
        try:
            store = WindowsKeyringRefreshTokenStore()
        except Exception:
            raise RealtimeFactoryError("credential_store_failed") from None
    try:
        manager = manager_factory(store=store)
        managed = manager.login_saved()
    except Exception:
        raise RealtimeFactoryError("authentication_failed") from None
    if managed is None:
        category = getattr(manager, "last_error_category", None)
        if category not in {
            "session_missing",
            "discovery_failed",
            "authentication_rejected",
            "authentication_failed",
            "credential_store_failed",
        }:
            category = "authentication_failed"
        raise RealtimeFactoryError(category)
    try:
        mapit_client = mapit_client_factory(managed.config, managed.session)
        summary = mapit_client.get_core("/v1/account-summary", max_response_bytes=2 * 1024 * 1024)
    except Exception:
        raise RealtimeFactoryError("account_summary_failed") from None
    account = summary.get("account") if isinstance(summary, Mapping) else None
    account_id = account.get("id") if isinstance(account, Mapping) else None
    if not isinstance(account_id, str) or not account_id.strip():
        raise RealtimeFactoryError("account_missing")
    refresh_lock = RLock()

    def token_provider() -> str:
        with refresh_lock:
            try:
                managed.session.refresh_if_needed()
            except Exception:
                raise RealtimeAuthenticationError("authentication_failed") from None
            token = managed.session.id_token
            if not isinstance(token, str) or not token:
                raise RealtimeAuthenticationError("authentication_failed")
            return token

    try:
        realtime_client = realtime_client_factory(account_id, token_provider=token_provider)
        return service_factory(realtime_client, **service_kwargs)
    except Exception:
        raise RealtimeAuthenticationError("authentication_failed") from None


create_realtime_service = realtime_service_from_saved_session
