from __future__ import annotations

import json
import threading
import time

import pytest
from pydantic import ValidationError

from mapit.realtime import (
    MAX_CACHE_ENTRIES,
    RealtimeAuthenticationError,
    RealtimeClient,
    RealtimeService,
    account_socket_url,
    normalize_realtime_message,
    realtime_service_from_saved_session,
)
from mapit.websocket import connect_account_socket


def test_normalizer_accepts_text_json_and_falls_back_to_last_coord_timestamp():
    state = normalize_realtime_message(
        json.dumps(
            {
                "deviceId": "device-one",
                "status": "moving",
                "battery": "87.5",
                "lat": 40.4,
                "lng": "-3.7",
                "hdop": "bad",
                "lastTs": "bad",
                "lastCoordTs": "42",
            }
        )
    )

    assert state is not None
    assert state.entity_id == "device-one"
    assert state.status == "moving"
    assert state.battery == 87.5
    assert state.lat == 40.4
    assert state.lng == -3.7
    assert state.hdop is None
    assert state.last_ts == 42.0
    with pytest.raises(ValidationError):
        state.status = "changed"


@pytest.mark.parametrize("message", [b'{"id":"binary"}', "not-json", {"status": "missing-id"}, {"id": ""}])
def test_normalizer_discards_ineligible_or_binary_messages(message):
    assert normalize_realtime_message(message) is None


def test_account_url_and_connector_reject_invalid_target_before_token(monkeypatch):
    assert account_socket_url("acct/one ?") == "wss://dsw.prod.mapit.me/accounts/acct%2Fone%20%3F"
    token_calls = []
    connector_calls = []

    def connector(*args, **kwargs):
        connector_calls.append((args, kwargs))

    client = RealtimeClient("account", token_provider=lambda: token_calls.append(True) or "token", connector=connector)
    client.url = "wss://evil.example/accounts/account"
    with pytest.raises(ValueError):
        client.connect()
    assert token_calls == []
    assert connector_calls == []

    with pytest.raises(ValueError):
        connect_account_socket(
            "wss://dsw.prod.mapit.me:443/accounts/account",
            "token",
            timeout=1,
            max_size=64,
            max_queue=1,
        )


def test_realtime_client_refreshes_before_each_handshake_and_sets_control_limits():
    tokens = iter(["token-one", "token-two"])
    calls = []

    class Socket:
        def close(self):
            pass

    def connector(url, token, **kwargs):
        calls.append((url, token, kwargs))
        return Socket()

    client = RealtimeClient("account", token_provider=lambda: next(tokens), connector=connector)
    client.connect()
    client.close()
    client.connect()

    assert [call[1] for call in calls] == ["token-one", "token-two"]
    assert calls[0][2]["max_size"] == 64 * 1024
    assert calls[0][2]["max_queue"] == 4
    assert calls[0][2]["ping_interval"] == 20.0
    assert calls[0][2]["ping_timeout"] == 20.0
    client.close()


def test_realtime_client_enters_and_exits_connector_context_once():
    calls = []

    class ContextSocket:
        def __enter__(self):
            calls.append("enter")
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            calls.append("exit")
            return False

        def close(self):
            calls.append("close")

    socket = ContextSocket()
    client = RealtimeClient("account", token_provider=lambda: "token", connector=lambda *args, **kwargs: socket)
    client.connect()
    client.close()

    assert calls == ["enter", "exit"]


def test_saved_session_factory_reads_account_and_refreshes_before_handshake():
    refresh_calls = []

    class Session:
        id_token = "id-token"

        def refresh_if_needed(self, *args, **kwargs):
            refresh_calls.append((args, kwargs))

    class Managed:
        config = object()
        session = Session()

    class Manager:
        last_error_category = None

        def login_saved(self):
            return Managed()

    class CoreClient:
        def __init__(self):
            self.calls = []

        def get_core(self, path, *, max_response_bytes):
            self.calls.append((path, max_response_bytes))
            return {"account": {"id": "account/one"}}

    core = CoreClient()
    captured = {}

    def realtime_factory(account_id, *, token_provider):
        captured["url"] = account_id
        captured["token"] = token_provider
        return object()

    result = realtime_service_from_saved_session(
        store=object(),
        manager_factory=lambda **kwargs: Manager(),
        mapit_client_factory=lambda config, session: core,
        realtime_client_factory=realtime_factory,
        service_factory=lambda client, **kwargs: client,
    )

    assert result is not None
    assert captured["url"] == "account/one"
    assert captured["token"]() == "id-token"
    # The saved-session path must allow the session's normal freshness/skew
    # policy to decide whether Cognito refresh is needed; no force=True.
    assert refresh_calls == [((), {})]
    assert core.calls == [("/v1/account-summary", 2 * 1024 * 1024)]


def test_saved_session_factory_redacts_factory_failures():
    class Session:
        id_token = "id-token"

        def refresh_if_needed(self):
            pass

    class Managed:
        config = object()
        session = Session()

    class Manager:
        last_error_category = None

        def login_saved(self):
            return Managed()

    core = type(
        "Core",
        (),
        {"get_core": lambda self, path, *, max_response_bytes: {"account": {"id": "account"}}},
    )()
    for factory in (
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret factory detail")),
        lambda *args, **kwargs: object(),
    ):
        kwargs = {
            "store": object(),
            "manager_factory": lambda **kwargs: Manager(),
            "mapit_client_factory": lambda config, session: core,
            "realtime_client_factory": factory,
            "service_factory": lambda client, **kwargs: (_ for _ in ()).throw(RuntimeError("secret service detail")),
        }
        with pytest.raises(RealtimeAuthenticationError) as caught:
            realtime_service_from_saved_session(**kwargs)
        assert caught.value.category == "authentication_failed"
        assert "secret" not in str(caught.value)


def test_cache_replaces_state_bounds_entries_and_reports_stale():
    class Client:
        def connect(self):
            pass

        def receive(self, *, timeout):
            raise TimeoutError

        def close(self):
            pass

    service = RealtimeService(Client(), stale_seconds=120, clock=lambda: 200.0)
    first = normalize_realtime_message({"id": "one", "status": "old"})
    replacement = normalize_realtime_message({"id": "one", "status": "new"})
    assert first is not None and replacement is not None
    service._store(first, 0.0)
    service._store(replacement, 100.0)
    assert service.latest("one").status == "new"
    assert service.is_stale("one") is False
    for index in range(MAX_CACHE_ENTRIES + 1):
        state = normalize_realtime_message({"id": f"id-{index}"})
        assert state is not None
        service._store(state, 200.0)
    assert len(service.snapshot()) == MAX_CACHE_ENTRIES
    assert service.latest("one") is None


def test_service_starts_non_daemon_thread_and_stops_cleanly():
    connected = threading.Event()

    class Client:
        def __init__(self):
            self.closed = False

        def connect(self):
            connected.set()

        def receive(self, *, timeout):
            if self.closed:
                raise RuntimeError("closed")
            raise TimeoutError

        def close(self):
            self.closed = True

    client = Client()
    service = RealtimeService(client, sleep=lambda _: None)
    assert service.start() is True
    assert connected.wait(1)
    assert service.stop() is True
    assert service.thread is not None
    assert service.thread.daemon is False
    assert not service.thread.is_alive()
    assert service.stop() is True


def test_service_reconnects_with_bounded_backoff_and_stops_after_budget():
    calls = []
    sleeps = []

    class Client:
        def connect(self):
            calls.append("connect")
            raise RuntimeError("handshake details")

        def receive(self, *, timeout):
            raise AssertionError("receive must not run")

        def close(self):
            pass

    service = RealtimeService(
        Client(),
        max_reconnects=2,
        sleep=lambda seconds: sleeps.append(seconds),
        jitter=lambda: 0,
    )
    service.start()
    deadline = time.monotonic() + 1
    while service.thread is not None and service.thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert service.lifecycle == "failed"
    assert service.failure_category == "reconnect_exhausted"
    assert len(calls) == 3
    assert sleeps == [1.0, 2.0]
    assert service.stop() is True


def test_backoff_uses_exact_observed_sequence_and_caps_at_thirty():
    service = RealtimeService(type("Client", (), {})(), jitter=lambda: 0)
    assert [service._backoff(index) for index in range(8)] == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0]


def test_stale_timer_starts_at_connection_without_a_valid_frame():
    now = [0.0]
    connected = threading.Event()
    calls = []

    class Client:
        def connect(self):
            calls.append("connect")
            connected.set()

        def receive(self, *, timeout):
            raise TimeoutError

        def close(self):
            pass

    service = RealtimeService(
        Client(),
        stale_seconds=5,
        max_reconnects=0,
        clock=lambda: now[0],
        sleep=lambda _: None,
    )
    service.start()
    assert connected.wait(1)
    now[0] = 6.0
    deadline = time.monotonic() + 1
    while service.thread is not None and service.thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert calls == ["connect"]
    assert service.failure_category == "reconnect_exhausted"
    assert service.stop() is True


def test_stop_during_blocked_handshake_is_bounded_and_cooperative():
    started = threading.Event()
    release = threading.Event()

    class Socket:
        def close(self):
            pass

    def connector(*args, **kwargs):
        started.set()
        release.wait(5)
        return Socket()

    client = RealtimeClient("account", token_provider=lambda: "token", connector=connector)
    service = RealtimeService(client, join_timeout=0.05)
    service.start()
    assert started.wait(1)
    started_at = time.monotonic()
    assert service.stop() is False
    assert time.monotonic() - started_at < 0.5
    release.set()
    deadline = time.monotonic() + 1
    while service.thread is not None and service.thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert service.thread is not None and not service.thread.is_alive()
    assert service.lifecycle == "stopped"


def test_close_does_not_wait_for_blocked_token_provider():
    started = threading.Event()
    release = threading.Event()
    result = []

    def token_provider():
        started.set()
        release.wait(5)
        return "token"

    client = RealtimeClient("account", token_provider=token_provider, connector=lambda *args, **kwargs: object())

    def run_connect():
        try:
            client.connect()
        except Exception as exc:
            result.append(exc)

    thread = threading.Thread(target=run_connect)
    thread.start()
    assert started.wait(1)
    started_at = time.monotonic()
    client.close()
    assert time.monotonic() - started_at < 0.5
    release.set()
    thread.join(1)
    assert not thread.is_alive()
    assert result and getattr(result[0], "category", None) == "connect_cancelled"


def test_stop_from_state_callback_is_successful_and_worker_finishes_stopped():
    connected = threading.Event()
    stopped_from_callback = []
    holder = {}

    class Client:
        def connect(self):
            connected.set()

        def receive(self, *, timeout):
            return {"id": "one"}

        def close(self):
            pass

    def on_state(state):
        stopped_from_callback.append(holder["service"].stop())

    service = RealtimeService(Client(), on_state=on_state)
    holder["service"] = service
    service.start()
    assert connected.wait(1)
    deadline = time.monotonic() + 1
    while service.thread is not None and service.thread.is_alive() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert stopped_from_callback == [True]
    assert service.lifecycle == "stopped"
    assert service.failure_category is None
