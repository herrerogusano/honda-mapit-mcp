from __future__ import annotations

import json
import sys
import types
import warnings
from datetime import datetime, timezone
from pathlib import Path

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitHTTPError, MapitResponseError, MapitTransportError
from mapit.config import MapitConfig
from mapit.session import ManagedSession, SessionManagerError
from mapit.websocket import WebSocketDependencyError, connect_account_socket
from scripts import probe_websocket as probe


def _session() -> MapitSession:
    now = datetime(2026, 9, 28, tzinfo=timezone.utc)
    return MapitSession(
        id_token="id-token-secret",
        access_token="access-secret",
        refresh_token="refresh-secret",
        token_expiration=now,
        credentials=TemporaryCredentials("access", "secret", "session", now),
    )


class SavedManager:
    def __init__(self, context: ManagedSession | None, category: str | None = None, **_: object) -> None:
        self.context = context
        self.last_error_category = category

    def login_saved(self):
        return self.context


class RecordingClient:
    def __init__(self, summary=None, error=None):
        self.summary = summary if summary is not None else {"account": {"id": "acct/one ?"}}
        self.error = error
        self.calls: list[str] = []

    def get_core(self, path):
        self.calls.append(path)
        if self.error:
            raise self.error
        return self.summary


class RecordingSocket:
    def __init__(self, frames=None, recv_error=None):
        self.frames = list(frames or [])
        self.recv_error = recv_error
        self.recv_calls = 0
        self.closed = False
        self.close_calls = 0
        self.enter_calls = 0
        self.exit_calls = 0

    def __enter__(self):
        self.enter_calls += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.exit_calls += 1
        self.closed = True
        return False

    def recv(self, *, timeout):
        self.recv_calls += 1
        if self.recv_error is not None:
            raise self.recv_error
        if self.frames:
            return self.frames.pop(0)
        raise TimeoutError("secret timeout detail")

    def close(self):
        self.close_calls += 1
        self.closed = True


def _run(tmp_path: Path, socket: RecordingSocket, *, summary=None, connector_error=None, manager=None, error=None):
    manager = manager or SavedManager(ManagedSession(MapitConfig(), _session()))
    calls: list[dict] = []

    def connector(url, id_token, **kwargs):
        calls.append({"url": url, "subprotocols": [id_token], **kwargs})
        if connector_error is not None:
            raise connector_error
        return socket

    client = RecordingClient(summary=summary, error=error)
    result = probe.perform_websocket_probe(
        store=object(),
        manager_factory=lambda **kwargs: manager,
        client_factory=lambda config, session: client,
        connector_factory=connector,
        save_path=tmp_path / "websocket-message.schema.json",
        clock=lambda: 100.0,
    )
    return result, client, calls


def test_exact_account_url_subprotocol_and_schema_merge(tmp_path):
    socket = RecordingSocket(
        frames=[
            json.dumps({"id": "vehicle-secret", "lat": 1.5, "status": "moving"}),
            json.dumps({"deviceId": "device-secret", "battery": 90, "lat": None}),
        ]
    )
    result, client, calls = _run(tmp_path, socket)

    assert result["success"] is True
    assert result["connected"] is True
    assert result["valid_shape_observed"] is True
    assert result["schema_written"] is True
    assert client.calls == ["/v1/account-summary"]
    assert calls == [
        {
            "url": "wss://dsw.prod.mapit.me/accounts/acct%2Fone%20%3F",
            "subprotocols": ["id-token-secret"],
            "timeout": 10.0,
            "max_size": probe.MAX_FRAME_BYTES,
            "max_queue": probe.MAX_QUEUE,
        }
    ]
    assert socket.closed is True
    assert socket.enter_calls == 1
    assert socket.exit_calls == 1
    assert socket.close_calls == 0
    saved = json.loads((tmp_path / "websocket-message.schema.json").read_text(encoding="utf-8"))
    rendered = json.dumps(saved)
    assert set(saved["fields"]) == {"battery", "deviceId", "id", "lat", "status"}
    assert "vehicle-secret" not in rendered
    assert "device-secret" not in rendered
    assert "moving" not in rendered
    assert "90" not in rendered
    assert result["path"].endswith("websocket-message.schema.json")


def test_connector_wrapper_signature_matches_probe_and_websockets_sync_api(monkeypatch):
    calls = []
    sentinel = object()

    def fake_connect(url, **kwargs):
        calls.append((url, kwargs))
        return sentinel

    client_module = types.ModuleType("websockets.sync.client")
    client_module.connect = fake_connect
    sync_module = types.ModuleType("websockets.sync")
    sync_module.client = client_module
    websockets_module = types.ModuleType("websockets")
    websockets_module.sync = sync_module
    monkeypatch.setitem(sys.modules, "websockets", websockets_module)
    monkeypatch.setitem(sys.modules, "websockets.sync", sync_module)
    monkeypatch.setitem(sys.modules, "websockets.sync.client", client_module)

    result = connect_account_socket(
        "wss://dsw.prod.mapit.me/accounts/account",
        "id-token-secret",
        timeout=10.0,
        max_size=64 * 1024,
        max_queue=4,
    )

    assert result is sentinel
    assert calls == [
        (
            "wss://dsw.prod.mapit.me/accounts/account",
            {
                "subprotocols": ["id-token-secret"],
                "open_timeout": 10.0,
                "close_timeout": 1.0,
                "max_size": 64 * 1024,
                "max_queue": 4,
            },
        )
    ]


def test_invalid_binary_json_and_shape_are_ignored_without_fixture(tmp_path):
    socket = RecordingSocket(frames=[b"binary-secret", "not-json", json.dumps({"status": "secret"})])
    result, _, _ = _run(tmp_path, socket)

    assert result == {
        "success": True,
        "region": "eu-west-1",
        "connected": True,
        "valid_shape_observed": False,
        "schema_written": False,
    }
    assert not (tmp_path / "websocket-message.schema.json").exists()
    assert socket.recv_calls == 3


def test_timeout_after_connect_is_safe_success_without_fixture(tmp_path):
    socket = RecordingSocket(recv_error=TimeoutError("url secret"))
    result, _, _ = _run(tmp_path, socket)
    assert result["success"] is True
    assert result["connected"] is True
    assert result["valid_shape_observed"] is False
    assert result["schema_written"] is False
    assert result["status"] == "websocket_timeout"
    assert "secret" not in json.dumps(result)
    assert socket.enter_calls == 1
    assert socket.exit_calls == 1


def test_close_after_connect_is_safe_without_fixture(tmp_path):
    class ConnectionClosedError(RuntimeError):
        pass

    socket = RecordingSocket(recv_error=ConnectionClosedError("close reason secret"))
    result, _, _ = _run(tmp_path, socket)
    assert result["success"] is True
    assert result["status"] == "websocket_closed"
    assert socket.closed is True
    assert socket.enter_calls == 1
    assert socket.exit_calls == 1


def test_no_session_makes_zero_core_or_websocket_calls(tmp_path):
    class NoDataClient:
        def __init__(self, *_):
            raise AssertionError("client must not be created")

    result = probe.perform_websocket_probe(
        store=object(),
        manager_factory=lambda **kwargs: SavedManager(None),
        client_factory=NoDataClient,
        connector_factory=lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("socket must not open")),
    )
    assert result["error"] == "session_missing"
    assert not list(tmp_path.iterdir())


def test_missing_account_stops_before_websocket(tmp_path):
    socket = RecordingSocket()
    result, client, calls = _run(tmp_path, socket, summary={"account": {"id": ""}})
    assert result["error"] == "websocket_missing_account"
    assert client.calls == ["/v1/account-summary"]
    assert calls == []


@pytest.mark.parametrize(
    ("connector_error", "expected"),
    [
        (WebSocketDependencyError("module secret"), "websocket_dependency_missing"),
        (TimeoutError("handshake secret"), "websocket_timeout"),
    ],
)
def test_connector_failures_are_safe(tmp_path, connector_error, expected):
    result, _, _ = _run(tmp_path, RecordingSocket(), connector_error=connector_error)
    assert result["error"] == expected
    assert "secret" not in json.dumps(result)


def test_handshake_class_is_categorized_without_details(tmp_path):
    class InvalidStatusHandshakeError(RuntimeError):
        pass

    result, _, _ = _run(tmp_path, RecordingSocket(), connector_error=InvalidStatusHandshakeError("HTTP secret"))
    assert result["error"] == "websocket_handshake_failed"
    assert "secret" not in json.dumps(result)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (MapitHTTPError(403, "https://secret.invalid/account"), "account_summary_http_403"),
        (MapitTransportError("https://secret.invalid"), "account_summary_transport_failed"),
        (MapitResponseError("body secret"), "account_summary_invalid_response"),
    ],
)
def test_account_failures_are_safe(tmp_path, error, expected):
    result, _, _ = _run(tmp_path, RecordingSocket(), error=error)
    assert result["error"] == expected
    assert "secret.invalid" not in json.dumps(result)


def test_session_manager_error_is_safe(tmp_path):
    class FailingManager:
        def __init__(self, **kwargs):
            pass

        def login_saved(self):
            raise SessionManagerError("authentication_rejected")

    result = probe.perform_websocket_probe(store=object(), manager_factory=FailingManager)
    assert result["error"] == "authentication_rejected"
    assert not list(tmp_path.iterdir())


def test_persist_failure_is_safe(tmp_path, monkeypatch):
    socket = RecordingSocket(frames=[json.dumps({"id": "secret", "status": "ok"})])
    monkeypatch.setattr(probe, "atomic_write_schema", lambda schema, path: (_ for _ in ()).throw(OSError("secret")))
    result, _, _ = _run(tmp_path, socket)
    assert result["error"] == "websocket_schema_persist_failed"
    assert "secret" not in json.dumps(result)
    assert socket.enter_calls == 1
    assert socket.exit_calls == 1


def test_context_exit_runs_on_schema_failure(tmp_path, monkeypatch):
    socket = RecordingSocket(frames=[json.dumps({"id": "secret", "status": "ok"})])
    monkeypatch.setattr(probe, "schema_only", lambda value: (_ for _ in ()).throw(ValueError("secret")))
    result, _, _ = _run(tmp_path, socket)
    assert result["error"] == "websocket_schema_failed"
    assert socket.enter_calls == 1
    assert socket.exit_calls == 1
    assert socket.close_calls == 0


def test_connector_result_must_be_entered_as_context_manager(tmp_path):
    class BareSocket:
        def recv(self, *, timeout):
            raise TimeoutError

    result, _, _ = _run(tmp_path, BareSocket())
    assert result["success"] is False
    assert result["error"] == "websocket_transport_failed"


def test_strict_context_manager_path_has_no_deprecation_warning(tmp_path):
    class StrictSocket:
        def __init__(self):
            self.entered = False
            self.exited = False
            self.frames = [json.dumps({"id": "secret", "status": "ok"})]

        def __enter__(self):
            self.entered = True
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self.exited = True
            return False

        def recv(self, *, timeout):
            if self.frames:
                return self.frames.pop(0)
            raise TimeoutError("stop")

    socket = StrictSocket()
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        result, _, _ = _run(tmp_path, socket)

    assert result["success"] is True
    assert socket.entered is True
    assert socket.exited is True
