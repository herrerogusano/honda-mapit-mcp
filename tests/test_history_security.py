from __future__ import annotations

import os
import sqlite3
import stat
import urllib.error
import urllib.request
from pathlib import Path
from types import SimpleNamespace

import pytest

from mapit import history_cli, history_runtime
from mapit.config import MapitConfig
from mapit.history_runtime import HistoryRuntimeError, WindowsHistorySecrets


APP_ID = 0x4D504C47
SCHEMA_VERSION = 1


class FakeKeyring:
    def __init__(self, values=None):
        self.values = dict(values or {})

    def get_password(self, service, account):
        return self.values.get((service, account))

    def set_password(self, service, account, value):
        self.values[(service, account)] = value

    def delete_password(self, service, account):
        self.values.pop((service, account), None)


class NativeStore:
    def __init__(self, keyring):
        self._keyring = keyring

    def _assert_native_backend(self):
        return None


class EmptyResponse:
    def __init__(self, raw: bytes):
        self.raw = raw
        self.amounts: list[int] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, amount=-1):
        self.amounts.append(amount)
        return self.raw[:amount]


def _owned_db(path: Path) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.execute(f"PRAGMA application_id = {APP_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    finally:
        connection.close()


def _skip_if_no_symlink(source: Path, target: Path) -> None:
    try:
        source.symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink unavailable in this environment: {type(exc).__name__}")


def test_acl_restriction_uses_current_user_and_verifies_allowlist(tmp_path, monkeypatch):
    monkeypatch.setattr(history_runtime.sys, "platform", "win32")
    monkeypatch.setattr(history_runtime.subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[0] == "powershell.exe" and len(calls) == 1:
            return SimpleNamespace(returncode=0, stdout="S-1-5-21-123\r\n")
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(history_runtime.subprocess, "run", fake_run)
    target = tmp_path / "private-ledger"

    history_runtime.restrict_directory_access(target)

    assert target.is_dir()
    assert [call[0][0] for call in calls] == ["powershell.exe", "icacls.exe", "powershell.exe"]
    assert "*S-1-5-21-123:(OI)(CI)F" in calls[1][0]
    assert "*S-1-5-18:(OI)(CI)F" in calls[1][0]
    assert "*S-1-5-32-544:(OI)(CI)F" in calls[1][0]
    assert "notin $allowed" in calls[2][0][-1]
    assert all(call[1]["timeout"] == 10 for call in calls)


def test_acl_verification_failure_is_closed_and_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(history_runtime.sys, "platform", "win32")
    monkeypatch.setattr(history_runtime.subprocess, "CREATE_NO_WINDOW", 0, raising=False)
    calls = 0

    def fake_run(argv, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return SimpleNamespace(returncode=0, stdout="S-1-5-21-123")
        return SimpleNamespace(returncode=1, stdout="private ACL detail")

    monkeypatch.setattr(history_runtime.subprocess, "run", fake_run)
    with pytest.raises(HistoryRuntimeError) as caught:
        history_runtime.restrict_directory_access(tmp_path / "private")
    assert caught.value.category == "history_permissions_failed"
    assert "private ACL detail" not in str(caught.value)


def test_regular_path_rejects_symlinks_for_database_sidecar_and_lock(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("owned sentinel", encoding="utf-8")
    for name in ("distance-history.sqlite3", "distance-history.sqlite3-wal", "history-operation.lock"):
        link = tmp_path / name
        _skip_if_no_symlink(link, outside)
        with pytest.raises(HistoryRuntimeError) as caught:
            history_runtime._regular_path(link)
        assert caught.value.category == "history_path_invalid"
        assert link.is_symlink()
        assert outside.read_text(encoding="utf-8") == "owned sentinel"
        link.unlink()


def test_regular_path_rejects_windows_reparse_point_metadata(tmp_path, monkeypatch):
    target = tmp_path / "junction-like-directory"
    target.mkdir()
    real_lstat = Path.lstat

    def fake_lstat(path):
        if path == target:
            original = real_lstat(path)
            return SimpleNamespace(st_mode=stat.S_IFDIR | stat.S_IMODE(original.st_mode), st_file_attributes=0x400)
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", fake_lstat)
    with pytest.raises(HistoryRuntimeError) as caught:
        history_runtime._regular_path(target, directory=True)
    assert caught.value.category == "history_path_invalid"


def test_operation_lock_does_not_follow_or_remove_an_existing_lock_symlink(tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("leave me", encoding="utf-8")
    lock = tmp_path / "history-operation.lock"
    _skip_if_no_symlink(lock, outside)

    with pytest.raises(HistoryRuntimeError) as caught:
        with history_runtime._operation_lock(tmp_path):
            pytest.fail("an existing lock symlink must not be followed")

    assert caught.value.category == "history_busy"
    assert lock.is_symlink()
    assert outside.read_text(encoding="utf-8") == "leave me"


def test_bounded_mapit_transport_is_proxy_free_no_redirect_get_only_and_four_attempts(monkeypatch):
    built = []
    opened = []

    class Opener:
        def open(self, request, timeout):
            opened.append((request, timeout))
            return EmptyResponse(b"{}")

    opener = Opener()

    def build_opener(*handlers):
        built.extend(handlers)
        return opener

    monkeypatch.setattr(history_runtime.urllib.request, "build_opener", build_opener)
    client = history_runtime._bounded_client(MapitConfig(), object())
    transport = client.transport

    with pytest.raises(HistoryRuntimeError) as caught:
        transport("POST", "https://geo.prod.mapit.me/v1/routes", {})
    assert caught.value.category == "read_budget_exceeded"
    assert not opened
    assert any(isinstance(handler, urllib.request.ProxyHandler) and handler.proxies == {} for handler in built)
    redirects = [handler for handler in built if isinstance(handler, history_runtime._NoRedirect)]
    assert len(redirects) == 1
    assert redirects[0].redirect_request(None, None, 302, "Found", {}, "https://outside.invalid") is None

    for _ in range(4):
        assert transport("GET", "https://geo.prod.mapit.me/v1/routes", {}) == b"{}"
    with pytest.raises(HistoryRuntimeError) as caught:
        transport("GET", "https://geo.prod.mapit.me/v1/routes", {})
    assert caught.value.category == "read_budget_exceeded"
    assert len(opened) == 4
    assert all(timeout <= 20 for _, timeout in opened)


def test_bounded_mapit_transport_caps_response_at_two_mib_and_consumes_attempt(monkeypatch):
    raw = b"x" * (history_runtime.MAX_RESPONSE_BYTES + 1)
    responses = []

    class Opener:
        def open(self, _request, timeout):
            assert timeout <= 20
            response = EmptyResponse(raw)
            responses.append(response)
            return response

    monkeypatch.setattr(history_runtime.urllib.request, "build_opener", lambda *_handlers: Opener())
    client = history_runtime._bounded_client(MapitConfig(), object())
    from mapit.client import MapitResponseTooLarge

    with pytest.raises(MapitResponseTooLarge):
        client.transport("GET", "https://geo.prod.mapit.me/v1/routes", {})
    assert responses[0].amounts == [history_runtime.MAX_RESPONSE_BYTES + 1]


def test_missing_hmac_key_does_not_rekey_existing_database_or_touch_mapit_secret():
    values = {("honda-mapit-refresh", "mapit-refresh-v1"): "refresh-secret"}
    keyring = FakeKeyring(values)
    secrets = WindowsHistorySecrets(native_store=NativeStore(keyring))

    with pytest.raises(HistoryRuntimeError) as caught:
        secrets.load_key(database_exists=True, create=True)

    assert caught.value.category == "history_key_missing"
    assert (history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT) not in keyring.values
    assert keyring.values[("honda-mapit-refresh", "mapit-refresh-v1")] == "refresh-secret"


def test_generated_hmac_key_is_stable_and_delete_only_removes_history_credentials():
    keyring = FakeKeyring({
        ("honda-mapit-refresh", "mapit-refresh-v1"): "refresh-secret",
        (history_runtime.KEY_SERVICE, history_runtime.SCOPE_ACCOUNT): "a" * 64,
    })
    secrets = WindowsHistorySecrets(native_store=NativeStore(keyring))
    key = secrets.load_key(database_exists=False, create=True)

    assert len(key) == 32
    assert secrets.load_key(database_exists=True) == key
    secrets.delete()
    assert ("honda-mapit-refresh", "mapit-refresh-v1") in keyring.values
    assert (history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT) not in keyring.values
    assert (history_runtime.KEY_SERVICE, history_runtime.SCOPE_ACCOUNT) not in keyring.values


def test_forget_requires_cli_confirmation_without_calling_deletion(monkeypatch, capsys):
    def forbidden():
        pytest.fail("forget_history must not run without explicit confirmation")

    monkeypatch.setattr(history_cli, "forget_history", forbidden)
    assert history_cli.main(["forget"]) == 1
    output = capsys.readouterr().out
    assert "confirmation_required" in output
    assert "forget_history" not in output


def test_forget_removes_only_owned_db_sidecars_and_history_keys(tmp_path, monkeypatch):
    db = tmp_path / "distance-history.sqlite3"
    _owned_db(db)
    sidecars = [Path(str(db) + suffix) for suffix in ("-journal", "-wal", "-shm")]
    for path in sidecars:
        path.write_bytes(b"synthetic owned sidecar")
    unrelated = tmp_path / "user-notes.txt"
    unrelated.write_text("keep this", encoding="utf-8")
    keyring = FakeKeyring({
        ("honda-mapit-refresh", "mapit-refresh-v1"): "refresh-secret",
        (history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT): "f" * 64,
        (history_runtime.KEY_SERVICE, history_runtime.SCOPE_ACCOUNT): "a" * 64,
    })

    real_connect = sqlite3.connect

    class ReadOnlySchema:
        def execute(self, statement):
            if "application_id" in statement:
                return SimpleNamespace(fetchone=lambda: (APP_ID,))
            if "user_version" in statement:
                return SimpleNamespace(fetchone=lambda: (SCHEMA_VERSION,))
            raise AssertionError("forget should inspect only owned schema markers")

        def close(self):
            return None

    def safe_connect(*args, **kwargs):
        if kwargs.get("uri") and "mode=ro" in args[0]:
            return ReadOnlySchema()
        return real_connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", safe_connect)
    history_runtime.forget_history(directory=tmp_path, secret_store=WindowsHistorySecrets(native_store=NativeStore(keyring)))

    assert not db.exists()
    assert all(not path.exists() for path in sidecars)
    assert unrelated.read_text(encoding="utf-8") == "keep this"
    assert ("honda-mapit-refresh", "mapit-refresh-v1") in keyring.values
    assert not (tmp_path / "history-operation.lock").exists()


def test_forget_preserves_unknown_database_and_history_credentials(tmp_path):
    db = tmp_path / "distance-history.sqlite3"
    with sqlite3.connect(db) as connection:
        connection.execute("CREATE TABLE unrelated(value TEXT)")
    before = db.read_bytes()
    keyring = FakeKeyring({
        (history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT): "f" * 64,
        (history_runtime.KEY_SERVICE, history_runtime.SCOPE_ACCOUNT): "a" * 64,
    })

    with pytest.raises(HistoryRuntimeError) as caught:
        history_runtime.forget_history(directory=tmp_path, secret_store=WindowsHistorySecrets(native_store=NativeStore(keyring)))

    assert caught.value.category == "schema_unsupported"
    assert db.read_bytes() == before
    assert keyring.values[(history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT)] == "f" * 64
    assert keyring.values[(history_runtime.KEY_SERVICE, history_runtime.SCOPE_ACCOUNT)] == "a" * 64
    assert not (tmp_path / "history-operation.lock").exists()


def test_forget_rejects_database_symlink_before_deleting_sidecars_or_outside_target(tmp_path):
    db = tmp_path / "distance-history.sqlite3"
    outside = tmp_path / "outside.sqlite"
    _owned_db(outside)
    _skip_if_no_symlink(db, outside)
    sidecar = Path(str(db) + "-wal")
    sidecar.write_bytes(b"preserve sidecar")
    keyring = FakeKeyring({(history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT): "f" * 64})

    with pytest.raises(HistoryRuntimeError) as caught:
        history_runtime.forget_history(directory=tmp_path, secret_store=WindowsHistorySecrets(native_store=NativeStore(keyring)))

    assert caught.value.category == "history_path_invalid"
    assert db.is_symlink()
    assert outside.exists()
    assert sidecar.read_bytes() == b"preserve sidecar"
    assert (history_runtime.KEY_SERVICE, history_runtime.KEY_ACCOUNT) in keyring.values
