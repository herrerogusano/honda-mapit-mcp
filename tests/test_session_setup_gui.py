import ast
import json
from pathlib import Path

from mapit.session import SessionManagerError
from scripts.session_setup_gui import perform_session_setup


def test_setup_and_check_sources_have_no_core_geo_client_imports():
    for relative in ("scripts/session_setup_gui.py", "scripts/check_saved_session.py"):
        tree = ast.parse(Path(relative).read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        assert "mapit.client" not in imported


class FakeStore:
    def __init__(self):
        self.saved = []

    def save(self, token):
        self.saved.append(token)

    def load(self):
        return None

    def delete(self):
        return None


class FakeManager:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.login_calls = []
        self.last_error_category = None

    def login_manual(self, email, password):
        self.login_calls.append((email, password))
        return object()


def test_session_setup_saves_only_via_manager_and_returns_safe_result():
    store = FakeStore()
    managers = []

    def factory(**kwargs):
        manager = FakeManager(**kwargs)
        managers.append(manager)
        return manager

    result = perform_session_setup(
        "person@example.test",
        "password-secret",
        store=store,
        manager_factory=factory,
    )
    assert result == {"success": True, "saved": True}
    assert managers[0].login_calls == [("person@example.test", "password-secret")]
    assert "password-secret" not in json.dumps(result)


def test_session_setup_exposes_only_public_manager_category():
    class RejectingManager(FakeManager):
        def login_manual(self, email, password):
            self.last_error_category = "authentication_rejected"
            raise SessionManagerError("authentication_rejected")

    result = perform_session_setup(
        "person@example.test",
        "password-secret",
        store=FakeStore(),
        manager_factory=lambda **kwargs: RejectingManager(**kwargs),
    )
    assert result == {"success": False, "error": "authentication_rejected"}
    assert "password-secret" not in json.dumps(result)


def test_session_setup_sanitizes_non_string_manager_category():
    class LeakyManager(FakeManager):
        def login_manual(self, email, password):
            self.last_error_category = {"secret": "password-secret"}
            raise RuntimeError("secret exception")

    result = perform_session_setup(
        "person@example.test",
        "password-secret",
        store=FakeStore(),
        manager_factory=lambda **kwargs: LeakyManager(**kwargs),
    )
    assert result == {"success": False, "error": "authentication_failed"}
    assert "password-secret" not in json.dumps(result)


def test_session_setup_fails_closed_without_store(monkeypatch):
    monkeypatch.setattr("scripts.session_setup_gui._default_store", lambda: None)
    called = []

    def factory(**kwargs):
        called.append(kwargs)
        return FakeManager(**kwargs)

    result = perform_session_setup("person@example.test", "password-secret", manager_factory=factory)
    assert result == {"success": False, "error": "credential_store_failed"}
    assert called == []
