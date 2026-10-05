import json

from scripts.check_saved_session import perform_saved_session_check


class FakeStore:
    def load(self):
        return "refresh-secret"

    def save(self, token):
        raise AssertionError("check must not save a token directly")

    def delete(self):
        raise AssertionError("check must not delete a token")


class FakeManager:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.last_error_category = None
        self.saved_login_calls = 0

    def login_saved(self):
        self.saved_login_calls += 1
        return object()


def test_saved_session_check_only_reports_boolean_and_does_no_data_call():
    managers = []

    def factory(**kwargs):
        manager = FakeManager(**kwargs)
        managers.append(manager)
        return manager

    result = perform_saved_session_check(store=FakeStore(), manager_factory=factory)
    assert result == {"success": True, "session_valid": True}
    assert managers[0].saved_login_calls == 1
    assert "refresh-secret" not in json.dumps(result)
    assert not hasattr(managers[0], "get_core")


def test_saved_session_check_returns_safe_category_when_session_is_missing():
    class MissingManager(FakeManager):
        def login_saved(self):
            self.last_error_category = "authentication_rejected"
            return None

    result = perform_saved_session_check(
        store=FakeStore(),
        manager_factory=lambda **kwargs: MissingManager(**kwargs),
    )
    assert result == {"success": False, "session_valid": False, "error": "authentication_rejected"}


def test_saved_session_check_sanitizes_non_string_manager_category():
    class LeakyManager(FakeManager):
        def login_saved(self):
            self.last_error_category = {"secret": "refresh-secret"}
            raise RuntimeError("secret exception")

    result = perform_saved_session_check(
        store=FakeStore(),
        manager_factory=lambda **kwargs: LeakyManager(**kwargs),
    )
    assert result == {"success": False, "session_valid": False, "error": "authentication_failed"}
    assert "refresh-secret" not in json.dumps(result)


def test_saved_session_check_fails_closed_without_store(monkeypatch):
    monkeypatch.setattr("scripts.check_saved_session._default_store", lambda: None)
    result = perform_saved_session_check()
    assert result == {"success": False, "session_valid": False, "error": "credential_store_failed"}
