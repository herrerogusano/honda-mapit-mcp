from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from mapit.auth import CognitoHTTPError, MapitSession, TemporaryCredentials, UnsupportedCognitoChallenge
from mapit.config import MapitConfig, RuntimeConfig
from mapit.session import (
    RefreshTokenStoreError,
    SessionManager,
    SessionManagerError,
    WindowsKeyringRefreshTokenStore,
)


def _session(refresh="refresh-token"):
    now = datetime.now(timezone.utc)
    return MapitSession(
        "id-token", "access-token", refresh,
        now + timedelta(hours=1),
        TemporaryCredentials("access-key", "secret-key", "session-token", now + timedelta(hours=2)),
    )


def _native_backend():
    return type("WinVaultKeyring", (), {"__module__": "keyring.backends.Windows"})()


class FakeKeyring:
    def __init__(self):
        self.values = {}
        self.errors = SimpleNamespace(PasswordDeleteError=type("PasswordDeleteError", (Exception,), {}))

    def set_password(self, service, account, value):
        self.values[(service, account)] = value

    def get_password(self, service, account):
        return self.values.get((service, account))

    def delete_password(self, service, account):
        key = (service, account)
        if key not in self.values:
            raise self.errors.PasswordDeleteError()
        del self.values[key]


def test_keyring_store_is_fail_closed_for_wrong_backend():
    fake = FakeKeyring()
    with pytest.raises(RefreshTokenStoreError):
        WindowsKeyringRefreshTokenStore(keyring_module=fake, backend=object())


def test_keyring_store_save_load_delete_is_idempotent_and_constant_scoped():
    fake = FakeKeyring()
    store = WindowsKeyringRefreshTokenStore(keyring_module=fake, backend=_native_backend())
    store.save("refresh-secret")
    assert store.load() == "refresh-secret"
    assert list(fake.values) == [("mapit-client", "refresh-token")]
    store.delete()
    store.delete()
    assert store.load() is None
    with pytest.raises(RefreshTokenStoreError):
        store.save("")


class MemoryStore:
    def __init__(self, value=None):
        self.value = value
        self.saved = []
        self.deleted = 0

    def save(self, value):
        self.saved.append(value)
        self.value = value

    def load(self):
        return self.value

    def delete(self):
        self.deleted += 1
        self.value = None


class FakeAuthenticator:
    sessions = []
    refresh_calls = []

    def __init__(self, config):
        self.config = config

    def authenticate(self):
        self.sessions.append(("manual", self.config.email, self.config.password))
        return _session("manual-refresh")

    def authenticate_with_refresh_token(self, token):
        self.refresh_calls.append(token)
        return _session("rotated-refresh")


def _manager(store):
    return SessionManager(
        base_config=MapitConfig(),
        store=store,
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
    )


def test_manual_login_saves_only_refresh_token():
    store = MemoryStore()
    context = _manager(store).login_manual("person@example.test", "password-secret")
    assert context.session.refresh_token == "manual-refresh"
    assert store.saved == ["manual-refresh"]


def test_manual_discovery_failure_exposes_only_public_category():
    def failing_discovery(url, timeout):
        raise RuntimeError("secret response body and https://private.example.invalid")

    manager = SessionManager(
        base_config=MapitConfig(),
        discover=failing_discovery,
        authenticator_factory=FakeAuthenticator,
    )
    with pytest.raises(SessionManagerError) as caught:
        manager.login_manual("person@example.test", "password-secret")
    assert caught.value.category == "discovery_failed"
    assert str(caught.value) == "discovery_failed"
    assert "private.example" not in str(caught.value)


def test_manual_authentication_rejection_exposes_only_public_category():
    class RejectingAuthenticator(FakeAuthenticator):
        def authenticate(self):
            raise CognitoHTTPError(400)

    manager = SessionManager(
        base_config=MapitConfig(),
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=RejectingAuthenticator,
    )
    with pytest.raises(SessionManagerError) as caught:
        manager.login_manual("person@example.test", "password-secret")
    assert caught.value.category == "authentication_rejected"
    assert str(caught.value) == "authentication_rejected"


def test_manual_keyring_failure_exposes_credential_store_category():
    class FailingSaveStore(MemoryStore):
        def save(self, value):
            raise OSError("Credential Manager size limit; refresh token not persisted")

    manager = _manager(FailingSaveStore())
    with pytest.raises(SessionManagerError) as caught:
        manager.login_manual("person@example.test", "password-secret")
    assert caught.value.category == "credential_store_failed"
    assert str(caught.value) == "credential_store_failed"


def test_saved_login_refreshes_and_persists_rotated_token():
    store = MemoryStore("old-refresh")
    context = _manager(store).login_saved()
    assert context is not None
    assert FakeAuthenticator.refresh_calls[-1] == "old-refresh"
    assert store.saved == ["rotated-refresh"]


def test_saved_login_does_not_delete_token_when_discovery_is_unavailable():
    store = MemoryStore("still-usable")

    def unavailable_discovery(url, timeout):
        raise OSError("frontend temporarily unavailable")

    manager = SessionManager(
        base_config=MapitConfig(),
        store=store,
        discover=unavailable_discovery,
        authenticator_factory=FakeAuthenticator,
    )
    assert manager.login_saved() is None
    assert store.deleted == 0 and store.value == "still-usable"
    assert manager.last_error_category == "discovery_failed"


def test_refresh_rotation_after_login_updates_saved_token():
    store = MemoryStore()
    current = _session("before-refresh")

    def refresh(session):
        session.refresh_token = "after-refresh"

    current._refresh_callback = refresh

    class Authenticator:
        def __init__(self, config):
            pass

        def authenticate(self):
            return current

    manager = SessionManager(
        base_config=MapitConfig(),
        store=store,
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=Authenticator,
    )
    context = manager.login_manual("person@example.test", "password-secret")
    context.session.refresh_if_needed(force=True)
    assert store.saved == ["before-refresh", "after-refresh"]


def test_rotated_saved_token_save_failure_does_not_delete_previous_value():
    class FailingSaveStore(MemoryStore):
        def save(self, value):
            raise OSError("keyring temporarily unavailable")

    store = FailingSaveStore("old-refresh")
    manager = _manager(store)
    assert manager.login_saved() is None
    assert store.deleted == 0 and store.value == "old-refresh"
    assert manager.last_error_category == "credential_store_failed"


def test_forget_saved_session_reports_delete_failure():
    class FailingDeleteStore(MemoryStore):
        def delete(self):
            raise OSError("keyring temporarily unavailable")

    manager = _manager(FailingDeleteStore("saved"))
    assert manager.forget_saved_session() is False


def test_rejected_saved_login_deletes_and_returns_fallback_state():
    store = MemoryStore("rejected-refresh")

    class RejectingAuthenticator(FakeAuthenticator):
        def authenticate_with_refresh_token(self, token):
            raise CognitoHTTPError(400)

    manager = SessionManager(
        base_config=MapitConfig(),
        store=store,
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=RejectingAuthenticator,
    )
    assert manager.login_saved() is None
    assert store.deleted == 1 and store.value is None


def test_saved_login_preserves_token_for_unsupported_challenge():
    store = MemoryStore("challenge-refresh")

    class ChallengeAuthenticator(FakeAuthenticator):
        def authenticate_with_refresh_token(self, token):
            raise UnsupportedCognitoChallenge("NEW_PASSWORD_REQUIRED")

    manager = SessionManager(
        base_config=MapitConfig(),
        store=store,
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=ChallengeAuthenticator,
    )
    assert manager.login_saved() is None
    assert store.deleted == 0 and store.value == "challenge-refresh"
    assert manager.last_error_category == "authentication_rejected"


def test_no_valid_saved_session_means_no_future_data_client_call():
    store = MemoryStore("bad-refresh")
    data_client_calls = []

    class RejectingAuthenticator(FakeAuthenticator):
        def authenticate_with_refresh_token(self, token):
            raise ValueError("rejected")

    manager = SessionManager(
        base_config=MapitConfig(),
        store=store,
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=RejectingAuthenticator,
    )
    context = manager.login_saved()
    if context is not None:
        data_client_calls.append(context)
    assert context is None
    assert data_client_calls == []
    assert store.deleted == 0 and store.value == "bad-refresh"
    assert manager.last_error_category == "authentication_failed"
