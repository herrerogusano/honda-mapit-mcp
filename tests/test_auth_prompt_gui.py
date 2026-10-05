import json
from datetime import datetime, timedelta, timezone

from mapit.auth import MapitSession, TemporaryCredentials, UnsupportedCognitoChallenge
from mapit.config import RuntimeConfig
from scripts.auth_prompt_gui import perform_auth_probe


def _session():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return MapitSession(
        "id-token-secret", "access-token-secret", "refresh-token-secret",
        now + timedelta(hours=1),
        TemporaryCredentials("access-key-secret", "secret-key-secret", "session-secret", now + timedelta(hours=2)),
    )


def test_gui_probe_logic_is_injectable_and_redacted():
    seen = {}

    def discover(url, timeout):
        seen["url"] = url
        return RuntimeConfig(region="eu-west-1")

    class FakeAuthenticator:
        def __init__(self, config):
            seen["email"] = config.email
            seen["password"] = config.password

        def authenticate(self):
            return _session()

    result = perform_auth_probe("person@example.test", "secret-test", discover=discover, authenticator_factory=FakeAuthenticator)
    assert result["success"] is True
    assert "secret-test" not in json.dumps(result)
    assert seen["email"] == "person@example.test"
    assert seen["password"] == "secret-test"


def test_gui_probe_logic_categorizes_challenge_without_payload():
    class FakeAuthenticator:
        def __init__(self, config):
            pass

        def authenticate(self):
            raise UnsupportedCognitoChallenge("NEW_PASSWORD_REQUIRED")

    result = perform_auth_probe(
        "person@example.test",
        "secret-test",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "unsupported_cognito_challenge"}
    assert "NEW_PASSWORD_REQUIRED" not in json.dumps(result)


def test_gui_probe_logic_handles_keyboard_interrupt_without_traceback():
    def interrupt(url, timeout):
        raise KeyboardInterrupt

    result = perform_auth_probe("person@example.test", "secret-test", discover=interrupt)
    assert result == {"success": False, "region": "eu-west-1", "error": "authentication_interrupted"}
