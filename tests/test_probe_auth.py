import json
from datetime import datetime, timedelta, timezone

from mapit.auth import MapitSession, TemporaryCredentials, UnsupportedCognitoChallenge
from mapit.config import MapitConfig
from scripts.probe_auth import error_category, safe_error_summary, safe_session_summary
import scripts.probe_auth as probe_auth


def test_safe_session_summary_contains_only_non_sensitive_facts():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    session = MapitSession(
        "id-token-secret", "access-token-secret", "refresh-token-secret",
        now + timedelta(hours=1),
        TemporaryCredentials("access-key-secret", "secret-key-secret", "session-secret", now + timedelta(hours=2)),
    )
    rendered = json.dumps(safe_session_summary(session, region="eu-west-1"))
    assert "id-token-secret" not in rendered
    assert "access-key-secret" not in rendered
    assert json.loads(rendered)["refresh_available"] is True
    assert json.loads(rendered)["temporary_credentials_available"] is True


def test_error_summary_categorizes_challenge_without_payload():
    exc = UnsupportedCognitoChallenge("NEW_PASSWORD_REQUIRED")
    assert error_category(exc, stage="authentication") == "unsupported_cognito_challenge"
    summary = safe_error_summary(region="eu-west-1", category="unsupported_cognito_challenge")
    assert summary == {"success": False, "region": "eu-west-1", "error": "unsupported_cognito_challenge"}
    assert "Session" not in json.dumps(summary)


def test_invalid_config_is_categorized_without_exception_payload(monkeypatch, capsys):
    def fail_from_env(cls):
        raise ValueError("password=secret-test")

    monkeypatch.setattr(MapitConfig, "from_env", classmethod(fail_from_env))
    assert probe_auth.main() == 1
    output = capsys.readouterr().out
    assert json.loads(output) == {
        "success": False,
        "region": "eu-west-1",
        "error": "configuration_or_credentials_missing",
    }
    assert "secret-test" not in output


def test_keyboard_interrupt_is_safe_and_has_no_traceback(monkeypatch, capsys):
    def interrupt_from_env(cls):
        raise KeyboardInterrupt

    monkeypatch.setattr(MapitConfig, "from_env", classmethod(interrupt_from_env))
    assert probe_auth.main() == 130
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {
        "success": False,
        "region": "eu-west-1",
        "error": "authentication_interrupted",
    }
    assert captured.err == ""
