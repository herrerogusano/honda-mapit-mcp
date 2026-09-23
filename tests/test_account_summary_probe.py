import json
from datetime import datetime, timedelta, timezone

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitHTTPError
from mapit.config import RuntimeConfig
from scripts.account_summary_prompt_gui import perform_account_summary_probe


def _session():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return MapitSession(
        "id-token-secret", "access-token-secret", "refresh-token-secret",
        now + timedelta(hours=1),
        TemporaryCredentials("access-key-secret", "secret-key-secret", "session-secret", now + timedelta(hours=2)),
    )


def test_account_probe_gets_exactly_one_path_and_writes_schema_only(tmp_path):
    calls = []
    raw = {"account": {"name": "Alice Example", "email": "alice@example.test"}, "vehicles": [{"vin": "1HGCM82633A004352", "lat": 40.4}]}

    class FakeAuthenticator:
        def __init__(self, config):
            pass

        def authenticate(self):
            return _session()

    class FakeClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            calls.append(path)
            return raw

    output = tmp_path / "account-summary.schema.json"
    result = perform_account_summary_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FakeClient,
        save_path=output,
    )
    assert result["success"] is True
    assert calls == ["/v1/account-summary"]
    schema = json.loads(output.read_text(encoding="utf-8"))
    rendered = json.dumps(schema)
    assert "Alice Example" not in rendered
    assert "alice@example.test" not in rendered
    assert "1HGCM82633A004352" not in rendered
    assert "40.4" not in rendered
    assert result["top_level_keys"] == ["account", "vehicles"]


def test_account_probe_categorizes_request_failure_without_creating_file(tmp_path):
    class FakeAuthenticator:
        def __init__(self, config):
            pass

        def authenticate(self):
            return _session()

    class FailingClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            raise MapitHTTPError(403, "https://core.prod.mapit.me/v1/account-summary")

    output = tmp_path / "account-summary.schema.json"
    result = perform_account_summary_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FailingClient,
        save_path=output,
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "account_summary_request_failed"}
    assert not output.exists()

