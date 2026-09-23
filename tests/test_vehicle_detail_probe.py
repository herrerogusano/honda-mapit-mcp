import json
from datetime import datetime, timedelta, timezone

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.config import RuntimeConfig
from scripts.vehicle_detail_prompt_gui import perform_vehicle_detail_probe


def _session():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return MapitSession(
        "id-token-secret", "access-token-secret", "refresh-token-secret",
        now + timedelta(hours=1),
        TemporaryCredentials("access-key-secret", "secret-key-secret", "session-secret", now + timedelta(hours=2)),
    )


class FakeAuthenticator:
    def __init__(self, config):
        pass

    def authenticate(self):
        return _session()


def test_detail_probe_selects_first_valid_vehicle_encodes_one_segment_and_saves_no_values(tmp_path):
    calls = []
    raw_summary = {
        "vehicles": [
            {"id": "", "device": {"id": "ignored"}},
            {"id": "vehicle/one with space?", "device": {"id": "device-secret"}},
            {"id": "vehicle-two", "device": {"id": "not-selected"}},
        ]
    }
    raw_detail = {"id": "vehicle/one with space?", "name": "Alice's car", "lat": 40.4, "vin": "1HGCM82633A004352"}

    class FakeClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            calls.append(path)
            return raw_summary if path == "/v1/account-summary" else raw_detail

    output = tmp_path / "vehicle-detail.schema.json"
    result = perform_vehicle_detail_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FakeClient,
        save_path=output,
    )
    assert result["success"] is True
    assert calls == ["/v1/account-summary", "/v1/vehicles/vehicle%2Fone%20with%20space%3F"]
    rendered = output.read_text(encoding="utf-8")
    assert "vehicle/one with space?" not in rendered
    assert "Alice's car" not in rendered
    assert "40.4" not in rendered
    assert "1HGCM82633A004352" not in rendered
    assert result["top_level_keys"] == ["id", "lat", "name", "vin"]


def test_no_valid_vehicle_makes_no_detail_call_or_file(tmp_path):
    calls = []

    class FakeClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            calls.append(path)
            return {"vehicles": [{"id": "", "device": {}}, {"id": "vehicle-two", "device": None}]}

    output = tmp_path / "vehicle-detail.schema.json"
    result = perform_vehicle_detail_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FakeClient,
        save_path=output,
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "vehicle_detail_missing_vehicle"}
    assert calls == ["/v1/account-summary"]
    assert not output.exists()


def test_detail_failure_is_safe_and_does_not_persist_vehicle_id(tmp_path):
    calls = []

    class FailingClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            calls.append(path)
            if path == "/v1/account-summary":
                return {"vehicles": [{"id": "vehicle-secret", "device": {}}]}
            raise RuntimeError("vehicle-secret must never be shown")

    output = tmp_path / "vehicle-detail.schema.json"
    result = perform_vehicle_detail_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FailingClient,
        save_path=output,
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "vehicle_detail_request_failed"}
    assert calls == ["/v1/account-summary", "/v1/vehicles/vehicle-secret"]
    assert not output.exists()
    assert "vehicle-secret" not in json.dumps(result)

