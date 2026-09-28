import json
from datetime import datetime, timedelta, timezone

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.config import MapitConfig, RuntimeConfig
from mapit.session import SessionManagerError
from scripts.routes_list_prompt_gui import _safe_session_category, perform_routes_list_probe, perform_routes_list_with_session


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


def test_routes_probe_uses_one_bounded_geo_get_and_persists_schema_only(tmp_path):
    calls = []
    raw_routes = {
        "data": [{"id": "route-secret", "lat": 40.4, "timestamp": "2026-09-23T14:00:00Z"}],
        "lastEvaluatedKey": "cursor-secret",
    }

    class FakeClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            calls.append(("core", path, None))
            return {"vehicles": [{"id": "vehicle/one", "device": {}}]}

        def get_geo(self, path, *, params):
            calls.append(("geo", path, params))
            return raw_routes

    output = tmp_path / "routes-list.schema.json"
    result = perform_routes_list_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FakeClient,
        save_path=output,
    )
    assert result["success"] is True
    assert calls == [
        ("core", "/v1/account-summary", None),
        ("geo", "/v1/routes", {"vehicleId": "vehicle/one", "limit": 1}),
    ]
    rendered = output.read_text(encoding="utf-8")
    for secret in ("vehicle/one", "route-secret", "40.4", "2026-09-23T14:00:00Z", "cursor-secret"):
        assert secret not in rendered
    assert result["top_level_keys"] == ["data", "lastEvaluatedKey"]


def test_routes_probe_prefers_non_null_device_then_falls_back_to_first_id(tmp_path):
    calls = []

    class FakeClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            return {"vehicles": [{"id": "first-id", "device": None}, {"id": "preferred/id", "device": {}}]}

        def get_geo(self, path, *, params):
            calls.append(params)
            return {"data": []}

    result = perform_routes_list_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FakeClient,
        save_path=tmp_path / "routes.schema.json",
    )
    assert result["success"] is True
    assert calls == [{"vehicleId": "preferred/id", "limit": 1}]


def test_routes_probe_skips_geo_when_no_id_candidate(tmp_path):
    calls = []

    class FakeClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            calls.append(path)
            return {"vehicles": [{"id": "", "device": {}}, {"id": 7, "device": {}}]}

        def get_geo(self, path, *, params):
            raise AssertionError("Geo routes must not be called")

    output = tmp_path / "routes.schema.json"
    result = perform_routes_list_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FakeClient,
        save_path=output,
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "routes_list_missing_vehicle"}
    assert calls == ["/v1/account-summary"]
    assert not output.exists()


def test_routes_probe_failure_is_categorized_without_payload_or_id(tmp_path):
    class FailingClient:
        def __init__(self, config, session):
            pass

        def get_core(self, path):
            return {"vehicles": [{"id": "vehicle-secret", "device": {}}]}

        def get_geo(self, path, *, params):
            raise RuntimeError("body contains vehicle-secret and route-secret")

    result = perform_routes_list_probe(
        "person@example.test",
        "password-secret",
        discover=lambda url, timeout: RuntimeConfig(region="eu-west-1"),
        authenticator_factory=FakeAuthenticator,
        client_factory=FailingClient,
        save_path=tmp_path / "routes.schema.json",
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "routes_list_request_failed"}
    assert "vehicle-secret" not in json.dumps(result)


def test_routes_probe_never_calls_data_client_without_a_session(tmp_path):
    class ExplodingClient:
        def __init__(self, config, session):
            raise AssertionError("data client must not be created without a session")

    result = perform_routes_list_with_session(
        MapitConfig(),
        None,  # type: ignore[arg-type]
        client_factory=ExplodingClient,
        save_path=tmp_path / "routes.schema.json",
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "authentication_failed"}


def test_routes_probe_surfaces_refresh_store_failure_before_data_call(tmp_path):
    session = _session()
    data_calls = []

    def failed_refresh(current):
        raise SessionManagerError("credential_store_failed")

    session._refresh_callback = failed_refresh

    class Client:
        def __init__(self, config, current):
            self.session = current

        def get_core(self, path):
            self.session.refresh_if_needed(force=True)
            data_calls.append(("core", path))
            return {"vehicles": []}

        def get_geo(self, path, *, params):
            data_calls.append(("geo", path, params))
            raise AssertionError("Geo must not be reached after store failure")

    result = perform_routes_list_with_session(
        MapitConfig(),
        session,
        client_factory=Client,
        save_path=tmp_path / "routes.schema.json",
    )
    assert result == {"success": False, "region": "eu-west-1", "error": "credential_store_failed"}
    assert data_calls == []


def test_routes_saved_session_category_is_allowlisted():
    assert _safe_session_category("credential_store_failed") == "credential_store_failed"
    assert _safe_session_category({"secret": "refresh-token"}) == "authentication_failed"
