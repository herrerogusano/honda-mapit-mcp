from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from mapit.auth import MapitSession, TemporaryCredentials
from mapit.client import MapitClient
from mapit.config import MapitConfig
from mapit.ledger import DistanceLedger
from mapit.session import ManagedSession, RefreshTokenStoreError, SessionManager
from mapit import history_runtime as runtime


NOW = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
ACCOUNT_ID = "account-private-id"
VEHICLE_ID = "vehicle-private-id"
ROUTE_ID = "route-private-id"
KEY = bytes(range(32))


def _session_context() -> ManagedSession:
    now = datetime.now(timezone.utc)
    session = MapitSession(
        "id-token-private",
        "access-token-private",
        "refresh-token-private",
        now,
        TemporaryCredentials("access-key-private", "secret-key-private", "session-token-private", now),
    )
    return ManagedSession(MapitConfig(), session)


def _route(
    route_id: str = ROUTE_ID,
    *,
    started_at: str = "2026-01-08T04:00:00Z",
    ended_at: str | None = None,
    distance: float = 8.0,
    **extra,
):
    if ended_at is None:
        try:
            parsed = datetime.fromisoformat(started_at[:-1] + "+00:00" if started_at.endswith("Z") else started_at)
            ended_at = (parsed + timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
        except (AttributeError, OverflowError, ValueError):
            ended_at = "2026-01-08T04:30:00Z"
    return {"id": route_id, "startedAt": started_at, "endedAt": ended_at, "distance": distance, **extra}


class SavedManager:
    def __init__(self, context: ManagedSession | None, **_kwargs) -> None:
        self.context = context

    def login_saved(self):
        return self.context


class FakeClient:
    def __init__(self, routes, *, pagination=None, malformed=None) -> None:
        self.routes = routes
        self.pagination = pagination
        self.malformed = malformed
        self.calls: list[tuple[str, str, dict, int]] = []

    def get_core(self, path, *, max_response_bytes):
        self.calls.append(("core", path, {}, max_response_bytes))
        return {
            "account": {"id": ACCOUNT_ID},
            "vehicles": [{"id": VEHICLE_ID, "device": {"state": {}}}],
        }

    def get_geo(self, path, *, params, max_response_bytes):
        self.calls.append(("geo", path, dict(params), max_response_bytes))
        payload = {"data": self.routes}
        if self.pagination is not None:
            payload["lastEvaluatedKey"] = self.pagination
        if self.malformed is not None:
            return self.malformed
        return payload


class FakeSecrets:
    def __init__(self, *, key: bytes | None = KEY, active: str | None = None) -> None:
        self.key = key
        self.active = active
        self.load_key_calls: list[tuple[bool, bool]] = []
        self.set_scope_calls: list[str] = []
        self.delete_calls = 0

    def load_key(self, *, database_exists: bool, create: bool = False) -> bytes:
        self.load_key_calls.append((database_exists, create))
        if self.key is None:
            raise runtime.HistoryRuntimeError("history_key_missing")
        return self.key

    def set_active_scope(self, value: str) -> None:
        self.set_scope_calls.append(value)
        self.active = value

    def active_scope(self) -> str:
        if self.active is None:
            raise runtime.HistoryRuntimeError("history_scope_missing")
        return self.active

    def delete(self) -> None:
        self.delete_calls += 1
        self.active = None
        self.key = None


def _run_import(root: Path, routes, *, client=None, secrets_store=None, now=NOW, pagination=None, malformed=None):
    context = _session_context()
    client = client or FakeClient(routes, pagination=pagination, malformed=malformed)
    secrets_store = secrets_store or FakeSecrets()
    secure_calls: list[Path] = []

    def secure_directory(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        secure_calls.append(path)

    result = runtime.import_current_month(
        directory=root,
        secret_store=secrets_store,
        manager_factory=lambda **kwargs: SavedManager(context, **kwargs),
        client_factory=lambda _config, _session: client,
        now=now,
        secure_directory=secure_directory,
        refresh_store_factory=lambda: object(),
    )
    return result, client, secrets_store, secure_calls


def test_import_uses_one_synthetic_core_and_geo_get_and_writes_only_redacted_result(tmp_path):
    root = tmp_path / "history"
    result, client, secrets_store, secure_calls = _run_import(root, [_route(complete=False)])

    assert result == {
        "success": True,
        "category": "success",
        "imported_band": "few",
        "duplicate_band": "none",
        "coverage": "PARTIAL",
        "metric_unit": "mapit_native_unconfirmed",
        "private_values_printed": False,
        "facts_committed": True,
    }
    assert [call[0] for call in client.calls] == ["core", "geo"]
    assert client.calls[0][1] == "/v1/account-summary"
    assert client.calls[1][1] == "/v1/routes"
    assert client.calls[1][2] == {
        "vehicleId": VEHICLE_ID,
        "from": "2026-01-01T00:00:00.000Z",
        "to": "2026-02-01T00:00:00.000Z",
    }
    assert all(call[3] == runtime.MAX_RESPONSE_BYTES for call in client.calls)
    assert secure_calls == [root]
    assert len(secrets_store.load_key_calls) == 1
    assert secrets_store.load_key_calls[0] == (False, True)
    assert len(secrets_store.set_scope_calls) == 1
    assert (root / "distance-history.sqlite3").is_file()
    serialized = json.dumps(result)
    for private_value in (ACCOUNT_ID, VEHICLE_ID, ROUTE_ID, "id-token-private", "refresh-token-private"):
        assert private_value not in serialized


@pytest.mark.parametrize(
    ("routes", "pagination", "malformed", "now", "expected"),
    [
        ([_route("missing-id") | {"id": ""}], None, None, NOW, "route_invalid"),
        ([_route("outside-before", started_at="2025-12-31T23:59:59Z")], None, None, NOW, "routes_outside_window"),
        ([_route("outside-after", started_at="2026-02-01T00:00:00Z")], None, None, NOW, "route_invalid"),
        ([_route("missing-end") | {"endedAt": None}], None, None, NOW, "route_invalid"),
        (
            [_route("valid-first"), _route("future-second", started_at="2026-01-16T00:00:00Z")],
            None,
            None,
            NOW,
            "route_invalid",
        ),
        ([_route()], "opaque-cursor", None, NOW, "pagination_unsupported"),
        ([], None, {"unexpected": []}, NOW, "routes_list_invalid"),
        ([_route()], None, None, datetime(2026, 1, 15), "time_invalid"),
    ],
)
def test_invalid_import_stops_before_directory_key_or_database_creation(tmp_path, routes, pagination, malformed, now, expected):
    root = tmp_path / "not-created"
    result, client, secrets_store, secure_calls = _run_import(
        root,
        routes,
        pagination=pagination,
        malformed=malformed,
        now=now,
    )

    assert result["success"] is False
    assert result["category"] == expected
    assert not root.exists()
    assert secrets_store.load_key_calls == []
    assert secrets_store.set_scope_calls == []
    assert secure_calls == []
    expected_stages = ["core"] if expected == "time_invalid" else ["core", "geo"]
    assert [call[0] for call in client.calls] == expected_stages
    assert ACCOUNT_ID not in json.dumps(result)
    assert VEHICLE_ID not in json.dumps(result)


def test_injected_validation_instant_is_shared_by_preflight_and_import(tmp_path, monkeypatch):
    seen = []
    validate = DistanceLedger.validate_routes
    import_routes = DistanceLedger.import_routes

    def wrapped_validate(routes, *, now=None):
        seen.append(("validate", now))
        return validate(routes, now=now)

    def wrapped_import(self, account_scope, vehicle_id, routes, *, now=None):
        seen.append(("import", now))
        return import_routes(self, account_scope, vehicle_id, routes, now=now)

    monkeypatch.setattr(DistanceLedger, "validate_routes", staticmethod(wrapped_validate))
    monkeypatch.setattr(DistanceLedger, "import_routes", wrapped_import)
    result, _, _, _ = _run_import(tmp_path / "history", [_route()], now=NOW)
    assert result["success"] is True
    assert seen == [("validate", NOW), ("import", NOW)]


def test_repeat_import_is_idempotent_and_local_query_makes_no_upstream_calls(tmp_path, monkeypatch):
    root = tmp_path / "history"
    routes = [_route("r1", distance=4), _route("r2", distance=6)]
    secrets_store = FakeSecrets()
    result1, client1, secrets_store, _ = _run_import(root, routes, secrets_store=secrets_store)
    result2, client2, secrets_store, _ = _run_import(root, routes, secrets_store=secrets_store)
    assert result1["imported_band"] == "few"
    assert result1["duplicate_band"] == "none"
    assert result2["imported_band"] == "none"
    assert result2["duplicate_band"] == "few"
    assert secrets_store.load_key_calls == [(False, True), (True, True)]

    calls_before = len(client1.calls) + len(client2.calls)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("local history query must not load a session or make an HTTP request")

    monkeypatch.setattr(MapitClient, "get", forbidden)
    monkeypatch.setattr(SessionManager, "login_saved", forbidden)
    breakdown = runtime.local_breakdown(
        "month", directory=root, secret_store=secrets_store, secure_directory=lambda _path: None
    )
    calls_after = len(client1.calls) + len(client2.calls)
    assert calls_after == calls_before
    assert breakdown.group_by == "month"
    assert [(bucket.bucket, bucket.distance, bucket.observed_route_count) for bucket in breakdown.buckets] == [("2026-01", 10, 2)]


def test_existing_database_with_missing_key_fails_closed_without_rekey_or_mutation(tmp_path):
    root = tmp_path / "history"
    root.mkdir()
    db = root / "distance-history.sqlite3"
    original = DistanceLedger(db, KEY)
    original.import_routes("scope", "vehicle", [_route()])
    before = db.read_bytes()
    secrets_store = FakeSecrets(key=None)
    result, _, secrets_store, _ = _run_import(root, [_route("other")], secrets_store=secrets_store)

    assert result["category"] == "history_key_missing"
    assert secrets_store.load_key_calls == [(True, True)]
    assert db.read_bytes() == before


class FakeKeyring:
    def __init__(self, *, fail_get=False, fail_set=False, fail_delete=False):
        self.entries: dict[tuple[str, str], str] = {}
        self.fail_get = fail_get
        self.fail_set = fail_set
        self.fail_delete = fail_delete

    def get_password(self, service: str, account: str):
        if self.fail_get:
            raise RuntimeError("private get exception")
        return self.entries.get((service, account))

    def set_password(self, service: str, account: str, value: str):
        if self.fail_set:
            raise RuntimeError("private set exception")
        self.entries[(service, account)] = value

    def delete_password(self, service: str, account: str):
        if self.fail_delete:
            raise RuntimeError("private delete exception")
        del self.entries[(service, account)]


class FakeNativeStore:
    def __init__(self, keyring: FakeKeyring | None = None, *, native=True):
        self._keyring = keyring or FakeKeyring()
        self.native = native

    def _assert_native_backend(self):
        if not self.native:
            raise RefreshTokenStoreError("backend is not native")


def test_own_native_keyservice_readback_validation_and_delete_preserves_mapit_refresh_entry():
    keyring = FakeKeyring()
    keyring.entries[("mapit-client", "refresh-token")] = "refresh-token-do-not-touch"
    secrets_store = runtime.WindowsHistorySecrets(native_store=FakeNativeStore(keyring))
    key = secrets_store.load_key(database_exists=False, create=True)

    assert len(key) == 32
    saved = keyring.entries[(runtime.KEY_SERVICE, runtime.KEY_ACCOUNT)]
    assert len(saved) == 64
    assert bytes.fromhex(saved) == key
    secrets_store.set_active_scope("a" * 64)
    assert secrets_store.active_scope() == "a" * 64
    secrets_store.delete()
    assert ("mapit-client", "refresh-token") in keyring.entries
    assert (runtime.KEY_SERVICE, runtime.KEY_ACCOUNT) not in keyring.entries
    assert (runtime.KEY_SERVICE, runtime.SCOPE_ACCOUNT) not in keyring.entries


def test_missing_or_invalid_key_is_not_silently_recreated_for_existing_database():
    keyring = FakeKeyring()
    secrets_store = runtime.WindowsHistorySecrets(native_store=FakeNativeStore(keyring))
    with pytest.raises(runtime.HistoryRuntimeError) as caught:
        secrets_store.load_key(database_exists=True, create=True)
    assert caught.value.category == "history_key_missing"
    assert (runtime.KEY_SERVICE, runtime.KEY_ACCOUNT) not in keyring.entries

    keyring.entries[(runtime.KEY_SERVICE, runtime.KEY_ACCOUNT)] = "not-a-64-char-key"
    with pytest.raises(runtime.HistoryRuntimeError) as caught:
        secrets_store.load_key(database_exists=True)
    assert caught.value.category == "history_key_invalid"


def test_non_native_keyservice_and_keyring_failures_are_closed_categories():
    with pytest.raises(RefreshTokenStoreError):
        runtime.WindowsHistorySecrets(native_store=FakeNativeStore(native=False))

    for keyring in (FakeKeyring(fail_get=True), FakeKeyring(fail_set=True), FakeKeyring(fail_delete=True)):
        secrets_store = runtime.WindowsHistorySecrets(native_store=FakeNativeStore(keyring))
        if keyring.fail_get:
            action = lambda: secrets_store.load_key(database_exists=True)
        elif keyring.fail_set:
            action = lambda: secrets_store.load_key(database_exists=False, create=True)
        else:
            keyring.entries[(runtime.KEY_SERVICE, runtime.KEY_ACCOUNT)] = "a" * 64
            action = secrets_store.delete
        with pytest.raises(runtime.HistoryRuntimeError) as caught:
            action()
        assert caught.value.category == "credential_store_failed"
        assert "private" not in str(caught.value)
