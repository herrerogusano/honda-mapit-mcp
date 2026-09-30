from __future__ import annotations

import hashlib
import hmac
import math
import sqlite3
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from mapit import ledger as ledger_module
from mapit.ledger import (
    APPLICATION_ID,
    COMPLETENESS,
    MAPIT_NATIVE_UNIT,
    MAX_IMPORT_ROUTES,
    DistanceLedger,
    LedgerError,
)


KEY = bytes(range(32))
ACCOUNT_SCOPE = "https://core.prod.mapit.me:account-private"
VEHICLE_ID = "vehicle-private"


def _route(
    route_id: str = "route-private",
    *,
    started_at: str = "2026-01-02T00:30:00+01:00",
    ended_at: str | None = None,
    distance: float = 12.5,
    **extra,
):
    if ended_at is None:
        try:
            parsed = datetime.fromisoformat(started_at[:-1] + "+00:00" if started_at.endswith("Z") else started_at)
            ended_at = (parsed + timedelta(minutes=30)).isoformat()
        except (AttributeError, OverflowError, ValueError):
            ended_at = "2026-01-02T01:00:00+01:00"
    return {"id": route_id, "startedAt": started_at, "endedAt": ended_at, "distance": distance, **extra}


def _ledger(tmp_path: Path, name: str = "distance-ledger.sqlite", key: bytes = KEY) -> DistanceLedger:
    return DistanceLedger(tmp_path / name, key)


def test_unpaired_unicode_identifier_has_safe_validation_error():
    with pytest.raises(LedgerError) as caught:
        DistanceLedger.validate_routes([_route("synthetic-\ud800")])
    assert caught.value.category == "route_invalid"
    assert "synthetic" not in str(caught.value)


def test_new_schema_has_only_allowlisted_facts_and_rebuildable_aggregate_views(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = DistanceLedger(path, KEY)
    assert ledger.scope_alias(ACCOUNT_SCOPE, VEHICLE_ID) == ledger.scope_alias(ACCOUNT_SCOPE, VEHICLE_ID)

    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        objects = dict(connection.execute("SELECT name, type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"))
        assert objects == {
            "route_facts": "table",
            "ledger_metadata": "table",
            "route_distance_daily": "view",
            "route_distance_monthly": "view",
            "route_distance_yearly": "view",
        }
        columns = [row[1] for row in connection.execute("PRAGMA table_info(route_facts)")]
        assert columns == [
            "scope_alias",
            "route_alias",
            "utc_day",
            "distance",
            "source_version",
            "metric_unit",
            "completeness",
        ]
        assert [row[1] for row in connection.execute("PRAGMA table_info(ledger_metadata)")] == ["key_check"]
        key_check = connection.execute("SELECT key_check FROM ledger_metadata").fetchone()[0]
        assert len(key_check) == 32
        assert key_check == hmac.new(KEY, b"distance-ledger-key-check-v1", hashlib.sha256).digest()

    with ledger._connection(hmac.new(KEY, b"distance-ledger-key-check-v1", hashlib.sha256).digest()) as connection:
        assert connection.execute("PRAGMA secure_delete").fetchone()[0] == 1
        assert connection.execute("PRAGMA journal_mode").fetchone()[0].lower() == "delete"


def test_scoped_hmac_aliases_differ_by_account_vehicle_and_route_and_are_not_persisted(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = DistanceLedger(path, KEY)
    scope = ledger.scope_alias(ACCOUNT_SCOPE, VEHICLE_ID)
    other_account = ledger.scope_alias("https://core.prod.mapit.me:another-account", VEHICLE_ID)
    other_vehicle = ledger.scope_alias(ACCOUNT_SCOPE, "another-vehicle")
    assert len(scope) == 64
    assert len({scope, other_account, other_vehicle}) == 3

    result = ledger.import_routes(
        ACCOUNT_SCOPE,
        VEHICLE_ID,
        [_route(
            "route-private",
            ended_at="2026-01-02T01:37:42+01:00",
            vin="vin-private",
            coordinates=["coordinate-private"],
            street="street-private",
        )],
    )
    assert result.added == 1
    raw_db = path.read_bytes()
    for private_value in (
        ACCOUNT_SCOPE,
        VEHICLE_ID,
        "route-private",
        "vin-private",
        "coordinate-private",
        "street-private",
        "2026-01-02T01:37:42+01:00",
        KEY,
    ):
        encoded = private_value if isinstance(private_value, bytes) else private_value.encode("utf-8")
        assert encoded not in raw_db


def test_route_alias_hmac_is_scoped_by_account_and_vehicle(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = DistanceLedger(path, KEY)
    same_id = _route("same-route-id")
    ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [same_id])
    ledger.import_routes("https://core.prod.mapit.me:another-account", VEHICLE_ID, [same_id])
    ledger.import_routes(ACCOUNT_SCOPE, "another-vehicle", [same_id])
    with sqlite3.connect(path) as connection:
        aliases = [row[0] for row in connection.execute("SELECT route_alias FROM route_facts")]
    assert len(aliases) == 3
    assert len(set(aliases)) == 3
    assert all(len(alias) == 32 for alias in aliases)


def test_import_is_idempotent_and_duplicate_counts_include_same_batch_duplicates(tmp_path):
    ledger = _ledger(tmp_path)
    first = _route("route-1", distance=10)
    same = dict(first)
    result = ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [first, same])
    assert (result.added, result.duplicate) == (1, 1)

    repeated = ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [same])
    assert (repeated.added, repeated.duplicate) == (0, 1)


@pytest.mark.parametrize(
    "bad_route",
    [
        {"startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": 1},
        {"id": "r", "endedAt": "2026-01-01T01:00:00Z", "distance": 1},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "distance": 1},
        {"id": "r", "startedAt": "2026-01-01", "endedAt": "2026-01-01T01:00:00Z", "distance": 1},
        {"id": "r", "startedAt": "2026-01-01T00:00:00", "endedAt": "2026-01-01T01:00:00Z", "distance": 1},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z"},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": None},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": True},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": -0.1},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": math.nan},
        {"id": "r", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": math.inf},
        {"id": "", "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": 1},
        {"id": "r" * 257, "startedAt": "2026-01-01T00:00:00Z", "endedAt": "2026-01-01T01:00:00Z", "distance": 1},
    ],
)
def test_invalid_required_route_data_fails_closed_without_partial_import(tmp_path, bad_route):
    ledger = _ledger(tmp_path)
    with pytest.raises(LedgerError) as caught:
        ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("valid-first"), bad_route])
    assert caught.value.category == "route_invalid"
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets == ()


def test_start_and_end_timestamps_must_be_aware_coherent_and_not_future():
    now = datetime(2026, 1, 15, 12, tzinfo=timezone.utc)
    invalid_routes = [
        {"id": "missing-end", "startedAt": "2026-01-01T00:00:00Z", "distance": 1},
        _route("naive-end", ended_at="2026-01-02T01:00:00"),
        _route("ends-before-start", started_at="2026-01-02T02:00:00Z", ended_at="2026-01-02T01:00:00Z"),
        _route("future-start", started_at="2026-01-15T13:00:00Z", ended_at="2026-01-15T14:00:00Z"),
    ]
    conflicting_start_alias = _route("start-alias-conflict")
    conflicting_start_alias["started_at"] = "2026-01-03T00:00:00Z"
    conflicting_end_alias = _route("end-alias-conflict")
    conflicting_end_alias["ended_at"] = "2026-01-04T00:00:00Z"
    invalid_routes.extend([conflicting_start_alias, conflicting_end_alias])

    for invalid in invalid_routes:
        with pytest.raises(LedgerError) as caught:
            DistanceLedger.validate_routes([invalid], now=now)
        assert caught.value.category == "route_invalid"

    same_aliases = _route("same-alias-values")
    same_aliases["started_at"] = same_aliases["startedAt"]
    same_aliases["ended_at"] = same_aliases["endedAt"]
    snake_only = _route("snake-only")
    snake_only["started_at"] = snake_only.pop("startedAt")
    snake_only["ended_at"] = snake_only.pop("endedAt")
    boundary = _route(
        "ends-at-validation-now",
        started_at="2026-01-15T11:00:00Z",
        ended_at="2026-01-15T12:00:00Z",
    )
    assert DistanceLedger.validate_routes([same_aliases, boundary, snake_only], now=now) == (
        "2026-01-01", "2026-01-15", "2026-01-01"
    )
    with pytest.raises(LedgerError) as caught:
        DistanceLedger.validate_routes([same_aliases], now=datetime(2026, 1, 15, 12))
    assert caught.value.category == "route_invalid"


def test_complete_values_do_not_change_fact_validity_or_persisted_facts(tmp_path):
    ledger = _ledger(tmp_path)
    variants = [
        _route("same-facts", complete=True),
        _route("same-facts", complete=False),
        _route("same-facts"),
        _route("same-facts", complete="opaque"),
    ]
    result = ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, variants)
    assert (result.added, result.duplicate) == (1, 3)
    bucket = ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets[0]
    assert bucket.distance == 12.5
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").completeness == COMPLETENESS


def test_conflict_rolls_back_the_entire_batch_including_prior_new_rows(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("existing", distance=10)])
    before = ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day")
    with pytest.raises(LedgerError) as caught:
        ledger.import_routes(
            ACCOUNT_SCOPE,
            VEHICLE_ID,
            [_route("new-before-conflict", distance=5), _route("existing", distance=11)],
        )
    assert caught.value.category == "route_conflict"
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day") == before


def test_conflicting_same_batch_duplicates_are_rejected_before_write(tmp_path):
    ledger = _ledger(tmp_path)
    with pytest.raises(LedgerError) as caught:
        ledger.import_routes(
            ACCOUNT_SCOPE,
            VEHICLE_ID,
            [_route("same", distance=10), _route("same", distance=11)],
        )
    assert caught.value.category == "route_conflict"
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets == ()


def test_batch_limit_checked_before_any_transaction(tmp_path):
    ledger = _ledger(tmp_path)
    oversized_batch = [_route(str(index)) for index in range(MAX_IMPORT_ROUTES + 1)]
    with pytest.raises(LedgerError) as caught:
        ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, oversized_batch)
    assert caught.value.category == "route_limit_exceeded"
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets == ()


def test_distance_is_grouped_into_utc_day_month_year_and_date_range_is_half_open(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.import_routes(
        ACCOUNT_SCOPE,
        VEHICLE_ID,
        [
            _route("r1", started_at="2026-01-02T00:30:00+01:00", distance=2),
            _route("r2", started_at="2026-01-31T23:00:00-02:00", distance=3),
            _route("r3", started_at="2026-02-01T00:00:00Z", distance=4),
            _route("r4", started_at="2027-02-01T00:00:00Z", distance=5),
        ],
        now=datetime(2028, 1, 1, tzinfo=timezone.utc),
    )

    days = ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets
    assert [(item.bucket, item.distance, item.observed_route_count) for item in days] == [
        ("2026-01-01", 2, 1),
        ("2026-02-01", 7, 2),
        ("2027-02-01", 5, 1),
    ]
    months = ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "month").buckets
    assert [(item.bucket, item.distance) for item in months] == [("2026-01", 2), ("2026-02", 7), ("2027-02", 5)]
    years = ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "year").buckets
    assert [(item.bucket, item.distance) for item in years] == [("2026", 9), ("2027", 5)]
    bounded = ledger.distance_breakdown(
        ACCOUNT_SCOPE,
        VEHICLE_ID,
        "day",
        date_from=date(2026, 2, 1),
        date_to="2027-02-01",
    )
    assert [(item.bucket, item.distance) for item in bounded.buckets] == [("2026-02-01", 7)]
    assert bounded.metric_unit == MAPIT_NATIVE_UNIT
    assert bounded.completeness == COMPLETENESS


def test_scope_alias_query_isolated_and_manual_delete_removes_only_owned_facts(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("one", distance=3)])
    ledger.import_routes(ACCOUNT_SCOPE, "other-vehicle", [_route("two", distance=7)])
    alias = ledger.scope_alias(ACCOUNT_SCOPE, VEHICLE_ID)

    assert ledger.distance_breakdown_by_scope_alias(alias, "day").buckets[0].distance == 3
    assert ledger.delete_scope(ACCOUNT_SCOPE, VEHICLE_ID) == 1
    assert ledger.distance_breakdown_by_scope_alias(alias, "day").buckets == ()
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, "other-vehicle", "day").buckets[0].distance == 7


def test_invalid_query_arguments_are_safe_and_fixed(tmp_path):
    ledger = _ledger(tmp_path)
    for group_by, expected in [("week", "invalid_group_by")]:
        with pytest.raises(LedgerError) as caught:
            ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, group_by)
        assert caught.value.category == expected
    with pytest.raises(LedgerError) as caught:
        ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day", date_from="2026-02-02", date_to="2026-02-02")
    assert caught.value.category == "invalid_date_range"
    with pytest.raises(LedgerError) as caught:
        ledger.distance_breakdown_by_scope_alias("not-an-alias", "day")
    assert caught.value.category == "invalid_scope_alias"


def test_overflowing_import_rolls_back_and_query_rejects_nonfinite_sum(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = DistanceLedger(path, KEY)
    ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("large-one", distance=1e308)])
    with pytest.raises(LedgerError) as caught:
        ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("large-two", distance=1e308)])
    assert caught.value.category == "numeric_overflow"
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets[0].observed_route_count == 1

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE route_facts SET distance = ?", (math.inf,))
    with pytest.raises(LedgerError) as caught:
        ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day")
    assert caught.value.category == "numeric_overflow"


def test_import_rejects_null_sum_when_scope_has_facts_and_rolls_back(tmp_path, monkeypatch):
    path = tmp_path / "ledger.sqlite"
    ledger = DistanceLedger(path, KEY)
    ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("first", distance=1e308)])

    real_connect = sqlite3.connect
    query = "SELECT SUM(distance), COUNT(*) FROM route_facts WHERE scope_alias = ?"

    class NullSumCursor:
        def fetchone(self):
            return (None, 2)

    class ConnectionProxy:
        def __init__(self, connection):
            self._connection = connection

        def execute(self, sql, parameters=()):
            if sql == query:
                return NullSumCursor()
            return self._connection.execute(sql, parameters)

        def __getattr__(self, name):
            return getattr(self._connection, name)

    with monkeypatch.context() as patcher:
        patcher.setattr(
            ledger_module.sqlite3,
            "connect",
            lambda *args, **kwargs: ConnectionProxy(real_connect(*args, **kwargs)),
        )
        with pytest.raises(LedgerError) as caught:
            ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route("second", distance=1e308)])

    assert caught.value.category == "numeric_overflow"
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets[0].observed_route_count == 1


def test_wrong_key_is_detected_before_use_and_preserves_database_bytes(tmp_path):
    path = tmp_path / "ledger.sqlite"
    ledger = DistanceLedger(path, KEY)
    ledger.import_routes(ACCOUNT_SCOPE, VEHICLE_ID, [_route()])
    before = path.read_bytes()

    with pytest.raises(LedgerError) as caught:
        DistanceLedger(path, b"x" * 32)
    assert caught.value.category == "key_mismatch"
    assert path.read_bytes() == before
    assert ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "day").buckets[0].distance == 12.5


@pytest.mark.parametrize("schema_kind", ["unknown-table", "future-version", "empty-existing-file"])
def test_unknown_existing_schema_is_rejected_without_modifying_file(tmp_path, schema_kind):
    path = tmp_path / "unknown.sqlite"
    if schema_kind == "unknown-table":
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE preexisting_private_table(value TEXT)")
    elif schema_kind == "future-version":
        with sqlite3.connect(path) as connection:
            connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
            connection.execute("PRAGMA user_version = 99")
    else:
        path.touch()
    before = path.read_bytes()

    with pytest.raises(LedgerError) as caught:
        DistanceLedger(path, KEY)
    assert caught.value.category == "schema_unsupported"
    assert path.read_bytes() == before


def test_wrong_key_length_fails_before_creating_file(tmp_path):
    path = tmp_path / "must-not-exist.sqlite"
    with pytest.raises(LedgerError) as caught:
        DistanceLedger(path, b"short")
    assert caught.value.category == "invalid_key"
    assert not path.exists()


def test_static_route_validation_is_available_before_database_or_key_creation(tmp_path):
    path = tmp_path / "not-created.sqlite"
    dates = DistanceLedger.validate_routes(
        [
            _route("same-route", started_at="2026-01-02T00:30:00+01:00"),
            _route("same-route", started_at="2026-01-02T00:30:00+01:00"),
        ],
        now=datetime(2026, 1, 15, tzinfo=timezone.utc),
    )
    assert dates == ("2026-01-01", "2026-01-01")
    assert not path.exists()
    ignored_complete_values = [
        _route("complete-true", complete=True),
        _route("complete-false", complete=False),
        _route("complete-missing"),
        _route("complete-unknown", complete={"not": "interpreted"}),
    ]
    assert DistanceLedger.validate_routes(
        ignored_complete_values, now=datetime(2026, 1, 15, tzinfo=timezone.utc)
    ) == ("2026-01-01",) * 4


def test_static_route_validation_rejects_conflicting_duplicates_and_overflow():
    with pytest.raises(LedgerError) as caught:
        DistanceLedger.validate_routes([_route("duplicate", distance=1), _route("duplicate", distance=2)])
    assert caught.value.category == "route_conflict"
    with pytest.raises(LedgerError) as caught:
        DistanceLedger.validate_routes([_route("large-one", distance=1e308), _route("large-two", distance=1e308)])
    assert caught.value.category == "numeric_overflow"


def test_ten_identical_offline_queries_reuse_facts_without_network_client(tmp_path):
    ledger = _ledger(tmp_path)
    ledger.import_routes(
        ACCOUNT_SCOPE,
        VEHICLE_ID,
        [_route(f"route-{index}", distance=float(index + 1)) for index in range(10)],
    )
    results = [ledger.distance_breakdown(ACCOUNT_SCOPE, VEHICLE_ID, "month") for _ in range(10)]
    assert all(result == results[0] for result in results)
    assert results[0].buckets[0].distance == 55
    # This is a local reuse check only; it makes no latency or live MAPIT claim.
