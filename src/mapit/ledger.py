"""Opt-in local distance ledger with scoped, pseudonymous route identities."""

from __future__ import annotations

import hashlib
import hmac
import math
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal, Mapping, Sequence

MAPIT_NATIVE_UNIT = "mapit_native_unconfirmed"
COMPLETENESS = "unverified"
SOURCE_VERSION = "mapit_route_v1"
GroupBy = Literal["day", "month", "year"]

MAX_IMPORT_ROUTES = 10_000
MAX_ID_CHARS = 256
SQLITE_BUSY_TIMEOUT_MS = 5_000
APPLICATION_ID = 0x4D504C47  # "MPLG"
SCHEMA_VERSION = 1
_KEY_CHECK_DOMAIN = b"distance-ledger-key-check-v1"
_SCOPE_DOMAIN = b"distance-ledger-scope-v1"
_ROUTE_DOMAIN = b"distance-ledger-route-v1"
_BUCKET_COLUMNS = {
    "day": "utc_day",
    "month": "substr(utc_day, 1, 7)",
    "year": "substr(utc_day, 1, 4)",
}
_ALIAS_RE = re.compile(r"^[0-9a-f]{64}$")
_CREATE_FACTS_SQL = (
    "CREATE TABLE route_facts ("
    "scope_alias BLOB NOT NULL CHECK(typeof(scope_alias) = 'blob' AND length(scope_alias) = 32), "
    "route_alias BLOB NOT NULL CHECK(typeof(route_alias) = 'blob' AND length(route_alias) = 32), "
    "utc_day TEXT NOT NULL CHECK(length(utc_day) = 10), "
    "distance REAL NOT NULL CHECK(typeof(distance) = 'real' AND distance >= 0), "
    "source_version TEXT NOT NULL CHECK(source_version = 'mapit_route_v1'), "
    "metric_unit TEXT NOT NULL CHECK(metric_unit = 'mapit_native_unconfirmed'), "
    "completeness TEXT NOT NULL CHECK(completeness = 'unverified'), "
    "PRIMARY KEY(scope_alias, route_alias)"
    ") WITHOUT ROWID"
)
_CREATE_METADATA_SQL = (
    "CREATE TABLE ledger_metadata ("
    "key_check BLOB NOT NULL CHECK(typeof(key_check) = 'blob' AND length(key_check) = 32)"
    ")"
)
_CREATE_VIEW_SQL = {
    "route_distance_daily": (
        "CREATE VIEW route_distance_daily AS "
        "SELECT scope_alias, utc_day AS bucket, SUM(distance) AS distance, COUNT(*) AS observed_route_count "
        "FROM route_facts GROUP BY scope_alias, utc_day"
    ),
    "route_distance_monthly": (
        "CREATE VIEW route_distance_monthly AS "
        "SELECT scope_alias, substr(utc_day, 1, 7) AS bucket, SUM(distance) AS distance, COUNT(*) AS observed_route_count "
        "FROM route_facts GROUP BY scope_alias, substr(utc_day, 1, 7)"
    ),
    "route_distance_yearly": (
        "CREATE VIEW route_distance_yearly AS "
        "SELECT scope_alias, substr(utc_day, 1, 4) AS bucket, SUM(distance) AS distance, COUNT(*) AS observed_route_count "
        "FROM route_facts GROUP BY scope_alias, substr(utc_day, 1, 4)"
    ),
}


class LedgerError(RuntimeError):
    """A ledger failure with a safe, stable category and no source values."""

    _MESSAGES = {
        "invalid_key": "ledger key is invalid",
        "key_mismatch": "ledger key does not match this database",
        "invalid_path": "ledger path is invalid",
        "invalid_scope": "ledger scope is invalid",
        "invalid_routes": "route batch is invalid",
        "route_limit_exceeded": "route batch exceeds the accepted limit",
        "route_invalid": "a route is missing required valid fields",
        "route_not_confirmed_complete": "routes with a false complete flag cannot be imported",
        "route_conflict": "a route conflicts with a previously imported fact",
        "numeric_overflow": "distance totals exceed finite numeric bounds",
        "invalid_group_by": "group_by must be day, month, or year",
        "invalid_date_range": "UTC date range is invalid",
        "invalid_scope_alias": "scope alias is invalid",
        "schema_unsupported": "ledger schema is unsupported",
        "storage_failed": "ledger storage operation failed",
    }

    def __init__(self, category: str) -> None:
        self.category = category if category in self._MESSAGES else "storage_failed"
        super().__init__(self._MESSAGES[self.category])


@dataclass(frozen=True)
class ImportResult:
    added: int
    duplicate: int


@dataclass(frozen=True)
class LedgerDistanceBucket:
    bucket: str
    distance: float
    observed_route_count: int


@dataclass(frozen=True)
class LedgerDistanceBreakdown:
    group_by: GroupBy
    buckets: tuple[LedgerDistanceBucket, ...]
    date_from: str | None
    date_to: str | None
    metric_unit: Literal["mapit_native_unconfirmed"] = MAPIT_NATIVE_UNIT
    bucket_timezone: Literal["UTC"] = "UTC"
    completeness: Literal["unverified"] = COMPLETENESS


@dataclass(frozen=True)
class _RouteFact:
    route_alias: bytes
    utc_day: str
    distance: float


@dataclass(frozen=True)
class _ValidatedRoute:
    route_id: str
    utc_day: str
    distance: float


def _length_prefix(parts: Sequence[bytes]) -> bytes:
    encoded = bytearray()
    for part in parts:
        if len(part) >= 2**32:
            raise LedgerError("invalid_scope")
        encoded.extend(len(part).to_bytes(4, "big"))
        encoded.extend(part)
    return bytes(encoded)


def _identity_bytes(value: Any, *, max_chars: int = MAX_ID_CHARS, category: str = "invalid_scope") -> bytes:
    if not isinstance(value, str) or not value.strip() or len(value) > max_chars:
        raise LedgerError(category)
    try:
        return value.strip().encode("utf-8")
    except UnicodeEncodeError:
        raise LedgerError(category) from None


def _route_start(value: Any) -> datetime:
    if not isinstance(value, str) or not value:
        raise LedgerError("route_invalid")
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except (ValueError, OverflowError):
        raise LedgerError("route_invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LedgerError("route_invalid")
    try:
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise LedgerError("route_invalid") from None


def _route_date(route: Mapping[str, Any]) -> Any:
    camel = route.get("startedAt")
    snake = route.get("started_at")
    if camel is not None and snake is not None and camel != snake:
        raise LedgerError("route_invalid")
    return camel if camel is not None else snake


def _distance_value(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LedgerError("route_invalid")
    try:
        distance = float(value)
    except (OverflowError, ValueError):
        raise LedgerError("route_invalid") from None
    if not math.isfinite(distance) or distance < 0:
        raise LedgerError("route_invalid")
    return distance


def _validated_route_batch(routes: Sequence[Mapping[str, Any]]) -> tuple[_ValidatedRoute, ...]:
    if isinstance(routes, (str, bytes)) or not isinstance(routes, Sequence):
        raise LedgerError("invalid_routes")
    if len(routes) > MAX_IMPORT_ROUTES:
        raise LedgerError("route_limit_exceeded")
    validated: list[_ValidatedRoute] = []
    unique: dict[str, _ValidatedRoute] = {}
    for route in routes:
        if not isinstance(route, Mapping):
            raise LedgerError("route_invalid")
        raw_id = route.get("id")
        route_id = _identity_bytes(raw_id, category="route_invalid").decode("utf-8")
        start = _route_start(_route_date(route))
        distance = _distance_value(route.get("distance"))
        if "complete" in route and not isinstance(route["complete"], bool):
            raise LedgerError("route_invalid")
        if route.get("complete") is False:
            # Only the boolean schema is confirmed; False does not prove an active trip.
            raise LedgerError("route_not_confirmed_complete")
        fact = _ValidatedRoute(route_id, start.date().isoformat(), distance)
        prior = unique.get(route_id)
        if prior is not None and (prior.utc_day != fact.utc_day or prior.distance != fact.distance):
            raise LedgerError("route_conflict")
        unique.setdefault(route_id, fact)
        validated.append(fact)
    total = 0.0
    for fact in unique.values():
        total += fact.distance
        if not math.isfinite(total):
            raise LedgerError("numeric_overflow")
    return tuple(validated)


def _date_bound(value: date | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        raise LedgerError("invalid_date_range")
    if isinstance(value, date):
        return value.isoformat()
    if not isinstance(value, str):
        raise LedgerError("invalid_date_range")
    try:
        parsed = date.fromisoformat(value)
    except ValueError:
        raise LedgerError("invalid_date_range") from None
    if parsed.isoformat() != value:
        raise LedgerError("invalid_date_range")
    return value


class DistanceLedger:
    """Single-owner SQLite ledger. The caller supplies its external HMAC key."""

    def __init__(self, path: str | Path, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise LedgerError("invalid_key")
        try:
            database_path = Path(path)
        except (TypeError, ValueError, OSError):
            raise LedgerError("invalid_path") from None
        if str(database_path) in {"", ".", ":memory:"}:
            raise LedgerError("invalid_path")
        self._path = database_path
        self._key = key
        key_check = hmac.new(key, _KEY_CHECK_DOMAIN, hashlib.sha256).digest()
        self._prepare_schema(key_check)

    def __repr__(self) -> str:
        return "DistanceLedger(<local database>, <external key>)"

    def scope_alias(self, account_scope: str, vehicle_id: str) -> str:
        account = _identity_bytes(account_scope, max_chars=2048)
        vehicle = _identity_bytes(vehicle_id)
        payload = _length_prefix((_SCOPE_DOMAIN, account, vehicle))
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    @staticmethod
    def validate_routes(routes: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
        """Validate a bounded source batch before any ledger/key setup and return UTC days."""
        return tuple(fact.utc_day for fact in _validated_route_batch(routes))

    def import_routes(
        self,
        account_scope: str,
        vehicle_id: str,
        routes: Sequence[Mapping[str, Any]],
    ) -> ImportResult:
        scope = self.scope_alias(account_scope, vehicle_id)
        validated_routes = _validated_route_batch(routes)
        prepared: dict[bytes, _RouteFact] = {}
        duplicate_count = 0
        for route in validated_routes:
            route_payload = _length_prefix(
                (
                    _ROUTE_DOMAIN,
                    _identity_bytes(account_scope, max_chars=2048),
                    _identity_bytes(vehicle_id),
                    route.route_id.encode("utf-8"),
                )
            )
            route_alias = hmac.new(self._key, route_payload, hashlib.sha256).digest()
            fact = _RouteFact(route_alias, route.utc_day, route.distance)
            prior = prepared.get(route_alias)
            if prior is not None:
                if prior != fact:
                    raise LedgerError("route_conflict")
                duplicate_count += 1
            else:
                prepared[route_alias] = fact

        added_count = 0
        key_check = hmac.new(self._key, _KEY_CHECK_DOMAIN, hashlib.sha256).digest()
        with self._connection(key_check) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                for fact in prepared.values():
                    existing = connection.execute(
                        "SELECT utc_day, distance, source_version, metric_unit, completeness "
                        "FROM route_facts WHERE scope_alias = ? AND route_alias = ?",
                        (bytes.fromhex(scope), fact.route_alias),
                    ).fetchone()
                    if existing is not None:
                        if (
                            existing[0] != fact.utc_day
                            or float(existing[1]) != fact.distance
                            or existing[2] != SOURCE_VERSION
                            or existing[3] != MAPIT_NATIVE_UNIT
                            or existing[4] != COMPLETENESS
                        ):
                            raise LedgerError("route_conflict")
                        duplicate_count += 1
                        continue
                    connection.execute(
                        "INSERT INTO route_facts "
                        "(scope_alias, route_alias, utc_day, distance, source_version, metric_unit, completeness) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            bytes.fromhex(scope),
                            fact.route_alias,
                            fact.utc_day,
                            fact.distance,
                            SOURCE_VERSION,
                            MAPIT_NATIVE_UNIT,
                            COMPLETENESS,
                        ),
                    )
                    added_count += 1
                total, fact_count = connection.execute(
                    "SELECT SUM(distance), COUNT(*) FROM route_facts WHERE scope_alias = ?",
                    (bytes.fromhex(scope),),
                ).fetchone()
                if fact_count > 0 and (total is None or not math.isfinite(float(total))):
                    raise LedgerError("numeric_overflow")
                connection.commit()
            except LedgerError:
                connection.rollback()
                raise
            except sqlite3.Error:
                connection.rollback()
                raise LedgerError("storage_failed") from None
        return ImportResult(added=added_count, duplicate=duplicate_count)

    def distance_breakdown(
        self,
        account_scope: str,
        vehicle_id: str,
        group_by: GroupBy,
        *,
        date_from: date | str | None = None,
        date_to: date | str | None = None,
    ) -> LedgerDistanceBreakdown:
        scope_alias = self.scope_alias(account_scope, vehicle_id)
        return self.distance_breakdown_by_scope_alias(
            scope_alias,
            group_by,
            date_from=date_from,
            date_to=date_to,
        )

    def distance_breakdown_by_scope_alias(
        self,
        scope_alias: str,
        group_by: GroupBy,
        *,
        date_from: date | str | None = None,
        date_to: date | str | None = None,
    ) -> LedgerDistanceBreakdown:
        if group_by not in _BUCKET_COLUMNS:
            raise LedgerError("invalid_group_by")
        if not isinstance(scope_alias, str) or not _ALIAS_RE.fullmatch(scope_alias):
            raise LedgerError("invalid_scope_alias")
        lower = _date_bound(date_from)
        upper = _date_bound(date_to)
        if lower is not None and upper is not None and lower >= upper:
            raise LedgerError("invalid_date_range")
        where = ["scope_alias = ?"]
        params: list[Any] = [bytes.fromhex(scope_alias)]
        if lower is not None:
            where.append("utc_day >= ?")
            params.append(lower)
        if upper is not None:
            where.append("utc_day < ?")
            params.append(upper)
        bucket_expr = _BUCKET_COLUMNS[group_by]
        query = (
            f"SELECT {bucket_expr} AS bucket, SUM(distance) AS distance, COUNT(*) AS observed_route_count "
            f"FROM route_facts WHERE {' AND '.join(where)} GROUP BY bucket ORDER BY bucket"
        )
        key_check = hmac.new(self._key, _KEY_CHECK_DOMAIN, hashlib.sha256).digest()
        try:
            with self._connection(key_check) as connection:
                rows = connection.execute(query, params).fetchall()
        except LedgerError:
            raise
        except sqlite3.Error:
            raise LedgerError("storage_failed") from None
        buckets: list[LedgerDistanceBucket] = []
        for bucket, distance, count in rows:
            try:
                numeric_distance = float(distance)
            except (TypeError, ValueError, OverflowError):
                raise LedgerError("numeric_overflow") from None
            if not math.isfinite(numeric_distance):
                raise LedgerError("numeric_overflow")
            buckets.append(LedgerDistanceBucket(str(bucket), numeric_distance, int(count)))
        return LedgerDistanceBreakdown(
            group_by=group_by,
            buckets=tuple(buckets),
            date_from=lower,
            date_to=upper,
        )

    def delete_scope(self, account_scope: str, vehicle_id: str) -> int:
        scope = bytes.fromhex(self.scope_alias(account_scope, vehicle_id))
        key_check = hmac.new(self._key, _KEY_CHECK_DOMAIN, hashlib.sha256).digest()
        with self._connection(key_check) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute("DELETE FROM route_facts WHERE scope_alias = ?", (scope,))
                deleted = cursor.rowcount
                connection.commit()
                return max(0, deleted)
            except sqlite3.Error:
                connection.rollback()
                raise LedgerError("storage_failed") from None

    @contextmanager
    def _connection(self, key_check: bytes) -> Iterator[sqlite3.Connection]:
        try:
            connection = sqlite3.connect(self._path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
            connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
            self._verify_existing_schema(connection, key_check)
            self._configure_connection(connection)
        except LedgerError:
            try:
                connection.close()
            except (UnboundLocalError, sqlite3.Error):
                pass
            raise
        except (sqlite3.Error, OSError, TypeError, ValueError):
            try:
                connection.close()
            except (UnboundLocalError, sqlite3.Error):
                pass
            raise LedgerError("storage_failed") from None
        try:
            yield connection
        finally:
            try:
                connection.close()
            except sqlite3.Error:
                raise LedgerError("storage_failed") from None

    def _prepare_schema(self, key_check: bytes) -> None:
        try:
            existed_before = self._path.exists()
        except OSError:
            raise LedgerError("invalid_path") from None
        try:
            connection = sqlite3.connect(self._path, timeout=SQLITE_BUSY_TIMEOUT_MS / 1000, isolation_level=None)
            try:
                connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
                application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                objects = self._schema_objects(connection)
                if application_id == 0 and version == 0 and not objects and not existed_before:
                    connection.execute("BEGIN IMMEDIATE")
                    # Recheck after obtaining the write lock in case another
                    # constructor initialized the new file concurrently.
                    application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
                    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                    objects = self._schema_objects(connection)
                    if application_id == 0 and version == 0 and not objects:
                        self._create_schema(connection, key_check)
                    connection.commit()
                self._verify_existing_schema(connection, key_check)
                self._configure_connection(connection)
            finally:
                connection.close()
        except LedgerError:
            raise
        except (sqlite3.Error, OSError, TypeError, ValueError):
            raise LedgerError("storage_failed") from None

    @staticmethod
    def _schema_objects(connection: sqlite3.Connection) -> dict[str, str]:
        return {
            str(name): str(kind)
            for kind, name in connection.execute(
                "SELECT type, name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }

    def _verify_existing_schema(self, connection: sqlite3.Connection, key_check: bytes) -> None:
        try:
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if application_id != APPLICATION_ID or version != SCHEMA_VERSION:
                raise LedgerError("schema_unsupported")
            expected_objects = {
                "route_facts": "table",
                "ledger_metadata": "table",
                "route_distance_daily": "view",
                "route_distance_monthly": "view",
                "route_distance_yearly": "view",
            }
            if self._schema_objects(connection) != expected_objects:
                raise LedgerError("schema_unsupported")
            schema_sql = {
                str(name): str(sql)
                for name, sql in connection.execute(
                    "SELECT name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                )
            }
            expected_sql = {"route_facts": _CREATE_FACTS_SQL, "ledger_metadata": _CREATE_METADATA_SQL, **_CREATE_VIEW_SQL}
            if any(
                "".join(schema_sql[name].lower().split()) != "".join(expected.lower().split())
                for name, expected in expected_sql.items()
            ):
                raise LedgerError("schema_unsupported")
            fact_columns = connection.execute("PRAGMA table_info(route_facts)").fetchall()
            expected_fact_columns = [
                ("scope_alias", "BLOB", 1, 1),
                ("route_alias", "BLOB", 1, 2),
                ("utc_day", "TEXT", 1, 0),
                ("distance", "REAL", 1, 0),
                ("source_version", "TEXT", 1, 0),
                ("metric_unit", "TEXT", 1, 0),
                ("completeness", "TEXT", 1, 0),
            ]
            if [
                (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
                for row in fact_columns
            ] != expected_fact_columns:
                raise LedgerError("schema_unsupported")
            metadata_columns = connection.execute("PRAGMA table_info(ledger_metadata)").fetchall()
            if [
                (str(row[1]), str(row[2]).upper(), int(row[3]))
                for row in metadata_columns
            ] != [("key_check", "BLOB", 1)]:
                raise LedgerError("schema_unsupported")
            for view, columns in (
                ("route_distance_daily", ["scope_alias", "bucket", "distance", "observed_route_count"]),
                ("route_distance_monthly", ["scope_alias", "bucket", "distance", "observed_route_count"]),
                ("route_distance_yearly", ["scope_alias", "bucket", "distance", "observed_route_count"]),
            ):
                actual = [str(row[1]) for row in connection.execute(f"PRAGMA table_info({view})")]
                if actual != columns:
                    raise LedgerError("schema_unsupported")
            rows = connection.execute("SELECT key_check FROM ledger_metadata").fetchall()
            if len(rows) != 1 or not isinstance(rows[0][0], bytes):
                raise LedgerError("schema_unsupported")
            if not hmac.compare_digest(rows[0][0], key_check):
                raise LedgerError("key_mismatch")
        except LedgerError:
            raise
        except sqlite3.Error:
            raise LedgerError("schema_unsupported") from None

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        try:
            connection.execute("PRAGMA secure_delete = ON")
            mode = str(connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]).lower()
            if mode != "delete":
                raise LedgerError("storage_failed")
        except LedgerError:
            raise
        except sqlite3.Error:
            raise LedgerError("storage_failed") from None

    @staticmethod
    def _create_schema(connection: sqlite3.Connection, key_check: bytes) -> None:
        connection.execute(_CREATE_FACTS_SQL)
        connection.execute(_CREATE_METADATA_SQL)
        for statement in _CREATE_VIEW_SQL.values():
            connection.execute(statement)
        connection.execute("INSERT INTO ledger_metadata (key_check) VALUES (?)", (key_check,))
        connection.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
