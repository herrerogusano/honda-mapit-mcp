"""Small, injected durable authorization store for the optional MCP path.

This module deliberately stores only an opaque tenant key, status and
monotonic revision.  It does not know about Telegram, sessions, credentials,
JWT claims or business data.  A database connection and schema are supplied
by the caller; no default path or migration is performed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import threading
from typing import Any, Protocol

_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_STATUSES = frozenset({"active", "revoked"})
MAX_RECORDS = 16


class DurableTenantError(ValueError):
    """Stable categories; storage errors never expose SQL or paths."""

    _ALLOWED = frozenset({
        "durable_configuration_invalid", "durable_store_failed",
        "durable_unauthorized", "durable_snapshot_invalid",
        "durable_record_invalid", "durable_capacity_exhausted",
    })

    def __init__(self, category: str):
        self.category = category if category in self._ALLOWED else "durable_store_failed"
        super().__init__(self.category)


@dataclass(frozen=True, repr=False)
class DurableTenantRecord:
    key: str
    status: str
    revision: int

    def __post_init__(self) -> None:
        if (
            type(self.key) is not str or _KEY.fullmatch(self.key) is None
            or type(self.status) is not str or self.status not in _STATUSES
            or type(self.revision) is not int or isinstance(self.revision, bool)
            or self.revision <= 0
        ):
            raise DurableTenantError("durable_record_invalid")

    def __repr__(self) -> str:
        return "DurableTenantRecord(<redacted>)"


class TenantAuthorizationStore(Protocol):
    def get(self, key: str) -> DurableTenantRecord | None: ...
    def cas(self, key: str, expected_revision: int | None,
            replacement: DurableTenantRecord) -> bool: ...


class SQLiteTenantStore:
    """Explicit-connection SQLite store with transactional CAS semantics."""

    _TABLE = "mapit_durable_tenants_v1"

    def __init__(self, connection: sqlite3.Connection, *, max_records: int = MAX_RECORDS):
        if type(connection) is not sqlite3.Connection or type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise DurableTenantError("durable_configuration_invalid")
        if connection.in_transaction:
            raise DurableTenantError("durable_configuration_invalid")
        self._connection = connection
        self._max_records = max_records
        self._lock = threading.RLock()
        try:
            columns = self._connection.execute("PRAGMA table_info(mapit_durable_tenants_v1)").fetchall()
            if [(row[1], row[2]) for row in columns] != [
                ("key", "TEXT"), ("status", "TEXT"), ("revision", "INTEGER")
            ] or any(row[3] != 1 for row in columns) or columns[0][5] != 1 or any(row[5] != 0 for row in columns[1:]):
                raise DurableTenantError("durable_configuration_invalid")
            # A contending CAS must fail closed immediately; never inherit an
            # unbounded SQLite busy wait from an injected connection.
            self._connection.execute("PRAGMA busy_timeout = 0")
            self._connection.execute("SELECT key, status, revision FROM mapit_durable_tenants_v1 LIMIT 0")
        except DurableTenantError:
            raise
        except Exception:
            raise DurableTenantError("durable_configuration_invalid") from None

    @classmethod
    def initialize(cls, connection: sqlite3.Connection, *, max_records: int = MAX_RECORDS) -> "SQLiteTenantStore":
        if type(connection) is not sqlite3.Connection or type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise DurableTenantError("durable_configuration_invalid")
        if connection.in_transaction:
            raise DurableTenantError("durable_configuration_invalid")
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS mapit_durable_tenants_v1 ("
                "key TEXT PRIMARY KEY NOT NULL, status TEXT NOT NULL, revision INTEGER NOT NULL)"
            )
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise DurableTenantError("durable_store_failed") from None
        return cls(connection, max_records=max_records)

    @staticmethod
    def _validate_key(key: str) -> None:
        if type(key) is not str or _KEY.fullmatch(key) is None:
            raise DurableTenantError("durable_record_invalid")

    @staticmethod
    def _row(row: tuple[Any, ...] | None) -> DurableTenantRecord | None:
        if row is None:
            return None
        if len(row) != 3:
            raise DurableTenantError("durable_store_failed")
        try:
            return DurableTenantRecord(row[0], row[1], row[2])
        except DurableTenantError:
            raise
        except Exception:
            raise DurableTenantError("durable_store_failed") from None

    def get(self, key: str) -> DurableTenantRecord | None:
        self._validate_key(key)
        with self._lock:
            if self._connection.in_transaction:
                raise DurableTenantError("durable_store_failed")
            try:
                row = self._connection.execute(
                    "SELECT key, status, revision FROM mapit_durable_tenants_v1 WHERE key = ?",
                    (key,),
                ).fetchone()
                return self._row(row)
            except DurableTenantError:
                raise
            except Exception:
                raise DurableTenantError("durable_store_failed") from None

    def cas(self, key: str, expected_revision: int | None,
            replacement: DurableTenantRecord) -> bool:
        self._validate_key(key)
        if not isinstance(replacement, DurableTenantRecord) or replacement.key != key:
            raise DurableTenantError("durable_record_invalid")
        if expected_revision is not None and (
            type(expected_revision) is not int or isinstance(expected_revision, bool) or expected_revision <= 0
        ):
            raise DurableTenantError("durable_record_invalid")
        with self._lock:
            if self._connection.in_transaction:
                raise DurableTenantError("durable_store_failed")
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._connection.execute(
                    "SELECT key, status, revision FROM mapit_durable_tenants_v1 WHERE key = ?",
                    (key,),
                ).fetchone()
                current = self._row(row)
                if current is None:
                    if expected_revision is not None:
                        self._connection.rollback()
                        return False
                    if replacement.revision != 1:
                        self._connection.rollback()
                        return False
                    count = self._connection.execute(
                        "SELECT COUNT(*) FROM mapit_durable_tenants_v1"
                    ).fetchone()[0]
                    if type(count) is not int or count >= self._max_records:
                        self._connection.rollback()
                        raise DurableTenantError("durable_capacity_exhausted")
                    self._connection.execute(
                        "INSERT INTO mapit_durable_tenants_v1(key, status, revision) VALUES (?, ?, ?)",
                        (key, replacement.status, replacement.revision),
                    )
                else:
                    if current.revision != expected_revision or replacement.revision != current.revision + 1:
                        self._connection.rollback()
                        return False
                    if current.status == "revoked" and replacement.status != "revoked":
                        self._connection.rollback()
                        return False
                    updated = self._connection.execute(
                        "UPDATE mapit_durable_tenants_v1 SET status = ?, revision = ? WHERE key = ? AND revision = ?",
                        (replacement.status, replacement.revision, key, current.revision),
                    ).rowcount
                    if updated != 1:
                        self._connection.rollback()
                        return False
                self._connection.commit()
                return True
            except DurableTenantError:
                try:
                    self._connection.rollback()
                except Exception:
                    pass
                raise
            except Exception:
                try:
                    self._connection.rollback()
                except Exception:
                    pass
                raise DurableTenantError("durable_store_failed") from None


@dataclass(frozen=True, repr=False)
class DurableTenantSnapshot:
    key: str
    revision: int
    _seal: bytes = field(repr=False)
    _guard: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "DurableTenantSnapshot(<redacted>)"


class DurableTenantGuard:
    """Authority-bound, revision-bound request guard."""

    def __init__(self, authority: Any, store: TenantAuthorizationStore):
        try:
            # Lazy import avoids the router/store module cycle while keeping
            # this boundary bound to the exact invitation authority type.
            from .tenant_router import InvitedTenantAuthority
            exact_authority = type(authority) is InvitedTenantAuthority
        except Exception:
            exact_authority = False
        if not exact_authority or not callable(getattr(authority, "validate", None)):
            raise DurableTenantError("durable_configuration_invalid")
        if not callable(getattr(store, "get", None)) or not callable(getattr(store, "cas", None)):
            raise DurableTenantError("durable_configuration_invalid")
        self._authority = authority
        self._store = store
        self._secret = secrets.token_bytes(32)
        self._marker = object()

    def is_bound_to(self, authority: Any) -> bool:
        return authority is self._authority

    def _seal_for(self, key: str, revision: int) -> bytes:
        payload = json.dumps([key, revision], separators=(",", ":")).encode("ascii")
        return hmac.new(self._secret, b"mapit-durable-grant-v1\0" + payload, hashlib.sha256).digest()

    def capture(self, grant: Any) -> DurableTenantSnapshot:
        try:
            self._authority.validate(grant)
        except Exception:
            raise DurableTenantError("durable_unauthorized") from None
        key = getattr(grant, "key", None)
        try:
            record = self._store.get(key)
        except DurableTenantError:
            raise
        except Exception:
            raise DurableTenantError("durable_store_failed") from None
        try:
            self._authority.validate(grant)
        except Exception:
            raise DurableTenantError("durable_unauthorized") from None
        if record is None:
            raise DurableTenantError("durable_unauthorized")
        if not isinstance(record, DurableTenantRecord):
            raise DurableTenantError("durable_store_failed")
        if record.key != key:
            raise DurableTenantError("durable_store_failed")
        if record.status != "active":
            raise DurableTenantError("durable_unauthorized")
        return DurableTenantSnapshot(key, record.revision, self._seal_for(key, record.revision), self._marker)

    def check(self, grant: Any, snapshot: DurableTenantSnapshot) -> None:
        try:
            self._authority.validate(grant)
        except Exception:
            raise DurableTenantError("durable_unauthorized") from None
        if (
            type(snapshot) is not DurableTenantSnapshot
            or snapshot._guard is not self._marker
            or snapshot.key != getattr(grant, "key", None)
            or type(snapshot.revision) is not int
            or type(snapshot._seal) is not bytes or len(snapshot._seal) != 32
            or not hmac.compare_digest(snapshot._seal, self._seal_for(snapshot.key, snapshot.revision))
        ):
            raise DurableTenantError("durable_snapshot_invalid")
        try:
            record = self._store.get(snapshot.key)
        except Exception:
            raise DurableTenantError("durable_store_failed") from None
        try:
            self._authority.validate(grant)
        except Exception:
            raise DurableTenantError("durable_unauthorized") from None
        if record is None or not isinstance(record, DurableTenantRecord):
            raise DurableTenantError("durable_store_failed")
        if record.key != snapshot.key:
            raise DurableTenantError("durable_store_failed")
        if record.status != "active" or record.revision != snapshot.revision:
            raise DurableTenantError("durable_unauthorized")


__all__ = [
    "DurableTenantError", "DurableTenantRecord", "TenantAuthorizationStore",
    "SQLiteTenantStore", "DurableTenantSnapshot", "DurableTenantGuard",
    "MAX_RECORDS",
]
