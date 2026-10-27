"""Opt-in durable binding between an invited tenant and verified MAPIT identity.

This is an offline library boundary: SQLite connections, authentication
transport and the create-only secret publisher are injected by the caller.
No database path, SDK, network client, credential source or onboarding UI is
created here. A pending row is an intentional one-shot tombstone after any
ambiguous external publication; recovery requires a separately reviewed flow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import sqlite3
import threading
from datetime import datetime
from typing import Any, Callable, Mapping

from .auth import CognitoAuthenticator, MapitSession
from .config import MapitConfig
from .cloud_transport import CloudTransportError, validate_cloud_config
from .durable_tenants import DurableTenantError, DurableTenantGuard, DurableTenantSnapshot
from .mapit_identity import MapitIdentityError, MapitIdentityProof, MapitIdentityVerifier
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority, TenantIsolationError

_TABLE = "mapit_identity_bindings_v1"
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RECORDS = 16
_MAX_REFRESH_TOKEN_BYTES = 4096


class IdentityBindingError(RuntimeError):
    """Stable diagnostics with no tenant, subject, token, path, or SDK text."""

    _ALLOWED = frozenset({
        "identity_binding_configuration_invalid", "identity_binding_unauthorized",
        "identity_binding_store_failed", "identity_binding_integrity_failed",
        "identity_binding_capacity_exhausted", "identity_binding_exists",
        "identity_binding_identity_in_use", "identity_binding_not_active",
        "identity_binding_revoked", "identity_binding_auth_failed",
        "identity_binding_identity_invalid", "identity_binding_publication_unknown",
        "identity_binding_receipt_invalid", "identity_binding_deadline_invalid",
        "identity_binding_deadline_expired", "identity_binding_clock_invalid",
        "identity_binding_clock_rollback",
    })

    def __init__(self, category: str):
        self.category = category if type(category) is str and category in self._ALLOWED else "identity_binding_store_failed"
        super().__init__(self.category)


@dataclass(frozen=True, repr=False)
class SecretPublicationReceipt:
    """Minimal create-only publication receipt; it contains no secret value."""

    path: str
    version: int
    created: bool

    def __repr__(self) -> str:
        return "SecretPublicationReceipt(<redacted>)"


@dataclass(frozen=True, repr=False)
class TenantIdentityBinding:
    tenant_key: str
    environment: str
    secret_path: str
    secret_version: int
    revision: int
    expected_identity_proof: MapitIdentityProof = field(repr=False)

    def __repr__(self) -> str:
        return "TenantIdentityBinding(<redacted>)"


class SQLiteIdentityBindingRegistry:
    """Explicit SQLite registry for one authority, environment and MAPIT config."""

    _CREATE_SQL = (
        "CREATE TABLE IF NOT EXISTS mapit_identity_bindings_v1 ("
        "tenant_key TEXT PRIMARY KEY NOT NULL,"
        "environment TEXT NOT NULL,"
        "identity_tag TEXT,"
        "secret_path TEXT NOT NULL UNIQUE,"
        "secret_version INTEGER NOT NULL,"
        "status TEXT NOT NULL CHECK(status IN ('pending','active','revoked')),"
        "revision INTEGER NOT NULL,"
        "proof_envelope BLOB,"
        "record_mac BLOB NOT NULL,"
        "UNIQUE(environment, identity_tag))"
    )

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        authority: InvitedTenantAuthority,
        durable_guard: DurableTenantGuard,
        environment: str,
        config: MapitConfig,
        verifier: MapitIdentityVerifier,
        binding_key: bytes,
        auth_transport: Callable[..., Mapping[str, Any]],
        clock: Callable[[], datetime],
    ) -> None:
        if (
            type(connection) is not sqlite3.Connection or connection.in_transaction
            or type(authority) is not InvitedTenantAuthority
            or type(durable_guard) is not DurableTenantGuard
            or not durable_guard.is_bound_to(authority)
            or type(environment) is not str or environment not in {"dev", "prod"}
            or authority.matches_environment(environment) is not True
            or type(config) is not MapitConfig
            or type(verifier) is not MapitIdentityVerifier or verifier.config is not config
            or config.email is not None or config.password is not None
            or type(binding_key) is not bytes or not 32 <= len(binding_key) <= 64
            or not callable(auth_transport) or not callable(clock)
        ):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        try:
            validate_cloud_config(config)
        except CloudTransportError:
            raise IdentityBindingError("identity_binding_configuration_invalid") from None
        self._connection = connection
        self._authority = authority
        self._durable_guard = durable_guard
        self._environment = environment
        self._config = config
        self._verifier = verifier
        self._binding_key = bytes(binding_key)
        self._auth_transport = auth_transport
        self._clock = clock
        self._lock = threading.RLock()
        self._verify_schema()

    @classmethod
    def initialize(
        cls,
        connection: sqlite3.Connection,
        **kwargs: Any,
    ) -> "SQLiteIdentityBindingRegistry":
        """Explicitly create the fixed table, then return a validated registry."""
        if type(connection) is not sqlite3.Connection or connection.in_transaction:
            raise IdentityBindingError("identity_binding_configuration_invalid")
        try:
            connection.execute(cls._CREATE_SQL)
            connection.commit()
        except Exception:
            try:
                connection.rollback()
            except Exception:
                pass
            raise IdentityBindingError("identity_binding_store_failed") from None
        return cls(connection, **kwargs)

    def __repr__(self) -> str:
        return "SQLiteIdentityBindingRegistry(<redacted>)"

    @property
    def environment(self) -> str:
        return self._environment

    @property
    def config(self) -> MapitConfig:
        return self._config

    @property
    def verifier(self) -> MapitIdentityVerifier:
        return self._verifier

    def is_bound_to(self, authority: Any, durable_guard: Any) -> bool:
        return authority is self._authority and durable_guard is self._durable_guard

    def _verify_schema(self) -> None:
        try:
            columns = self._connection.execute(f"PRAGMA table_info({_TABLE})").fetchall()
            expected = [
                ("tenant_key", "TEXT"), ("environment", "TEXT"), ("identity_tag", "TEXT"),
                ("secret_path", "TEXT"), ("secret_version", "INTEGER"), ("status", "TEXT"),
                ("revision", "INTEGER"), ("proof_envelope", "BLOB"), ("record_mac", "BLOB"),
            ]
            if (
                [(row[1], row[2].upper()) for row in columns] != expected
                or any(row[3] != 1 for row in columns if row[1] != "identity_tag" and row[1] != "proof_envelope")
                or sum(1 for row in columns if row[5] != 0) != 1
                or columns[0][5] != 1
            ):
                raise ValueError
            unique_sets: set[tuple[str, ...]] = set()
            for index in self._connection.execute(f"PRAGMA index_list({_TABLE})").fetchall():
                if index[2] == 1:
                    if index[4] != 0:
                        raise ValueError
                    index_name = index[1]
                    if type(index_name) is not str or not index_name:
                        raise ValueError
                    quoted_index = index_name.replace('"', '""')
                    cols = self._connection.execute(f'PRAGMA index_info("{quoted_index}")').fetchall()
                    unique_sets.add(tuple(row[2] for row in cols))
            if unique_sets != {("tenant_key",), ("secret_path",), ("environment", "identity_tag")}:
                raise ValueError
            self._connection.execute(f"PRAGMA busy_timeout = 0")
            self._connection.execute(f"SELECT * FROM {_TABLE} LIMIT 0")
        except Exception:
            raise IdentityBindingError("identity_binding_configuration_invalid") from None

    def _authorize(self, grant: Any, snapshot: Any) -> str:
        try:
            self._authority.validate(grant)
            key = grant.key
            if type(key) is not str or _TENANT_KEY.fullmatch(key) is None:
                raise ValueError
            if type(snapshot) is not DurableTenantSnapshot or snapshot.key != key:
                raise ValueError
            self._durable_guard.check(grant, snapshot)
            self._authority.validate(grant)
            return key
        except Exception:
            raise IdentityBindingError("identity_binding_unauthorized") from None

    def _path(self, key: str) -> str:
        return f"/honda-mapit-mcp/{self._environment}/tenants/{key}/mapit-refresh-token"

    def _canonical(self, values: list[Any]) -> bytes:
        return json.dumps(values, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")

    def _row_mac(
        self,
        tenant_key: str,
        environment: str,
        identity_tag: str | None,
        secret_path: str,
        secret_version: int,
        status: str,
        revision: int,
        envelope: bytes | None,
    ) -> bytes:
        envelope_digest = None if envelope is None else hashlib.sha256(envelope).hexdigest()
        payload = self._canonical([
            tenant_key, environment, identity_tag, secret_path, secret_version,
            status, revision, envelope_digest,
        ])
        return hmac.new(self._binding_key, b"mapit-identity-row-v1\0" + payload, hashlib.sha256).digest()

    def _identity_tag(self, proof: MapitIdentityProof) -> str:
        payload = self._canonical([self._environment, proof.issuer, proof.subject_digest.hex()])
        return hmac.new(self._binding_key, b"mapit-identity-unique-v1\0" + payload, hashlib.sha256).hexdigest()

    def _read_row(self, tenant_key: str) -> tuple[Any, ...] | None:
        try:
            row = self._connection.execute(
                f"SELECT tenant_key, environment, identity_tag, secret_path, secret_version, status, revision, proof_envelope, record_mac FROM {_TABLE} WHERE tenant_key = ?",
                (tenant_key,),
            ).fetchone()
        except Exception:
            raise IdentityBindingError("identity_binding_store_failed") from None
        if row is None:
            return None
        try:
            key, env, tag, path, version, status, revision, envelope, mac = row
            if (
                type(key) is not str or _TENANT_KEY.fullmatch(key) is None
                or type(env) is not str or env not in {"dev", "prod"}
                or (tag is not None and (type(tag) is not str or _HEX64.fullmatch(tag) is None))
                or type(path) is not str or path != f"/honda-mapit-mcp/{env}/tenants/{key}/mapit-refresh-token"
                or type(version) is not int or version != 1
                or type(status) is not str or status not in {"pending", "active", "revoked"}
                or type(revision) is not int or revision < 1
                or (envelope is not None and type(envelope) is not bytes)
                or type(mac) is not bytes or len(mac) != 32
            ):
                raise ValueError
            expected = self._row_mac(key, env, tag, path, version, status, revision, envelope)
            if not hmac.compare_digest(mac, expected):
                raise ValueError
            if status == "active" and (tag is None or envelope is None):
                raise ValueError
            return row
        except Exception:
            raise IdentityBindingError("identity_binding_integrity_failed") from None

    def _begin_pending(self, key: str, path: str) -> None:
        with self._lock:
            if self._connection.in_transaction:
                raise IdentityBindingError("identity_binding_store_failed")
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                if self._read_row(key) is not None:
                    self._connection.rollback()
                    raise IdentityBindingError("identity_binding_exists")
                count = self._connection.execute(f"SELECT COUNT(*) FROM {_TABLE}").fetchone()
                if type(count[0]) is not int or count[0] >= _MAX_RECORDS:
                    self._connection.rollback()
                    raise IdentityBindingError("identity_binding_capacity_exhausted")
                mac = self._row_mac(key, self._environment, None, path, 1, "pending", 1, None)
                self._connection.execute(
                    f"INSERT INTO {_TABLE}(tenant_key, environment, identity_tag, secret_path, secret_version, status, revision, proof_envelope, record_mac) VALUES (?, ?, NULL, ?, 1, 'pending', 1, NULL, ?)",
                    (key, self._environment, path, mac),
                )
                self._connection.commit()
            except IdentityBindingError:
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
                raise IdentityBindingError("identity_binding_store_failed") from None

    def _prepare_proof(self, key: str, proof: MapitIdentityProof) -> None:
        try:
            self._verifier.validate_proof(proof)
            tag = self._identity_tag(proof)
            path = self._path(key)
            envelope = self._verifier.export_proof(
                proof, environment=self._environment, tenant_key=key,
                secret_path=path, secret_version=1,
            )
        except Exception:
            raise IdentityBindingError("identity_binding_identity_invalid") from None
        with self._lock:
            try:
                if self._connection.in_transaction:
                    raise ValueError
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._read_row(key)
                if row is None or row[5] != "pending" or row[6] != 1 or row[2] is not None or row[7] is not None:
                    raise ValueError
                mac = self._row_mac(key, self._environment, tag, path, 1, "pending", 2, envelope)
                changed = self._connection.execute(
                    f"UPDATE {_TABLE} SET identity_tag=?, revision=2, proof_envelope=?, record_mac=? WHERE tenant_key=? AND status='pending' AND revision=1",
                    (tag, envelope, mac, key),
                ).rowcount
                if changed != 1:
                    raise ValueError
                self._connection.commit()
            except sqlite3.IntegrityError:
                try:
                    self._connection.rollback()
                except Exception:
                    pass
                raise IdentityBindingError("identity_binding_identity_in_use") from None
            except IdentityBindingError:
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
                raise IdentityBindingError("identity_binding_store_failed") from None

    def enroll(
        self,
        grant: AuthenticatedTenant,
        snapshot: DurableTenantSnapshot,
        refresh_token: str,
        *,
        publisher: Any,
    ) -> TenantIdentityBinding:
        """Enroll one verified identity and publish its token once, create-only.

        A pending row is committed before authentication/publication. Any
        interrupted or ambiguous attempt remains non-active and cannot replay.
        The publisher is injected and must implement bounded, single-attempt
        create-only publication plus exact readback; this method makes no claim
        about remote-store atomicity.
        """
        key = self._authorize(grant, snapshot)
        try:
            token_size = len(refresh_token.encode("utf-8", errors="strict")) if type(refresh_token) is str else 0
            publisher_method = getattr(publisher, "publish", None)
        except Exception:
            raise IdentityBindingError("identity_binding_configuration_invalid") from None
        if (
            type(refresh_token) is not str or not refresh_token or token_size > _MAX_REFRESH_TOKEN_BYTES
            or any(ord(char) < 32 or ord(char) == 127 for char in refresh_token)
            or not callable(publisher_method)
        ):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        path = self._path(key)
        self._begin_pending(key, path)
        self._authorize(grant, snapshot)
        try:
            def explicit_transport(url: str, headers: Mapping[str, str], payload: Mapping[str, Any]) -> Mapping[str, Any]:
                return self._auth_transport(url, headers, payload)

            authenticator = CognitoAuthenticator(
                self._config, transport=explicit_transport,
                identity_verifier=self._verifier, clock=self._clock,
            )
            session = authenticator.authenticate_with_refresh_token(refresh_token)
            if (
                type(session) is not MapitSession or type(session.refresh_token) is not str
                or session.refresh_token != refresh_token
            ):
                raise IdentityBindingError("identity_binding_identity_invalid")
            proof = session.identity_proof
            if type(proof) is not MapitIdentityProof:
                raise IdentityBindingError("identity_binding_identity_invalid")
            self._verifier.validate_proof(proof)
        except IdentityBindingError:
            raise
        except MapitIdentityError:
            raise IdentityBindingError("identity_binding_identity_invalid") from None
        except Exception:
            raise IdentityBindingError("identity_binding_auth_failed") from None
        self._authorize(grant, snapshot)
        self._prepare_proof(key, proof)
        self._authorize(grant, snapshot)
        try:
            receipt = publisher_method(
                path=path, version=1, refresh_token=refresh_token, create_only=True,
            )
        except Exception:
            raise IdentityBindingError("identity_binding_publication_unknown") from None
        if (
            type(receipt) is not SecretPublicationReceipt
            or type(receipt.path) is not str or receipt.path != path
            or type(receipt.version) is not int or receipt.version != 1
            or type(receipt.created) is not bool or receipt.created is not True
        ):
            raise IdentityBindingError("identity_binding_receipt_invalid")
        self._authorize(grant, snapshot)
        self._activate(key)
        self._authorize(grant, snapshot)
        return self.get_binding(grant, snapshot)

    def _activate(self, key: str) -> None:
        with self._lock:
            try:
                if self._connection.in_transaction:
                    raise ValueError
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._read_row(key)
                if row is None or row[5] != "pending" or row[6] != 2 or row[2] is None or row[7] is None:
                    raise ValueError
                mac = self._row_mac(key, row[1], row[2], row[3], row[4], "active", 3, row[7])
                changed = self._connection.execute(
                    f"UPDATE {_TABLE} SET status='active', revision=3, record_mac=? WHERE tenant_key=? AND status='pending' AND revision=2",
                    (mac, key),
                ).rowcount
                if changed != 1:
                    raise ValueError
                self._connection.commit()
            except IdentityBindingError:
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
                raise IdentityBindingError("identity_binding_store_failed") from None

    def get_binding(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot) -> TenantIdentityBinding:
        key = self._authorize(grant, snapshot)
        with self._lock:
            if self._connection.in_transaction:
                raise IdentityBindingError("identity_binding_store_failed")
            row = self._read_row(key)
        if row is None:
            raise IdentityBindingError("identity_binding_not_active")
        if row[5] == "revoked":
            raise IdentityBindingError("identity_binding_revoked")
        if row[5] != "active" or row[7] is None:
            raise IdentityBindingError("identity_binding_not_active")
        try:
            proof = self._verifier.restore_proof(
                row[7], environment=self._environment, tenant_key=key,
                secret_path=row[3], secret_version=row[4],
            )
            if row[2] != self._identity_tag(proof):
                raise ValueError
        except Exception:
            raise IdentityBindingError("identity_binding_integrity_failed") from None
        self._authorize(grant, snapshot)
        return TenantIdentityBinding(key, self._environment, row[3], row[4], row[6], proof)

    def validate_binding(
        self,
        grant: AuthenticatedTenant,
        snapshot: DurableTenantSnapshot,
        binding: TenantIdentityBinding,
    ) -> None:
        """Revalidate an active binding and its revision against durable state."""
        key = self._authorize(grant, snapshot)
        if (
            type(binding) is not TenantIdentityBinding
            or binding.tenant_key != key
            or binding.environment != self._environment
            or binding.secret_path != self._path(key)
            or type(binding.secret_version) is not int or binding.secret_version != 1
            or type(binding.revision) is not int or binding.revision < 1
            or type(binding.expected_identity_proof) is not MapitIdentityProof
        ):
            raise IdentityBindingError("identity_binding_unauthorized")
        with self._lock:
            if self._connection.in_transaction:
                raise IdentityBindingError("identity_binding_store_failed")
            row = self._read_row(key)
        if row is None or row[5] != "active" or row[6] != binding.revision or row[7] is None:
            raise IdentityBindingError("identity_binding_revoked")
        try:
            stored_proof = self._verifier.restore_proof(
                row[7], environment=self._environment, tenant_key=key,
                secret_path=row[3], secret_version=row[4],
            )
            if row[2] != self._identity_tag(stored_proof):
                raise ValueError
            self._verifier.ensure_continuity(binding.expected_identity_proof, stored_proof)
        except Exception:
            raise IdentityBindingError("identity_binding_integrity_failed") from None
        self._authorize(grant, snapshot)

    def revoke(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot) -> None:
        """Permanently tombstone an existing binding; never deletes its secret."""
        key = self._authorize(grant, snapshot)
        with self._lock:
            try:
                if self._connection.in_transaction:
                    raise ValueError
                self._connection.execute("BEGIN IMMEDIATE")
                row = self._read_row(key)
                if row is None:
                    self._connection.rollback()
                    raise IdentityBindingError("identity_binding_not_active")
                if row[5] == "revoked":
                    self._connection.rollback()
                    raise IdentityBindingError("identity_binding_revoked")
                mac = self._row_mac(key, row[1], row[2], row[3], row[4], "revoked", row[6] + 1, row[7])
                changed = self._connection.execute(
                    f"UPDATE {_TABLE} SET status='revoked', revision=?, record_mac=? WHERE tenant_key=? AND revision=?",
                    (row[6] + 1, mac, key, row[6]),
                ).rowcount
                if changed != 1:
                    raise ValueError
                self._connection.commit()
            except IdentityBindingError:
                raise
            except Exception:
                try:
                    self._connection.rollback()
                except Exception:
                    pass
                raise IdentityBindingError("identity_binding_store_failed") from None
        self._authorize(grant, snapshot)


__all__ = [
    "IdentityBindingError", "SecretPublicationReceipt", "TenantIdentityBinding",
    "SQLiteIdentityBindingRegistry",
]
