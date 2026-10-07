"""Injected shared DynamoDB backend for opted-in MAPIT identity bindings.

This module constructs no AWS SDK client and creates no table. Callers must
inject one-attempt, bounded, same-account clients for the dedicated identity
binding table; it must not be the existing tenant-authorization table. A single
revisioned document keeps the maximum sixteen records, unique identity claims,
and pending/revoked tombstones in one conditional write domain. This is a
preparation backend, not evidence of deployed IAM or table configuration.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
import hashlib
import hmac
import json
import math
import re
import threading
import time
from datetime import datetime
from typing import Any, Callable

from .auth import CognitoAuthenticator, MapitSession
from .cloud_transport import CloudTransportError, validate_cloud_config
from .config import MapitConfig
from .durable_tenants import DurableTenantGuard, DurableTenantSnapshot
from .identity_binding import (
    IdentityBindingError,
    SecretPublicationReceipt,
    TenantIdentityBinding,
)
from .mapit_identity import MapitIdentityError, MapitIdentityProof, MapitIdentityVerifier
from .tenant_router import AuthenticatedTenant, InvitedTenantAuthority

_TABLE_ARN = re.compile(r"arn:aws:dynamodb:eu-west-1:([0-9]{12}):table/honda-mapit-mcp-(dev|prod)-identity-bindings\Z")
_TENANT_KEY = re.compile(r"tenant-[0-9a-f]{64}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_DECIMAL = re.compile(r"(?:0|[1-9][0-9]{0,17})\Z")
_TABLE_KEY = "identity-bindings-v1"
_MAX_RECORDS = 16
_MAX_DOCUMENT_BYTES = 96 * 1024
_MAX_REFRESH_TOKEN_BYTES = 4096
_MAX_CALL_WINDOW_SECONDS = 14.0


class DynamoDBIdentityBindingRegistry:
    """Registry-compatible CAS store over one fixed DynamoDB document item.

    Strong reads and conditional writes are single-attempt. Any ambiguous
    write is surfaced without retry; a later invocation may only proceed after
    a fresh read proves whether the tombstone was committed. Conditional
    conflicts are not retried by this object. This layout requires a dedicated
    table with string partition key ``key`` and IAM access to only the fixed
    ``identity-bindings-v1`` item; it does not reuse authorization-table IAM.
    """

    def __init__(
        self,
        reader: Any,
        writer: Any = None,
        *,
        table_arn: str,
        account_id: str,
        authority: InvitedTenantAuthority,
        durable_guard: DurableTenantGuard,
        environment: str,
        config: MapitConfig,
        verifier: MapitIdentityVerifier,
        binding_key: bytes,
        auth_transport: Callable[..., Mapping[str, Any]],
        clock: Callable[[], datetime],
        deadline: float,
        account_verifier: Callable[[Any, str], bool] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        match = _TABLE_ARN.fullmatch(table_arn) if type(table_arn) is str else None
        if (
            match is None or type(account_id) is not str or match.group(1) != account_id
            or type(environment) is not str or match.group(2) != environment
            or type(authority) is not InvitedTenantAuthority
            or type(durable_guard) is not DurableTenantGuard
            or not durable_guard.is_bound_to(authority)
            or authority.matches_environment(environment) is not True
            or type(config) is not MapitConfig
            or type(verifier) is not MapitIdentityVerifier or verifier.config is not config
            or config.email is not None or config.password is not None
            or type(binding_key) is not bytes or not 32 <= len(binding_key) <= 64
            or not callable(auth_transport) or not callable(clock) or not callable(monotonic)
            or type(deadline) not in (int, float) or not math.isfinite(deadline)
            or (writer is not None and not callable(account_verifier))
            or (writer is None and account_verifier is not None and not callable(account_verifier))
        ):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        try:
            validate_cloud_config(config)
            getter = getattr(reader, "get_item", None)
            putter = getattr(writer, "put_item", None)
        except Exception:
            raise IdentityBindingError("identity_binding_configuration_invalid") from None
        if (not callable(getter) or (writer is not None and not callable(putter))
            or not self._client_is_bounded(reader)
            or (writer is not None and not self._client_is_bounded(writer))):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        self._reader, self._writer = reader, writer
        self._table_arn, self._account_id = table_arn, account_id
        self._authority, self._durable_guard = authority, durable_guard
        self._environment, self._config = environment, config
        self._verifier, self._binding_key = verifier, bytes(binding_key)
        self._auth_transport, self._clock = auth_transport, clock
        self._account_verifier = account_verifier
        self._account_verification_attempted = False
        self._account_verified = writer is None
        # Once a PutItem dispatch has an uncertain outcome, this instance may
        # not issue another write. A new instance needs an operator-approved
        # reconciliation decision; a missing immediate read is not proof that
        # an earlier request can no longer commit.
        self._write_outcome_unknown = False
        self._lock = threading.RLock()
        self._monotonic = monotonic
        self._deadline = float(deadline)
        self._last_clock: float | None = None
        self._check_clock()
        if self._deadline - self._last_clock > _MAX_CALL_WINDOW_SECONDS:
            raise IdentityBindingError("identity_binding_deadline_invalid")
        # Validate any existing state before accepting the object.
        self._read_document()

    @staticmethod
    def _client_is_bounded(client: Any) -> bool:
        try:
            meta = client.meta
            config = meta.config
            return (
                meta.service_model.service_name == "dynamodb"
                and meta.region_name == "eu-west-1"
                and meta.endpoint_url == "https://dynamodb.eu-west-1.amazonaws.com"
                and isinstance(config.retries, Mapping)
                and type(config.retries.get("total_max_attempts")) is int
                and config.retries.get("total_max_attempts") == 1
                and all(type(value) in (int, float) and math.isfinite(value) and 0 < value <= 3
                        for value in (config.connect_timeout, config.read_timeout))
            )
        except Exception:
            return False

    def _check_clock(self) -> float:
        try:
            now = self._monotonic()
            if type(now) not in (int, float) or not math.isfinite(now) or now < 0:
                raise ValueError
            now = float(now)
        except Exception:
            raise IdentityBindingError("identity_binding_clock_invalid") from None
        if self._last_clock is not None and now < self._last_clock:
            raise IdentityBindingError("identity_binding_clock_rollback")
        self._last_clock = now
        if now >= self._deadline:
            raise IdentityBindingError("identity_binding_deadline_expired")
        return now

    def __repr__(self) -> str:
        return "DynamoDBIdentityBindingRegistry(<redacted>)"

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

    @staticmethod
    def _status(response: Any, expected: int = 200) -> Mapping[str, Any]:
        if not isinstance(response, Mapping):
            raise IdentityBindingError("identity_binding_store_failed")
        metadata = response.get("ResponseMetadata")
        if (not isinstance(metadata, Mapping)
            or type(metadata.get("HTTPStatusCode")) is not int
            or metadata.get("HTTPStatusCode") != expected):
            raise IdentityBindingError("identity_binding_store_failed")
        return response

    @staticmethod
    def _attribute(item: Mapping[str, Any], name: str, kind: str) -> Any:
        value = item.get(name)
        if not isinstance(value, Mapping) or set(value) != {kind} or type(value[kind]) is not str:
            raise ValueError
        return value[kind]

    @staticmethod
    def _canonical(value: Any) -> bytes:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")

    def _row_mac(self, row: Mapping[str, Any]) -> str:
        envelope = row["proof_envelope"]
        digest = None if envelope is None else hashlib.sha256(envelope).hexdigest()
        context = self._canonical([self._table_arn, self._account_id, self._environment])
        values = [
            row["tenant_key"], row["environment"], row["identity_tag"], row["secret_path"],
            row["secret_version"], row["status"], row["revision"], digest,
        ]
        return hmac.new(
            self._binding_key,
            b"mapit-identity-row-v2\0" + context + b"\0" + self._canonical(values),
            hashlib.sha256,
        ).hexdigest()

    def _identity_tag(self, proof: MapitIdentityProof) -> str:
        payload = self._canonical([self._environment, proof.issuer, proof.subject_digest.hex()])
        return hmac.new(self._binding_key, b"mapit-identity-unique-v1\0" + payload, hashlib.sha256).hexdigest()

    def _document_mac(self, revision: int, payload: str) -> str:
        context = self._canonical([self._table_arn, self._account_id, self._environment])
        body = (
            b"mapit-identity-document-v2\0" + context + b"\0"
            + str(revision).encode("ascii") + b"\0" + payload.encode("ascii")
        )
        return hmac.new(self._binding_key, body, hashlib.sha256).hexdigest()

    def _decode_document(self, item: Any) -> tuple[int, dict[str, dict[str, Any]]]:
        if item is None:
            return 0, {}
        if not isinstance(item, Mapping) or set(item) != {"key", "revision", "payload", "mac"}:
            raise ValueError
        if self._attribute(item, "key", "S") != _TABLE_KEY:
            raise ValueError
        revision_text = self._attribute(item, "revision", "N")
        if _DECIMAL.fullmatch(revision_text) is None or revision_text == "0":
            raise ValueError
        revision = int(revision_text)
        payload = self._attribute(item, "payload", "S")
        mac = self._attribute(item, "mac", "S")
        if len(payload.encode("ascii", errors="strict")) > _MAX_DOCUMENT_BYTES or _HEX64.fullmatch(mac) is None:
            raise ValueError
        if not hmac.compare_digest(mac, self._document_mac(revision, payload)):
            raise ValueError
        parsed = json.loads(payload, object_pairs_hook=self._unique_object)
        if (type(parsed) is not dict or set(parsed) != {"records", "schema"}
            or type(parsed["schema"]) is not int or parsed["schema"] != 1
            or type(parsed["records"]) is not list):
            raise ValueError
        if self._canonical(parsed).decode("ascii") != payload or len(parsed["records"]) > _MAX_RECORDS:
            raise ValueError
        records: dict[str, dict[str, Any]] = {}
        paths: set[str] = set()
        tags: set[tuple[str, str]] = set()
        for row in parsed["records"]:
            if type(row) is not dict or set(row) != {
                "tenant_key", "environment", "identity_tag", "secret_path", "secret_version",
                "status", "revision", "proof_envelope", "record_mac",
            }:
                raise ValueError
            key = row["tenant_key"]
            env = row["environment"]
            tag = row["identity_tag"]
            path = row["secret_path"]
            version, state, row_revision = row["secret_version"], row["status"], row["revision"]
            encoded_envelope, row_mac = row["proof_envelope"], row["record_mac"]
            if (
                type(key) is not str or _TENANT_KEY.fullmatch(key) is None
                or type(env) is not str or env != self._environment
                or (tag is not None and (type(tag) is not str or _HEX64.fullmatch(tag) is None))
                or type(path) is not str or path != f"/honda-mapit-mcp/{env}/tenants/{key}/mapit-refresh-token"
                or type(version) is not int or version != 1
                or type(state) is not str or state not in {"pending", "active", "revoked"}
                or type(row_revision) is not int or row_revision not in {1, 2, 3, 4}
                or (encoded_envelope is not None and type(encoded_envelope) is not str)
                or type(row_mac) is not str or _HEX64.fullmatch(row_mac) is None
                or key in records or path in paths
            ):
                raise ValueError
            envelope = None
            if encoded_envelope is not None:
                envelope = base64.urlsafe_b64decode(encoded_envelope + "=" * (-len(encoded_envelope) % 4))
                if base64.urlsafe_b64encode(envelope).decode("ascii").rstrip("=") != encoded_envelope or len(envelope) > 4096:
                    raise ValueError
            normalized = dict(row)
            normalized["proof_envelope"] = envelope
            if row_mac != self._row_mac(normalized):
                raise ValueError
            if (state == "pending" and row_revision == 1 and (tag is not None or envelope is not None)):
                raise ValueError
            if (state == "pending" and row_revision == 2 and (tag is None or envelope is None)):
                raise ValueError
            if (state == "active" and (row_revision != 3 or tag is None or envelope is None)):
                raise ValueError
            if (state == "revoked" and (
                row_revision not in {2, 3, 4}
                or (row_revision == 2 and (tag is not None or envelope is not None))
                or (row_revision > 2 and (tag is None or envelope is None))
            )):
                raise ValueError
            if tag is not None:
                identity = (env, tag)
                if identity in tags:
                    raise ValueError
                tags.add(identity)
            records[key] = normalized
            paths.add(path)
        return revision, records

    @staticmethod
    def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def _read_document(self) -> tuple[int, dict[str, dict[str, Any]]]:
        try:
            self._check_clock()
            response = self._status(self._reader.get_item(
                TableName=self._table_arn, Key={"key": {"S": _TABLE_KEY}},
                ConsistentRead=True, ReturnConsumedCapacity="NONE",
            ))
            self._check_clock()
            if set(response) - {"ResponseMetadata", "Item"}:
                raise ValueError
            return self._decode_document(response.get("Item"))
        except IdentityBindingError:
            raise
        except Exception:
            raise IdentityBindingError("identity_binding_integrity_failed") from None

    def _write_document(self, old_revision: int, records: dict[str, dict[str, Any]]) -> None:
        if self._write_outcome_unknown:
            raise IdentityBindingError("identity_binding_store_failed")
        if not callable(getattr(self._writer, "put_item", None)):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        if type(old_revision) is not int or not 0 <= old_revision < 10**18 - 1:
            raise IdentityBindingError("identity_binding_capacity_exhausted")
        revision = old_revision + 1
        rows = []
        for record in sorted(records.values(), key=lambda row: row["tenant_key"]):
            row = dict(record)
            envelope = row["proof_envelope"]
            row["proof_envelope"] = None if envelope is None else base64.urlsafe_b64encode(envelope).decode("ascii").rstrip("=")
            row["record_mac"] = self._row_mac(record)
            rows.append(row)
        payload = self._canonical({"records": rows, "schema": 1}).decode("ascii")
        if len(payload.encode("ascii")) > _MAX_DOCUMENT_BYTES:
            raise IdentityBindingError("identity_binding_capacity_exhausted")
        item = {
            "key": {"S": _TABLE_KEY}, "revision": {"N": str(revision)},
            "payload": {"S": payload}, "mac": {"S": self._document_mac(revision, payload)},
        }
        request: dict[str, Any] = {
            "TableName": self._table_arn, "Item": item,
            "ReturnValues": "NONE", "ReturnConsumedCapacity": "NONE",
        }
        if old_revision == 0:
            request["ConditionExpression"] = "attribute_not_exists(#pk)"
            request["ExpressionAttributeNames"] = {"#pk": "key"}
        else:
            request["ConditionExpression"] = "#revision = :revision"
            request["ExpressionAttributeNames"] = {"#revision": "revision"}
            request["ExpressionAttributeValues"] = {":revision": {"N": str(old_revision)}}
        try:
            self._ensure_writer_account()
            self._check_clock()
            self._write_outcome_unknown = True
            response = self._status(self._writer.put_item(**request))
            self._check_clock()
            if set(response) != {"ResponseMetadata"}:
                raise ValueError
            self._write_outcome_unknown = False
        except IdentityBindingError:
            raise
        except Exception as exc:
            try:
                error = getattr(exc, "response", None)
            except Exception:
                error = None
            if (
                isinstance(error, Mapping) and isinstance(error.get("Error"), Mapping)
                and error["Error"].get("Code") == "ConditionalCheckFailedException"
                and isinstance(error.get("ResponseMetadata"), Mapping)
                and type(error["ResponseMetadata"].get("HTTPStatusCode")) is int
                and error["ResponseMetadata"].get("HTTPStatusCode") == 400
            ):
                # DynamoDB's conditional failure response is the one known
                # no-commit outcome; later fresh mutations may proceed.
                self._write_outcome_unknown = False
                raise IdentityBindingError("identity_binding_exists") from None
            raise IdentityBindingError("identity_binding_store_failed") from None

    def _ensure_writer_account(self) -> None:
        if self._account_verified:
            return
        if self._account_verification_attempted or not callable(self._account_verifier):
            raise IdentityBindingError("identity_binding_unauthorized")
        self._account_verification_attempted = True
        self._check_clock()
        try:
            verified = self._account_verifier(self._writer, self._account_id) is True
        except Exception:
            verified = False
        self._check_clock()
        if not verified:
            raise IdentityBindingError("identity_binding_unauthorized")
        self._account_verified = True

    def _authorize(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot) -> str:
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

    def _record(self, key: str, tag: str | None, path: str, state: str, revision: int, envelope: bytes | None) -> dict[str, Any]:
        record = {
            "tenant_key": key, "environment": self._environment, "identity_tag": tag,
            "secret_path": path, "secret_version": 1, "status": state,
            "revision": revision, "proof_envelope": envelope,
        }
        record["record_mac"] = self._row_mac(record)
        return record

    def _mutate(
        self,
        updater: Callable[[int, dict[str, dict[str, Any]]], None],
        *,
        grant: AuthenticatedTenant,
        snapshot: DurableTenantSnapshot,
    ) -> None:
        if not callable(getattr(self._writer, "put_item", None)):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        with self._lock:
            if self._write_outcome_unknown:
                raise IdentityBindingError("identity_binding_store_failed")
            revision, records = self._read_document()
            updater(revision, records)
            self._ensure_writer_account()
            self._authorize(grant, snapshot)
            self._write_document(revision, records)

    def enroll(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot,
               refresh_token: str, *, publisher: Any) -> TenantIdentityBinding:
        if not callable(getattr(self._writer, "put_item", None)):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        key = self._authorize(grant, snapshot)
        try:
            token_size = len(refresh_token.encode("utf-8", errors="strict")) if type(refresh_token) is str else 0
            publish = getattr(publisher, "publish", None)
        except Exception:
            raise IdentityBindingError("identity_binding_configuration_invalid") from None
        if (type(refresh_token) is not str or not refresh_token or token_size > _MAX_REFRESH_TOKEN_BYTES
            or any(ord(char) < 32 or ord(char) == 127 for char in refresh_token) or not callable(publish)):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        path = self._path(key)

        def reserve(revision: int, records: dict[str, dict[str, Any]]) -> None:
            if key in records:
                raise IdentityBindingError("identity_binding_exists")
            if len(records) >= _MAX_RECORDS:
                raise IdentityBindingError("identity_binding_capacity_exhausted")
            records[key] = self._record(key, None, path, "pending", 1, None)

        self._mutate(reserve, grant=grant, snapshot=snapshot)
        self._authorize(grant, snapshot)
        try:
            def explicit_transport(url: str, headers: Mapping[str, str], payload: Mapping[str, Any]) -> Mapping[str, Any]:
                self._check_clock()
                response = self._auth_transport(url, headers, payload)
                self._check_clock()
                return response

            session = CognitoAuthenticator(
                self._config, transport=explicit_transport, identity_verifier=self._verifier,
                clock=self._clock,
            ).authenticate_with_refresh_token(refresh_token)
            if (type(session) is not MapitSession or type(session.refresh_token) is not str
                or session.refresh_token != refresh_token or type(session.identity_proof) is not MapitIdentityProof):
                raise IdentityBindingError("identity_binding_identity_invalid")
            proof = session.identity_proof
            self._verifier.validate_proof(proof)
        except IdentityBindingError:
            raise
        except MapitIdentityError:
            raise IdentityBindingError("identity_binding_identity_invalid") from None
        except Exception:
            raise IdentityBindingError("identity_binding_auth_failed") from None
        self._authorize(grant, snapshot)
        try:
            envelope = self._verifier.export_proof(
                proof, environment=self._environment, tenant_key=key,
                secret_path=path, secret_version=1,
            )
            tag = self._identity_tag(proof)
        except Exception:
            raise IdentityBindingError("identity_binding_identity_invalid") from None

        def prepare(revision: int, records: dict[str, dict[str, Any]]) -> None:
            row = records.get(key)
            if row is None or row["status"] != "pending" or row["revision"] != 1:
                raise IdentityBindingError("identity_binding_exists")
            if any((other["environment"], other["identity_tag"]) == (self._environment, tag)
                   for other in records.values() if other["identity_tag"] is not None):
                raise IdentityBindingError("identity_binding_identity_in_use")
            records[key] = self._record(key, tag, path, "pending", 2, envelope)

        self._mutate(prepare, grant=grant, snapshot=snapshot)
        self._authorize(grant, snapshot)
        self._check_clock()
        try:
            receipt = publish(path=path, version=1, refresh_token=refresh_token, create_only=True)
        except Exception:
            raise IdentityBindingError("identity_binding_publication_unknown") from None
        self._check_clock()
        if (type(receipt) is not SecretPublicationReceipt or type(receipt.path) is not str
            or receipt.path != path or type(receipt.version) is not int or receipt.version != 1
            or type(receipt.created) is not bool or receipt.created is not True):
            raise IdentityBindingError("identity_binding_receipt_invalid")
        self._authorize(grant, snapshot)

        def activate(revision: int, records: dict[str, dict[str, Any]]) -> None:
            row = records.get(key)
            if row is None or row["status"] != "pending" or row["revision"] != 2:
                raise IdentityBindingError("identity_binding_not_active")
            records[key] = self._record(key, row["identity_tag"], path, "active", 3, row["proof_envelope"])

        self._mutate(activate, grant=grant, snapshot=snapshot)
        self._authorize(grant, snapshot)
        return self.get_binding(grant, snapshot)

    def get_binding(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot) -> TenantIdentityBinding:
        key = self._authorize(grant, snapshot)
        _revision, records = self._read_document()
        row = records.get(key)
        if row is None:
            raise IdentityBindingError("identity_binding_not_active")
        if row["status"] == "revoked":
            raise IdentityBindingError("identity_binding_revoked")
        if row["status"] != "active" or row["proof_envelope"] is None:
            raise IdentityBindingError("identity_binding_not_active")
        try:
            proof = self._verifier.restore_proof(
                row["proof_envelope"], environment=self._environment, tenant_key=key,
                secret_path=row["secret_path"], secret_version=row["secret_version"],
            )
            if row["identity_tag"] != self._identity_tag(proof):
                raise ValueError
        except Exception:
            raise IdentityBindingError("identity_binding_integrity_failed") from None
        self._authorize(grant, snapshot)
        self._check_clock()
        return TenantIdentityBinding(key, self._environment, row["secret_path"], row["secret_version"], row["revision"], proof)

    def validate_binding(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot,
                         binding: TenantIdentityBinding) -> None:
        key = self._authorize(grant, snapshot)
        if (type(binding) is not TenantIdentityBinding or binding.tenant_key != key
            or binding.environment != self._environment or binding.secret_path != self._path(key)
            or type(binding.secret_version) is not int or binding.secret_version != 1
            or type(binding.revision) is not int or binding.revision < 1
            or type(binding.expected_identity_proof) is not MapitIdentityProof):
            raise IdentityBindingError("identity_binding_unauthorized")
        _revision, records = self._read_document()
        row = records.get(key)
        if row is None or row["status"] != "active" or row["revision"] != binding.revision:
            raise IdentityBindingError("identity_binding_revoked")
        try:
            proof = self._verifier.restore_proof(
                row["proof_envelope"], environment=self._environment, tenant_key=key,
                secret_path=row["secret_path"], secret_version=1,
            )
            if row["identity_tag"] != self._identity_tag(proof):
                raise ValueError
            self._verifier.ensure_continuity(binding.expected_identity_proof, proof)
        except Exception:
            raise IdentityBindingError("identity_binding_integrity_failed") from None
        self._authorize(grant, snapshot)
        self._check_clock()

    def revoke(self, grant: AuthenticatedTenant, snapshot: DurableTenantSnapshot) -> None:
        if not callable(getattr(self._writer, "put_item", None)):
            raise IdentityBindingError("identity_binding_configuration_invalid")
        key = self._authorize(grant, snapshot)

        def tombstone(revision: int, records: dict[str, dict[str, Any]]) -> None:
            row = records.get(key)
            if row is None:
                raise IdentityBindingError("identity_binding_not_active")
            if row["status"] == "revoked":
                raise IdentityBindingError("identity_binding_revoked")
            next_revision = row["revision"] + 1
            records[key] = self._record(
                key, row["identity_tag"], row["secret_path"], "revoked",
                next_revision, row["proof_envelope"],
            )

        self._mutate(tombstone, grant=grant, snapshot=snapshot)
        self._authorize(grant, snapshot)


__all__ = ["DynamoDBIdentityBindingRegistry"]
